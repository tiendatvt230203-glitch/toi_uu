#include "../../../inc/crypto/crypto.h"
#include "../../../inc/core_types.h"

#include "scrypt.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static pthread_once_t g_cipher_once = PTHREAD_ONCE_INIT;
static int g_cipher_ready;

static atomic_uint g_jumbo_id = 1;
static _Thread_local struct core_fragment_slot *g_jumbo_slots;


/* =========================================================
 * Cipher initialization
 * ========================================================= */

static void core_cipher_init(void)
{
    g_cipher_ready = scrypt_Init() == 0;
}


/* =========================================================
 * Encrypt
 *
 * Input:
 *
 * [ ETH 14 ][ plaintext ]
 *
 * Output:
 *
 * [ ETH 14 ]
 * [ ciphertext ]
 * [ tag 16 ]
 * [ nonce 12 ]
 * [ policy 1 ]
 * [ core 1 ]
 *
 * Total overhead: 30 bytes
 * ========================================================= */

int core_l2_pqc_encrypt(uint8_t *pkt,
                        uint32_t *len,
                        uint32_t capacity,
                        uint16_t type,
                        uint8_t policy,
                        uint8_t core,
                        const uint8_t key[32])
{
    if (!pkt ||
        !len ||
        !key ||
        *len < 34 ||
        *len > ETH_FRAME_MAX ||
        capacity < *len + 30 ||
        !policy ||
        core >= CORE_TX_WORKERS ||
        pkt[12] != 8 ||
        pkt[13] != 0)
        return -EINVAL;

    pthread_once(&g_cipher_once, core_cipher_init);

    if (!g_cipher_ready)
        return -EIO;

    uint32_t original_len = *len;
    uint32_t bytes = original_len - 14;

    uint8_t *tag   = pkt + original_len;
    uint8_t *nonce = pkt + original_len + 16;

    /*
     * Sinh nonce trực tiếp vào vùng cuối packet.
     * Không cần nonce[] + memcpy().
     */
    if (scrypt_RandomBytes(nonce, 12))
        return -EIO;

    /*
     * Đổi EtherType trước khi tạo AAD.
     */
    pkt[12] = (uint8_t)(type >> 8);
    pkt[13] = (uint8_t)type;

    SCryptCipherCtx *ctx = scrypt_CipherCtxNew();

    if (!ctx)
        return -ENOMEM;

    word32 written = 0;
    word32 final = 0;
    word32 tag_len = 16;

    int rc = -EIO;

    if (scrypt_CipherInit(ctx,
                         CIPHER_TYPE_AES_256_GCM,
                         key,
                         32,
                         nonce,
                         12,
                         SCRYPT_ENCRYPTION) ||

        scrypt_CipherSetTagSize(ctx, 16) ||

        /*
         * Ethernet header dùng trực tiếp làm AAD.
         */
        scrypt_CipherUpdateAAD(ctx,
                              pkt,
                              14) ||

        /*
         * Encrypt payload trực tiếp tại chỗ.
         */
        scrypt_CipherUpdate(ctx,
                           pkt + 14,
                           bytes,
                           pkt + 14,
                           &written) ||

        scrypt_CipherFinal(ctx,
                          pkt + 14 + written,
                          &final) ||

        written + final != bytes ||

        scrypt_CipherGetTag(ctx,
                           tag,
                           &tag_len) ||

        tag_len != 16)
        goto done;

    pkt[original_len + 28] = policy;
    pkt[original_len + 29] = core;

    *len = original_len + 30;

    rc = 0;

done:
    scrypt_CipherCtxFree(ctx);
    return rc;
}


/* =========================================================
 * Decrypt
 * ========================================================= */

int core_l2_pqc_decrypt(uint8_t *pkt,
                        uint32_t *len,
                        uint32_t capacity,
                        uint16_t type,
                        const uint8_t key[32])
{
    if (!pkt ||
        !len ||
        !key ||
        *len < 64 ||
        *len > capacity ||
        *len > CORE_ENCRYPTED_FRAME_MAX ||
        pkt[12] != (uint8_t)(type >> 8) ||
        pkt[13] != (uint8_t)type ||
        pkt[*len - 1] >= CORE_TX_WORKERS ||
        !pkt[*len - 2])
        return -EINVAL;

    pthread_once(&g_cipher_once, core_cipher_init);

    if (!g_cipher_ready)
        return -EIO;

    /*
     * encrypted length:
     *
     * ETH 14
     * ciphertext bytes
     * tag 16
     * nonce 12
     * policy 1
     * core 1
     *
     * bytes = len - 44
     */
    uint32_t bytes = *len - 44;

    uint8_t *tag   = pkt + 14 + bytes;
    uint8_t *nonce = pkt + *len - 14;

    SCryptCipherCtx *ctx = scrypt_CipherCtxNew();

    if (!ctx)
        return -ENOMEM;

    word32 written = 0;
    word32 final = 0;

    int rc = -EBADMSG;

    if (scrypt_CipherInit(ctx,
                         CIPHER_TYPE_AES_256_GCM,
                         key,
                         32,
                         nonce,
                         12,
                         SCRYPT_DECRYPTION) ||

        scrypt_CipherSetTagSize(ctx, 16) ||

        scrypt_CipherUpdateAAD(ctx,
                              pkt,
                              14) ||

        scrypt_CipherSetTag(ctx,
                           tag,
                           16) ||

        /*
         * Decrypt in-place.
         */
        scrypt_CipherUpdate(ctx,
                           pkt + 14,
                           bytes,
                           pkt + 14,
                           &written) ||

        scrypt_CipherFinal(ctx,
                          pkt + 14 + written,
                          &final) ||

        written + final != bytes)
        goto done;

    *len -= 30;

    /*
     * Restore IPv4 EtherType.
     */
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    rc = 0;

done:
    scrypt_CipherCtxFree(ctx);
    return rc;
}


/* =========================================================
 * Jumbo helpers
 * ========================================================= */

static uint16_t jumbo_get16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) |
           (uint16_t)p[1];
}

static void jumbo_put16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}


/*
 * Không memset toàn bộ slot->data[] vì vùng data có thể lớn.
 *
 * Khi active == 0, các field còn lại được xem là invalid.
 */
static inline void jumbo_slot_reset(struct core_fragment_slot *slot)
{
    slot->active = 0;
    slot->received = 0;
}


/* =========================================================
 * Output batching
 * ========================================================= */

struct core_emit_part {
    const uint8_t *data;
    uint32_t len;
};


/*
 * Copy một logical Ethernet frame trực tiếp vào
 * core_packet_batch.
 *
 * Không cần wire[] trung gian.
 */
static int core_batch_emit_frame(struct core_packet_batch *out,
                                 const struct core_emit_part *parts,
                                 unsigned part_count)
{
    if (!out || !parts || !part_count)
        return -EINVAL;

    uint32_t frame_len = 0;

    for (unsigned i = 0; i < part_count; i++)
        frame_len += parts[i].len;

    if (!frame_len)
        return -EINVAL;

    uint32_t needed =
        (frame_len + NE_FRAME_DATA_MAX - 1u) /
        NE_FRAME_DATA_MAX;

    if (out->count + needed > NE_PACKET_MAX_SEGMENTS)
        return -EMSGSIZE;

    uint32_t seg = out->count;
    uint32_t used = 0;

    for (unsigned i = 0; i < part_count; i++) {

        const uint8_t *src = parts[i].data;
        uint32_t left = parts[i].len;

        while (left) {

            if (used == NE_FRAME_DATA_MAX) {

                out->len[seg] = used;
                out->end_of_packet[seg] = 0;

                seg++;
                used = 0;
            }

            uint32_t room =
                NE_FRAME_DATA_MAX - used;

            uint32_t copy =
                left < room ? left : room;

            memcpy(out->data[seg] + used,
                   src,
                   copy);

            src += copy;
            left -= copy;
            used += copy;
        }
    }

    out->len[seg] = used;
    out->end_of_packet[seg] = 1;

    out->count += needed;
    out->packet_count++;

    return 0;
}


/* =========================================================
 * Fragment
 *
 * pkt bị encrypt trực tiếp.
 *
 * Không còn:
 *
 *   pkt -> encrypted[]
 *   encrypted[] -> wire[]
 *   wire[] -> out
 *
 * Mà thành:
 *
 *   pkt -> encrypt in-place
 *       -> out
 * ========================================================= */

int core_l2_pqc_fragment(uint8_t *pkt,
                         uint32_t len,
                         uint32_t capacity,
                         uint16_t type,
                         uint8_t policy,
                         uint8_t core,
                         const uint8_t key[32],
                         struct core_packet_batch *out)
{
    if (!pkt ||
        !out ||
        len > ETH_FRAME_MAX ||
        capacity < len + 30)
        return -EINVAL;

    /*
     * Không memset(out, 0, sizeof(*out)).
     *
     * data[][] không cần zero.
     * Chỉ reset metadata cần thiết.
     */
    out->count = 0;
    out->packet_count = 0;

    /*
     * Encrypt trực tiếp trên pkt.
     */
    int rc = core_l2_pqc_encrypt(pkt,
                                 &len,
                                 capacity,
                                 type,
                                 policy,
                                 core,
                                 key);

    if (rc)
        return rc;

    /*
     * Sau encrypt vẫn <= ETH_FRAME_MAX:
     * không cần jumbo fragmentation.
     */
    if (len <= ETH_FRAME_MAX) {

        struct core_emit_part part = {
            .data = pkt,
            .len = len
        };

        return core_batch_emit_frame(out,
                                     &part,
                                     1);
    }

    /*
     * Jumbo encrypted layout:
     *
     * [ETH 14]
     * [DATA total]
     * [core 1]
     *
     * total không bao gồm:
     *
     * ETH header
     * final core byte
     */
    uint32_t total = len - 15u;
    uint32_t offset = 0;

    uint32_t id =
        atomic_fetch_add(&g_jumbo_id, 1);

    for (unsigned frame = 0; frame < 2; frame++) {

        uint32_t bytes =
            total - offset;

        /*
         * Frame #0 phải chừa dữ liệu cho frame #1.
         */
        if (frame == 0) {

            bytes -= 29u;

            if (bytes > CORE_JUMBO_DATA_MAX)
                bytes = CORE_JUMBO_DATA_MAX;
        }

        /*
         * Đảm bảo Ethernet frame sau fragment
         * không vượt ETH_FRAME_MAX.
         */
        if (14u + bytes + CORE_JUMBO_HEADER_SIZE >
            ETH_FRAME_MAX)
            return -EMSGSIZE;

        uint8_t shim[CORE_JUMBO_HEADER_SIZE];

        /*
         * Shim nhỏ nên memset ở đây không đáng kể.
         * Đồng thời tránh gửi byte chưa initialize nếu
         * CORE_JUMBO_HEADER_SIZE có padding.
         */
        memset(shim, 0, sizeof(shim));

        memcpy(shim, "JMB\2", 4);

        shim[4] = (uint8_t)(id >> 24);
        shim[5] = (uint8_t)(id >> 16);
        shim[6] = (uint8_t)(id >> 8);
        shim[7] = (uint8_t)id;

        jumbo_put16(shim + 8,
                    (uint16_t)total);

        jumbo_put16(shim + 10,
                    (uint16_t)offset);

        jumbo_put16(shim + 12,
                    (uint16_t)bytes);

        shim[14] = (uint8_t)frame;
        shim[15] = 2;

        /*
         * Metadata xử lý đầu tiên được đặt cuối frame.
         */
        shim[CORE_JUMBO_HEADER_SIZE - 1] =
            core | CORE_JUMBO_FLAG;

        /*
         * Frame được tạo trực tiếp từ 3 vùng:
         *
         * Ethernet header
         * encrypted payload slice
         * jumbo shim
         */
        struct core_emit_part parts[3] = {
            {
                .data = pkt,
                .len = 14
            },
            {
                .data = pkt + 14 + offset,
                .len = bytes
            },
            {
                .data = shim,
                .len = CORE_JUMBO_HEADER_SIZE
            }
        };

        rc = core_batch_emit_frame(out,
                                   parts,
                                   3);

        if (rc)
            return rc;

        offset += bytes;
    }

    /*
     * Hai fragment phải cover đúng toàn bộ payload.
     */
    if (offset != total)
        return -EMSGSIZE;

    return 0;
}


/* =========================================================
 * Reassembly reset
 * ========================================================= */

void core_l2_pqc_reassembly_reset(void)
{
    free(g_jumbo_slots);
    g_jumbo_slots = NULL;
}


/* =========================================================
 * Reassembly
 *
 * Frame #0:
 *      lưu payload vào slot
 *
 * Frame #1:
 *      payload đang nằm ngay trong pkt
 *      -> memmove tới vị trí cuối
 *      -> copy frame #0 từ slot vào đầu
 *
 * Không còn:
 *
 *      frame #1 -> slot
 *      toàn slot -> pkt
 * ========================================================= */

int core_l2_pqc_reassemble(uint8_t *pkt,
                           uint32_t *len,
                           uint32_t capacity,
                           uint16_t type)
{
    if (!pkt ||
        !len ||
        *len < 60 ||
        *len > ETH_FRAME_MAX ||
        *len > capacity ||
        pkt[12] != (uint8_t)(type >> 8) ||
        pkt[13] != (uint8_t)type)
        return -EINVAL;

    uint8_t core =
        pkt[*len - 1];

    if ((core & CORE_JUMBO_CORE_MASK) >=
        CORE_TX_WORKERS)
        return -EINVAL;

    /*
     * Không có jumbo flag:
     * packet encrypted bình thường.
     */
    if (!(core & CORE_JUMBO_FLAG))
        return *len >= 64 ? 0 : -EBADMSG;

    /*
     * Jumbo shim nằm cuối frame.
     */
    uint8_t *shim =
        pkt + *len - CORE_JUMBO_HEADER_SIZE;

    if (memcmp(shim, "JMB\2", 4))
        return -EBADMSG;

    uint32_t id =
        ((uint32_t)shim[4] << 24) |
        ((uint32_t)shim[5] << 16) |
        ((uint32_t)shim[6] << 8) |
        (uint32_t)shim[7];

    uint16_t total =
        jumbo_get16(shim + 8);

    uint16_t offset =
        jumbo_get16(shim + 10);

    uint16_t bytes =
        jumbo_get16(shim + 12);

    uint8_t index =
        shim[14];

    if (shim[15] != 2 ||
        index > 1 ||
        total + 15u <= ETH_FRAME_MAX ||
        total + 15u > CORE_ENCRYPTED_FRAME_MAX ||
        total + 15u > capacity ||
        !bytes ||
        bytes > CORE_JUMBO_DATA_MAX ||
        (uint32_t)offset + bytes > total ||
        *len != 14u + bytes + CORE_JUMBO_HEADER_SIZE)
        return -EBADMSG;

    /*
     * Allocate slot table một lần cho mỗi thread.
     */
    if (!g_jumbo_slots) {

        /*
         * Không chấp nhận frame #1 tới trước frame #0.
         */
        if (index)
            return -EBADMSG;

        g_jumbo_slots =
            calloc(CORE_JUMBO_SLOTS,
                   sizeof(*g_jumbo_slots));

        if (!g_jumbo_slots)
            return -ENOMEM;
    }

    struct core_fragment_slot *slot =
        &g_jumbo_slots[id % CORE_JUMBO_SLOTS];

    core &= CORE_JUMBO_CORE_MASK;

    /*
     * Slot đang chứa packet khác.
     */
    if (slot->active &&
        (slot->id != id ||
         slot->core_id != core ||
         memcmp(slot->ethernet, pkt, 14)))
        return -ENOSPC;

    /*
     * Khởi tạo slot bằng frame #0.
     */
    if (!slot->active) {

        if (index || offset)
            return -EBADMSG;

        slot->id = id;
        slot->core_id = core;
        slot->total = total;
        slot->received = 0;

        /*
         * Chỉ copy Ethernet header 14 bytes.
         */
        memcpy(slot->ethernet,
               pkt,
               14);
    }

    /*
     * Verify ordering / consistency.
     */
    if (slot->total != total ||
        index != slot->active ||
        offset != slot->received ||
        (!index && bytes > total - 29u) ||
        (index &&
         (uint32_t)offset + bytes != total)) {

        jumbo_slot_reset(slot);
        return -EBADMSG;
    }

    /*
     * =====================================================
     * Fragment #0
     * =====================================================
     *
     * Bắt buộc giữ lại vì khi return,
     * RX buffer hiện tại có thể được recycle.
     */
    if (!index) {

        memcpy(slot->data,
               pkt + 14,
               bytes);

        slot->received = bytes;
        slot->active = 1;

        /*
         * 1 = đang chờ fragment tiếp theo.
         */
        return 1;
    }

    /*
     * =====================================================
     * Fragment #1
     * =====================================================
     *
     * Payload frame #1 hiện tại:
     *
     * pkt + 14
     *
     * vị trí cuối cùng cần nằm:
     *
     * pkt + 14 + offset
     *
     * Có khả năng overlap nên bắt buộc dùng memmove.
     */
    memmove(pkt + 14 + offset,
            pkt + 14,
            bytes);

    /*
     * Copy duy nhất phần frame #0 đã lưu.
     *
     * Không còn copy toàn bộ slot->data.
     */
    memcpy(pkt + 14,
           slot->data,
           offset);

    /*
     * Ethernet header của frame #1 đã được verify
     * giống frame #0 nên giữ nguyên header đang có.
     */

    pkt[14u + total] = core;

    *len = 15u + total;

    /*
     * Không memset toàn struct lớn.
     */
    jumbo_slot_reset(slot);

    return 0;
}