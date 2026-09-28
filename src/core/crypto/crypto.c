#include "../../../inc/crypto/crypto.h"
#include "../../../inc/core_types.h"
#include "../../../inc/interface/interface.h"

#include "scrypt.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CORE_META_WITH_CORE 30u
#define CORE_META_NO_CORE 29u
#define CORE_ETH_HEADER 14u

static pthread_once_t g_cipher_once = PTHREAD_ONCE_INIT;
static int g_cipher_ready;
static atomic_uint g_jumbo_id = 1;
static _Thread_local struct core_fragment_slot *g_jumbo_slots;

static void core_cipher_init(void)
{
    g_cipher_ready = scrypt_Init() == 0;
}

static uint16_t jumbo_get16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static void jumbo_put16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static void jumbo_put32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static uint32_t jumbo_get32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void jumbo_make(uint8_t shim[CORE_JUMBO_HEADER_SIZE], uint32_t id,
                       uint16_t total, uint16_t offset, uint16_t bytes,
                       uint8_t index, uint8_t core)
{
    memcpy(shim, "JMB\2", 4);
    jumbo_put32(shim + 4, id);
    jumbo_put16(shim + 8, total);
    jumbo_put16(shim + 10, offset);
    jumbo_put16(shim + 12, bytes);
    shim[14] = index;
    shim[15] = 2;
    shim[16] = core | CORE_JUMBO_FLAG;
}

static int cipher_update_packet(SCryptCipherCtx *ctx, struct ne_pair *pair,
                                struct ne_packet *pkt, uint32_t offset,
                                uint32_t bytes)
{
    while (bytes) {
        uint32_t available;
        uint8_t *data = ne_packet_at(pair, pkt, offset, &available);
        if (!data)
            return -EMSGSIZE;
        uint32_t take = available < bytes ? available : bytes;
        word32 written = 0;
        if (scrypt_CipherUpdate(ctx, data, take, data, &written) ||
            written != take)
            return -EIO;
        offset += take;
        bytes -= take;
    }
    return 0;
}

int core_l2_pqc_encrypt(struct ne_pair *pair, struct ne_packet *pkt,
                        uint16_t type, uint8_t policy, uint8_t core,
                        const uint8_t key[32])
{
    if (!pair || !pkt || !key || pkt->total_len < 34 ||
        pkt->total_len > ETH_FRAME_MAX || !policy ||
        core >= CORE_CRYPTO_WORKERS)
        return -EINVAL;

    uint32_t contiguous;
    uint8_t *ethernet = ne_packet_at(pair, pkt, 0, &contiguous);
    if (!ethernet || contiguous < CORE_ETH_HEADER ||
        ethernet[12] != 0x08 || ethernet[13] != 0x00)
        return -EINVAL;
    pthread_once(&g_cipher_once, core_cipher_init);
    if (!g_cipher_ready)
        return -EIO;

    uint32_t plaintext_len = pkt->total_len - CORE_ETH_HEADER;
    uint8_t *meta;
    int rc = ne_packet_append_alloc(pair, pkt, CORE_META_WITH_CORE, &meta);
    if (rc)
        return rc;

#if defined(PQC_UNSAFE_FIXED_NONCE) && PQC_UNSAFE_FIXED_NONCE
    memset(meta + 16, 0, 12);
#else
    if (scrypt_RandomBytes(meta + 16, 12)) {
        ne_packet_trim_tail(pair, pkt, CORE_META_WITH_CORE);
        return -EIO;
    }
#endif

    ethernet[12] = (uint8_t)(type >> 8);
    ethernet[13] = (uint8_t)type;


    SCryptCipherCtx *ctx = scrypt_CipherCtxNew();
    if (!ctx) {
        ne_packet_trim_tail(pair, pkt, CORE_META_WITH_CORE);
        return -ENOMEM;
    }

    word32 final = 0;
    word32 tag_len = 16;
    uint8_t final_data[16];
    rc = -EIO;
    if (scrypt_CipherInit(ctx, CIPHER_TYPE_AES_256_GCM, key, 32,
                         meta + 16, 12, SCRYPT_ENCRYPTION) ||
        scrypt_CipherSetTagSize(ctx, 16) ||
        scrypt_CipherUpdateAAD(ctx, ethernet, CORE_ETH_HEADER) ||
        cipher_update_packet(ctx, pair, pkt, CORE_ETH_HEADER, plaintext_len) ||
        scrypt_CipherFinal(ctx, final_data, &final) || final != 0 ||
        scrypt_CipherGetTag(ctx, meta, &tag_len) || tag_len != 16)
        goto done;

    meta[28] = policy;
    meta[29] = core;
    rc = 0;

done:
    scrypt_CipherCtxFree(ctx);
    if (rc) {
        ethernet[12] = 0x08;
        ethernet[13] = 0x00;
        ne_packet_trim_tail(pair, pkt, CORE_META_WITH_CORE);
    }
    return rc;
}

int core_l2_pqc_decrypt(struct ne_pair *pair, struct ne_packet *pkt,
                        uint16_t type, const uint8_t key[32])
{
    if (!pair || !pkt || !key || pkt->total_len < 63 ||
        pkt->total_len > CORE_ENCRYPTED_FRAME_MAX - 1u)
        return -EINVAL;

    uint32_t contiguous;
    uint8_t *ethernet = ne_packet_at(pair, pkt, 0, &contiguous);
    if (!ethernet || contiguous < CORE_ETH_HEADER ||
        ethernet[12] != (uint8_t)(type >> 8) ||
        ethernet[13] != (uint8_t)type)
        return -EINVAL;

    uint8_t meta[CORE_META_NO_CORE];
    if (ne_packet_read(pair, pkt, pkt->total_len - CORE_META_NO_CORE,
                       meta, sizeof(meta)) || !meta[28])
        return -EINVAL;

    pthread_once(&g_cipher_once, core_cipher_init);
    if (!g_cipher_ready)
        return -EIO;

    SCryptCipherCtx *ctx = scrypt_CipherCtxNew();
    if (!ctx)
        return -ENOMEM;

    uint32_t ciphertext_len = pkt->total_len - CORE_ETH_HEADER - CORE_META_NO_CORE;
    word32 final = 0;
    uint8_t final_data[16];
    int rc = -EBADMSG;
    if (scrypt_CipherInit(ctx, CIPHER_TYPE_AES_256_GCM, key, 32,
                         meta + 16, 12, SCRYPT_DECRYPTION) ||
        scrypt_CipherSetTagSize(ctx, 16) ||
        scrypt_CipherUpdateAAD(ctx, ethernet, CORE_ETH_HEADER) ||
        scrypt_CipherSetTag(ctx, meta, 16) ||
        cipher_update_packet(ctx, pair, pkt, CORE_ETH_HEADER, ciphertext_len) ||
        scrypt_CipherFinal(ctx, final_data, &final) || final != 0)
        goto done;

    rc = ne_packet_trim_tail(pair, pkt, CORE_META_NO_CORE);
    if (!rc) {
        ethernet[12] = 0x08;
        ethernet[13] = 0x00;
    }

done:
    scrypt_CipherCtxFree(ctx);
    return rc;
}

int core_l2_pqc_fragment(struct ne_pair *pair, struct ne_packet *pkt,
                         uint16_t type, uint8_t policy, uint8_t core,
                         const uint8_t key[32], struct core_packet_batch *out)
{
    if (!pair || !pkt || !out)
        return -EINVAL;
    out->count = 0;

    int rc = core_l2_pqc_encrypt(pair, pkt, type, policy, core, key);
    if (rc)
        return rc;

    if (pkt->total_len <= ETH_FRAME_MAX) {
        out->packets[0] = *pkt;
        out->count = 1;
        memset(pkt, 0, sizeof(*pkt));
        return 0;
    }

    if (pkt->segment_count < 2)
        return -EMSGSIZE;

    uint32_t logical_len = pkt->total_len;
    uint32_t original_len = logical_len - CORE_META_WITH_CORE;
    unsigned original_segments = pkt->segment_count - 1u;
    uint32_t prefix_len = CORE_ETH_HEADER + CORE_JUMBO_DATA_MAX;
    if (prefix_len > original_len)
        prefix_len = original_len;
    if (prefix_len <= CORE_ETH_HEADER ||
        logical_len - 15u > UINT16_MAX)
        return -EMSGSIZE;

    uint64_t shim_addr, header_addr;
    if (ne_frame_alloc(pair, &shim_addr))
        return -ENOSPC;
    if (ne_frame_alloc(pair, &header_addr)) {
        ne_frame_free(pair, shim_addr);
        return -ENOSPC;
    }

    uint8_t *header = ne_packet_data(pair, header_addr);
    uint8_t *first_header = ne_packet_data(pair, pkt->segment_addr[0]);
    memcpy(header, first_header, CORE_ETH_HEADER);

    struct ne_packet *first = &out->packets[0];
    struct ne_packet *second = &out->packets[1];
    memset(first, 0, sizeof(*first));
    memset(second, 0, sizeof(*second));

    second->segment_addr[second->segment_count] = header_addr;
    second->segment_len[second->segment_count++] = CORE_ETH_HEADER;
    second->total_len = CORE_ETH_HEADER;

    uint32_t position = 0;
    uint64_t shared_addr = 0;
    for (unsigned i = 0; i < original_segments; i++) {
        uint32_t length = pkt->segment_len[i];
        uint32_t end = position + length;

        if (end <= prefix_len) {
            first->segment_addr[first->segment_count] = pkt->segment_addr[i];
            first->segment_len[first->segment_count++] = length;
            first->total_len += length;
        } else if (position >= prefix_len) {
            second->segment_addr[second->segment_count] = pkt->segment_addr[i];
            second->segment_len[second->segment_count++] = length;
            second->total_len += length;
        } else {
            uint32_t left = prefix_len - position;
            uint32_t right = length - left;
            if (first->segment_count >= NE_PACKET_MAX_SEGMENTS - 1u ||
                second->segment_count >= NE_PACKET_MAX_SEGMENTS - 1u ||
                ne_frame_ref(pair, pkt->segment_addr[i])) {
                ne_frame_free(pair, header_addr);
                ne_frame_free(pair, shim_addr);
                memset(first, 0, sizeof(*first));
                memset(second, 0, sizeof(*second));
                return -EMSGSIZE;
            }
            shared_addr = pkt->segment_addr[i];
            first->segment_addr[first->segment_count] = pkt->segment_addr[i];
            first->segment_len[first->segment_count++] = left;
            first->total_len += left;
            second->segment_addr[second->segment_count] =
                pkt->segment_addr[i] + left;
            second->segment_len[second->segment_count++] = right;
            second->total_len += right;
        }
        position = end;
    }
    if (position != original_len || first->total_len != prefix_len ||
        first->segment_count >= NE_PACKET_MAX_SEGMENTS ||
        second->segment_count >= NE_PACKET_MAX_SEGMENTS) {
        ne_frame_free(pair, header_addr);
        ne_frame_free(pair, shim_addr);
        if (shared_addr)
            ne_frame_free(pair, shared_addr);
        memset(first, 0, sizeof(*first));
        memset(second, 0, sizeof(*second));
        return -EMSGSIZE;
    }

    uint32_t id = atomic_fetch_add_explicit(&g_jumbo_id, 1,
                                             memory_order_relaxed);
    uint16_t total = (uint16_t)(logical_len - 15u);
    uint16_t first_bytes = (uint16_t)(prefix_len - CORE_ETH_HEADER);
    uint8_t *shim0 = ne_packet_data(pair, shim_addr);
    jumbo_make(shim0, id, total, 0, first_bytes, 0, core);

    uint8_t *tail = ne_packet_data(pair,
        pkt->segment_addr[pkt->segment_count - 1u]);
    jumbo_make(tail + CORE_META_NO_CORE, id, total, first_bytes,
               (uint16_t)(total - first_bytes), 1, core);
    pkt->segment_len[pkt->segment_count - 1u] =
        CORE_META_NO_CORE + CORE_JUMBO_HEADER_SIZE;

    first->segment_addr[first->segment_count] = shim_addr;
    first->segment_len[first->segment_count++] = CORE_JUMBO_HEADER_SIZE;
    first->total_len += CORE_JUMBO_HEADER_SIZE;

    unsigned meta = pkt->segment_count - 1u;
    second->segment_addr[second->segment_count] = pkt->segment_addr[meta];
    second->segment_len[second->segment_count++] = pkt->segment_len[meta];
    second->total_len += pkt->segment_len[meta];

    if (first->total_len > ETH_FRAME_MAX ||
        second->total_len > ETH_FRAME_MAX ||
        first->total_len != prefix_len + CORE_JUMBO_HEADER_SIZE ||
        second->total_len != CORE_ETH_HEADER +
            (uint32_t)(total - first_bytes) + CORE_JUMBO_HEADER_SIZE) {
        ne_packet_free(pair, first);
        ne_packet_free(pair, second);
        memset(first, 0, sizeof(*first));
        memset(second, 0, sizeof(*second));
        memset(pkt, 0, sizeof(*pkt));
        return -EMSGSIZE;
    }

    first->dir = second->dir = pkt->dir;
    first->wan_idx = second->wan_idx = pkt->wan_idx;
    first->local_idx = second->local_idx = pkt->local_idx;
    first->tx_slot = second->tx_slot = pkt->tx_slot;
    first->wire_ethertype = second->wire_ethertype = type;
    out->count = 2;
    memset(pkt, 0, sizeof(*pkt));
    return 0;
}

void core_l2_pqc_reassembly_reset(struct ne_pair *pair)
{
    if (g_jumbo_slots && pair) {
        for (unsigned i = 0; i < CORE_JUMBO_SLOTS; i++)
            if (g_jumbo_slots[i].active == 1)
                ne_packet_free(pair, &g_jumbo_slots[i].packet);
    }
    free(g_jumbo_slots);
    g_jumbo_slots = NULL;
}

static void jumbo_slot_drop(struct ne_pair *pair,
                            struct core_fragment_slot *slot)
{
    if (slot->active == 1)
        ne_packet_free(pair, &slot->packet);
    memset(slot, 0, sizeof(*slot));
}

int core_l2_pqc_reassemble(struct ne_pair *pair, struct ne_packet *pkt,
                           uint16_t type)
{
    if (!pair || !pkt || pkt->total_len < CORE_ETH_HEADER + 1u ||
        pkt->total_len > ETH_FRAME_MAX)
        return -EINVAL;

    uint8_t header[CORE_ETH_HEADER];
    uint8_t core;
    if (ne_packet_read(pair, pkt, 0, header, sizeof(header)) ||
        ne_packet_read(pair, pkt, pkt->total_len - 1u, &core, 1) ||
        header[12] != (uint8_t)(type >> 8) ||
        header[13] != (uint8_t)type ||
        (core & CORE_JUMBO_CORE_MASK) >= CORE_CRYPTO_WORKERS)
        return -EBADMSG;

    if (!(core & CORE_JUMBO_FLAG))
        return pkt->total_len >= 64u ? ne_packet_trim_tail(pair, pkt, 1) : -EBADMSG;

    if (pkt->total_len < CORE_ETH_HEADER + CORE_JUMBO_HEADER_SIZE)
        return -EBADMSG;
    uint8_t shim[CORE_JUMBO_HEADER_SIZE];
    if (ne_packet_read(pair, pkt, pkt->total_len - sizeof(shim),
                       shim, sizeof(shim)) || memcmp(shim, "JMB\2", 4) ||
        shim[15] != 2 || shim[14] > 1)
        return -EBADMSG;

    uint32_t id = jumbo_get32(shim + 4);
    uint16_t total = jumbo_get16(shim + 8);
    uint16_t offset = jumbo_get16(shim + 10);
    uint16_t bytes = jumbo_get16(shim + 12);
    uint8_t index = shim[14];
    core &= CORE_JUMBO_CORE_MASK;
    if (!bytes || (uint32_t)offset + bytes > total ||
        pkt->total_len != CORE_ETH_HEADER + bytes + CORE_JUMBO_HEADER_SIZE)
        return -EBADMSG;

    if (!g_jumbo_slots) {
        g_jumbo_slots = calloc(CORE_JUMBO_SLOTS, sizeof(*g_jumbo_slots));
        if (!g_jumbo_slots)
            return -ENOMEM;
    }

    struct core_fragment_slot *slot = &g_jumbo_slots[id % CORE_JUMBO_SLOTS];
    if (slot->active == 2) {
        if (slot->id == id)
            return -EBADMSG;
        memset(slot, 0, sizeof(*slot));
    }
    if (slot->active && (slot->id != id || slot->core_id != core ||
        slot->total != total || index != 1 || offset != slot->received)) {
        jumbo_slot_drop(pair, slot);
        slot->id = id;
        slot->active = 2;
        return -EBADMSG;
    }

    if (!index) {
        if (slot->active || offset) {
            jumbo_slot_drop(pair, slot);
            slot->id = id;
            slot->active = 2;
            return -EBADMSG;
        }
        if (ne_packet_trim_tail(pair, pkt, CORE_JUMBO_HEADER_SIZE))
            return -EBADMSG;
        slot->id = id;
        slot->total = total;
        slot->received = bytes;
        slot->core_id = core;
        slot->packet = *pkt;
        slot->active = 1;
        memset(pkt, 0, sizeof(*pkt));
        return 1;
    }

    if (!slot->active || (uint32_t)offset + bytes != total) {
        if (slot->active == 1)
            jumbo_slot_drop(pair, slot);
        slot->id = id;
        slot->active = 2;
        return -EBADMSG;
    }
    if (ne_packet_trim_tail(pair, pkt, CORE_JUMBO_HEADER_SIZE) ||
        ne_packet_trim_head(pair, pkt, CORE_ETH_HEADER)) {
        jumbo_slot_drop(pair, slot);
        return -EBADMSG;
    }
    if (ne_packet_concat(&slot->packet, pkt)) {
        jumbo_slot_drop(pair, slot);
        return -EMSGSIZE;
    }
    *pkt = slot->packet;
    memset(slot, 0, sizeof(*slot));
    return pkt->total_len == CORE_ETH_HEADER + total ? 0 : -EBADMSG;
}
