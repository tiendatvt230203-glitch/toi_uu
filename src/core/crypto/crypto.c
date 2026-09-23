#include "../../../inc/crypto/crypto.h"

#include "../../../inc/core_types.h"
#include "scrypt.h"

#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>

static pthread_once_t g_cipher_once = PTHREAD_ONCE_INIT;
static int g_cipher_ready;
static __thread uint8_t g_nonce_salt[8];
static __thread uint32_t g_nonce_counter;

static void core_cipher_init(void)
{
    g_cipher_ready = scrypt_Init() == 0;
}

static int core_nonce(uint8_t nonce[12])
{
    if (!g_nonce_counter || ++g_nonce_counter == 0) {
        if (scrypt_RandomBytes(g_nonce_salt, sizeof(g_nonce_salt)) != 0)
            return -EIO;
        g_nonce_counter = 1;
    }
    memcpy(nonce, g_nonce_salt, sizeof(g_nonce_salt));
    memcpy(nonce + sizeof(g_nonce_salt), &g_nonce_counter,
           sizeof(g_nonce_counter));
    return 0;
}


int core_l2_pqc_encrypt(uint8_t *pkt, uint32_t *len, uint32_t capacity,
                        uint16_t type, uint8_t policy, uint8_t core,
                        const uint8_t key[32])
{
    if (!pkt || !len || !key || *len < 34 || *len > ETH_FRAME_MAX ||
        capacity < *len + 30 || !policy || core >= CORE_TX_WORKERS ||
        pkt[12] != 8 || pkt[13]) return -EINVAL;
    pthread_once(&g_cipher_once, core_cipher_init);
    uint8_t nonce[12], aad[16];
    if (!g_cipher_ready || core_nonce(nonce)) return -EIO;
    uint32_t bytes = *len - 14;
    pkt[12] = type >> 8; pkt[13] = type;
    memcpy(aad, pkt, 14); aad[14] = policy; aad[15] = core;
    SCryptCipherCtx *ctx = scrypt_CipherCtxNew();
    if (!ctx) return -ENOMEM;
    word32 written = 0, final = 0, tag_len = 16;
    int rc = -EIO;
    if (scrypt_CipherInit(ctx, CIPHER_TYPE_AES_256_GCM, key, 32, nonce, 12, SCRYPT_ENCRYPTION) ||
        scrypt_CipherSetTagSize(ctx, 16) ||
        scrypt_CipherUpdateAAD(ctx, aad, sizeof(aad)) ||
        scrypt_CipherUpdate(ctx, pkt + 14, bytes, pkt + 14, &written) ||
        scrypt_CipherFinal(ctx, pkt + 14 + written, &final) ||
        written + final != bytes ||
        scrypt_CipherGetTag(ctx, pkt + 14 + bytes, &tag_len) || tag_len != 16) goto done;
    memcpy(pkt + *len + 16, nonce, 12);
    pkt[*len + 28] = policy; pkt[*len + 29] = core;
    *len += 30;
    rc = 0;
done:
    scrypt_CipherCtxFree(ctx);
    return rc;
}

int core_l2_pqc_decrypt(uint8_t *pkt, uint32_t *len, uint32_t capacity,
                        uint16_t type, const uint8_t key[32])
{
    if (!pkt || !len || !key || *len < 64 || *len > capacity ||
        *len > CORE_ENCRYPTED_FRAME_MAX || pkt[12] != (uint8_t)(type >> 8) ||
        pkt[13] != (uint8_t)type || pkt[*len-1] >= CORE_TX_WORKERS ||
        !pkt[*len-2]) return -EINVAL;
    pthread_once(&g_cipher_once, core_cipher_init);
    if (!g_cipher_ready) return -EIO;
    uint32_t bytes = *len - 44;
    uint8_t aad[16];
    memcpy(aad, pkt, 14); aad[14] = pkt[*len-2]; aad[15] = pkt[*len-1];
    SCryptCipherCtx *ctx = scrypt_CipherCtxNew();
    if (!ctx) return -ENOMEM;
    word32 written = 0, final = 0;
    int rc = -EBADMSG;
    if (scrypt_CipherInit(ctx, CIPHER_TYPE_AES_256_GCM, key, 32,
                         pkt + *len - 14, 12, SCRYPT_DECRYPTION) ||
        scrypt_CipherSetTagSize(ctx, 16) ||
        scrypt_CipherUpdateAAD(ctx, aad, sizeof(aad)) ||
        scrypt_CipherSetTag(ctx, pkt + 14 + bytes, 16) ||
        scrypt_CipherUpdate(ctx, pkt + 14, bytes, pkt + 14, &written) ||
        scrypt_CipherFinal(ctx, pkt + 14 + written, &final) ||
        written + final != bytes) goto done;
    *len -= 30; pkt[12] = 8; pkt[13] = 0;
    rc = 0;
done:
    scrypt_CipherCtxFree(ctx);
    return rc;
}

static atomic_uint g_jumbo_id = 1;
static _Thread_local struct core_fragment_slot *g_jumbo_slots;

static uint16_t jumbo_get16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static void jumbo_put16(uint8_t *p, uint16_t value)
{
    p[0] = value >> 8; p[1] = value;
}

int core_l2_pqc_fragment(const uint8_t *pkt, uint32_t len,
                          uint16_t type, uint8_t policy, uint8_t core,
                          const uint8_t key[32], struct core_packet_batch *out)
{
    if (!pkt || !out || len > ETH_FRAME_MAX) return -EINVAL;
    uint8_t encrypted[CORE_ENCRYPTED_FRAME_MAX], wire[ETH_FRAME_MAX];
    memcpy(encrypted, pkt, len);
    memset(out, 0, sizeof(*out));
    int rc = core_l2_pqc_encrypt(encrypted, &len, sizeof(encrypted), type, policy, core, key);
    if (rc) return rc;
    unsigned frames = len > ETH_FRAME_MAX ? 2 : 1;
    uint32_t id = frames == 2 ? atomic_fetch_add(&g_jumbo_id, 1) : 0;
    uint32_t total = len - 15, offset = 0;
    for (unsigned frame = 0; frame < frames; frame++) {
        uint32_t wire_len;
        if (frames == 1) {
            memcpy(wire, encrypted, len); wire_len = len;
        } else {
            uint32_t bytes = total - offset;
            if (!frame) {
                bytes -= 29;
                if (bytes > CORE_JUMBO_DATA_MAX) bytes = CORE_JUMBO_DATA_MAX;
            }
            memcpy(wire, encrypted, 14);
            memcpy(wire + 14, encrypted + 14 + offset, bytes);
            uint8_t *shim = wire + 14 + bytes;
            memcpy(shim, "JMB\2", 4);
            shim[4] = id >> 24; shim[5] = id >> 16;
            shim[6] = id >> 8; shim[7] = id;
            jumbo_put16(shim + 8, total); jumbo_put16(shim + 10, offset);
            jumbo_put16(shim + 12, bytes);
            shim[14] = frame; shim[15] = 2;
            wire_len = 14 + bytes + CORE_JUMBO_HEADER_SIZE;
            wire[wire_len - 1] = core | CORE_JUMBO_FLAG;
            offset += bytes;
        }
        for (uint32_t pos = 0; pos < wire_len;) {
            unsigned seg = out->count++;
            if (seg >= NE_PACKET_MAX_SEGMENTS) return -EMSGSIZE;
            uint32_t bytes = wire_len - pos;
            if (bytes > NE_FRAME_DATA_MAX) bytes = NE_FRAME_DATA_MAX;
            memcpy(out->data[seg], wire + pos, bytes);
            out->len[seg] = bytes; pos += bytes;
            out->end_of_packet[seg] = pos == wire_len;
        }
    }
    out->packet_count = frames;
    return 0;
}

void core_l2_pqc_reassembly_reset(void)
{
    free(g_jumbo_slots); g_jumbo_slots = NULL;
}

int core_l2_pqc_reassemble(uint8_t *pkt, uint32_t *len, uint32_t capacity,
                            uint16_t type)
{
    if (!pkt || !len || *len < 60 || *len > ETH_FRAME_MAX || *len > capacity ||
        pkt[12] != (uint8_t)(type >> 8) || pkt[13] != (uint8_t)type) return -EINVAL;
    uint8_t core = pkt[*len - 1];
    if ((core & CORE_JUMBO_CORE_MASK) >= CORE_TX_WORKERS) return -EINVAL;
    if (!(core & CORE_JUMBO_FLAG)) return *len >= 64 ? 0 : -EBADMSG;
    uint8_t *shim = pkt + *len - CORE_JUMBO_HEADER_SIZE;
    if (memcmp(shim, "JMB\2", 4)) return -EBADMSG;
    uint32_t id = ((uint32_t)shim[4] << 24) | ((uint32_t)shim[5] << 16) |
                  ((uint32_t)shim[6] << 8) | shim[7];
    uint16_t total = jumbo_get16(shim + 8), offset = jumbo_get16(shim + 10);
    uint16_t bytes = jumbo_get16(shim + 12);
    uint8_t index = shim[14];
    if (shim[15] != 2 || index > 1 || total + 15u <= ETH_FRAME_MAX ||
        total + 15u > CORE_ENCRYPTED_FRAME_MAX || total + 15u > capacity ||
        !bytes || bytes > CORE_JUMBO_DATA_MAX || offset + bytes > total ||
        *len != 14u + bytes + CORE_JUMBO_HEADER_SIZE) return -EBADMSG;
    if (!g_jumbo_slots) {
        if (index) return -EBADMSG;
        g_jumbo_slots = calloc(CORE_JUMBO_SLOTS, sizeof(*g_jumbo_slots));
        if (!g_jumbo_slots) return -ENOMEM;
    }
    struct core_fragment_slot *slot = &g_jumbo_slots[id % CORE_JUMBO_SLOTS];
    core &= CORE_JUMBO_CORE_MASK;
    if (slot->active && (slot->id != id || slot->core_id != core ||
                         memcmp(slot->ethernet, pkt, 14))) return -ENOSPC;
    if (!slot->active) {
        if (index || offset) return -EBADMSG;
        slot->id = id; slot->core_id = core; slot->total = total; slot->received = 0;
        memcpy(slot->ethernet, pkt, 14);
    }
    if (slot->total != total || index != slot->active || offset != slot->received ||
        (!index && bytes > total - 29u) || (index && offset + bytes != total)) {
        memset(slot, 0, sizeof(*slot)); return -EBADMSG;
    }
    memcpy(slot->data + offset, pkt + 14, bytes);
    slot->received += bytes; slot->active = 1;
    if (!index) return 1;
    memcpy(pkt, slot->ethernet, 14); memcpy(pkt + 14, slot->data, total);
    pkt[14 + total] = core; *len = 15 + total;
    memset(slot, 0, sizeof(*slot));
    return 0;
}
