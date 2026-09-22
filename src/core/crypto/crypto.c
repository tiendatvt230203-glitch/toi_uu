#include "../../../inc/core/crypto/crypto.h"

#include "../../../inc/core/core_types.h"
#include "../../../inc/pqc/scrypt.h"

#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

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
                        uint16_t wire_type, uint8_t policy_id,
                        uint8_t core_id, const uint8_t key[32])
{
    SCryptCipherCtx *cipher;
    uint8_t nonce[12];
    word32 written = 0, final = 0, tag_len = 16;
    uint32_t plain_len;
    int rc = -EIO;

    if (!pkt || !len || !key || *len < 14 || policy_id == 0 ||
        pkt[12] != 0x08 || pkt[13] != 0x00 ||
        *len > capacity || capacity < 30u ||
        *len > capacity - 30u || *len > NE_FRAME_DATA_MAX - 30u)
        return -EMSGSIZE;
    pthread_once(&g_cipher_once, core_cipher_init);
    if (!g_cipher_ready || core_nonce(nonce) != 0)
        return -EIO;
    cipher = scrypt_CipherCtxNew();
    if (!cipher)
        return -ENOMEM;
    plain_len = *len - 14u;
    memmove(pkt + 28, pkt + 14, plain_len);
    pkt[12] = (uint8_t)(wire_type >> 8);
    pkt[13] = (uint8_t)wire_type;
    pkt[14] = policy_id;
    pkt[15] = core_id;
    memcpy(pkt + 16, nonce, sizeof(nonce));
    if (scrypt_CipherInit(cipher, CIPHER_TYPE_AES_256_GCM, key, 32,
                          nonce, sizeof(nonce), SCRYPT_ENCRYPTION) != 0 ||
        scrypt_CipherSetTagSize(cipher, 16) != 0 ||
        scrypt_CipherUpdateAAD(cipher, pkt + 12, 4) != 0 ||
        scrypt_CipherUpdate(cipher, pkt + 28, plain_len, pkt + 28,
                            &written) != 0 ||
        scrypt_CipherFinal(cipher, pkt + 28 + written, &final) != 0 ||
        scrypt_CipherGetTag(cipher, pkt + 28 + written + final,
                            &tag_len) != 0 || tag_len != 16)
        goto out;
    *len = 28u + written + final + tag_len;
    rc = 0;
out:
    scrypt_CipherCtxFree(cipher);
    return rc;
}

int core_l2_pqc_decrypt(uint8_t *pkt, uint32_t *len, uint32_t capacity,
                        uint16_t wire_type, const uint8_t key[32])
{
    SCryptCipherCtx *cipher;
    word32 written = 0, final = 0;
    uint32_t cipher_len;
    int rc = -EBADMSG;

    if (!pkt || !len || !key || *len < 28u + 16u ||
        *len > capacity || *len > NE_FRAME_DATA_MAX ||
        pkt[12] != (uint8_t)(wire_type >> 8) ||
        pkt[13] != (uint8_t)wire_type)
        return -EINVAL;
    pthread_once(&g_cipher_once, core_cipher_init);
    if (!g_cipher_ready)
        return -EIO;
    cipher = scrypt_CipherCtxNew();
    if (!cipher)
        return -ENOMEM;
    cipher_len = *len - 28u - 16u;
    if (scrypt_CipherInit(cipher, CIPHER_TYPE_AES_256_GCM, key, 32,
                          pkt + 16, 12, SCRYPT_DECRYPTION) != 0 ||
        scrypt_CipherSetTagSize(cipher, 16) != 0 ||
        scrypt_CipherUpdateAAD(cipher, pkt + 12, 4) != 0 ||
        scrypt_CipherSetTag(cipher, pkt + 28 + cipher_len, 16) != 0 ||
        scrypt_CipherUpdate(cipher, pkt + 28, cipher_len, pkt + 28,
                            &written) != 0 ||
        scrypt_CipherFinal(cipher, pkt + 28 + written, &final) != 0 ||
        written + final != cipher_len)
        goto out;
    memmove(pkt + 14, pkt + 28, cipher_len);
    pkt[12] = 0x08;
    pkt[13] = 0x00;
    *len = 14u + cipher_len;
    rc = 0;
out:
    scrypt_CipherCtxFree(cipher);
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
    p[0] = value >> 8;
    p[1] = value;
}

int core_l2_pqc_fragment(const uint8_t *pkt, uint32_t len,
                          uint16_t wire_type, uint8_t policy_id,
                          uint8_t core_id, const uint8_t key[32],
                          struct core_packet_batch *out)
{
    if (!pkt || !out || !key || len < 14 || len > ETH_FRAME_MAX ||
        core_id >= CORE_CRYPTO_WORKERS || pkt[12] != 8 || pkt[13] != 0)
        return -EINVAL;
    out->count = 0;
    if (len + 30u <= NE_FRAME_DATA_MAX) {
        memcpy(out->data[0], pkt, len);
        out->len[0] = len;
        int rc = core_l2_pqc_encrypt(out->data[0], &out->len[0],
                                     NE_FRAME_DATA_MAX, wire_type,
                                     policy_id, core_id, key);
        if (!rc) out->count = 1;
        return rc;
    }
    uint32_t room = NE_FRAME_DATA_MAX - 14u - 30u - CORE_JUMBO_SHIM_SIZE;
    uint32_t count = (len + room - 1u) / room;
    uint32_t id = atomic_fetch_add(&g_jumbo_id, 1);
    uint32_t offset = 0;
    if (count > NE_PACKET_MAX_SEGMENTS) return -EMSGSIZE;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t bytes = len - offset;
        if (bytes > room) bytes = room;
        uint8_t *wire = out->data[i], *shim = wire + 14;
        memcpy(wire, pkt, 14);
        memcpy(shim, "JMB\1", 4);
        shim[4] = id >> 24; shim[5] = id >> 16;
        shim[6] = id >> 8; shim[7] = id;
        jumbo_put16(shim + 8, len);
        jumbo_put16(shim + 10, offset);
        jumbo_put16(shim + 12, bytes);
        shim[14] = i; shim[15] = count;
        memcpy(shim + CORE_JUMBO_SHIM_SIZE, pkt + offset, bytes);
        out->len[i] = 14u + CORE_JUMBO_SHIM_SIZE + bytes;
        int rc = core_l2_pqc_encrypt(wire, &out->len[i], NE_FRAME_DATA_MAX,
                                     wire_type, policy_id,
                                     core_id | CORE_JUMBO_FLAG, key);
        if (rc) return rc;
        offset += bytes;
    }
    out->count = count;
    return 0;
}

void core_l2_pqc_reassembly_reset(void)
{
    free(g_jumbo_slots);
    g_jumbo_slots = NULL;
}

int core_l2_pqc_reassemble(uint8_t *pkt, uint32_t *len, uint32_t capacity,
                            uint16_t wire_type, const uint8_t key[32])
{
    if (!pkt || !len || *len < 16) return -EINVAL;
    uint8_t policy = pkt[14], core = pkt[15];
    if ((core & CORE_JUMBO_CORE_MASK) >= CORE_CRYPTO_WORKERS) return -EINVAL;
    int rc = core_l2_pqc_decrypt(pkt, len, capacity, wire_type, key);
    if (rc || !(core & CORE_JUMBO_FLAG)) return rc;
    if (*len < 14u + CORE_JUMBO_SHIM_SIZE) return -EBADMSG;
    uint8_t *shim = pkt + 14;
    if (memcmp(shim, "JMB\1", 4)) return -EBADMSG;
    uint32_t id = ((uint32_t)shim[4] << 24) | ((uint32_t)shim[5] << 16) |
                  ((uint32_t)shim[6] << 8) | shim[7];
    uint16_t total = jumbo_get16(shim + 8), offset = jumbo_get16(shim + 10);
    uint16_t bytes = jumbo_get16(shim + 12);
    uint8_t index = shim[14], count = shim[15];
    if (total < 14 || total > ETH_FRAME_MAX || total > capacity ||
        count < 2 || count > NE_PACKET_MAX_SEGMENTS || index >= count ||
        !bytes || offset + bytes > total ||
        *len != 14u + CORE_JUMBO_SHIM_SIZE + bytes) return -EBADMSG;
    if (!g_jumbo_slots) g_jumbo_slots = calloc(CORE_JUMBO_SLOTS, sizeof(*g_jumbo_slots));
    if (!g_jumbo_slots) return -ENOMEM;
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return -errno;
    uint64_t now = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    uint32_t hash = id ^ ((uint32_t)policy << 24) ^ wire_type;
    for (unsigned i = 6; i < 12; i++) hash = hash * 33u ^ pkt[i];
    struct core_fragment_slot *slot = NULL, *empty = NULL;
    for (unsigned i = 0; i < CORE_JUMBO_SLOTS; i++) {
        struct core_fragment_slot *s = &g_jumbo_slots[(hash + i) % CORE_JUMBO_SLOTS];
        if (s->seen && now - s->seen_ns >= CORE_JUMBO_TIMEOUT_NS)
            memset(s, 0, sizeof(*s));
        if (!s->seen) { if (!empty) empty = s; continue; }
        if (s->id == id && s->policy_id == policy && s->wire_type == wire_type &&
            s->core_id == (core & CORE_JUMBO_CORE_MASK) &&
            !memcmp(s->source_mac, pkt + 6, 6)) { slot = s; break; }
    }
    if (!slot) {
        slot = empty;
        if (!slot) return -ENOSPC;
        memset(slot, 0, sizeof(*slot));
        slot->id = id; slot->policy_id = policy; slot->wire_type = wire_type;
        slot->core_id = core & CORE_JUMBO_CORE_MASK;
        slot->total_len = total; slot->count = count;
        memcpy(slot->source_mac, pkt + 6, 6);
    }
    if (slot->total_len != total || slot->count != count) return -EBADMSG;
    if (slot->seen & (1u << index)) return -EALREADY;
    for (unsigned i = 0; i < count; i++)
        if ((slot->seen & (1u << i)) && offset < slot->offset[i] + slot->length[i] &&
            slot->offset[i] < offset + bytes) return -EBADMSG;
    memcpy(slot->data + offset, shim + CORE_JUMBO_SHIM_SIZE, bytes);
    slot->offset[index] = offset; slot->length[index] = bytes;
    slot->seen |= 1u << index;
    slot->seen_ns = now;
    if (slot->seen != (1u << count) - 1u) return 1;
    uint32_t covered = 0;
    for (unsigned i = 0; i < count; i++) covered += slot->length[i];
    if (covered != total) { memset(slot, 0, sizeof(*slot)); return -EBADMSG; }
    memcpy(pkt, slot->data, total);
    *len = total;
    memset(slot, 0, sizeof(*slot));
    return 0;
}
