#include "../../../inc/core/crypto/crypto.h"

#include "../../../inc/core/core_types.h"
#include "../../../inc/pqc/scrypt.h"

#include <errno.h>
#include <pthread.h>
#include <string.h>

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

    if (!pkt || !len || !key || *len < 32 || policy_id == 0 ||
        pkt[12] != 0x08 || pkt[13] != 0x00 ||
        *len > capacity || capacity < 30u ||
        *len > capacity - 30u || *len > PATH_MTU - 30u ||
        (wire_type == NE_L2_TCP_ETHERTYPE && (pkt[14] >> 4) != 4))
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

    if (!pkt || !len || !key || *len < 28u + 16u + 18u ||
        *len > capacity || *len > PATH_MTU ||
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
        written + final != cipher_len ||
        (wire_type == NE_L2_TCP_ETHERTYPE && (pkt[28] >> 4) != 4))
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
