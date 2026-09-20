#ifndef CORE_L2_PQC_CRYPTO_H
#define CORE_L2_PQC_CRYPTO_H
#include <stdint.h>
int core_l2_pqc_encrypt(uint8_t *pkt, uint32_t *len, uint32_t capacity,
                        uint16_t wire_type, uint8_t policy_id,
                        uint8_t core_id, const uint8_t key[32]);
int core_l2_pqc_decrypt(uint8_t *pkt, uint32_t *len, uint32_t capacity,
                        uint16_t wire_type, const uint8_t key[32]);
#endif
