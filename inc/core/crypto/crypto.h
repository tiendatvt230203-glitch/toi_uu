#ifndef CORE_L2_PQC_CRYPTO_H
#define CORE_L2_PQC_CRYPTO_H
#include <stdint.h>
#include "../core_types.h"
int core_l2_pqc_fragment(const uint8_t *pkt, uint32_t len,
                          uint16_t wire_type, uint8_t policy_id,
                          uint8_t core_id, const uint8_t key[32],
                          struct core_packet_batch *out);
/* 0: complete packet; 1: fragment stored; negative: rejected. */
int core_l2_pqc_reassemble(uint8_t *pkt, uint32_t *len, uint32_t capacity,
                            uint16_t wire_type, const uint8_t key[32]);
void core_l2_pqc_reassembly_reset(void);
int core_l2_pqc_encrypt(uint8_t *pkt, uint32_t *len, uint32_t capacity,
                        uint16_t wire_type, uint8_t policy_id,
                        uint8_t core_id, const uint8_t key[32]);
int core_l2_pqc_decrypt(uint8_t *pkt, uint32_t *len, uint32_t capacity,
                        uint16_t wire_type, const uint8_t key[32]);
#endif
