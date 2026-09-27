#ifndef CORE_L2_PQC_CRYPTO_H
#define CORE_L2_PQC_CRYPTO_H
#include <stdint.h>
#include "../core_types.h"
int core_l2_pqc_fragment(struct ne_pair *pair, struct ne_packet *pkt,
                         uint16_t wire_type, uint8_t policy_id,
                         uint8_t core_id, const uint8_t key[32],
                         struct core_packet_batch *out);
int core_l2_pqc_reassemble(struct ne_pair *pair, struct ne_packet *pkt,
                           uint16_t wire_type);
void core_l2_pqc_reassembly_reset(struct ne_pair *pair);
int core_l2_pqc_encrypt(struct ne_pair *pair, struct ne_packet *pkt,
                        uint16_t wire_type, uint8_t policy_id,
                        uint8_t core_id, const uint8_t key[32]);
int core_l2_pqc_decrypt(struct ne_pair *pair, struct ne_packet *pkt,
                        uint16_t wire_type, const uint8_t key[32]);
#endif
