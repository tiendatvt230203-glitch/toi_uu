#ifndef CORE_L2_PQC_CRYPTO_H
#define CORE_L2_PQC_CRYPTO_H
#include <stdint.h>
int core_l2_pqc_encrypt(int policy_id, void *ethernet_frame,
                        uint32_t *frame_length);
int core_l2_pqc_decrypt(int policy_id, void *ethernet_frame,
                        uint32_t *frame_length);
#endif
