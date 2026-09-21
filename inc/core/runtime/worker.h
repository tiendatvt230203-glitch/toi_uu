#ifndef CORE_WORKER_H
#define CORE_WORKER_H

#include "../core_types.h"

int core_worker_start_all();
void core_worker_stop_all();
int core_worker_pin_cpu();
int core_worker_select_encrypt_core(const uint8_t *pkt, uint32_t len);
int core_worker_select_tx_core(const uint8_t *pkt, uint32_t len);
int core_worker_select_decrypt_core(const uint8_t *pkt, uint32_t len);
int core_worker_rx_submit(struct core_runtime *rt, const struct ne_packet *pkt);
int core_worker_crypto_step(struct core_runtime *rt, struct ne_packet *pkt,
                            int worker_idx);
int core_worker_tx_step();
#endif
