#ifndef CORE_WORKER_H
#define CORE_WORKER_H

#include "../core_types.h"

int core_worker_start_all(struct core_runtime *);
void core_worker_stop_all(struct core_runtime *);
int core_worker_pin_cpu(int cpu_id);
int core_worker_rx_submit(struct core_runtime *, const struct ne_packet *,
                          int needs_crypto, int worker_id);
int core_worker_crypto_step(struct core_runtime *, int worker_id);
int core_worker_tx_step(struct core_runtime *, int tx_slot);
#endif
