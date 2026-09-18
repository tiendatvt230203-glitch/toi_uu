#ifndef CORE_WORKER_H
#define CORE_WORKER_H

#include "../core_types.h"

int core_worker_start_all();
void core_worker_stop_all();
int core_worker_pin_cpu();
int core_worker_rx_submit();
int core_worker_crypto_step();
int core_worker_tx_step();
#endif
