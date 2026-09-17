#include "../../../inc/core/runtime/worker.h"

#include <errno.h>

int core_worker_start_all(struct core_runtime *runtime)
{
    (void)runtime;
    return 0;
}

void core_worker_stop_all(struct core_runtime *runtime)
{
    (void)runtime;
}

int core_worker_pin_cpu(int cpu_id)
{
    (void)cpu_id;
    return 0;
}

int core_worker_rx_submit(struct core_runtime *runtime,
                          const struct ne_packet *packet,
                          int needs_crypto, int worker_id)
{
    (void)runtime;
    (void)packet;
    (void)needs_crypto;
    (void)worker_id;
    return -ENOSYS;
}

int core_worker_crypto_step(struct core_runtime *runtime, int worker_id)
{
    (void)runtime;
    (void)worker_id;
    return -ENOSYS;
}

int core_worker_tx_step(struct core_runtime *runtime, int tx_slot)
{
    (void)runtime;
    (void)tx_slot;
    return -ENOSYS;
}
