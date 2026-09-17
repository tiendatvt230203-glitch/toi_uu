#include "../../../inc/core/dataplane/tx.h"

int core_tx_match_in(struct core_runtime *runtime, const void *packet,
                     uint32_t packet_length, int *policy_id)
{
    (void)runtime;
    (void)packet;
    (void)packet_length;
    if (policy_id)
        *policy_id = 0;
    return 0;
}

int core_tx_match_out(struct core_runtime *runtime, const void *packet,
                      uint32_t packet_length, int *policy_id)
{
    (void)runtime;
    (void)packet;
    (void)packet_length;
    if (policy_id)
        *policy_id = 0;
    return 0;
}

int core_tx_select_wan(struct core_runtime *runtime, const void *packet,
                       uint32_t packet_length)
{
    (void)runtime;
    (void)packet;
    (void)packet_length;
    return 0;
}

int core_tx_lan(struct core_runtime *runtime, int lan_id,
                const void *packet, uint32_t packet_length)
{
    (void)runtime;
    (void)lan_id;
    (void)packet;
    (void)packet_length;
    return 0;
}

int core_tx_wan(struct core_runtime *runtime, int wan_id,
                const void *packet, uint32_t packet_length)
{
    (void)runtime;
    (void)wan_id;
    (void)packet;
    (void)packet_length;
    return 0;
}
