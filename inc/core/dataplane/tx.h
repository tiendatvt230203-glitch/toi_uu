#ifndef CORE_TX_H
#define CORE_TX_H
#include <stdint.h>
#include "../core_types.h"
int core_tx_match_in(struct core_runtime *, const void *packet,
                     uint32_t packet_length, int *policy_id);
int core_tx_match_out(struct core_runtime *, const void *packet,
                      uint32_t packet_length, int *policy_id);
int core_tx_select_wan(struct core_runtime *, const void *packet,
                       uint32_t packet_length);
int core_tx_lan(struct core_runtime *, int lan_id,
                const void *packet, uint32_t packet_length);
int core_tx_wan(struct core_runtime *, int wan_id,
                const void *packet, uint32_t packet_length);
#endif
