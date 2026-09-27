#ifndef CORE_LAN_H
#define CORE_LAN_H
#include "../core_types.h"
int core_lan_process(const struct app_config *cfg, struct ne_pair *pair,
                     struct ne_packet *pkt, uint8_t core_id,
                     struct core_packet_batch *out);
#endif
