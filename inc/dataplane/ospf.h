#ifndef CORE_OSPF_H
#define CORE_OSPF_H
#include "../core_types.h"
int core_ospf_handle_lan_wan(const struct app_config *cfg,
    struct ne_pair *pair, struct ne_packet *pkt, uint8_t policy_id,
    uint8_t core_id, struct core_packet_batch *out);
int core_ospf_handle_wan_lan(const struct app_config *cfg,
    struct ne_pair *pair, struct ne_packet *pkt);
#endif
