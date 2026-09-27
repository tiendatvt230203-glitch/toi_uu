#ifndef CORE_WAN_H
#define CORE_WAN_H
#include "../core_types.h"
int core_wan_process(const struct app_config *cfg, struct ne_pair *pair,
                     struct ne_packet *pkt);
#endif
