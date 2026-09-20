#ifndef CORE_UDP_H
#define CORE_UDP_H
#include <stdint.h>
#include "../core_types.h"
int core_udp_handle_lan_wan();
int core_udp_handle_wan_lan(const struct app_config *cfg, uint8_t *pkt, uint32_t *len);
#endif
