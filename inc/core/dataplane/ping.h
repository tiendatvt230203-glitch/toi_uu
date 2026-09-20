#ifndef CORE_PING_H
#define CORE_PING_H

#include <stdint.h>
#include "../core_types.h"

int core_ping_handle_lan_wan();
int core_ping_handle_wan_lan(const struct app_config *cfg, uint8_t *pkt, uint32_t *len);

#endif
