#ifndef CORE_LAN_H
#define CORE_LAN_H
#include <stdint.h>
#include "../core_types.h"
int core_lan_process(const struct app_config *cfg, const uint8_t *pkt,
                     uint32_t len, uint8_t ip_protocol);
#endif
