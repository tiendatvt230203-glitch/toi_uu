#ifndef CORE_WAN_H
#define CORE_WAN_H
#include <stdint.h>
#include "../core_types.h"
int core_wan_process(const struct app_config *cfg, uint8_t *pkt,
                     uint32_t *len);
#endif
