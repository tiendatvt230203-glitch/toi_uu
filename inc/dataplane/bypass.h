#ifndef CORE_BYPASS_H
#define CORE_BYPASS_H

#include "../core_types.h"

int core_bypass_handle_lan_wan(const struct app_config *cfg,
                               const uint8_t *pkt, uint32_t len,
                               uint8_t *wan_idx);
int core_bypass_handle_wan_lan(const struct app_config *cfg,
                               uint8_t *pkt, uint32_t *len);

#endif
