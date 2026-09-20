#ifndef CORE_PING_H
#define CORE_PING_H

#include <stdint.h>
#include "../core_types.h"

int core_ping_handle_lan_wan(const struct app_config *cfg, uint8_t *pkt,
                             uint32_t *len, uint32_t capacity,
                             uint8_t policy_id, uint8_t core_id,
                             uint8_t *second, uint32_t *second_len,
                             uint8_t *wan_idx);
int core_ping_handle_wan_lan(const struct app_config *cfg, uint8_t *pkt,
                             uint32_t *len, uint32_t capacity);
int core_ping_per_flow(const struct app_config *cfg, const uint8_t *pkt,
                       uint32_t len, uint8_t *wan_idx);

#endif
