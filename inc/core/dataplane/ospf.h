#ifndef CORE_OSPF_H
#define CORE_OSPF_H

#include <stdint.h>
#include "../core_types.h"

int core_ospf_handle_lan_wan(const struct app_config *cfg, uint8_t *pkt,
                             uint32_t *len, uint32_t capacity,
                             uint8_t policy_id, uint8_t core_id,
                             uint8_t *second, uint32_t *second_len,
                             uint8_t *wan_idx);
int core_ospf_handle_wan_lan(const struct app_config *cfg, uint8_t *pkt,
                             uint32_t *len, uint32_t capacity);
int core_ospf_per_flow(const struct app_config *cfg, const uint8_t *pkt,
                       uint32_t len, uint8_t *wan_idx);
#endif
