#ifndef CORE_LAN_H
#define CORE_LAN_H
#include <stdint.h>
#include "../core_types.h"
int core_lan_process(const struct app_config *cfg, uint8_t *pkt,
                     uint32_t *len, uint32_t capacity, uint8_t ip_protocol,
                     uint8_t core_id, uint8_t *second, uint32_t *second_len,
                     uint8_t *wan_idx);
#endif
