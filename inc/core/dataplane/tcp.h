#ifndef CORE_TCP_H
#define CORE_TCP_H
#include <stdint.h>
#include "../core_types.h"
int core_tcp_handle(struct core_runtime *, void *packet,
                    uint32_t *packet_length);
int core_tcp_clamp_mss(struct core_runtime *, void *packet,
                       uint32_t *packet_length);
int core_tcp_encrypt(struct core_runtime *, int policy_id,
                     void *packet, uint32_t *packet_length);
int core_tcp_decrypt(struct core_runtime *, int policy_id,
                     void *packet, uint32_t *packet_length);
int core_tcp_select_wan(struct core_runtime *, const void *packet,
                        uint32_t packet_length);
int core_tcp_bond(struct core_runtime *, void *packet,
                  uint32_t *packet_length);
#endif
