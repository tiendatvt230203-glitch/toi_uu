#ifndef CORE_UDP_H
#define CORE_UDP_H
#include <stdint.h>
#include "../core_types.h"
int core_udp_handle(struct core_runtime *, void *packet,
                    uint32_t *packet_length);
int core_udp_fragment(struct core_runtime *, void *packet,
                      uint32_t packet_length);
int core_udp_reassemble(struct core_runtime *, void *packet,
                        uint32_t *packet_length);
int core_udp_encrypt(struct core_runtime *, int policy_id,
                     void *packet, uint32_t *packet_length);
int core_udp_decrypt(struct core_runtime *, int policy_id,
                     void *packet, uint32_t *packet_length);
int core_udp_select_wan(struct core_runtime *, const void *packet,
                        uint32_t packet_length);
int core_udp_bond(struct core_runtime *, void *packet,
                  uint32_t *packet_length);
int core_udp_reorder(struct core_runtime *, void *packet,
                     uint32_t *packet_length);
#endif
