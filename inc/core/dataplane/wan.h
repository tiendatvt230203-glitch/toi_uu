#ifndef CORE_WAN_H
#define CORE_WAN_H
#include <stdint.h>
#include "../core_types.h"
int core_wan_receive(struct core_runtime *);
int core_wan_process(struct core_runtime *, int ip_protocol,
                     void *packet, uint32_t *packet_length);
#endif
