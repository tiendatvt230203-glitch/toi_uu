#ifndef CORE_LAN_H
#define CORE_LAN_H
#include <stdint.h>
#include "../core_types.h"
int core_lan_receive(struct core_runtime *);
int core_lan_process(struct core_runtime *, int ip_protocol,
                     void *packet, uint32_t *packet_length);
#endif
