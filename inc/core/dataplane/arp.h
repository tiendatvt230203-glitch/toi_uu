#ifndef CORE_ARP_H
#define CORE_ARP_H
#include <stdint.h>
#include "../core_types.h"
int core_arp_handle(struct core_runtime *, const void *, uint32_t);
#endif
