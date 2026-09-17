#ifndef CORE_PING_H
#define CORE_PING_H

#include <stdint.h>
#include "../core_types.h"

int core_ping_handle(struct core_runtime *, void *packet,
                     uint32_t *packet_length);
int core_ping_fragment(struct core_runtime *, void *packet,
                       uint32_t packet_length);
int core_ping_reassemble(struct core_runtime *, void *packet,
                         uint32_t *packet_length);

#endif
