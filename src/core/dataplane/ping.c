#include "../../../inc/core/dataplane/ping.h"

int core_ping_handle(struct core_runtime *runtime, void *packet,
                     uint32_t *packet_length)
{
    (void)runtime;
    (void)packet;
    (void)packet_length;
    return 0;
}

int core_ping_fragment(struct core_runtime *runtime, void *packet,
                       uint32_t packet_length)
{
    (void)runtime;
    (void)packet;
    (void)packet_length;
    return 0;
}

int core_ping_reassemble(struct core_runtime *runtime, void *packet,
                         uint32_t *packet_length)
{
    (void)runtime;
    (void)packet;
    (void)packet_length;
    return 0;
}
