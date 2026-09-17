#include "../../../inc/core/dataplane/arp.h"

#include <errno.h>

int core_arp_handle(struct core_runtime *runtime, const void *packet,
                    uint32_t packet_length)
{
    (void)runtime;
    (void)packet;
    (void)packet_length;
    return -ENOSYS;
}
