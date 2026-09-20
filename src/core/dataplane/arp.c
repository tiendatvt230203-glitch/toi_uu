#include "../../../inc/core/dataplane/arp.h"

#include <errno.h>

int core_arp_handle()
{
    /* ARP's separate fixed-key path is not wired yet. */
    return -ENOSYS;
}
