#include "../../../inc/core/dataplane/bypass.h"

#include <errno.h>

int core_bypass_handle_wan_lan(const struct app_config *cfg,
                               uint8_t *pkt, uint32_t *len)
{
    (void)cfg;
    (void)pkt;
    (void)len;
    return -ENOSYS;
}
