#include "../../../inc/core/interface/interface.h"

int core_interface_open(struct core_interfaces *interfaces,
                        const struct app_config *config)
{
    (void)interfaces;
    (void)config;
    return 0;
}

void core_interface_close(struct core_interfaces *interfaces)
{
    (void)interfaces;
}
