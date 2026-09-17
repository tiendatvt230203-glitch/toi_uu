#ifndef CORE_INTERFACE_H
#define CORE_INTERFACE_H

#include "../core_types.h"

int core_interface_open(struct core_interfaces *, const struct app_config *);
void core_interface_close(struct core_interfaces *);
#endif
