#ifndef CORE_WAN_FAILOVER_H
#define CORE_WAN_FAILOVER_H
#include "../core_types.h"
int core_wan_set_state(struct core_runtime *, int wan_id, int is_up);
int core_wan_is_available(struct core_runtime *, int wan_id);
int core_wan_add(struct core_runtime *, int wan_id);
int core_wan_remove(struct core_runtime *, int wan_id);
#endif
