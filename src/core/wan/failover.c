#include "../../../inc/core/wan/failover.h"

#include <errno.h>

int core_wan_set_state(struct core_runtime *runtime, int wan_id, int is_up)
{
    (void)runtime;
    (void)wan_id;
    (void)is_up;
    return -ENOSYS;
}

int core_wan_is_available(struct core_runtime *runtime, int wan_id)
{
    (void)runtime;
    (void)wan_id;
    return -ENOSYS;
}

int core_wan_add(struct core_runtime *runtime, int wan_id)
{
    (void)runtime;
    (void)wan_id;
    return -ENOSYS;
}

int core_wan_remove(struct core_runtime *runtime, int wan_id)
{
    (void)runtime;
    (void)wan_id;
    return -ENOSYS;
}
