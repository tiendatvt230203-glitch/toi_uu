#include "../../../inc/core/runtime/runtime.h"

int core_runtime_init(struct core_runtime *runtime,
                      const struct app_config *config)
{
    (void)runtime;
    (void)config;
    return 0;
}

int core_runtime_run(struct core_runtime *runtime)
{
    (void)runtime;
    return 0;
}

void core_runtime_stop(struct core_runtime *runtime)
{
    (void)runtime;
}

void core_runtime_cleanup(struct core_runtime *runtime)
{
    (void)runtime;
}
