#ifndef CORE_RUNTIME_H
#define CORE_RUNTIME_H

#include "../core_types.h"

int core_runtime_init(struct core_runtime *, const struct app_config *);
int core_runtime_run(struct core_runtime *);
void core_runtime_stop(struct core_runtime *);
void core_runtime_cleanup(struct core_runtime *);
#endif
