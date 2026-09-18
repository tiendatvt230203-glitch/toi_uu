#ifndef CORE_RUNTIME_H
#define CORE_RUNTIME_H

#include "../core_types.h"

int core_runtime_init();
int core_runtime_run();
void core_runtime_stop();
void core_runtime_cleanup();
#endif
