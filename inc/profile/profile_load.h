#ifndef CORE_PROFILE_LOAD_H
#define CORE_PROFILE_LOAD_H

#include "../core_types.h"

int core_profile_load(struct core_runtime *runtime, int profile_id);
void core_profile_unload(struct core_runtime *runtime);

#endif
