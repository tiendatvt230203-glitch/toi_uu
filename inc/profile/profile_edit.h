#ifndef CORE_PROFILE_EDIT_H
#define CORE_PROFILE_EDIT_H

#include "../core_types.h"

int core_profile_edit_apply(struct core_runtime *runtime,
                            const struct app_config *new_config);

int core_profile_edit_lan(struct core_runtime *runtime,
                          const struct app_config *new_config);

int core_profile_edit_wan(struct core_runtime *runtime,
                          const struct app_config *new_config);

int core_profile_edit_policy(struct core_runtime *runtime,
                             const struct app_config *new_config);

int core_profile_edit_key(struct core_runtime *runtime,
                          const struct app_config *new_config);

#endif
