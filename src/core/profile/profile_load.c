#include "../../../inc/profile/profile_load.h"
#include "../../../inc/profile/profile_edit.h"
#include "../../../inc/runtime/worker.h"
#include "../../../inc/interface/interface.h"
#include "../../../inc/crypto/key_manager.h"

#include "../../../src/db/db_runtime.h"
#include "../../../src/db/db_config.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>


static int profile_validate_id(int profile_id)
{
    if (profile_id <= 0) {
        fprintf(stderr,
                "[PROFILE] invalid profile id: %d\n",
                profile_id);

        return -EINVAL;
    }

    return 0;
}


static int profile_load_from_db(struct app_config *config,
                                int profile_id)
{
    int rc;

    if (!config)
        return -EINVAL;

    memset(config, 0, sizeof(*config));

    rc = load_active_profile_config(config, profile_id);
    if (rc != 0) {
        fprintf(stderr,
                "[PROFILE] failed to load profile %d from database\n",
                profile_id);

        memset(config, 0, sizeof(*config));
        return rc;
    }

    return 0;
}


static int profile_validate_config(struct app_config *config)
{
    int rc;

    if (!config)
        return -EINVAL;

    if (config->profile_id <= 0) {
        fprintf(stderr,
                "[PROFILE] loaded configuration has invalid profile id\n");

        return -EINVAL;
    }

    if (config->local_count < 0 ||
        config->local_count > 1) {
        fprintf(stderr,
                "[PROFILE] invalid LAN count: %d\n",
                config->local_count);

        return -EINVAL;
    }

    if (config->wan_count < 0 ||
        config->wan_count > 1) {
        fprintf(stderr,
                "[PROFILE] invalid WAN count: %d\n",
                config->wan_count);

        return -EINVAL;
    }

    if (config->bridge_count < 0 ||
        config->bridge_count > 1) {
        fprintf(stderr,
                "[PROFILE] invalid bridge count: %d\n",
                config->bridge_count);

        return -EINVAL;
    }

    if (config->policy_count < 0 ||
        config->policy_count > MAX_CRYPTO_POLICIES) {
        fprintf(stderr,
                "[PROFILE] invalid policy count: %d\n",
                config->policy_count);

        return -EINVAL;
    }

    rc = config_validate(config);
    if (rc != 0) {
        fprintf(stderr,
                "[PROFILE] profile %d configuration is invalid\n",
                config->profile_id);

        return -EINVAL;
    }

    return 0;
}


void core_profile_unload(struct core_runtime *runtime)
{
    core_worker_stop_all(runtime);
    ne_pair_close(&runtime->pair, &runtime->config);
    for (int id = 1; id < 256; id++) core_key_remove(id);
    memset(&runtime->config, 0, sizeof(runtime->config));
    memset(runtime->workers, 0, sizeof(runtime->workers));
    fprintf(stderr, "[PROFILE] dataplane cleared; daemon listening\n");
}

int core_profile_load(struct core_runtime *runtime, int profile_id)
{
    struct app_config new_config;
    int rc;

    if (!runtime)
        return -EINVAL;

    rc = profile_validate_id(profile_id);
    if (rc != 0)
        return rc;

    if (runtime->config.profile_id && runtime->config.profile_id != profile_id) {
        fprintf(stderr, "[PROFILE] profile %d already loaded; cannot load %d\n",
                runtime->config.profile_id, profile_id);
        return -EBUSY;
    }

    memset(&new_config, 0, sizeof(new_config));

    rc = profile_load_from_db(&new_config, profile_id);
    if (rc != 0) {
        if (rc == -ENOENT) {
            fprintf(stderr, "[PROFILE] profile %d does not exist\n", profile_id);
            if (runtime->config.profile_id == 0) {
                fprintf(stderr, "[DAEMON] waiting for profile load\n");
            }
        }
        if (runtime->config.profile_id == profile_id &&
            (rc == -ENOENT || rc == -ENODEV))
            core_profile_unload(runtime);
        return rc;
    }

    rc = profile_validate_config(&new_config);
    if (rc != 0) {
        return rc;
    }


    if (new_config.profile_id != profile_id) {
        fprintf(stderr,
                "[PROFILE] profile id mismatch: requested=%d loaded=%d\n",
                profile_id,
                new_config.profile_id);

        return -EINVAL;
    }

    rc = core_profile_edit_apply(runtime, &new_config);
    if (rc == 0)
        fprintf(stderr, "[PROFILE] applied id=%d running=%d\n",
                profile_id, runtime->running);
    return rc;
}
