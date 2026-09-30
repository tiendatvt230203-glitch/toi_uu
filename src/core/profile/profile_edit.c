#include "../../../inc/profile/profile_edit.h"
#include "../../../inc/profile/profile_load.h"

#include "../../../inc/runtime/worker.h"
#include "../../../inc/interface/interface.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>


static const struct local_config *
find_local(const struct app_config *config, const char *ifname)
{
    int i;

    if (!config || !ifname)
        return NULL;

    for (i = 0; i < config->local_count; i++) {
        if (strcmp(config->locals[i].ifname, ifname) == 0)
            return &config->locals[i];
    }

    return NULL;
}


static const struct wan_config *
find_wan(const struct app_config *config, const char *ifname)
{
    int i;

    if (!config || !ifname)
        return NULL;

    for (i = 0; i < config->wan_count; i++) {
        if (strcmp(config->wans[i].ifname, ifname) == 0)
            return &config->wans[i];
    }

    return NULL;
}


static int local_equal(const struct local_config *a,
                       const struct local_config *b)
{
    if (!a || !b)
        return 0;

    return strcmp(a->ifname, b->ifname) == 0;
}


static int wan_equal(const struct wan_config *a,
                     const struct wan_config *b)
{
    if (!a || !b)
        return 0;

    return strcmp(a->ifname, b->ifname) == 0 &&
           a->dataplane == b->dataplane &&
           a->bandwidth_weight == b->bandwidth_weight;
}


static int policy_equal(const struct crypto_policy *a,
                        const struct crypto_policy *b)
{
    if (!a || !b)
        return 0;

    return a->id == b->id &&
           a->db_id == b->db_id &&
           a->priority == b->priority &&
           a->action == b->action &&
           a->protocol == b->protocol &&
           a->src_port_from == b->src_port_from &&
           a->src_port_to == b->src_port_to &&
           a->dst_port_from == b->dst_port_from &&
           a->dst_port_to == b->dst_port_to &&
           a->src_any == b->src_any &&
           a->dst_any == b->dst_any &&
           a->src_negate == b->src_negate &&
           a->dst_negate == b->dst_negate &&
           a->src_net == b->src_net &&
           a->src_mask == b->src_mask &&
           a->dst_net == b->dst_net &&
           a->dst_mask == b->dst_mask;
}


static int lan_changed(const struct app_config *old_config,
                       const struct app_config *new_config)
{
    int i;

    if (old_config->local_count != new_config->local_count)
        return 1;

    for (i = 0; i < old_config->local_count; i++) {
        const struct local_config *new_local;

        new_local = find_local(new_config,
                               old_config->locals[i].ifname);

        if (!new_local)
            return 1;

        if (!local_equal(&old_config->locals[i], new_local))
            return 1;
        if (old_config->locals[i].ifindex > 0 &&
            if_nametoindex(new_local->ifname) != (unsigned)old_config->locals[i].ifindex)
            return 1;
    }

    return 0;
}


static int wan_changed(const struct app_config *old_config,
                       const struct app_config *new_config)
{
    int i;

    if (old_config->wan_count != new_config->wan_count)
        return 1;

    for (i = 0; i < old_config->wan_count; i++) {
        const struct wan_config *new_wan;

        new_wan = find_wan(new_config,
                           old_config->wans[i].ifname);

        if (!new_wan)
            return 1;

        if (!wan_equal(&old_config->wans[i], new_wan))
            return 1;
        if (old_config->wans[i].ifindex > 0 &&
            if_nametoindex(new_wan->ifname) != (unsigned)old_config->wans[i].ifindex)
            return 1;
    }

    return 0;
}


static int policy_changed(const struct app_config *a, const struct app_config *b)
{
    if (a->policy_count != b->policy_count) return 1;
    for (int i = 0; i < a->policy_count; i++)
        if (!policy_equal(&a->policies[i], &b->policies[i])) return 1;
    return 0;
}

int core_profile_edit_lan(struct core_runtime *runtime,
                          const struct app_config *new_config)
{
    if (!runtime || !new_config) return -EINVAL;
    if (runtime->running || runtime->pair.umem) return -EBUSY;

    if (new_config->local_count < 0 ||
        new_config->local_count > 1)
        return -EINVAL;

    memset(runtime->config.locals,
           0,
           sizeof(runtime->config.locals));

    memcpy(runtime->config.locals,
           new_config->locals,
           sizeof(struct local_config) *
               (size_t)new_config->local_count);

    runtime->config.local_count = new_config->local_count;

    fprintf(stderr,
            "[PROFILE] LAN updated: %d interface(s)\n",
            runtime->config.local_count);

    return 0;
}


int core_profile_edit_wan(struct core_runtime *runtime,
                          const struct app_config *new_config)
{
    if (!runtime || !new_config) return -EINVAL;
    if (runtime->running || runtime->pair.umem) return -EBUSY;

    if (new_config->wan_count < 0 ||
        new_config->wan_count > 1)
        return -EINVAL;

    memset(runtime->config.wans,
           0,
           sizeof(runtime->config.wans));

    memcpy(runtime->config.wans,
           new_config->wans,
           sizeof(struct wan_config) *
               (size_t)new_config->wan_count);

    runtime->config.wan_count = new_config->wan_count;

    fprintf(stderr,
            "[PROFILE] WAN updated: %d interface(s)\n",
            runtime->config.wan_count);

    return 0;
}


int core_profile_edit_policy(struct core_runtime *runtime,
                             const struct app_config *new_config)
{
    if (!runtime || !new_config) return -EINVAL;
    if (runtime->running || runtime->pair.umem) return -EBUSY;

    if (new_config->policy_count < 0 ||
        new_config->policy_count > MAX_CRYPTO_POLICIES)
        return -EINVAL;

    memset(runtime->config.policies,
           0,
           sizeof(runtime->config.policies));

    memcpy(runtime->config.policies,
           new_config->policies,
           sizeof(struct crypto_policy) *
               (size_t)new_config->policy_count);

    runtime->config.policy_count = new_config->policy_count;
    runtime->config.crypto_enabled = new_config->crypto_enabled;

    fprintf(stderr,
            "[PROFILE] policies updated: %d policy(s), crypto=%d\n",
            runtime->config.policy_count,
            runtime->config.crypto_enabled);

    return 0;
}


int core_profile_edit_apply(struct core_runtime *runtime,
                            const struct app_config *new_config)
{
    if (!runtime || !new_config || !runtime->initialized ||
        new_config->profile_id <= 0 ||
        new_config->local_count < 0 || new_config->local_count > 1 ||
        new_config->wan_count < 0 || new_config->wan_count > 1 ||
        new_config->policy_count < 0 || new_config->policy_count > MAX_CRYPTO_POLICIES ||
        new_config->bridge_count < 0 || new_config->bridge_count > 1)
        return -EINVAL;
    if (new_config->enabled && (new_config->local_count != 1 ||
        new_config->wan_count != 1 || !new_config->wans[0].dataplane))
        return -EINVAL;
    if (runtime->config.profile_id &&
        runtime->config.profile_id != new_config->profile_id) {
        fprintf(stderr, "[PROFILE] profile %d already loaded; cannot load %d\n",
                runtime->config.profile_id, new_config->profile_id);
        return -EBUSY;
    }
    if (new_config == &runtime->config) return -EINVAL;

    int topology_changed = lan_changed(&runtime->config, new_config) ||
        wan_changed(&runtime->config, new_config) ||
        runtime->config.bridge_count != new_config->bridge_count ||
        memcmp(runtime->config.bridges, new_config->bridges, sizeof(new_config->bridges)) ||
        strcmp(runtime->config.bpf_lan_file, new_config->bpf_lan_file) ||
        strcmp(runtime->config.bpf_wan_file, new_config->bpf_wan_file);
    if (runtime->config.profile_id && topology_changed) {
        int profile_id = new_config->profile_id;
        core_profile_unload(runtime);
        return core_profile_load(runtime, profile_id);
    }
    int changed = topology_changed ||
        policy_changed(&runtime->config, new_config) ||
        runtime->config.crypto_enabled != new_config->crypto_enabled ||
        runtime->config.enabled != new_config->enabled;
    if (runtime->running && !changed) {
        memcpy(runtime->config.profile_name, new_config->profile_name,
               sizeof(runtime->config.profile_name));
        return 0;
    }

    if (runtime->running && new_config->enabled) {
        pthread_rwlock_wrlock(&runtime->config_lock);
        memcpy(runtime->config.policies, new_config->policies, sizeof(new_config->policies));
        runtime->config.policy_count = new_config->policy_count;
        runtime->config.crypto_enabled = new_config->crypto_enabled;
        memcpy(runtime->config.profile_name, new_config->profile_name, sizeof(new_config->profile_name));
        pthread_rwlock_unlock(&runtime->config_lock);
        fprintf(stderr, "[PROFILE] policy metadata updated live; fixed key unchanged\n");
        return 0;
    }

    int was_running = runtime->running;
    core_worker_stop_all(runtime);
    ne_pair_close(&runtime->pair, &runtime->config);

    struct app_config old_config = runtime->config;
    int rc = core_profile_edit_lan(runtime, new_config);
    if (!rc) rc = core_profile_edit_wan(runtime, new_config);
    if (!rc) rc = core_profile_edit_policy(runtime, new_config);
    if (rc) goto rollback;
    runtime->config.profile_id = new_config->profile_id;
    runtime->config.enabled = new_config->enabled;
    runtime->config.bridge_count = new_config->bridge_count;
    memcpy(runtime->config.bridges, new_config->bridges, sizeof(new_config->bridges));
    memcpy(runtime->config.profile_name, new_config->profile_name, sizeof(new_config->profile_name));
    memcpy(runtime->config.bpf_lan_file, new_config->bpf_lan_file, sizeof(new_config->bpf_lan_file));
    memcpy(runtime->config.bpf_wan_file, new_config->bpf_wan_file, sizeof(new_config->bpf_wan_file));
    if (!new_config->enabled) return 0;
    rc = ne_pair_open(&runtime->pair, &runtime->config);
    if (!rc) rc = core_worker_start_all(runtime);
    if (!rc) return 0;

rollback:
    core_worker_stop_all(runtime);
    ne_pair_close(&runtime->pair, &runtime->config);
    runtime->config = old_config;
    int restore = 0;
    if (!restore && was_running) {
        restore = ne_pair_open(&runtime->pair, &runtime->config);
        if (!restore) restore = core_worker_start_all(runtime);
        if (restore) ne_pair_close(&runtime->pair, &runtime->config);
    }
    fprintf(stderr, "[PROFILE] apply failed: %d; restore: %d\n", rc, restore);
    return rc;
}
