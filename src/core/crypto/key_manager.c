#include "../../../inc/crypto/key_manager.h"
#include "../../../inc/core_types.h"
#include "pqc_handshake.h"

#include <errno.h>
#include <pthread.h>
#include <string.h>



static uint8_t g_keys[256][PQC_POLICY_KEY_SIZE];
static uint8_t g_valid[256];
static pthread_mutex_t g_keys_lock = PTHREAD_MUTEX_INITIALIZER;

static int key_policy_valid(int policy_id)
{
    return policy_id > 0 && policy_id < 256;
}

int core_key_install(int policy_id, const uint8_t *key, size_t key_size)
{
    if (!key_policy_valid(policy_id) || !key ||
        key_size != PQC_POLICY_KEY_SIZE)
        return -EINVAL;
    pthread_mutex_lock(&g_keys_lock);
    memcpy(g_keys[policy_id], key, key_size);
    g_valid[policy_id] = 1;
    pthread_mutex_unlock(&g_keys_lock);
    return 0;
}

int core_key_get(int policy_id, uint8_t *key, size_t key_size)
{
    if (!key_policy_valid(policy_id) || !key || key_size != PQC_POLICY_KEY_SIZE)
        return -EINVAL;
    pthread_mutex_lock(&g_keys_lock);
    if (!g_valid[policy_id]) {
        pthread_mutex_unlock(&g_keys_lock);
        return -ENOENT;
    }
    memcpy(key, g_keys[policy_id], key_size);
    pthread_mutex_unlock(&g_keys_lock);
    return 0;
}

int core_key_request(const struct pqc_policy_input *policy)
{
    struct pqc_policy_key next = {0};
    int rc;

    if (!policy || !key_policy_valid(policy->policy_id))
        return -EINVAL;
    rc = sig_pqc_handshake_policy(policy, &next);
    if (rc == 0 && next.policy_id != policy->policy_id)
        rc = -EPROTO;
    if (rc == 0)
        rc = core_key_install(policy->policy_id, next.bytes, sizeof(next.bytes));
    memset(&next, 0, sizeof(next));
    return rc;
}

void core_key_remove(int policy_id)
{
    if (!key_policy_valid(policy_id))
        return;
    pthread_mutex_lock(&g_keys_lock);
    memset(g_keys[policy_id], 0, sizeof(g_keys[policy_id]));
    g_valid[policy_id] = 0;
    pthread_mutex_unlock(&g_keys_lock);
}
