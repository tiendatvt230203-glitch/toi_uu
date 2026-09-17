#include "../../../inc/core/crypto/key_manager.h"

#include <errno.h>

int core_key_install(int policy_id, const uint8_t *key, size_t key_size)
{
    (void)policy_id;
    (void)key;
    (void)key_size;
    return -ENOSYS;
}

int core_key_get(int policy_id, uint8_t *key, size_t key_size)
{
    (void)policy_id;
    (void)key;
    (void)key_size;
    return -ENOSYS;
}

int core_key_request(const struct pqc_policy_input *policy)
{
    (void)policy;
    return -ENOSYS;
}

int core_key_expired(int policy_id)
{
    (void)policy_id;
    return -ENOSYS;
}

int core_key_tick(void)
{
    return -ENOSYS;
}

void core_key_remove(int policy_id)
{
    (void)policy_id;
}
