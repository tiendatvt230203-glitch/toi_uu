#include "../../../inc/crypto/key_manager.h"
#include <errno.h>
#include <string.h>



static const uint8_t g_fixed_key[32] = {
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a
};

static int key_policy_valid(int policy_id)
{
    return policy_id > 0 && policy_id < 256;
}

int core_key_get(int policy_id, uint8_t *key, size_t key_size)
{
    if (!key_policy_valid(policy_id) || !key || key_size != sizeof(g_fixed_key))
        return -EINVAL;
    memcpy(key, g_fixed_key, sizeof(g_fixed_key));
    return 0;
}
