#include "../../../inc/core/dataplane/ospf.h"
#include "../../../inc/core/crypto/crypto.h"
#include "../../../inc/core/crypto/key_manager.h"
#include "../../../inc/core/dataplane/tx.h"
#include <errno.h>
#include <string.h>

static int core_ospf_decrypt(uint8_t *pkt, uint32_t *len, const uint8_t key[32]);

int core_ospf_handle_lan_wan()
{
    core_ospf_encrypt();
}

int core_ospf_handle_wan_lan(const struct app_config *cfg, uint8_t *pkt, uint32_t *len)
{
    uint8_t key[32];
    uint8_t policy_id;
    int rc;

    if (*len < 16)
        return -EINVAL;
    policy_id = pkt[14];
    rc = core_key_get(policy_id, key, sizeof(key));
    if (rc != 0)
        return rc;
    rc = core_ospf_decrypt(pkt, len, key);
    memset(key, 0, sizeof(key));
    if (rc != 0)
        return rc;
    return core_tx_match_in(cfg, pkt, *len, policy_id) ? 0 : -EACCES;
}

int core_ospf_fragment()
{
}

int core_ospf_reassemble()
{
}

int core_ospf_encrypt()
{
}

static int core_ospf_decrypt(uint8_t *pkt, uint32_t *len, const uint8_t key[32])
{
    (void)pkt; (void)len; (void)key;
    return -ENOSYS;
}

int core_ospf_per_flow()
{
}
