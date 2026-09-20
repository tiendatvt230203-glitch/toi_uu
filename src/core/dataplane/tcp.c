#include "../../../inc/core/dataplane/tcp.h"
#include "../../../inc/core/crypto/crypto.h"
#include "../../../inc/core/crypto/key_manager.h"
#include "../../../inc/core/dataplane/tx.h"
#include <errno.h>
#include <string.h>

static int core_tcp_decrypt(uint8_t *pkt, uint32_t *len, const uint8_t key[32]);

int core_tcp_handle_lan_wan()
{
    core_tcp_clamp_mss();
    core_tcp_encrypt();
    core_tcp_per_flow();
    core_tcp_per_packet();
}
int core_tcp_handle_wan_lan(const struct app_config *cfg, uint8_t *pkt, uint32_t *len)
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
    rc = core_tcp_decrypt(pkt, len, key);
    memset(key, 0, sizeof(key));
    if (rc != 0)
        return rc;
    return core_tx_match_in(cfg, pkt, *len, policy_id) ? 0 : -EACCES;
}

int core_tcp_clamp_mss()
{
    
}

int core_tcp_encrypt()
{
    
}

static int core_tcp_decrypt(uint8_t *pkt, uint32_t *len, const uint8_t key[32])
{
    (void)pkt; (void)len; (void)key;
    return -ENOSYS;
}

int core_tcp_per_flow()
{
    
}

int core_tcp_per_packet()
{
    
}

int core_tcp_retry()
{
    
}
