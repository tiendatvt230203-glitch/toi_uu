#include "../../../inc/dataplane/ospf.h"
#include "../../../inc/crypto/crypto.h"
#include "../../../inc/crypto/key_manager.h"
#include "../../../inc/dataplane/tx.h"
#include <errno.h>
#include <string.h>

int core_ospf_handle_lan_wan(const struct app_config *cfg,
    const uint8_t *pkt, uint32_t len, uint8_t policy_id, uint8_t core_id,
    struct core_packet_batch *out)
{
    uint8_t key[32];
    if (!cfg || cfg->wan_count != 1 || !cfg->wans[0].dataplane)
        return -ENODEV;
    int rc = core_key_get(policy_id, key, sizeof(key));
    if (rc) return rc;
    rc = core_l2_pqc_fragment(pkt, len, NE_L2_OSPF_ETHERTYPE,
                              policy_id, core_id, key, out);
    memset(key, 0, sizeof(key));
    return rc;
}

int core_ospf_handle_wan_lan(const struct app_config *cfg, uint8_t *pkt,
    uint32_t *len, uint32_t capacity)
{
    uint8_t key[32];
    if (!pkt || !len || *len < 16) return -EINVAL;
    uint8_t policy_id = pkt[14];
    int rc = core_key_get(policy_id, key, sizeof(key));
    if (rc) return rc;
    rc = core_l2_pqc_reassemble(pkt, len, capacity, NE_L2_OSPF_ETHERTYPE, key);
    memset(key, 0, sizeof(key));
    if (rc) return rc;
    return core_tx_match_in(cfg, pkt, *len, policy_id) > 0 ? 0 : -EACCES;
}
