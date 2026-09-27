#include "../../../inc/dataplane/ping.h"
#include "../../../inc/crypto/crypto.h"
#include "../../../inc/crypto/key_manager.h"
#include "../../../inc/dataplane/tx.h"
#include "../../../inc/interface/interface.h"
#include <errno.h>
#include <string.h>

int core_ping_handle_lan_wan(const struct app_config *cfg,
    struct ne_pair *pair, struct ne_packet *pkt, uint8_t policy_id,
    uint8_t core_id, struct core_packet_batch *out)
{
    uint8_t key[32];
    if (!cfg || cfg->wan_count != 1 || !cfg->wans[0].dataplane)
        return -ENODEV;
    int rc = core_key_get(policy_id, key, sizeof(key));
    if (!rc)
        rc = core_l2_pqc_fragment(pair, pkt, NE_L2_PING_ETHERTYPE,
                                  policy_id, core_id, key, out);
    memset(key, 0, sizeof(key));
    return rc;
}

int core_ping_handle_wan_lan(const struct app_config *cfg,
    struct ne_pair *pair, struct ne_packet *pkt)
{
    uint8_t key[32];
    uint8_t policy_id;
    int rc = core_l2_pqc_reassemble(pair, pkt, NE_L2_PING_ETHERTYPE);
    if (rc)
        return rc;
    if (ne_packet_read(pair, pkt, pkt->total_len - 1u, &policy_id, 1))
        return -EINVAL;
    rc = core_key_get(policy_id, key, sizeof(key));
    if (!rc)
        rc = core_l2_pqc_decrypt(pair, pkt, NE_L2_PING_ETHERTYPE, key);
    memset(key, 0, sizeof(key));
    if (rc)
        return rc;
    uint32_t contiguous;
    uint8_t *data = ne_packet_at(pair, pkt, 0, &contiguous);
    return data && contiguous >= 34 &&
           core_tx_match_in(cfg, data, pkt->total_len, policy_id) > 0
        ? 0 : -EACCES;
}
