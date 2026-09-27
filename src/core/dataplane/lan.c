#include "../../../inc/dataplane/lan.h"
#include "../../../inc/dataplane/tcp.h"
#include "../../../inc/dataplane/udp.h"
#include "../../../inc/dataplane/ping.h"
#include "../../../inc/dataplane/ospf.h"
#include "../../../inc/dataplane/tx.h"
#include "../../../inc/interface/interface.h"
#include <errno.h>

int core_lan_process(const struct app_config *cfg, struct ne_pair *pair,
                     struct ne_packet *pkt, uint8_t core_id,
                     struct core_packet_batch *out)
{
    uint32_t contiguous;
    uint8_t *data = ne_packet_at(pair, pkt, 0, &contiguous);
    const struct crypto_policy *policy;
    if (!data || contiguous < 34 || !out)
        return -EINVAL;
    out->count = 0;
    if (core_tx_match_out(cfg, data, pkt->total_len, &policy) <= 0)
        return -EACCES;
    if (policy->action != POLICY_ACTION_ENCRYPT_L2)
        return -EOPNOTSUPP;
    if (policy->id <= 0 || policy->id > 255)
        return -EINVAL;
    switch (data[23]) {
    case IPPROTO_TCP_VAL:
        return core_tcp_handle_lan_wan(cfg, pair, pkt, policy->id, core_id, out);
    case IPPROTO_UDP_VAL:
        return core_udp_handle_lan_wan(cfg, pair, pkt, policy->id, core_id, out);
    case IPPROTO_ICMP_VAL:
        return core_ping_handle_lan_wan(cfg, pair, pkt, policy->id, core_id, out);
    case IPPROTO_OSPF_VAL:
        return core_ospf_handle_lan_wan(cfg, pair, pkt, policy->id, core_id, out);
    default:
        return -EAFNOSUPPORT;
    }
}
