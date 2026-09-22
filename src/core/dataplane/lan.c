#include "../../../inc/dataplane/lan.h"
#include "../../../inc/dataplane/tcp.h"
#include "../../../inc/dataplane/udp.h"
#include "../../../inc/dataplane/ping.h"
#include "../../../inc/dataplane/ospf.h"
#include "../../../inc/dataplane/tx.h"
#include <errno.h>

int core_lan_process(const struct app_config *cfg, const uint8_t *pkt,
    uint32_t len, uint8_t core_id, struct core_packet_batch *out)
{
    const struct crypto_policy *policy;
    if (!pkt || !out || len < 34 || len > ETH_FRAME_MAX) return -EINVAL;
    out->count = 0;
    if (core_tx_match_out(cfg, pkt, len, &policy) <= 0) return -EACCES;
    if (policy->action != POLICY_ACTION_ENCRYPT_L2) return -EOPNOTSUPP;
    if (policy->id <= 0 || policy->id > 255) return -EINVAL;
    switch (pkt[23]) {
    case IPPROTO_TCP_VAL:
        return core_tcp_handle_lan_wan(cfg, pkt, len, policy->id, core_id, out);
    case IPPROTO_UDP_VAL:
        return core_udp_handle_lan_wan(cfg, pkt, len, policy->id, core_id, out);
    case IPPROTO_ICMP_VAL:
        return core_ping_handle_lan_wan(cfg, pkt, len, policy->id, core_id, out);
    case IPPROTO_OSPF_VAL:
        return core_ospf_handle_lan_wan(cfg, pkt, len, policy->id, core_id, out);
    default:
        return -EAFNOSUPPORT;
    }
}
