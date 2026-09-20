#include "../../../inc/core/dataplane/lan.h"
#include "../../../inc/core/dataplane/bypass.h"
#include "../../../inc/core/dataplane/ospf.h"
#include "../../../inc/core/dataplane/ping.h"
#include "../../../inc/core/dataplane/tcp.h"
#include "../../../inc/core/dataplane/tx.h"
#include "../../../inc/core/dataplane/udp.h"
#include "../../../inc/core/crypto/crypto.h"

#include <errno.h>
#include <netinet/in.h>


int core_lan_process(const struct app_config *cfg, uint8_t *pkt,
                     uint32_t *len, uint32_t capacity, uint8_t ip_protocol,
                     uint8_t core_id, uint8_t *second, uint32_t *second_len,
                     uint8_t *wan_idx)
{
    const struct crypto_policy *policy;

    if (!pkt || !len || !second_len || !wan_idx || *len > capacity)
        return -EINVAL;
    *second_len = 0;
    *wan_idx = UINT8_MAX;
    if (core_tx_match_out(cfg, pkt, *len, &policy) <= 0)
        return -EACCES;
    if (policy->action == POLICY_ACTION_BYPASS)
        return core_bypass_handle_lan_wan(cfg, pkt, *len, wan_idx);
    if (policy->id <= 0 || policy->id > 255)
        return -EINVAL;

    if (ip_protocol == IPPROTO_TCP)
        return core_tcp_handle_lan_wan(cfg, pkt, len, capacity, policy->id,
                                       core_id, wan_idx);
    if (ip_protocol == IPPROTO_UDP)
        return core_udp_handle_lan_wan(cfg, pkt, len, capacity, policy->id,
                                        core_id, second, second_len, wan_idx);
    if (ip_protocol == IPPROTO_ICMP)
        return core_ping_handle_lan_wan(cfg, pkt, len, capacity, policy->id,
                                         core_id, second, second_len, wan_idx);
    if (ip_protocol == IPPROTO_OSPF_VAL)
        return core_ospf_handle_lan_wan(cfg, pkt, len, capacity, policy->id,
                                         core_id, second, second_len, wan_idx);
    return -EAFNOSUPPORT;
}
