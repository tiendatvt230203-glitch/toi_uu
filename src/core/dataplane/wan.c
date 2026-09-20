#include "../../../inc/core/dataplane/wan.h"
#include "../../../inc/core/dataplane/arp.h"
#include "../../../inc/core/dataplane/ospf.h"
#include "../../../inc/core/dataplane/ping.h"
#include "../../../inc/core/dataplane/tcp.h"
#include "../../../inc/core/dataplane/tx.h"
#include "../../../inc/core/dataplane/udp.h"
#include "../../../inc/core/crypto/crypto.h"

#include <errno.h>
#include <netinet/in.h>

int core_wan_process(const struct app_config *cfg, uint8_t *pkt,
                     uint32_t *len, uint16_t wire_ethertype,
                     uint8_t wire_policy_id)
{
    int rc;

    if (wire_ethertype == ETH_P_NE_ARP_ENC)
        return core_arp_handle();
    if (wire_ethertype == NE_L2_TCP_ETHERTYPE)
        rc = core_tcp_handle_wan_lan();
    else if (wire_ethertype == NE_L2_UDP_ETHERTYPE)
        rc = core_udp_handle_wan_lan();
    else if (wire_ethertype == NE_L2_PING_ETHERTYPE)
        rc = core_ping_handle_wan_lan();
    else if (wire_ethertype == NE_L2_OSPF_ETHERTYPE)
        rc = core_ospf_handle_wan_lan();
    else
        return -EAFNOSUPPORT;

    if (rc != 0)
        return rc;

    if (!len || core_tx_match_in(cfg, pkt, *len, wire_policy_id) <= 0)
        return -EACCES;
    return 0;
}
