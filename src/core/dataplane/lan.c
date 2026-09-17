#include "../../../inc/core/dataplane/lan.h"
#include "../../../inc/core/dataplane/ospf.h"
#include "../../../inc/core/dataplane/ping.h"
#include "../../../inc/core/dataplane/tcp.h"
#include "../../../inc/core/dataplane/tx.h"
#include "../../../inc/core/dataplane/udp.h"
#include "../../../inc/core/crypto/crypto.h"

#include <errno.h>
#include <netinet/in.h>

int core_lan_receive(struct core_runtime *runtime)
{
    (void)runtime;
    return 0;
}

int core_lan_process(struct core_runtime *runtime, int ip_protocol,
                     void *packet, uint32_t *packet_length)
{
    int policy_id;
    int wan_id;
    int rc;

    rc = core_tx_match_out(runtime, packet, *packet_length, &policy_id);
    if (rc != 0)
        return rc;

    if (ip_protocol == IPPROTO_TCP) {
        rc = core_tcp_handle(runtime, packet, packet_length);
        if (rc == 0)
            rc = core_tcp_clamp_mss(runtime, packet, packet_length);
        if (rc == 0)
            rc = core_tcp_encrypt(runtime, policy_id, packet, packet_length);
        if (rc == 0)
            rc = core_tcp_bond(runtime, packet, packet_length);
        if (rc != 0)
            return rc;
        wan_id = core_tcp_select_wan(runtime, packet, *packet_length);
    } else if (ip_protocol == IPPROTO_UDP) {
        rc = core_udp_handle(runtime, packet, packet_length);
        if (rc == 0)
            rc = core_udp_fragment(runtime, packet, *packet_length);
        if (rc == 0)
            rc = core_udp_encrypt(runtime, policy_id, packet, packet_length);
        if (rc == 0)
            rc = core_udp_bond(runtime, packet, packet_length);
        if (rc != 0)
            return rc;
        wan_id = core_udp_select_wan(runtime, packet, *packet_length);
    } else if (ip_protocol == IPPROTO_ICMP) {
        rc = core_ping_handle(runtime, packet, packet_length);
        if (rc == 0)
            rc = core_ping_fragment(runtime, packet, *packet_length);
        if (rc == 0)
            rc = core_l2_pqc_encrypt(policy_id, packet, packet_length);
        if (rc != 0)
            return rc;
        wan_id = core_tx_select_wan(runtime, packet, *packet_length);
    } else if (ip_protocol == 89) {
        rc = core_ospf_handle(runtime, packet, packet_length);
        if (rc == 0)
            rc = core_ospf_encrypt(runtime, policy_id, packet, packet_length);
        if (rc != 0)
            return rc;
        wan_id = core_tx_select_wan(runtime, packet, *packet_length);
    } else {
        return -EAFNOSUPPORT;
    }

    return core_tx_wan(runtime, wan_id, packet, *packet_length);
}
