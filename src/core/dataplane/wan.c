#include "../../../inc/core/dataplane/wan.h"
#include "../../../inc/core/dataplane/ospf.h"
#include "../../../inc/core/dataplane/ping.h"
#include "../../../inc/core/dataplane/tcp.h"
#include "../../../inc/core/dataplane/tx.h"
#include "../../../inc/core/dataplane/udp.h"
#include "../../../inc/core/crypto/crypto.h"

#include <errno.h>
#include <netinet/in.h>

int core_wan_receive(struct core_runtime *runtime)
{
    (void)runtime;
    return 0;
}

int core_wan_process(struct core_runtime *runtime, int ip_protocol,
                     void *packet, uint32_t *packet_length)
{
    int policy_id;
    int lan_id = 0;
    int rc;

    rc = core_tx_match_in(runtime, packet, *packet_length, &policy_id);
    if (rc != 0)
        return rc;

    if (ip_protocol == IPPROTO_TCP) {
        rc = core_tcp_decrypt(runtime, policy_id, packet, packet_length);
        if (rc == 0)
            rc = core_tcp_handle(runtime, packet, packet_length);
    } else if (ip_protocol == IPPROTO_UDP) {
        rc = core_udp_decrypt(runtime, policy_id, packet, packet_length);
        if (rc == 0)
            rc = core_udp_reassemble(runtime, packet, packet_length);
        if (rc == 0)
            rc = core_udp_reorder(runtime, packet, packet_length);
        if (rc == 0)
            rc = core_udp_handle(runtime, packet, packet_length);
    } else if (ip_protocol == IPPROTO_ICMP) {
        rc = core_l2_pqc_decrypt(policy_id, packet, packet_length);
        if (rc == 0)
            rc = core_ping_reassemble(runtime, packet, packet_length);
        if (rc == 0)
            rc = core_ping_handle(runtime, packet, packet_length);
    } else if (ip_protocol == 89) {
        rc = core_ospf_decrypt(runtime, policy_id, packet, packet_length);
        if (rc == 0)
            rc = core_ospf_handle(runtime, packet, packet_length);
    } else {
        return -EAFNOSUPPORT;
    }

    if (rc != 0)
        return rc;
    return core_tx_lan(runtime, lan_id, packet, *packet_length);
}
