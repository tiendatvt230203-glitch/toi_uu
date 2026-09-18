#include "../../../inc/core/dataplane/lan.h"
#include "../../../inc/core/dataplane/ospf.h"
#include "../../../inc/core/dataplane/ping.h"
#include "../../../inc/core/dataplane/tcp.h"
#include "../../../inc/core/dataplane/tx.h"
#include "../../../inc/core/dataplane/udp.h"
#include "../../../inc/core/crypto/crypto.h"

#include <errno.h>
#include <netinet/in.h>


int core_lan_process(uint8_t ip_protocol)
{
    if (core_tx_match_out() <= 0)
        return -EACCES;

    if (ip_protocol == IPPROTO_TCP)
        return core_tcp_handle_lan_wan();
    if (ip_protocol == IPPROTO_UDP)
        return core_udp_handle_lan_wan();
    if (ip_protocol == IPPROTO_ICMP)
        return core_ping_handle_lan_wan();
    if (ip_protocol == IPPROTO_OSPF_VAL)
        return core_ospf_handle_lan_wan();
    return -EAFNOSUPPORT;
}
