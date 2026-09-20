#include "../../../inc/core/dataplane/wan.h"
#include "../../../inc/core/dataplane/bypass.h"
#include "../../../inc/core/dataplane/ospf.h"
#include "../../../inc/core/dataplane/ping.h"
#include "../../../inc/core/dataplane/tcp.h"
#include "../../../inc/core/dataplane/udp.h"

#include <errno.h>

int core_wan_process(const struct app_config *cfg, uint8_t *pkt,
                     uint32_t *len)
{
    const uint16_t wire_ethertype = ((uint16_t)pkt[12] << 8) | pkt[13];

    if (wire_ethertype == NE_L2_TCP_ETHERTYPE)
        return core_tcp_handle_wan_lan(cfg, pkt, len);
    if (wire_ethertype == NE_L2_UDP_ETHERTYPE)
        return core_udp_handle_wan_lan(cfg, pkt, len);
    if (wire_ethertype == NE_L2_PING_ETHERTYPE)
        return core_ping_handle_wan_lan(cfg, pkt, len);
    if (wire_ethertype == NE_L2_OSPF_ETHERTYPE)
        return core_ospf_handle_wan_lan(cfg, pkt, len);
    if (wire_ethertype == 0x0800u)
        return core_bypass_handle_wan_lan(cfg, pkt, len);
    return -EAFNOSUPPORT;
}
