#include "../../../inc/dataplane/wan.h"
#include "../../../inc/dataplane/bypass.h"
#include "../../../inc/dataplane/ospf.h"
#include "../../../inc/dataplane/ping.h"
#include "../../../inc/dataplane/tcp.h"
#include "../../../inc/dataplane/udp.h"
#include "../../../inc/interface/interface.h"
#include <errno.h>

int core_wan_process(const struct app_config *cfg, struct ne_pair *pair,
                     struct ne_packet *pkt)
{
    uint32_t contiguous;
    uint8_t *data = ne_packet_at(pair, pkt, 0, &contiguous);
    if (!data || contiguous < 14)
        return -EINVAL;
    uint16_t type = ((uint16_t)data[12] << 8) | data[13];
    if (type == NE_L2_TCP_ETHERTYPE)
        return core_tcp_handle_wan_lan(cfg, pair, pkt);
    if (type == NE_L2_UDP_ETHERTYPE)
        return core_udp_handle_wan_lan(cfg, pair, pkt);
    if (type == NE_L2_PING_ETHERTYPE)
        return core_ping_handle_wan_lan(cfg, pair, pkt);
    if (type == NE_L2_OSPF_ETHERTYPE)
        return core_ospf_handle_wan_lan(cfg, pair, pkt);
    if (type == 0x0800u)
        return core_bypass_handle_wan_lan(cfg, data, &pkt->total_len);
    return -EAFNOSUPPORT;
}
