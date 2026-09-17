#ifndef ARP_BRIDGE_H
#define ARP_BRIDGE_H

#include "core/forwarder/forwarder.h"


void arp_bridge_reload_policies(struct app_config *cfg);
int arp_bridge_is_packet(const uint8_t *packet, uint32_t packet_len);
void arp_bridge_failover_reset(void);
void arp_bridge_link_state_changed(int wan_dp, int is_up);

int arp_bridge_from_local(struct forwarder *fwd, struct ne_packet *job,
                          const uint8_t *pkt, int ingress_li,
                          char egress_ifname[IF_NAMESIZE]);
int arp_bridge_from_wan(struct forwarder *fwd, struct ne_packet *job,
                        const uint8_t *pkt, int ingress_wan_dp,
                        char egress_ifname[IF_NAMESIZE]);

#endif
