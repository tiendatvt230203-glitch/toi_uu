#ifndef TCP_BOND_REORDER_H
#define TCP_BOND_REORDER_H

#include "core/iface/interface.h"
#include <stdint.h>

struct forwarder;
struct packet_crypto_ctx;

/* Send mode and all bonding decisions are private to this module. */
int dp_tcp_bond_tx_prepare(struct forwarder *fwd, int profile_idx, int flow_ok,
                           uint32_t src_ip, uint32_t dst_ip,
                           uint16_t src_port, uint16_t dst_port,
                           int feature_allowed);
int dp_tcp_bond_tx_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                           uint32_t *packet_len, int l3_offset);
int dp_tcp_bond_clamp_mss(uint8_t *packet, uint32_t packet_len, int l3_offset);
void dp_tcp_bond_clear_rx_meta(void);
void dp_tcp_bond_set_rx_meta(uint32_t epoch, uint32_t seq);
int dp_tcp_bond_take_rx_meta(uint32_t *epoch, uint32_t *seq);
void dp_tcp_bond_rx(struct forwarder *fwd, uint8_t wire_policy_id,
                    uint32_t epoch, uint32_t seq, struct ne_packet packet,
                    int profile_pi, int ingress_wan_dp);
void dp_tcp_bond_runtime_gc(struct forwarder *fwd, int worker_idx);
void dp_tcp_bond_runtime_reset(struct forwarder *fwd, int worker_idx);

int dp_tcp_bond_next_tx_meta(uint8_t wire_policy_id, uint8_t worker_idx, uint32_t *epoch,
                             uint32_t *seq);

void dp_tcp_bond_reorder_configure_from_env(void);

#endif
