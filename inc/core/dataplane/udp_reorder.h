#ifndef UDP_REORDER_H
#define UDP_REORDER_H

#include "core/iface/interface.h"
#include <stdint.h>

struct forwarder;

struct dp_udp_reorder_stats {
    uint64_t held;
    uint64_t released;
    uint64_t late_or_duplicate;
    uint64_t gap_skipped;
    uint64_t overflow;
    uint64_t evicted;
    uint64_t high_water;
};

/* Send mode and all bonding decisions are private to this module. */
int dp_udp_bond_tx_prepare(struct forwarder *fwd, int profile_idx, int flow_ok,
                           uint32_t src_ip, uint32_t dst_ip,
                           uint16_t src_port, uint16_t dst_port,
                           int feature_allowed, const uint8_t *packet,
                           uint32_t packet_len);
int dp_udp_bond_tx_meta(uint32_t *epoch, uint32_t *seq,
                        uint32_t *datagram_id);
void dp_udp_bond_clear_rx_meta(void);
void dp_udp_bond_set_rx_meta(uint32_t epoch, uint32_t seq);
int dp_udp_bond_take_rx_meta(uint32_t *epoch, uint32_t *seq);
void dp_udp_bond_rx(struct forwarder *fwd, uint32_t epoch, uint32_t seq,
                    struct ne_packet packet, int profile_pi,
                    int ingress_wan_dp);
void dp_udp_bond_runtime_gc(struct forwarder *fwd, int worker_idx);
void dp_udp_bond_runtime_reset(struct forwarder *fwd, int worker_idx);

/* Reassembly ownership belongs to UDP bonding; crypto only authenticates and
 * decrypts each wire fragment before passing the plaintext piece here. */
int dp_udp_fragment_reassemble(int worker_idx, uint8_t wire_policy_id,
                               const uint8_t *packet, uint32_t packet_len,
                               uint32_t epoch, uint32_t datagram_id,
                               uint32_t bond_seq, uint8_t fragment_index,
                               uint8_t *out, uint32_t *out_len);
void dp_udp_fragment_gc(int worker_idx, uint64_t now_ns);
void dp_udp_fragment_reset(int worker_idx);

void dp_udp_reorder_configure_from_env(void);
void dp_udp_reorder_get_stats(struct dp_udp_reorder_stats *out);

#endif
