#ifndef TCP_BOND_REORDER_H
#define TCP_BOND_REORDER_H

#include "core/iface/interface.h"
#include <stdint.h>

/* TCP ordering is per policy and crypto worker, never per connection.
 * One delayed worker cannot block all TCP connections in the policy. */
struct dp_tcp_bond_item {
    struct ne_packet packet;
    int16_t profile_pi;
    int8_t ingress_wan_dp;
};

struct dp_tcp_bond_ops {
    void *ctx;
    int (*emit)(void *ctx, struct dp_tcp_bond_item *item);
    void (*drop)(void *ctx, struct dp_tcp_bond_item *item);
};

int dp_tcp_bond_next_tx_meta(uint8_t wire_policy_id, uint8_t worker_idx, uint32_t *epoch,
                             uint32_t *seq);

void dp_tcp_bond_reorder_configure_from_env(void);
uint64_t dp_tcp_bond_reorder_now_ns(void);

/* Takes ownership of item in every return path. Each policy/worker has one
 * bounded stream, independent of TCP connection count. */
void dp_tcp_bond_reorder_submit(uint8_t wire_policy_id, int worker_idx,
                                uint32_t epoch, uint32_t seq,
                                struct dp_tcp_bond_item *item,
                                uint64_t now_ns,
                                const struct dp_tcp_bond_ops *ops);
void dp_tcp_bond_reorder_gc(int worker_idx, uint64_t now_ns,
                            const struct dp_tcp_bond_ops *ops);
void dp_tcp_bond_reorder_reset(int worker_idx, const struct dp_tcp_bond_ops *ops);

#endif
