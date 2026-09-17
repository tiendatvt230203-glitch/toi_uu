#define _POSIX_C_SOURCE 200809L

#include "../../../inc/core/dataplane/udp_reorder.h"
#include "../../../inc/core/dataplane/dataplane.h"
#include "../../../inc/core/dataplane/dataplane_util.h"
#include "../../../inc/core/dataplane/dataplane_stats.h"
#include "../../../inc/core/dataplane/crypto_route.h"
#include "../../../inc/core/forwarder/forwarder_wan.h"
#include "../../../inc/core/util/cpu_map.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

/* Change this one line to 1 to test UDP per-packet bonding. Default: per-flow. */
#define UDP_BOND_PER_PACKET 0

struct dp_udp_reorder_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
};

struct dp_udp_reorder_item {
    struct ne_packet packet;
    int16_t profile_pi;
    int8_t ingress_wan_dp;
};

struct dp_udp_reorder_ops {
    void *ctx;
    int (*emit)(void *ctx, struct dp_udp_reorder_item *item);
    void (*drop)(void *ctx, struct dp_udp_reorder_item *item);
};

static uint64_t dp_udp_reorder_now_ns(void);
static void dp_udp_reorder_submit(int worker_idx,
                                  const struct dp_udp_reorder_key *key,
                                  uint32_t epoch, uint32_t seq,
                                  struct dp_udp_reorder_item *item,
                                  uint64_t now_ns,
                                  const struct dp_udp_reorder_ops *ops);
static void dp_udp_reorder_gc(int worker_idx, uint64_t now_ns,
                              const struct dp_udp_reorder_ops *ops);
static void dp_udp_reorder_reset_worker(
    int worker_idx, const struct dp_udp_reorder_ops *ops);

struct udp_packet_picker {
    int wans[MAX_INTERFACES];
    int weights[MAX_INTERFACES];
    int64_t current[MAX_INTERFACES];
    int count;
    int tie;
};

static _Thread_local struct udp_packet_picker g_packet_picker;

#define UDP_TX_SEQ_SETS 2048u
#define UDP_TX_SEQ_WAYS 4u

struct udp_tx_seq_entry {
    struct dp_udp_reorder_key key;
    uint32_t next_seq;
    uint32_t stamp;
    uint8_t valid;
};

static atomic_uint_fast32_t g_tx_epoch;

struct udp_worker_state {
    struct udp_tx_seq_entry sequences[UDP_TX_SEQ_SETS][UDP_TX_SEQ_WAYS];
    uint32_t sequence_stamp;
    uint32_t tx_seq;
    uint32_t tx_datagram_id;
    uint32_t tx_datagram_clock;
    uint32_t rx_epoch;
    uint32_t rx_seq;
    uint8_t tx_meta_valid;
    uint8_t rx_meta_valid;
};

static _Thread_local struct udp_worker_state g_worker_state;

static uint32_t key_hash(const struct dp_udp_reorder_key *key);

static uint32_t udp_tx_epoch(void)
{
    uint32_t epoch = (uint32_t)atomic_load_explicit(&g_tx_epoch,
                                                    memory_order_acquire);

    if (epoch)
        return epoch;
    if (getrandom(&epoch, sizeof(epoch), GRND_NONBLOCK) != (ssize_t)sizeof(epoch) ||
        epoch == 0) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        epoch = (uint32_t)ts.tv_nsec ^ (uint32_t)ts.tv_sec ^
            ((uint32_t)getpid() * 0x9e3779b9u);
        if (!epoch)
            epoch = 1u;
    }
    {
        uint_fast32_t expected = 0;
        if (!atomic_compare_exchange_strong_explicit(&g_tx_epoch, &expected,
                                                      epoch,
                                                      memory_order_release,
                                                      memory_order_acquire))
            epoch = (uint32_t)expected;
    }
    return epoch;
}

static int udp_next_tx_seq(const uint8_t *packet, uint32_t packet_len,
                           uint32_t *seq_out)
{
    struct dp_udp_reorder_key key;
    struct udp_tx_seq_entry *set;
    uint8_t proto = 0;
    uint32_t hash;
    int victim = 0;

    if (!packet || !seq_out ||
        dp_parse_flow((void *)packet, packet_len, &key.src_ip, &key.dst_ip,
                      &key.src_port, &key.dst_port, &proto) != 0 ||
        proto != IPPROTO_UDP)
        return -1;
    hash = key_hash(&key);
    set = g_worker_state.sequences[hash & (UDP_TX_SEQ_SETS - 1u)];
    for (int way = 0; way < (int)UDP_TX_SEQ_WAYS; way++) {
        if (set[way].valid &&
            memcmp(&set[way].key, &key, sizeof(key)) == 0) {
            set[way].stamp = ++g_worker_state.sequence_stamp;
            *seq_out = set[way].next_seq++;
            return 0;
        }
        if (!set[way].valid) {
            victim = way;
            continue;
        }
        if (set[way].stamp < set[victim].stamp)
            victim = way;
    }
    set[victim].key = key;
    set[victim].next_seq = 1u;
    set[victim].stamp = ++g_worker_state.sequence_stamp;
    set[victim].valid = 1u;
    *seq_out = 0u;
    return 0;
}

int dp_udp_bond_tx_meta(uint32_t *epoch, uint32_t *seq,
                        uint32_t *datagram_id)
{
    if (!epoch || !seq || !datagram_id || !g_worker_state.tx_meta_valid)
        return -1;
    *epoch = udp_tx_epoch();
    *seq = g_worker_state.tx_seq;
    *datagram_id = g_worker_state.tx_datagram_id;
    return 0;
}

void dp_udp_bond_clear_rx_meta(void)
{
    g_worker_state.rx_meta_valid = 0u;
}

void dp_udp_bond_set_rx_meta(uint32_t epoch, uint32_t seq)
{
    g_worker_state.rx_epoch = epoch;
    g_worker_state.rx_seq = seq;
    g_worker_state.rx_meta_valid = 1u;
}

int dp_udp_bond_take_rx_meta(uint32_t *epoch, uint32_t *seq)
{
    if (!epoch || !seq || !g_worker_state.rx_meta_valid)
        return -1;
    *epoch = g_worker_state.rx_epoch;
    *seq = g_worker_state.rx_seq;
    g_worker_state.rx_meta_valid = 0u;
    return 0;
}

static int udp_select_per_flow(uint32_t src_ip, uint32_t dst_ip,
                               uint16_t src_port, uint16_t dst_port,
                               uint8_t proto, const int *wans,
                               const int *weights, int count)
{
    uint32_t a = ntohl(src_ip);
    uint32_t b = ntohl(dst_ip);
    uint32_t hash;
    uint64_t total = 0;
    uint64_t choice;

    if (a > b || (a == b && src_port > dst_port)) {
        uint32_t tmp_ip = src_ip;
        uint16_t tmp_port = src_port;
        src_ip = dst_ip;
        dst_ip = tmp_ip;
        src_port = dst_port;
        dst_port = tmp_port;
    }
    hash = src_ip ^ dst_ip ^ ((uint32_t)src_port << 16) ^ dst_port ^ proto;
    hash ^= hash >> 16;
    hash *= 0x85ebca6bu;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35u;
    hash ^= hash >> 16;
    for (int i = 0; i < count; i++)
        if (weights[i] > 0)
            total += (uint32_t)weights[i];
    if (!total)
        return -1;
    choice = hash % total;
    for (int i = 0; i < count; i++) {
        if (weights[i] <= 0)
            continue;
        if (choice < (uint32_t)weights[i])
            return wans[i];
        choice -= (uint32_t)weights[i];
    }
    return -1;
}

static int udp_select_per_packet(uint32_t src_ip, uint32_t dst_ip,
                                 uint16_t src_port, uint16_t dst_port,
                                 uint8_t proto, const int *wans,
                                 const int *weights, int count)
{
    int64_t total = 0;
    int64_t best_value = INT64_MIN;
    int best = -1;
    int changed = count != g_packet_picker.count;

    (void)src_ip;
    (void)dst_ip;
    (void)src_port;
    (void)dst_port;
    (void)proto;
    for (int i = 0; !changed && i < count; i++)
        changed = g_packet_picker.wans[i] != wans[i] ||
            g_packet_picker.weights[i] != weights[i];
    if (changed) {
        memset(&g_packet_picker, 0, sizeof(g_packet_picker));
        g_packet_picker.count = count;
        for (int i = 0; i < count; i++) {
            g_packet_picker.wans[i] = wans[i];
            g_packet_picker.weights[i] = weights[i];
        }
    }
    for (int i = 0; i < count; i++) {
        if (weights[i] <= 0)
            continue;
        g_packet_picker.current[i] += weights[i];
        total += weights[i];
    }
    for (int off = 0; off < count; off++) {
        int i = (g_packet_picker.tie + off) % count;
        if (weights[i] > 0 &&
            (best < 0 || g_packet_picker.current[i] > best_value)) {
            best = i;
            best_value = g_packet_picker.current[i];
        }
    }
    if (best < 0)
        return -1;
    g_packet_picker.current[best] -= total;
    g_packet_picker.tie = (best + 1) % count;
    return wans[best];
}

static int udp_resolve_selected_wan(struct forwarder *fwd, int selected_cfg,
                                    const int *wans, int count, int per_packet)
{
    int selected = fwd_wan_resolve_cfg(fwd, selected_cfg);
    int best = -1;
    uint32_t best_depth = UINT32_MAX;

    if (!per_packet || (selected >= 0 && fwd_wan_has_tx_room(fwd, selected)))
        return selected;
    for (int i = 0; i < count; i++) {
        int dp = fwd_wan_resolve_cfg(fwd, wans[i]);
        uint32_t depth;

        if (dp < 0 || !fwd_wan_has_tx_room(fwd, dp))
            continue;
        depth = fwd_mid_to_wan_depth(fwd, dp);
        if (best < 0 || depth < best_depth) {
            best = dp;
            best_depth = depth;
        }
    }
    return best >= 0 ? best : selected;
}

int dp_udp_bond_tx_prepare(struct forwarder *fwd, int profile_idx, int flow_ok,
                           uint32_t src_ip, uint32_t dst_ip,
                           uint16_t src_port, uint16_t dst_port,
                           int feature_allowed, const uint8_t *packet,
                           uint32_t packet_len)
{
    int wans[MAX_INTERFACES];
    int weights[MAX_INTERFACES];
    int count;
    int wan_cfg;
    uint32_t seq;
    int per_packet;

    if (!fwd || !fwd->cfg)
        return -1;
    count = fwd_wan_build_profile_pool(fwd, fwd->cfg, wans, weights,
                                       MAX_INTERFACES);
    if (count <= 0)
        return -1;
    per_packet = feature_allowed && UDP_BOND_PER_PACKET && count > 1;

    /* The authenticated UDP wire shim is prepared here for both modes.
     * In per-flow mode RX emits immediately; in per-packet mode RX reorders. */
    if (feature_allowed &&
        (!flow_ok || !packet ||
         udp_next_tx_seq(packet, packet_len, &seq) != 0))
        return -1;
    if (feature_allowed) {
        g_worker_state.tx_seq = seq;
        g_worker_state.tx_datagram_id = g_worker_state.tx_datagram_clock++;
        g_worker_state.tx_meta_valid = 1u;
    }
    wan_cfg = flow_ok
        ? (per_packet
            ? udp_select_per_packet(src_ip, dst_ip, src_port, dst_port,
                                    IPPROTO_UDP, wans, weights, count)
            : udp_select_per_flow(src_ip, dst_ip, src_port, dst_port,
                                  IPPROTO_UDP, wans, weights, count))
        : wans[0];
    (void)profile_idx;
    return udp_resolve_selected_wan(fwd, wan_cfg, wans, count, per_packet);
}

static int udp_bond_emit(void *ctx, struct dp_udp_reorder_item *item)
{
    struct forwarder *fwd = ctx;
    uint8_t *pkt;
    int rc;

    if (!fwd || !item)
        return -1;
    pkt = ne_packet_data(&fwd->pair, item->packet.addr);
    if (!pkt)
        return -1;
    dp_out_ring_bind(dp_flow_pick_tx_slot(pkt, item->packet.len,
                                          dp_crypto_current_worker_idx()));
    rc = dataplane_forward_wan_to_local(fwd, &item->packet, item->profile_pi,
                                         item->ingress_wan_dp);
    if (rc < 0)
        return -1;
    if (rc == 0)
        ne_dp_stats_wan_fwd(1);
    return 0;
}

static void udp_bond_drop(void *ctx, struct dp_udp_reorder_item *item)
{
    struct forwarder *fwd = ctx;

    if (!fwd || !item)
        return;
    ne_dp_stats_wan_drop(1);
    ne_frame_free(&fwd->pair, item->packet.addr);
}

static struct dp_udp_reorder_ops udp_bond_ops(struct forwarder *fwd)
{
    struct dp_udp_reorder_ops ops = {
        .ctx = fwd,
        .emit = udp_bond_emit,
        .drop = udp_bond_drop,
    };
    return ops;
}

void dp_udp_bond_rx(struct forwarder *fwd, uint32_t epoch, uint32_t seq,
                    struct ne_packet packet, int profile_pi,
                    int ingress_wan_dp)
{
    struct dp_udp_reorder_key key;
    struct dp_udp_reorder_item item;
    struct dp_udp_reorder_ops ops = udp_bond_ops(fwd);
    uint8_t *pkt;
    uint8_t proto = 0;

    if (!fwd)
        return;
    pkt = ne_packet_data(&fwd->pair, packet.addr);
    if (!pkt || dp_parse_flow(pkt, packet.len, &key.src_ip, &key.dst_ip,
                              &key.src_port, &key.dst_port, &proto) != 0 ||
        proto != IPPROTO_UDP) {
        ne_dp_stats_wan_drop(1);
        ne_frame_free(&fwd->pair, packet.addr);
        return;
    }
    memset(&item, 0, sizeof(item));
    item.packet = packet;
    item.profile_pi = (int16_t)profile_pi;
    item.ingress_wan_dp = (int8_t)ingress_wan_dp;
    dp_udp_reorder_submit(dp_crypto_current_worker_idx(), &key, epoch, seq,
                          &item, dp_udp_reorder_now_ns(), &ops);
}

void dp_udp_bond_runtime_gc(struct forwarder *fwd, int worker_idx)
{
    struct dp_udp_reorder_ops ops = udp_bond_ops(fwd);
    dp_udp_reorder_gc(worker_idx, dp_udp_reorder_now_ns(), &ops);
}

void dp_udp_bond_runtime_reset(struct forwarder *fwd, int worker_idx)
{
    struct dp_udp_reorder_ops ops = udp_bond_ops(fwd);
    dp_udp_reorder_reset_worker(worker_idx, &ops);
}

#define UDP_REORDER_SETS              2048u
#define UDP_REORDER_WAYS              4u
#define UDP_REORDER_FLOW_CAP          (UDP_REORDER_SETS * UDP_REORDER_WAYS)
#define UDP_REORDER_WINDOW            16384u
#define UDP_REORDER_START_BACKTRACK   (UDP_REORDER_WINDOW - 1u)
#define UDP_REORDER_HELD_CAP          16384u
#define UDP_REORDER_GC_SLICE          128u
#define UDP_REORDER_FLOW_IDLE_NS      (60ULL * 1000000000ULL)
#define UDP_REORDER_DEFAULT_HOLD_NS   (2ULL * 1000000ULL)
#define UDP_REORDER_NODE_NONE         UINT32_MAX

struct udp_reorder_node {
    struct dp_udp_reorder_item item;
    uint32_t seq;
    uint32_t next;
    uint32_t prev;
};

struct udp_reorder_flow {
    struct dp_udp_reorder_key key;
    uint32_t epoch;
    uint32_t next_seq;
    uint64_t gap_since_ns;
    uint64_t last_seen_ns;
    uint64_t stamp;
    uint32_t head;
    uint32_t tail;
    uint16_t held;
    uint8_t valid;
};

static struct udp_reorder_flow
    g_flows[NE_CRYPTO_WORKERS][UDP_REORDER_FLOW_CAP];
/* Sparse shared pool: RAM follows the number of packets actually waiting for
 * a gap, instead of multiplying a 16K array by every disordered UDP flow. */
static struct udp_reorder_node
    g_nodes[NE_CRYPTO_WORKERS][UDP_REORDER_HELD_CAP];
static uint32_t g_free_head[NE_CRYPTO_WORKERS];
static uint8_t g_pool_initialized[NE_CRYPTO_WORKERS];
static uint32_t g_held_by_worker[NE_CRYPTO_WORKERS];
static uint32_t g_gc_cursor[NE_CRYPTO_WORKERS];
static uint64_t g_stamp_by_worker[NE_CRYPTO_WORKERS];
static uint64_t g_hold_ns = UDP_REORDER_DEFAULT_HOLD_NS;
static int g_enabled = 1;

static atomic_uint_fast64_t g_stat_held;
static atomic_uint_fast64_t g_stat_released;
static atomic_uint_fast64_t g_stat_late;
static atomic_uint_fast64_t g_stat_gap;
static atomic_uint_fast64_t g_stat_overflow;
static atomic_uint_fast64_t g_stat_evicted;
static atomic_uint_fast64_t g_stat_high_water;

static int seq_delta(uint32_t seq, uint32_t base)
{
    return (int32_t)(seq - base);
}

static uint32_t key_hash(const struct dp_udp_reorder_key *key)
{
    uint32_t h = key->src_ip ^ (key->dst_ip * 0x9e3779b9u);

    h ^= ((uint32_t)key->src_port << 16) | key->dst_port;
    h ^= h >> 16;
    h *= 0x85ebca6bu;
    h ^= h >> 13;
    h *= 0xc2b2ae35u;
    return h ^ (h >> 16);
}

static int key_equal(const struct dp_udp_reorder_key *a,
                     const struct dp_udp_reorder_key *b)
{
    return a->src_ip == b->src_ip && a->dst_ip == b->dst_ip &&
           a->src_port == b->src_port && a->dst_port == b->dst_port;
}

static void item_drop(const struct dp_udp_reorder_ops *ops,
                      struct dp_udp_reorder_item *item)
{
    if (ops && ops->drop)
        ops->drop(ops->ctx, item);
}

static void item_emit(const struct dp_udp_reorder_ops *ops,
                      struct dp_udp_reorder_item *item, int was_held)
{
    if (!ops || !ops->emit || ops->emit(ops->ctx, item) != 0)
        item_drop(ops, item);
    if (was_held)
        atomic_fetch_add_explicit(&g_stat_released, 1u, memory_order_relaxed);
}

static void update_high_water(uint32_t held)
{
    uint_fast64_t old = atomic_load_explicit(&g_stat_high_water,
                                             memory_order_relaxed);

    while (held > old &&
           !atomic_compare_exchange_weak_explicit(&g_stat_high_water, &old, held,
                                                  memory_order_relaxed,
                                                  memory_order_relaxed)) {
    }
}

static void worker_pool_init(int worker_idx)
{
    if (g_pool_initialized[worker_idx])
        return;
    for (uint32_t i = 0; i < UDP_REORDER_HELD_CAP; i++) {
        g_nodes[worker_idx][i].next = i + 1u < UDP_REORDER_HELD_CAP
            ? i + 1u : UDP_REORDER_NODE_NONE;
        g_nodes[worker_idx][i].prev = UDP_REORDER_NODE_NONE;
    }
    g_free_head[worker_idx] = 0;
    g_pool_initialized[worker_idx] = 1u;
}

static uint32_t worker_node_alloc(int worker_idx)
{
    uint32_t idx;
    struct udp_reorder_node *node;

    worker_pool_init(worker_idx);
    idx = g_free_head[worker_idx];
    if (idx == UDP_REORDER_NODE_NONE)
        return idx;
    node = &g_nodes[worker_idx][idx];
    g_free_head[worker_idx] = node->next;
    memset(node, 0, sizeof(*node));
    node->next = UDP_REORDER_NODE_NONE;
    node->prev = UDP_REORDER_NODE_NONE;
    return idx;
}

static void worker_node_free(int worker_idx, uint32_t idx)
{
    struct udp_reorder_node *node;

    if (idx == UDP_REORDER_NODE_NONE || idx >= UDP_REORDER_HELD_CAP)
        return;
    node = &g_nodes[worker_idx][idx];
    memset(&node->item, 0, sizeof(node->item));
    node->seq = 0;
    node->prev = UDP_REORDER_NODE_NONE;
    node->next = g_free_head[worker_idx];
    g_free_head[worker_idx] = idx;
}

static void flow_drop_nodes(int worker_idx, uint32_t flow_idx,
                            const struct dp_udp_reorder_ops *ops)
{
    struct udp_reorder_flow *flow = &g_flows[worker_idx][flow_idx];
    uint32_t idx = flow->head;

    while (idx != UDP_REORDER_NODE_NONE) {
        struct udp_reorder_node *node = &g_nodes[worker_idx][idx];
        uint32_t next = node->next;

        item_drop(ops, &node->item);
        worker_node_free(worker_idx, idx);
        if (g_held_by_worker[worker_idx] > 0)
            g_held_by_worker[worker_idx]--;
        idx = next;
    }
    flow->head = UDP_REORDER_NODE_NONE;
    flow->tail = UDP_REORDER_NODE_NONE;
    flow->held = 0;
    flow->gap_since_ns = 0;
}

/* Insert by sequence into the sparse per-flow list. Starting from the tail
 * keeps the normal increasing-sequence path O(1), while still accepting
 * bounded displacement caused by WAN jitter.
 * Return 0=inserted, 1=duplicate, -1=shared pool full. */
static int flow_insert_node(int worker_idx, uint32_t flow_idx, uint32_t seq,
                            const struct dp_udp_reorder_item *item)
{
    struct udp_reorder_flow *flow = &g_flows[worker_idx][flow_idx];
    uint32_t before = UDP_REORDER_NODE_NONE;
    uint32_t after = flow->tail;
    uint32_t idx;
    struct udp_reorder_node *node;

    while (after != UDP_REORDER_NODE_NONE) {
        int delta = seq_delta(seq, g_nodes[worker_idx][after].seq);

        if (delta == 0)
            return 1;
        if (delta > 0) {
            before = g_nodes[worker_idx][after].next;
            break;
        }
        before = after;
        after = g_nodes[worker_idx][after].prev;
    }
    idx = worker_node_alloc(worker_idx);
    if (idx == UDP_REORDER_NODE_NONE)
        return -1;
    node = &g_nodes[worker_idx][idx];
    node->item = *item;
    node->seq = seq;
    node->prev = after;
    node->next = before;
    if (after != UDP_REORDER_NODE_NONE)
        g_nodes[worker_idx][after].next = idx;
    else
        flow->head = idx;
    if (before != UDP_REORDER_NODE_NONE)
        g_nodes[worker_idx][before].prev = idx;
    else
        flow->tail = idx;
    return 0;
}

static void flow_reset(int worker_idx, uint32_t flow_idx,
                       const struct dp_udp_reorder_key *key,
                       uint32_t epoch, uint32_t first_seq, uint64_t now_ns,
                       const struct dp_udp_reorder_ops *ops)
{
    struct udp_reorder_flow *flow = &g_flows[worker_idx][flow_idx];
    uint32_t backtrack = first_seq < UDP_REORDER_START_BACKTRACK
        ? first_seq : UDP_REORDER_START_BACKTRACK;

    if (flow->valid) {
        flow_drop_nodes(worker_idx, flow_idx, ops);
    }
    memset(flow, 0, sizeof(*flow));
    flow->key = *key;
    flow->epoch = epoch;
    flow->next_seq = first_seq - backtrack;
    flow->gap_since_ns = backtrack ? now_ns : 0;
    flow->last_seen_ns = now_ns;
    flow->stamp = ++g_stamp_by_worker[worker_idx];
    flow->head = UDP_REORDER_NODE_NONE;
    flow->tail = UDP_REORDER_NODE_NONE;
    flow->valid = 1;
}

static uint32_t flow_lookup(int worker_idx,
                            const struct dp_udp_reorder_key *key,
                            uint32_t epoch, uint32_t first_seq, uint64_t now_ns,
                            const struct dp_udp_reorder_ops *ops)
{
    uint32_t set = key_hash(key) & (UDP_REORDER_SETS - 1u);
    uint32_t base = set * UDP_REORDER_WAYS;
    uint32_t victim = base;

    for (uint32_t way = 0; way < UDP_REORDER_WAYS; way++) {
        uint32_t idx = base + way;
        struct udp_reorder_flow *flow = &g_flows[worker_idx][idx];

        if (flow->valid && key_equal(&flow->key, key)) {
            if (flow->epoch != epoch)
                flow_reset(worker_idx, idx, key, epoch, first_seq, now_ns, ops);
            flow->last_seen_ns = now_ns;
            flow->stamp = ++g_stamp_by_worker[worker_idx];
            return idx;
        }
        if (!flow->valid) {
            victim = idx;
            break;
        }
        if (flow->stamp < g_flows[worker_idx][victim].stamp)
            victim = idx;
    }
    if (g_flows[worker_idx][victim].valid)
        atomic_fetch_add_explicit(&g_stat_evicted, 1u, memory_order_relaxed);
    flow_reset(worker_idx, victim, key, epoch, first_seq, now_ns, ops);
    return victim;
}

static void flow_flush_contiguous(int worker_idx, uint32_t flow_idx,
                                  uint64_t now_ns,
                                  const struct dp_udp_reorder_ops *ops)
{
    struct udp_reorder_flow *flow = &g_flows[worker_idx][flow_idx];
    int advanced = 0;

    while (flow->head != UDP_REORDER_NODE_NONE) {
        uint32_t idx = flow->head;
        struct udp_reorder_node *node = &g_nodes[worker_idx][idx];
        struct dp_udp_reorder_item item;

        if (node->seq != flow->next_seq)
            break;
        item = node->item;
        flow->head = node->next;
        if (flow->head != UDP_REORDER_NODE_NONE)
            g_nodes[worker_idx][flow->head].prev = UDP_REORDER_NODE_NONE;
        else
            flow->tail = UDP_REORDER_NODE_NONE;
        worker_node_free(worker_idx, idx);
        if (flow->held > 0)
            flow->held--;
        if (g_held_by_worker[worker_idx] > 0)
            g_held_by_worker[worker_idx]--;
        flow->next_seq++;
        advanced = 1;
        item_emit(ops, &item, 1);
    }
    if (!flow->held)
        flow->gap_since_ns = 0;
    else if (advanced || !flow->gap_since_ns)
        flow->gap_since_ns = now_ns;
}

static int flow_smallest_ahead(int worker_idx, uint32_t flow_idx,
                               uint32_t *seq_out)
{
    struct udp_reorder_flow *flow = &g_flows[worker_idx][flow_idx];
    struct udp_reorder_node *node;
    int delta;

    if (flow->head == UDP_REORDER_NODE_NONE)
        return -1;
    node = &g_nodes[worker_idx][flow->head];
    delta = seq_delta(node->seq, flow->next_seq);
    if (delta < 0)
        return -1;
    *seq_out = node->seq;
    return delta;
}

static void flow_skip_gap(int worker_idx, uint32_t flow_idx,
                          uint64_t now_ns,
                          const struct dp_udp_reorder_ops *ops)
{
    struct udp_reorder_flow *flow = &g_flows[worker_idx][flow_idx];
    uint32_t seq;
    int delta = flow_smallest_ahead(worker_idx, flow_idx, &seq);

    if (delta < 0) {
        flow->gap_since_ns = 0;
        return;
    }
    if (delta > 0) {
        flow->next_seq = seq;
        atomic_fetch_add_explicit(&g_stat_gap, (uint32_t)delta,
                                  memory_order_relaxed);
    }
    flow_flush_contiguous(worker_idx, flow_idx, now_ns, ops);
    if (flow->held)
        flow->gap_since_ns = now_ns;
}

/* Under shared-pool pressure, advance the oldest outstanding gap instead of
 * dropping the newly arrived datagram. This preserves ordered delivery for
 * every flow while bounding memory; a genuinely missing packet is treated as
 * lost slightly earlier only when the entire worker pool is occupied. */
static int worker_release_oldest_gap(int worker_idx, uint64_t now_ns,
                                     const struct dp_udp_reorder_ops *ops)
{
    uint32_t victim = UDP_REORDER_NODE_NONE;
    uint64_t oldest = UINT64_MAX;
    uint32_t before = g_held_by_worker[worker_idx];

    for (uint32_t i = 0; i < UDP_REORDER_FLOW_CAP; i++) {
        struct udp_reorder_flow *flow = &g_flows[worker_idx][i];

        if (!flow->valid || !flow->held || !flow->gap_since_ns)
            continue;
        if (flow->gap_since_ns < oldest) {
            oldest = flow->gap_since_ns;
            victim = i;
        }
    }
    if (victim == UDP_REORDER_NODE_NONE)
        return -1;
    flow_skip_gap(worker_idx, victim, now_ns, ops);
    return g_held_by_worker[worker_idx] < before ? 0 : -1;
}

static void flow_make_window_room(int worker_idx, uint32_t flow_idx,
                                  uint32_t seq, uint64_t now_ns,
                                  const struct dp_udp_reorder_ops *ops)
{
    struct udp_reorder_flow *flow = &g_flows[worker_idx][flow_idx];

    while (flow->held && seq_delta(seq, flow->next_seq) >=
           (int)UDP_REORDER_WINDOW)
        flow_skip_gap(worker_idx, flow_idx, now_ns, ops);
    if (seq_delta(seq, flow->next_seq) >= (int)UDP_REORDER_WINDOW) {
        uint32_t target = seq - (UDP_REORDER_WINDOW - 1u);
        uint32_t skipped = (uint32_t)seq_delta(target, flow->next_seq);

        flow->next_seq = target;
        atomic_fetch_add_explicit(&g_stat_gap, skipped, memory_order_relaxed);
    }
}

void dp_udp_reorder_configure_from_env(void)
{
    const char *enabled = getenv("NE_UDP_REORDER");
    const char *hold_us = getenv("NE_UDP_REORDER_US");

    g_enabled = UDP_BOND_PER_PACKET && !(enabled && enabled[0] == '0');
    if (hold_us && hold_us[0]) {
        char *end = NULL;
        unsigned long value = strtoul(hold_us, &end, 10);

        if (end != hold_us && *end == '\0') {
            if (value < 100)
                value = 100;
            if (value > 200000)
                value = 200000;
            g_hold_ns = (uint64_t)value * 1000ULL;
        }
    }
}

static uint64_t dp_udp_reorder_now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void dp_udp_reorder_submit(int worker_idx,
                                  const struct dp_udp_reorder_key *key,
                                  uint32_t epoch, uint32_t seq,
                                  struct dp_udp_reorder_item *item,
                                  uint64_t now_ns,
                                  const struct dp_udp_reorder_ops *ops)
{
    uint32_t flow_idx;
    struct udp_reorder_flow *flow;
    int insert_rc;
    int delta;

    if (!item || !key || worker_idx < 0 ||
        worker_idx >= (int)NE_CRYPTO_WORKERS || !g_enabled) {
        item_emit(ops, item, 0);
        return;
    }
    flow_idx = flow_lookup(worker_idx, key, epoch, seq, now_ns, ops);
    flow = &g_flows[worker_idx][flow_idx];

    if (flow->held && flow->gap_since_ns &&
        now_ns - flow->gap_since_ns >= g_hold_ns)
        flow_skip_gap(worker_idx, flow_idx, now_ns, ops);

    delta = seq_delta(seq, flow->next_seq);
    if (delta < 0) {
        atomic_fetch_add_explicit(&g_stat_late, 1u, memory_order_relaxed);
        item_drop(ops, item);
        return;
    }
    if (delta == 0) {
        flow->next_seq++;
        item_emit(ops, item, 0);
        flow_flush_contiguous(worker_idx, flow_idx, now_ns, ops);
        return;
    }

    flow_make_window_room(worker_idx, flow_idx, seq, now_ns, ops);
    delta = seq_delta(seq, flow->next_seq);
    if (delta < 0) {
        atomic_fetch_add_explicit(&g_stat_late, 1u, memory_order_relaxed);
        item_drop(ops, item);
        return;
    }
    if (delta == 0) {
        flow->next_seq++;
        item_emit(ops, item, 0);
        flow_flush_contiguous(worker_idx, flow_idx, now_ns, ops);
        return;
    }
    insert_rc = flow_insert_node(worker_idx, flow_idx, seq, item);
    if (insert_rc > 0) {
        atomic_fetch_add_explicit(&g_stat_late, 1u, memory_order_relaxed);
        item_drop(ops, item);
        return;
    }
    if (insert_rc < 0) {
        if (worker_release_oldest_gap(worker_idx, now_ns, ops) == 0)
            insert_rc = flow_insert_node(worker_idx, flow_idx, seq, item);
        if (insert_rc != 0) {
            atomic_fetch_add_explicit(&g_stat_overflow, 1u,
                                      memory_order_relaxed);
            item_drop(ops, item);
            return;
        }
    }
    flow->held++;
    g_held_by_worker[worker_idx]++;
    if (!flow->gap_since_ns)
        flow->gap_since_ns = now_ns;
    atomic_fetch_add_explicit(&g_stat_held, 1u, memory_order_relaxed);
    update_high_water(g_held_by_worker[worker_idx]);
}

static void dp_udp_reorder_gc(int worker_idx, uint64_t now_ns,
                              const struct dp_udp_reorder_ops *ops)
{
    uint32_t cursor;

    if (worker_idx < 0 || worker_idx >= (int)NE_CRYPTO_WORKERS)
        return;
    cursor = g_gc_cursor[worker_idx];
    for (uint32_t n = 0; n < UDP_REORDER_GC_SLICE; n++) {
        uint32_t idx = (cursor + n) % UDP_REORDER_FLOW_CAP;
        struct udp_reorder_flow *flow = &g_flows[worker_idx][idx];

        if (!flow->valid)
            continue;
        if (flow->held && flow->gap_since_ns &&
            now_ns - flow->gap_since_ns >= g_hold_ns)
            flow_skip_gap(worker_idx, idx, now_ns, ops);
        if (!flow->held &&
            now_ns - flow->last_seen_ns > UDP_REORDER_FLOW_IDLE_NS) {
            memset(flow, 0, sizeof(*flow));
        }
    }
    g_gc_cursor[worker_idx] = (cursor + UDP_REORDER_GC_SLICE) %
        UDP_REORDER_FLOW_CAP;
}

static void dp_udp_reorder_reset_worker(
    int worker_idx, const struct dp_udp_reorder_ops *ops)
{
    if (worker_idx < 0 || worker_idx >= (int)NE_CRYPTO_WORKERS)
        return;
    for (uint32_t idx = 0; idx < UDP_REORDER_FLOW_CAP; idx++) {
        if (g_flows[worker_idx][idx].valid)
            flow_drop_nodes(worker_idx, idx, ops);
        memset(&g_flows[worker_idx][idx], 0,
               sizeof(g_flows[worker_idx][idx]));
    }
    g_held_by_worker[worker_idx] = 0;
    g_pool_initialized[worker_idx] = 0;
    worker_pool_init(worker_idx);
    g_gc_cursor[worker_idx] = 0;
}

void dp_udp_reorder_get_stats(struct dp_udp_reorder_stats *out)
{
    if (!out)
        return;
    out->held = atomic_load_explicit(&g_stat_held, memory_order_relaxed);
    out->released = atomic_load_explicit(&g_stat_released, memory_order_relaxed);
    out->late_or_duplicate = atomic_load_explicit(&g_stat_late,
                                                   memory_order_relaxed);
    out->gap_skipped = atomic_load_explicit(&g_stat_gap, memory_order_relaxed);
    out->overflow = atomic_load_explicit(&g_stat_overflow, memory_order_relaxed);
    out->evicted = atomic_load_explicit(&g_stat_evicted, memory_order_relaxed);
    out->high_water = atomic_load_explicit(&g_stat_high_water,
                                            memory_order_relaxed);
}
