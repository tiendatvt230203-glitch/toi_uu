#define _POSIX_C_SOURCE 200809L

#include "../../../inc/core/dataplane/udp_reorder.h"
#include "../../../inc/core/util/cpu_map.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

    g_enabled = !(enabled && enabled[0] == '0');
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

uint64_t dp_udp_reorder_now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void dp_udp_reorder_submit(int worker_idx,
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

void dp_udp_reorder_gc(int worker_idx, uint64_t now_ns,
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

void dp_udp_reorder_reset_worker(int worker_idx,
                                 const struct dp_udp_reorder_ops *ops)
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
