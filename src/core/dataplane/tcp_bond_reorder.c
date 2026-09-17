#include "../../../inc/core/dataplane/tcp_bond_reorder.h"
#include "../../../inc/core/dataplane/dataplane.h"
#include "../../../inc/core/dataplane/crypto_route.h"
#include "../../../inc/core/forwarder/forwarder_wan.h"
#include "../../../inc/core/util/cpu_map.h"
#include "../../../inc/crypto/crypto_option.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

/* Change this one line to 1 to test TCP per-packet bonding. Default: per-flow. */
#define TCP_BOND_PER_PACKET 0

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

static uint64_t dp_tcp_bond_reorder_now_ns(void);
static void dp_tcp_bond_reorder_submit(
    uint8_t wire_policy_id, int worker_idx, uint32_t epoch, uint32_t seq,
    struct dp_tcp_bond_item *item, uint64_t now_ns,
    const struct dp_tcp_bond_ops *ops);
static void dp_tcp_bond_reorder_gc(int worker_idx, uint64_t now_ns,
                                   const struct dp_tcp_bond_ops *ops);
static void dp_tcp_bond_reorder_reset(int worker_idx,
                                      const struct dp_tcp_bond_ops *ops);

struct tcp_packet_picker {
    int wans[MAX_INTERFACES];
    int weights[MAX_INTERFACES];
    int64_t current[MAX_INTERFACES];
    int count;
    int tie;
};

static _Thread_local struct tcp_packet_picker g_packet_picker;
static _Thread_local int g_tx_wire_ordering;
static _Thread_local uint32_t g_rx_epoch;
static _Thread_local uint32_t g_rx_seq;
static _Thread_local uint8_t g_rx_meta_valid;

void dp_tcp_bond_clear_rx_meta(void)
{
    g_rx_meta_valid = 0u;
}

void dp_tcp_bond_set_rx_meta(uint32_t epoch, uint32_t seq)
{
    g_rx_epoch = epoch;
    g_rx_seq = seq;
    g_rx_meta_valid = 1u;
}

int dp_tcp_bond_take_rx_meta(uint32_t *epoch, uint32_t *seq)
{
    if (!epoch || !seq || !g_rx_meta_valid)
        return -1;
    *epoch = g_rx_epoch;
    *seq = g_rx_seq;
    g_rx_meta_valid = 0u;
    return 0;
}

static int tcp_select_per_flow(uint32_t src_ip, uint32_t dst_ip,
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

static int tcp_select_per_packet(uint32_t src_ip, uint32_t dst_ip,
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

static int tcp_resolve_selected_wan(struct forwarder *fwd, int selected_cfg,
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

int dp_tcp_bond_tx_prepare(struct forwarder *fwd, int profile_idx, int flow_ok,
                           uint32_t src_ip, uint32_t dst_ip,
                           uint16_t src_port, uint16_t dst_port,
                           int feature_allowed)
{
    int wans[MAX_INTERFACES];
    int weights[MAX_INTERFACES];
    int count;
    int per_packet;
    int wan_cfg;

    if (!fwd || !fwd->cfg)
        return -1;
    count = fwd_wan_build_profile_pool(fwd, fwd->cfg, wans, weights,
                                       MAX_INTERFACES);
    if (count <= 0)
        return -1;
    per_packet = feature_allowed && TCP_BOND_PER_PACKET && count > 1;

    g_tx_wire_ordering = per_packet;
    wan_cfg = flow_ok
        ? (per_packet
            ? tcp_select_per_packet(src_ip, dst_ip, src_port, dst_port,
                                    IPPROTO_TCP, wans, weights, count)
            : tcp_select_per_flow(src_ip, dst_ip, src_port, dst_port,
                                  IPPROTO_TCP, wans, weights, count))
        : wans[0];
    (void)profile_idx;
    return tcp_resolve_selected_wan(fwd, wan_cfg, wans, count, per_packet);
}

int dp_tcp_bond_tx_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet,
                           uint32_t *packet_len, int l3_offset)
{
    if (g_tx_wire_ordering)
        dp_out_ring_bind(dp_crypto_worker_tx_slot(dp_crypto_current_worker_idx()));
    return crypto_l2_pqc_encrypt_tcp_l3(ctx, packet, packet_len, l3_offset,
                                        g_tx_wire_ordering);
}

static int tcp_bond_emit(void *ctx, struct dp_tcp_bond_item *item)
{
    struct forwarder *fwd = ctx;
    int rc;

    if (!fwd || !item)
        return -1;
    dp_out_ring_bind(dp_crypto_worker_tx_slot(dp_crypto_current_worker_idx()));
    rc = dataplane_forward_wan_to_local(fwd, &item->packet, item->profile_pi,
                                         item->ingress_wan_dp);
    return rc < 0 ? -1 : 0;
}

static void tcp_bond_drop(void *ctx, struct dp_tcp_bond_item *item)
{
    struct forwarder *fwd = ctx;

    if (fwd && item)
        ne_frame_free(&fwd->pair, item->packet.addr);
}

static struct dp_tcp_bond_ops tcp_bond_ops(struct forwarder *fwd)
{
    struct dp_tcp_bond_ops ops = {
        .ctx = fwd,
        .emit = tcp_bond_emit,
        .drop = tcp_bond_drop,
    };
    return ops;
}

void dp_tcp_bond_rx(struct forwarder *fwd, uint8_t wire_policy_id,
                    uint32_t epoch, uint32_t seq, struct ne_packet packet,
                    int profile_pi, int ingress_wan_dp)
{
    struct dp_tcp_bond_item item;
    struct dp_tcp_bond_ops ops = tcp_bond_ops(fwd);

    memset(&item, 0, sizeof(item));
    item.packet = packet;
    item.profile_pi = (int16_t)profile_pi;
    item.ingress_wan_dp = (int8_t)ingress_wan_dp;
    dp_tcp_bond_reorder_submit(wire_policy_id, dp_crypto_current_worker_idx(),
                               epoch, seq, &item,
                               dp_tcp_bond_reorder_now_ns(), &ops);
}

void dp_tcp_bond_runtime_gc(struct forwarder *fwd, int worker_idx)
{
    struct dp_tcp_bond_ops ops = tcp_bond_ops(fwd);
    dp_tcp_bond_reorder_gc(worker_idx, dp_tcp_bond_reorder_now_ns(), &ops);
}

void dp_tcp_bond_runtime_reset(struct forwarder *fwd, int worker_idx)
{
    struct dp_tcp_bond_ops ops = tcp_bond_ops(fwd);
    dp_tcp_bond_reorder_reset(worker_idx, &ops);
}

#define TCP_BOND_STREAMS          256u
#define TCP_BOND_WINDOW           2048u
#define TCP_BOND_DEFAULT_HOLD_NS  (2ULL * 1000000ULL)

struct tcp_bond_slot {
    struct dp_tcp_bond_item item;
    uint32_t seq;
    uint8_t valid;
};

struct tcp_bond_stream {
    pthread_spinlock_t lock;
    struct tcp_bond_slot *slots;
    uint32_t epoch;
    uint32_t next_seq;
    uint32_t held;
    uint64_t gap_since_ns;
    uint8_t valid;
    uint8_t emitting;
};

static struct tcp_bond_stream g_streams[TCP_BOND_STREAMS][NE_CRYPTO_WORKERS];
static int g_configured;
static int g_enabled = 1;
static uint64_t g_hold_ns = TCP_BOND_DEFAULT_HOLD_NS;
static atomic_ullong g_gap_skipped;
static atomic_ullong g_late_or_duplicate;
static atomic_ullong g_overflow;
static atomic_uint_fast32_t g_tx_epoch;
static atomic_uint_fast32_t g_tx_seq[TCP_BOND_STREAMS][NE_CRYPTO_WORKERS];

static uint32_t tx_epoch(void)
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

int dp_tcp_bond_next_tx_meta(uint8_t wire_policy_id, uint8_t worker_idx, uint32_t *epoch,
                             uint32_t *seq)
{
    uint32_t value;

    if (!epoch || !seq || worker_idx >= NE_CRYPTO_WORKERS)
        return -1;
    value = (uint32_t)atomic_fetch_add_explicit(&g_tx_seq[wire_policy_id][worker_idx], 1u,
                                                memory_order_relaxed) + 1u;
    if (!value)
        value = (uint32_t)atomic_fetch_add_explicit(&g_tx_seq[wire_policy_id][worker_idx],
                                                    1u,
                                                    memory_order_relaxed) + 1u;
    *epoch = tx_epoch();
    *seq = value;
    return 0;
}

static int32_t seq_delta(uint32_t a, uint32_t b)
{
    return (int32_t)(a - b);
}

static void item_emit(const struct dp_tcp_bond_ops *ops,
                      struct dp_tcp_bond_item *item)
{
    if (!ops || !ops->emit || ops->emit(ops->ctx, item) != 0) {
        if (ops && ops->drop)
            ops->drop(ops->ctx, item);
    }
}

static void item_drop(const struct dp_tcp_bond_ops *ops,
                      struct dp_tcp_bond_item *item)
{
    if (ops && ops->drop)
        ops->drop(ops->ctx, item);
}

static void stream_drop_all_locked(struct tcp_bond_stream *stream,
                                   const struct dp_tcp_bond_ops *ops)
{
    if (!stream->slots) {
        stream->held = 0;
        stream->gap_since_ns = 0;
        return;
    }
    for (uint32_t i = 0; i < TCP_BOND_WINDOW; i++) {
        struct tcp_bond_slot *slot = &stream->slots[i];

        if (!slot->valid)
            continue;
        item_drop(ops, &slot->item);
        slot->valid = 0;
    }
    stream->held = 0;
    stream->gap_since_ns = 0;
}

static void stream_new_epoch_locked(struct tcp_bond_stream *stream,
                                    uint32_t epoch,
                                    const struct dp_tcp_bond_ops *ops)
{
    stream_drop_all_locked(stream, ops);
    stream->epoch = epoch;
    stream->next_seq = 1u;
    stream->valid = 1u;
}

static int stream_expected_ready(const struct tcp_bond_stream *stream)
{
    const struct tcp_bond_slot *slot;

    if (!stream->valid || !stream->slots)
        return 0;
    slot = &stream->slots[stream->next_seq & (TCP_BOND_WINDOW - 1u)];
    return slot->valid && slot->seq == stream->next_seq;
}

static int stream_skip_expired_gap_locked(struct tcp_bond_stream *stream,
                                          uint64_t now_ns)
{
    uint32_t best_seq = 0;
    int32_t best_delta = INT32_MAX;

    if (!stream->held || !stream->gap_since_ns ||
        now_ns - stream->gap_since_ns < g_hold_ns || !stream->slots)
        return 0;
    for (uint32_t i = 0; i < TCP_BOND_WINDOW; i++) {
        const struct tcp_bond_slot *slot = &stream->slots[i];
        int32_t delta;

        if (!slot->valid)
            continue;
        delta = seq_delta(slot->seq, stream->next_seq);
        if (delta >= 0 && delta < best_delta) {
            best_delta = delta;
            best_seq = slot->seq;
        }
    }
    if (best_delta == INT32_MAX)
        return 0;
    if (best_delta > 0)
        atomic_fetch_add_explicit(&g_gap_skipped, (uint32_t)best_delta,
                                  memory_order_relaxed);
    stream->next_seq = best_seq;
    stream->gap_since_ns = 0;
    return 1;
}

/* Exactly one submitter/GC caller owns emission for a stream. It keeps the
 * ownership flag while callbacks run without the spinlock, so another CPU
 * may fill later slots but can never emit them ahead of this owner. */
static void stream_drain(struct tcp_bond_stream *stream,
                         const struct dp_tcp_bond_ops *ops,
                         uint64_t now_ns)
{
    for (;;) {
        struct dp_tcp_bond_item item;
        struct tcp_bond_slot *slot;
        int have_item = 0;

        pthread_spin_lock(&stream->lock);
        if (!stream->slots) {
            stream->emitting = 0;
            pthread_spin_unlock(&stream->lock);
            return;
        }
        slot = &stream->slots[stream->next_seq & (TCP_BOND_WINDOW - 1u)];
        if (slot->valid && slot->seq == stream->next_seq) {
            item = slot->item;
            slot->valid = 0;
            stream->held--;
            stream->next_seq++;
            have_item = 1;
            /* The old gap has just advanced. If another gap remains after
             * the contiguous run, its hold timer must start afresh instead
             * of inheriting the age of the previous gap. */
            stream->gap_since_ns = 0;
        } else {
            if (stream->held && !stream->gap_since_ns)
                stream->gap_since_ns = now_ns;
            stream->emitting = 0;
        }
        pthread_spin_unlock(&stream->lock);

        if (!have_item)
            return;
        item_emit(ops, &item);
    }
}

void dp_tcp_bond_reorder_configure_from_env(void)
{
    const char *enabled = getenv("NE_TCP_BOND_REORDER");
    const char *hold_us = getenv("NE_TCP_BOND_REORDER_US");

    if (!g_configured) {
        for (uint32_t i = 0; i < TCP_BOND_STREAMS; i++)
            for (uint32_t w = 0; w < NE_CRYPTO_WORKERS; w++)
                (void)pthread_spin_init(&g_streams[i][w].lock,
                                        PTHREAD_PROCESS_PRIVATE);
        g_configured = 1;
    }
    g_enabled = TCP_BOND_PER_PACKET && !(enabled && enabled[0] == '0');
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

static uint64_t dp_tcp_bond_reorder_now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void dp_tcp_bond_reorder_submit(
    uint8_t wire_policy_id, int worker_idx, uint32_t epoch, uint32_t seq,
    struct dp_tcp_bond_item *item, uint64_t now_ns,
    const struct dp_tcp_bond_ops *ops)
{
    struct tcp_bond_stream *stream;
    struct tcp_bond_slot *slot;
    int32_t delta;
    int owner = 0;
    int drop_input = 0;

    if (!item || worker_idx < 0 || worker_idx >= (int)NE_CRYPTO_WORKERS ||
        !g_enabled || !g_configured) {
        item_emit(ops, item);
        return;
    }
    stream = &g_streams[wire_policy_id][worker_idx];

    pthread_spin_lock(&stream->lock);
    if (!stream->valid || stream->epoch != epoch)
        stream_new_epoch_locked(stream, epoch, ops);
    if (!stream->slots) {
        stream->slots = calloc(TCP_BOND_WINDOW, sizeof(*stream->slots));
        if (!stream->slots) {
            drop_input = 1;
            goto unlock;
        }
    }
    (void)stream_skip_expired_gap_locked(stream, now_ns);

    delta = seq_delta(seq, stream->next_seq);
    if (delta < 0) {
        atomic_fetch_add_explicit(&g_late_or_duplicate, 1u,
                                  memory_order_relaxed);
        drop_input = 1;
        goto unlock;
    }
    if (delta >= (int32_t)TCP_BOND_WINDOW) {
        /* A loss burst larger than the bounded window cannot be repaired.
         * Drop old held frames and resume at this packet without allocating
         * memory proportional to the number of TCP connections. */
        stream_drop_all_locked(stream, ops);
        atomic_fetch_add_explicit(&g_gap_skipped, (uint32_t)delta,
                                  memory_order_relaxed);
        atomic_fetch_add_explicit(&g_overflow, 1u, memory_order_relaxed);
        stream->next_seq = seq;
    }

    slot = &stream->slots[seq & (TCP_BOND_WINDOW - 1u)];
    if (slot->valid) {
        atomic_fetch_add_explicit(&g_late_or_duplicate, 1u,
                                  memory_order_relaxed);
        drop_input = 1;
        goto unlock;
    }
    slot->item = *item;
    slot->seq = seq;
    slot->valid = 1u;
    stream->held++;
    if (seq != stream->next_seq && !stream->gap_since_ns)
        stream->gap_since_ns = now_ns;
    if (!stream->emitting && stream_expected_ready(stream)) {
        stream->emitting = 1u;
        owner = 1;
    }

unlock:
    pthread_spin_unlock(&stream->lock);
    if (drop_input)
        item_drop(ops, item);
    if (owner)
        stream_drain(stream, ops, now_ns);
}

static void dp_tcp_bond_reorder_gc(int worker_idx, uint64_t now_ns,
                                   const struct dp_tcp_bond_ops *ops)
{
    if (!g_enabled || !g_configured || worker_idx < 0 ||
        worker_idx >= (int)NE_CRYPTO_WORKERS)
        return;
    for (uint32_t i = 0; i < TCP_BOND_STREAMS; i++) {
        struct tcp_bond_stream *stream = &g_streams[i][worker_idx];
        int owner = 0;

        pthread_spin_lock(&stream->lock);
        if (stream->valid)
            (void)stream_skip_expired_gap_locked(stream, now_ns);
        if (stream->valid && !stream->emitting &&
            stream_expected_ready(stream)) {
            stream->emitting = 1u;
            owner = 1;
        }
        pthread_spin_unlock(&stream->lock);
        if (owner)
            stream_drain(stream, ops, now_ns);
    }
}

static void dp_tcp_bond_reorder_reset(int worker_idx,
                                      const struct dp_tcp_bond_ops *ops)
{
    if (!g_configured || worker_idx < 0 || worker_idx >= (int)NE_CRYPTO_WORKERS)
        return;
    for (uint32_t i = 0; i < TCP_BOND_STREAMS; i++) {
        struct tcp_bond_stream *stream = &g_streams[i][worker_idx];

        pthread_spin_lock(&stream->lock);
        stream_drop_all_locked(stream, ops);
        stream->epoch = 0;
        stream->next_seq = 0;
        stream->valid = 0;
        stream->emitting = 0;
        free(stream->slots);
        stream->slots = NULL;
        pthread_spin_unlock(&stream->lock);
    }
}
