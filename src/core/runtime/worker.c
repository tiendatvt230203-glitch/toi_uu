#include "../../../inc/core/runtime/worker.h"
#include "../../../inc/core/interface/interface.h"
#include "../../../inc/core/dataplane/bypass.h"
#include "../../../inc/core/dataplane/tx.h"
#include "../../../inc/core/dataplane/wan.h"

#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <time.h>
#include <sched.h>
#include "../../../inc/core/dataplane/lan.h"
#include "../../../inc/core/crypto/crypto.h"

static struct core_flow_route
    g_flow_routes[CORE_FLOW_ROUTE_SETS][CORE_FLOW_ROUTE_WAYS];
static uint64_t g_worker_load[CORE_CRYPTO_WORKERS];
static uint64_t g_tx_load[CORE_TX_WORKERS];
static unsigned g_worker_cursor, g_tx_cursor;
static pthread_mutex_t g_flow_route_lock = PTHREAD_MUTEX_INITIALIZER;

int core_worker_pin_cpu(int cpu_id)
{
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(cpu_id, &cpus);
    int rc = pthread_setaffinity_np(pthread_self(), sizeof(cpus), &cpus);
    return rc ? -rc : 0;
}

static int select_flow_core(const uint8_t *pkt, uint32_t len, int tx_mode, int worker_hint)
{
    uint32_t src_ip, dst_ip, hash, tmp_ip;
    uint16_t src_port = 0, dst_port = 0, tmp_port;
    uint32_t ihl, l4_off;
    uint8_t proto;
    struct core_flow_route *set;
    int empty = -1;

    if (!pkt || len < 34 || pkt[12] != 0x08 || pkt[13] != 0x00 ||
        (pkt[14] >> 4) != 4)
        return -EINVAL;
    ihl = (uint32_t)(pkt[14] & 15u) * 4u;
    if (ihl < 20 || len < 14u + ihl)
        return -EINVAL;
    memcpy(&src_ip, pkt + 26, sizeof(src_ip));
    memcpy(&dst_ip, pkt + 30, sizeof(dst_ip));
    src_ip = ntohl(src_ip);
    dst_ip = ntohl(dst_ip);
    proto = pkt[23];
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        l4_off = 14u + ihl;
        if (len < l4_off + 4u)
            return -EINVAL;
        src_port = ((uint16_t)pkt[l4_off] << 8) | pkt[l4_off + 1];
        dst_port = ((uint16_t)pkt[l4_off + 2] << 8) | pkt[l4_off + 3];
    }
    if ((proto == IPPROTO_TCP || proto == IPPROTO_UDP) &&
        (src_ip > dst_ip || (src_ip == dst_ip && src_port > dst_port))) {
        tmp_ip = src_ip;
        src_ip = dst_ip;
        dst_ip = tmp_ip;
        tmp_port = src_port;
        src_port = dst_port;
        dst_port = tmp_port;
    }
    hash = src_ip ^ dst_ip;
    hash ^= ((uint32_t)src_port << 16) | dst_port;
    hash ^= proto;
    hash ^= hash >> 16;
    hash *= 0x85ebca6bu;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35u;
    hash ^= hash >> 16;

    if (tx_mode == 1) return hash % CORE_TX_WORKERS;
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
        return hash % (tx_mode ? CORE_TX_WORKERS : CORE_CRYPTO_WORKERS);
    set = g_flow_routes[hash & (CORE_FLOW_ROUTE_SETS - 1u)];
    /* Entries are immutable until all workers have stopped. */
    for (unsigned way = 0; way < CORE_FLOW_ROUTE_WAYS; way++) {
        struct core_flow_route *flow = &set[way];
        if (atomic_load_explicit(&flow->valid, memory_order_acquire) &&
            flow->ip_a == src_ip && flow->ip_b == dst_ip &&
            flow->port_a == src_port && flow->port_b == dst_port &&
            flow->protocol == proto)
            return tx_mode ? flow->tx_slot : flow->worker_idx;
    }
    pthread_mutex_lock(&g_flow_route_lock);
    for (unsigned way = 0; way < CORE_FLOW_ROUTE_WAYS; way++) {
        struct core_flow_route *flow = &set[way];
        if (!flow->valid) {
            if (empty < 0) empty = (int)way;
            continue;
        }
        if (flow->ip_a != src_ip || flow->ip_b != dst_ip ||
            flow->port_a != src_port || flow->port_b != dst_port ||
            flow->protocol != proto)
            continue;
        int chosen = tx_mode ? flow->tx_slot : flow->worker_idx;
        pthread_mutex_unlock(&g_flow_route_lock);
        return chosen;
    }
    if (empty < 0) {
        pthread_mutex_unlock(&g_flow_route_lock);
        return hash % (tx_mode ? CORE_TX_WORKERS : CORE_CRYPTO_WORKERS);
    }
    struct core_flow_route *flow = &set[empty];
    flow->ip_a = src_ip;
    flow->ip_b = dst_ip;
    flow->port_a = src_port;
    flow->port_b = dst_port;
    flow->protocol = proto;
    unsigned wc = g_worker_cursor % CORE_CRYPTO_WORKERS;
    if (worker_hint < 0) g_worker_cursor++;
    unsigned tc = g_tx_cursor++ % CORE_TX_WORKERS;
    unsigned best_w = wc, best_t = tc;
    for (unsigned i = 1; i < CORE_CRYPTO_WORKERS; i++) {
        unsigned w = (wc + i) % CORE_CRYPTO_WORKERS;
        if (g_worker_load[w] < g_worker_load[best_w]) best_w = w;
    }
    for (unsigned i = 1; i < CORE_TX_WORKERS; i++) {
        unsigned t = (tc + i) % CORE_TX_WORKERS;
        if (g_tx_load[t] < g_tx_load[best_t]) best_t = t;
    }
    flow->worker_idx = worker_hint >= 0 ? (unsigned)worker_hint : best_w;
    flow->tx_slot = best_t;
    g_worker_load[flow->worker_idx]++;
    g_tx_load[flow->tx_slot]++;
    atomic_store_explicit(&flow->valid, 1, memory_order_release);
    int chosen = tx_mode ? flow->tx_slot : flow->worker_idx;
    pthread_mutex_unlock(&g_flow_route_lock);
    return chosen;
}

int core_worker_select_encrypt_core(const uint8_t *pkt, uint32_t len)
{
    return select_flow_core(pkt, len, 0, -1);
}

int core_worker_select_tx_core(const uint8_t *pkt, uint32_t len)
{
    return select_flow_core(pkt, len, 1, -1);
}

int core_worker_select_decrypt_core(const uint8_t *pkt, uint32_t len)
{
    if (!pkt || len < 16)
        return -EINVAL;
    /* Wire core ID is a worker index, not a physical CPU number. */
    uint8_t id = pkt[15] & CORE_JUMBO_CORE_MASK;
    if (id >= CORE_CRYPTO_WORKERS)
        return -EINVAL;
    return id;
}


int core_worker_rx_submit(struct core_runtime *rt, const struct ne_packet *pkt)
{
    uint8_t data[ETH_FRAME_MAX], wan_idx;
    const struct crypto_policy *policy = NULL;
    struct ne_packet job = *pkt;
    int len = ne_packet_copy(&rt->pair, pkt, data, sizeof(data));
    if (len < 0) return len;

    if (pkt->dir == NE_DIR_LOCAL) {
        if (core_tx_match_out(&rt->config, data, len, &policy) <= 0)
            return -EACCES;
        if (policy->action == POLICY_ACTION_BYPASS) {
            int rc = core_bypass_handle_lan_wan(&rt->config, data, len, &wan_idx);
            if (rc) return rc;
            int tx = core_worker_select_tx_core(data, len);
            if (tx < 0) return tx;
            job.dir = NE_DIR_WAN;
            job.wan_idx = wan_idx;
            job.tx_slot = tx;
            return ne_ring_try_push(&rt->to_wan_tx[wan_idx][tx], &job);
        }
        int worker = core_worker_select_encrypt_core(data, len);
        if (worker < 0) return worker;
        job.tx_slot = select_flow_core(data, len, 2, worker);
        return ne_ring_try_push(&rt->local_to_crypto[worker], &job);
    }

    if (pkt->dir != NE_DIR_WAN) return -EINVAL;
    if (len >= 14 && data[12] == 0x08 && data[13] == 0x00) {
        uint32_t plain_len = len;
        int rc = core_bypass_handle_wan_lan(&rt->config, data, &plain_len);
        if (rc) return rc;
        int tx = core_worker_select_tx_core(data, plain_len);
        if (tx < 0) return tx;
        job.dir = NE_DIR_LOCAL;
        job.local_idx = 0;
        job.tx_slot = tx;
        return ne_ring_try_push(&rt->to_lan_tx[0][tx], &job);
    }
    int worker = core_worker_select_decrypt_core(data, len);
    if (worker < 0) return worker;
    return ne_ring_try_push(&rt->wan_to_crypto[worker], &job);
}

int core_worker_crypto_step(struct core_runtime *rt, struct ne_packet *pkt,
                            int worker_idx)
{
    uint8_t data[ETH_FRAME_MAX];
    struct core_packet_batch batch;
    struct ne_packet output[NE_PACKET_MAX_SEGMENTS];
    struct ne_ring *ring;
    unsigned count = 0;
    int rc, tx;
    if (worker_idx < 0 || worker_idx >= (int)CORE_CRYPTO_WORKERS)
        return -EINVAL;
    rc = ne_packet_copy(&rt->pair, pkt, data, sizeof(data));
    if (rc < 0) return rc;
    uint32_t len = rc;

    if (pkt->dir == NE_DIR_LOCAL) {
        rc = core_lan_process(&rt->config, data, len, worker_idx, &batch);
        if (rc) return rc;
        tx = pkt->tx_slot;
        if (tx >= (int)CORE_TX_WORKERS) return -EINVAL;
        ring = &rt->to_wan_tx[0][tx];
        for (; count < batch.count; count++) {
            rc = ne_packet_store(&rt->pair, batch.data[count],
                                  batch.len[count], &output[count]);
            if (rc) goto discard;
            output[count].dir = NE_DIR_WAN;
            output[count].wan_idx = 0;
            output[count].tx_slot = tx;
            output[count].jumbo_fragment_index = count;
            output[count].jumbo_fragment_count = batch.count;
        }
    } else {
        if (pkt->dir != NE_DIR_WAN ||
            core_worker_select_decrypt_core(data, len) != worker_idx)
            return -EINVAL;
        rc = core_wan_process(&rt->config, data, &len, sizeof(data));
        if (rc == 1) {
            /* Reassembly owns a copy, not the RX UMEM frame. */
            ne_packet_free(&rt->pair, pkt);
            return 0;
        }
        if (rc) return rc;
        tx = select_flow_core(data, len, 2, worker_idx);
        if (tx < 0) return tx;
        ring = &rt->to_lan_tx[0][tx];
        rc = ne_packet_store(&rt->pair, data, len, &output[0]);
        if (rc) return rc;
        count = 1;
        output[0].dir = NE_DIR_LOCAL;
        output[0].local_idx = 0;
        output[0].tx_slot = tx;
    }

    /* Publish a complete jumbo group at once; no partial enqueue. */
    pthread_spin_lock(&ring->push_lock);
    uint32_t head = __atomic_load_n(&ring->head, __ATOMIC_RELAXED);
    uint32_t tail = __atomic_load_n(&ring->tail, __ATOMIC_ACQUIRE);
    if (head - tail + count > ring->cap) {
        pthread_spin_unlock(&ring->push_lock);
        rc = -ENOSPC;
        goto discard;
    }
    for (unsigned i = 0; i < count; i++)
        ring->buf[(head + i) & ring->mask] = output[i];
    __atomic_store_n(&ring->head, head + count, __ATOMIC_RELEASE);
    pthread_spin_unlock(&ring->push_lock);
    ne_packet_free(&rt->pair, pkt);
    return 0;

discard:
    for (unsigned i = 0; i < count; i++)
        ne_packet_free(&rt->pair, &output[i]);
    return rc;
}

int core_worker_tx_step(struct core_runtime *rt, int tx_slot)
{
    if (tx_slot < 0 || tx_slot >= (int)CORE_TX_WORKERS)
        return -EINVAL;
    int total = 0;
    for (int dir = NE_DIR_LOCAL; dir <= NE_DIR_WAN; dir++) {
        struct ne_ring *ring = dir == NE_DIR_LOCAL
            ? &rt->to_lan_tx[0][tx_slot] : &rt->to_wan_tx[0][tx_slot];
        int rc = ne_cq_drain_slot(&rt->pair, dir, tx_slot);
        if (rc < 0) return rc;
        rc = ne_tx_drain_all(&rt->pair, dir, &ring, 1, 0, tx_slot);
        if (rc < 0) return rc;
        total += rc;
    }
    return total;
}

static void *core_worker_run(void *arg)
{
    struct core_worker *worker = arg;
    struct core_runtime *rt = worker->context;
    while (!atomic_load_explicit(&rt->stop_requested, memory_order_acquire)) {
        if (worker->role == CORE_WORKER_TX) {
            core_worker_tx_step(rt, worker->slot);
        } else if (worker->role == CORE_WORKER_CRYPTO) {
            for (int dir = NE_DIR_LOCAL; dir <= NE_DIR_WAN; dir++) {
                struct ne_ring *ring = dir == NE_DIR_LOCAL
                    ? &rt->local_to_crypto[worker->slot]
                    : &rt->wan_to_crypto[worker->slot];
                struct ne_packet packets[NE_BATCH_SIZE];
                unsigned count = ne_ring_try_pop_batch(ring, packets, NE_BATCH_SIZE);
                for (unsigned i = 0; i < count; i++)
                    if (core_worker_crypto_step(rt, &packets[i], worker->slot))
                        ne_packet_free(&rt->pair, &packets[i]);
            }
        } else {
            enum ne_packet_dir dir = worker->role == CORE_WORKER_LAN_RX
                ? NE_DIR_LOCAL : NE_DIR_WAN;
            struct ne_packet packets[NE_BATCH_SIZE];
            int count = ne_recv_slot(&rt->pair, dir, worker->slot, packets, NE_BATCH_SIZE);
            for (int i = 0; i < count; i++)
                if (core_worker_rx_submit(rt, &packets[i]))
                    ne_packet_free(&rt->pair, &packets[i]);
            ne_fill_slot(&rt->pair, dir, worker->slot);
        }
    }
    core_l2_pqc_reassembly_reset();
    return NULL;
}

void core_worker_stop_all(struct core_runtime *rt)
{
    atomic_store_explicit(&rt->stop_requested, 1, memory_order_release);
    for (int i = 0; i < rt->worker_count; i++) {
        if (rt->workers[i].running) {
            pthread_join(rt->workers[i].thread, NULL);
            rt->workers[i].running = 0;
        }
    }
    rt->worker_count = 0;
    /* Free only queued frames; submitted TX frames belong to CQ/UMEM. */
    for (unsigned i = 0; i < CORE_CRYPTO_WORKERS + CORE_TX_WORKERS; i++) {
        for (int dir = NE_DIR_LOCAL; dir <= NE_DIR_WAN; dir++) {
            struct ne_ring *ring = i < CORE_CRYPTO_WORKERS
                ? (dir == NE_DIR_LOCAL ? &rt->local_to_crypto[i] : &rt->wan_to_crypto[i])
                : (dir == NE_DIR_LOCAL ? &rt->to_lan_tx[0][i-CORE_CRYPTO_WORKERS]
                                       : &rt->to_wan_tx[0][i-CORE_CRYPTO_WORKERS]);
            if (!ring->buf) continue;
            struct ne_packet pkt;
            while (ne_ring_try_pop(ring, &pkt) > 0)
                ne_packet_free(&rt->pair, &pkt);
            ne_ring_destroy(ring);
        }
    }
    rt->running = 0;
}

int core_worker_start_all(struct core_runtime *rt)
{
    if (rt->worker_count || rt->running) return -EBUSY;
    if (!rt->pair.umem || rt->config.local_count != 1 ||
        rt->config.wan_count != 1) return -ENODEV;
    int rc = 0;
    atomic_store(&rt->stop_requested, 0);
    for (unsigned i = 0; i < CORE_CRYPTO_WORKERS + CORE_TX_WORKERS; i++) {
        for (int dir = NE_DIR_LOCAL; dir <= NE_DIR_WAN; dir++) {
            struct ne_ring *ring = i < CORE_CRYPTO_WORKERS
                ? (dir == NE_DIR_LOCAL ? &rt->local_to_crypto[i] : &rt->wan_to_crypto[i])
                : (dir == NE_DIR_LOCAL ? &rt->to_lan_tx[0][i-CORE_CRYPTO_WORKERS]
                                       : &rt->to_wan_tx[0][i-CORE_CRYPTO_WORKERS]);
            rc = ne_ring_init(ring, CORE_RING_CAPACITY, 0);
            if (rc) goto fail;
        }
    }
    memset(g_flow_routes, 0, sizeof(g_flow_routes));
    memset(g_worker_load, 0, sizeof(g_worker_load));
    memset(g_tx_load, 0, sizeof(g_tx_load));
    g_worker_cursor = g_tx_cursor = 0;
    for (int role = CORE_WORKER_TX; role >= CORE_WORKER_LAN_RX; role--) {
        unsigned count = role == CORE_WORKER_TX ? CORE_TX_WORKERS :
                         role == CORE_WORKER_CRYPTO ? CORE_CRYPTO_WORKERS : 1;
        const uint8_t *cpus = role == CORE_WORKER_TX ? CORE_CPU_TX :
                             role == CORE_WORKER_CRYPTO ? CORE_CPU_CRYPTO :
                             role == CORE_WORKER_WAN_RX ? CORE_CPU_RX_WAN : CORE_CPU_RX_LAN;
        for (unsigned slot = 0; slot < count; slot++) {
            struct core_worker *w = &rt->workers[rt->worker_count];
            *w = (struct core_worker){ .role = role, .cpu_id = cpus[slot],
                                      .slot = slot, .context = rt };
            pthread_attr_t attr;
            cpu_set_t mask;
            CPU_ZERO(&mask);
            CPU_SET(w->cpu_id, &mask);
            rc = pthread_attr_init(&attr);
            if (rc) { rc = -rc; goto fail; }
            rc = pthread_attr_setaffinity_np(&attr, sizeof(mask), &mask);
            if (!rc) rc = pthread_create(&w->thread, &attr, core_worker_run, w);
            pthread_attr_destroy(&attr);
            if (rc) { rc = -rc; goto fail; }
            w->running = 1;
            rt->worker_count++;
        }
    }
    rt->running = 1;
    return 0;
fail:
    core_worker_stop_all(rt);
    return rc;
}
