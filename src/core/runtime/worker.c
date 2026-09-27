#include "../../../inc/runtime/worker.h"
#include "../../../inc/interface/interface.h"
#include "../../../inc/dataplane/bypass.h"
#include "../../../inc/dataplane/tx.h"
#include "../../../inc/dataplane/wan.h"
#include "../../../inc/dataplane/lan.h"
#include "../../../inc/crypto/crypto.h"

#include <errno.h>
#include <netinet/in.h>
#include <sched.h>
#include <string.h>
#include <time.h>

static struct core_flow_route
    g_flow_routes[CORE_FLOW_ROUTE_SETS][CORE_FLOW_ROUTE_WAYS];
static uint64_t g_worker_load[CORE_CRYPTO_WORKERS];
static pthread_mutex_t g_flow_route_lock = PTHREAD_MUTEX_INITIALIZER;

int core_worker_pin_cpu(int cpu_id)
{
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(cpu_id, &cpus);
    int rc = pthread_setaffinity_np(pthread_self(), sizeof(cpus), &cpus);
    return rc ? -rc : 0;
}

static int select_flow_core(const uint8_t *pkt, uint32_t len, int worker_hint)
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
    } else if (proto == IPPROTO_ICMP) {
        l4_off = 14u + ihl;
        if (len < l4_off + 8u)
            return -EINVAL;
        if (pkt[l4_off] == 0 || pkt[l4_off] == 8)
            src_port = dst_port = ((uint16_t)pkt[l4_off + 4] << 8) |
                                  pkt[l4_off + 5];
    }
    if (src_ip > dst_ip || (src_ip == dst_ip && src_port > dst_port)) {
        tmp_ip = src_ip; src_ip = dst_ip; dst_ip = tmp_ip;
        tmp_port = src_port; src_port = dst_port; dst_port = tmp_port;
    }
    hash = src_ip ^ dst_ip ^ (((uint32_t)src_port << 16) | dst_port) ^ proto;
    hash ^= hash >> 16;
    hash *= 0x85ebca6bu;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35u;
    hash ^= hash >> 16;
    set = g_flow_routes[hash & (CORE_FLOW_ROUTE_SETS - 1u)];

    for (unsigned way = 0; way < CORE_FLOW_ROUTE_WAYS; way++) {
        struct core_flow_route *flow = &set[way];
        if (atomic_load_explicit(&flow->valid, memory_order_acquire) &&
            flow->ip_a == src_ip && flow->ip_b == dst_ip &&
            flow->port_a == src_port && flow->port_b == dst_port &&
            flow->protocol == proto)
            return worker_hint >= 0 && worker_hint != flow->worker_idx
                ? -EXDEV : flow->worker_idx;
    }

    pthread_mutex_lock(&g_flow_route_lock);
    for (unsigned way = 0; way < CORE_FLOW_ROUTE_WAYS; way++) {
        struct core_flow_route *flow = &set[way];
        if (!atomic_load_explicit(&flow->valid, memory_order_relaxed)) {
            if (empty < 0)
                empty = (int)way;
            continue;
        }
        if (flow->ip_a == src_ip && flow->ip_b == dst_ip &&
            flow->port_a == src_port && flow->port_b == dst_port &&
            flow->protocol == proto) {
            int chosen = worker_hint >= 0 && worker_hint != flow->worker_idx
                ? -EXDEV : flow->worker_idx;
            pthread_mutex_unlock(&g_flow_route_lock);
            return chosen;
        }
    }
    if (empty < 0) {
        pthread_mutex_unlock(&g_flow_route_lock);
        return -ENOSPC;
    }

    unsigned chosen = 0;
    for (unsigned i = 1; i < CORE_CRYPTO_WORKERS; i++)
        if (g_worker_load[i] < g_worker_load[chosen])
            chosen = i;
    struct core_flow_route *flow = &set[empty];
    flow->ip_a = src_ip;
    flow->ip_b = dst_ip;
    flow->port_a = src_port;
    flow->port_b = dst_port;
    flow->protocol = proto;
    flow->worker_idx = worker_hint >= 0 ? (uint8_t)worker_hint : (uint8_t)chosen;
    g_worker_load[flow->worker_idx]++;
    atomic_store_explicit(&flow->valid, 1, memory_order_release);
    int result = flow->worker_idx;
    pthread_mutex_unlock(&g_flow_route_lock);
    return result;
}

int core_worker_select_encrypt_core(const uint8_t *pkt, uint32_t len)
{
    return select_flow_core(pkt, len, -1);
}

int core_worker_select_tx_core(const uint8_t *pkt, uint32_t len)
{
    int crypto = select_flow_core(pkt, len, -1);
    return crypto < 0 ? crypto : crypto % (int)CORE_TX_WORKERS;
}

int core_worker_select_decrypt_core(struct ne_pair *pair,
                                    const struct ne_packet *pkt)
{
    uint8_t id;
    if (!pair || !pkt || !pkt->total_len ||
        ne_packet_read(pair, pkt, pkt->total_len - 1u, &id, 1))
        return -EINVAL;
    id &= CORE_JUMBO_CORE_MASK;
    return id < CORE_CRYPTO_WORKERS ? id : -EINVAL;
}

int core_worker_rx_submit(struct core_runtime *rt, const struct ne_packet *pkt)
{
    uint32_t contiguous;
    uint8_t *data = ne_packet_at(&rt->pair, pkt, 0, &contiguous);
    if (!data || contiguous < 14)
        return -EINVAL;

    int worker;
    if (pkt->dir == NE_DIR_LOCAL) {
        if (contiguous < 34)
            return -EINVAL;
        const struct crypto_policy *policy = NULL;
        if (core_tx_match_out(&rt->config, data, pkt->total_len, &policy) <= 0)
            return -EACCES;
        worker = core_worker_select_encrypt_core(data, pkt->total_len);
    } else if (pkt->dir == NE_DIR_WAN) {
        worker = data[12] == 0x08 && data[13] == 0x00
            ? core_worker_select_encrypt_core(data, pkt->total_len)
            : core_worker_select_decrypt_core(&rt->pair, pkt);
    } else {
        return -EINVAL;
    }
    if (worker < 0)
        return worker;
    return ne_ring_try_push(&rt->rx_to_crypto[pkt->dir][worker], pkt);
}

static int push_crypto_batch(struct core_runtime *rt,
                             struct core_packet_batch *batch,
                             enum ne_packet_dir dir, int tx_slot)
{
    struct ne_ring *ring = &rt->tx_pending[dir][tx_slot];
    for (unsigned i = 0; i < batch->count; i++) {
        batch->packets[i].dir = dir;
        batch->packets[i].tx_slot = tx_slot;
        if (dir == NE_DIR_WAN)
            batch->packets[i].wan_idx = 0;
        else
            batch->packets[i].local_idx = 0;
    }
    int rc = batch->count == 2
        ? ne_ring_try_push_pair(ring, &batch->packets[0], &batch->packets[1])
        : ne_ring_try_push(ring, &batch->packets[0]);
    if (rc)
        for (unsigned i = 0; i < batch->count; i++)
            ne_packet_free(&rt->pair, &batch->packets[i]);
    return rc;
}

int core_worker_crypto_step(struct core_runtime *rt, struct ne_packet *pkt,
                            int worker_idx)
{
    if (worker_idx < 0 || worker_idx >= (int)CORE_CRYPTO_WORKERS)
        return -EINVAL;
    int tx_slot = worker_idx % (int)CORE_TX_WORKERS;
    uint32_t contiguous;
    uint8_t *data = ne_packet_at(&rt->pair, pkt, 0, &contiguous);
    if (!data || contiguous < 14)
        return -EINVAL;

    if (pkt->dir == NE_DIR_LOCAL) {
        if (contiguous < 34)
            return -EINVAL;
        const struct crypto_policy *policy = NULL;
        if (core_tx_match_out(&rt->config, data, pkt->total_len, &policy) <= 0)
            return -EACCES;
        if (policy->action == POLICY_ACTION_BYPASS) {
            uint8_t wan_idx;
            int rc = core_bypass_handle_lan_wan(&rt->config, data,
                                                 pkt->total_len, &wan_idx);
            if (rc)
                return rc;
            pkt->dir = NE_DIR_WAN;
            pkt->wan_idx = wan_idx;
            pkt->tx_slot = tx_slot;
            return ne_ring_try_push(&rt->tx_pending[NE_DIR_WAN][tx_slot], pkt);
        }
        struct core_packet_batch batch;
        int rc = core_lan_process(&rt->config, &rt->pair, pkt,
                                  (uint8_t)worker_idx, &batch);
        if (rc)
            return rc;
        return push_crypto_batch(rt, &batch, NE_DIR_WAN, tx_slot);
    }

    if (pkt->dir != NE_DIR_WAN)
        return -EINVAL;
    uint16_t type = ((uint16_t)data[12] << 8) | data[13];
    if (type != 0x0800u &&
        core_worker_select_decrypt_core(&rt->pair, pkt) != worker_idx)
        return -EXDEV;
    int rc = core_wan_process(&rt->config, &rt->pair, pkt);
    if (rc == 1)
        return 0;
    if (rc)
        return rc;
    pkt->dir = NE_DIR_LOCAL;
    pkt->local_idx = 0;
    pkt->tx_slot = tx_slot;
    return ne_ring_try_push(&rt->tx_pending[NE_DIR_LOCAL][tx_slot], pkt);
}

int core_worker_tx_step(struct core_runtime *rt, int tx_slot)
{
    if (tx_slot < 0 || tx_slot >= (int)CORE_TX_WORKERS)
        return -EINVAL;
    int total = 0;
    for (int dir = NE_DIR_LOCAL; dir <= NE_DIR_WAN; dir++) {
        struct ne_ring *ring = &rt->tx_pending[dir][tx_slot];
        int rc = ne_cq_drain_slot(&rt->pair, dir, tx_slot);
        if (rc < 0)
            return rc;
        total += rc;
        rc = ne_tx_drain_all(&rt->pair, dir, &ring, 1, 0, tx_slot);
        if (rc < 0)
            return rc;
        total += rc;
    }
    return total;
}

static void *core_worker_run(void *arg)
{
    struct core_worker *worker = arg;
    struct core_runtime *rt = worker->context;
    const struct timespec idle = { .tv_sec = 0, .tv_nsec = CORE_WORKER_IDLE_NS };
    while (!atomic_load_explicit(&rt->stop_requested, memory_order_acquire)) {
        int worked = 0;
        if (worker->role == CORE_WORKER_TX) {
            worked = core_worker_tx_step(rt, worker->slot) > 0;
        } else if (worker->role == CORE_WORKER_CRYPTO) {
            struct ne_packet packets[NE_BATCH_SIZE];
            for (int dir = NE_DIR_LOCAL; dir <= NE_DIR_WAN; dir++) {
                unsigned count = ne_ring_try_pop_batch(
                    &rt->rx_to_crypto[dir][worker->slot], packets, NE_BATCH_SIZE);
                worked |= count > 0;
                for (unsigned i = 0; i < count; i++) {
                    pthread_rwlock_rdlock(&rt->config_lock);
                    int rc = core_worker_crypto_step(rt, &packets[i], worker->slot);
                    pthread_rwlock_unlock(&rt->config_lock);
                    if (rc)
                        ne_packet_free(&rt->pair, &packets[i]);
                }
            }
        } else {
            enum ne_packet_dir dir = worker->role == CORE_WORKER_LAN_RX
                ? NE_DIR_LOCAL : NE_DIR_WAN;
            struct ne_packet packets[NE_BATCH_SIZE];
            int count = ne_recv_slot(&rt->pair, dir, worker->slot,
                                     packets, NE_BATCH_SIZE);
            worked |= count > 0;
            for (int i = 0; i < count; i++) {
                pthread_rwlock_rdlock(&rt->config_lock);
                int rc = core_worker_rx_submit(rt, &packets[i]);
                pthread_rwlock_unlock(&rt->config_lock);
                if (rc)
                    ne_packet_free(&rt->pair, &packets[i]);
            }
            worked |= ne_fill_slot(&rt->pair, dir, worker->slot) > 0;
        }
        if (!worked)
            nanosleep(&idle, NULL);
    }
    if (worker->role == CORE_WORKER_CRYPTO)
        core_l2_pqc_reassembly_reset(&rt->pair);
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

    for (int dir = NE_DIR_LOCAL; dir <= NE_DIR_WAN; dir++) {
        for (unsigned i = 0; i < CORE_CRYPTO_WORKERS; i++) {
            struct ne_ring *ring = &rt->rx_to_crypto[dir][i];
            if (!ring->buf)
                continue;
            struct ne_packet pkt;
            while (ne_ring_try_pop(ring, &pkt) > 0)
                ne_packet_free(&rt->pair, &pkt);
            ne_ring_destroy(ring);
        }
        for (unsigned i = 0; i < CORE_TX_WORKERS; i++) {
            struct ne_ring *ring = &rt->tx_pending[dir][i];
            if (!ring->buf)
                continue;
            struct ne_packet pkt;
            while (ne_ring_try_pop(ring, &pkt) > 0)
                ne_packet_free(&rt->pair, &pkt);
            ne_ring_destroy(ring);
        }
    }
    rt->running = 0;
}

static int start_worker(struct core_runtime *rt, enum core_worker_role role,
                        int cpu_id, int slot)
{
    struct core_worker *w = &rt->workers[rt->worker_count];
    *w = (struct core_worker){ .role = role, .cpu_id = cpu_id,
                              .slot = slot, .context = rt };
    pthread_attr_t attr;
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu_id, &mask);
    int rc = pthread_attr_init(&attr);
    if (rc)
        return -rc;
    rc = pthread_attr_setaffinity_np(&attr, sizeof(mask), &mask);
    if (!rc)
        rc = pthread_create(&w->thread, &attr, core_worker_run, w);
    pthread_attr_destroy(&attr);
    if (rc)
        return -rc;
    w->running = 1;
    rt->worker_count++;
    return 0;
}

int core_worker_start_all(struct core_runtime *rt)
{
    if (rt->worker_count || rt->running)
        return -EBUSY;
    if (!rt->pair.umem || rt->config.local_count != 1 ||
        rt->config.wan_count != 1)
        return -ENODEV;
    atomic_store(&rt->stop_requested, 0);
    int rc;
    for (int dir = NE_DIR_LOCAL; dir <= NE_DIR_WAN; dir++) {
        for (unsigned i = 0; i < CORE_CRYPTO_WORKERS; i++) {
            rc = ne_ring_init(&rt->rx_to_crypto[dir][i], CORE_RING_CAPACITY, 0);
            if (rc)
                goto fail;
        }
        for (unsigned i = 0; i < CORE_TX_WORKERS; i++) {
            rc = ne_ring_init(&rt->tx_pending[dir][i], CORE_RING_CAPACITY, 0);
            if (rc)
                goto fail;
        }
    }
    memset(g_flow_routes, 0, sizeof(g_flow_routes));
    memset(g_worker_load, 0, sizeof(g_worker_load));

    for (unsigned i = 0; i < CORE_TX_WORKERS; i++) {
        rc = start_worker(rt, CORE_WORKER_TX, CORE_CPU_TX[i], i);
        if (rc)
            goto fail;
    }
    for (unsigned i = 0; i < CORE_CRYPTO_WORKERS; i++) {
        rc = start_worker(rt, CORE_WORKER_CRYPTO, CORE_CPU_CRYPTO[i], i);
        if (rc)
            goto fail;
    }
    rc = start_worker(rt, CORE_WORKER_WAN_RX, CORE_CPU_RX_WAN[0], 0);
    if (rc)
        goto fail;
    rc = start_worker(rt, CORE_WORKER_LAN_RX, CORE_CPU_RX_LAN[0], 0);
    if (rc)
        goto fail;
    rt->running = 1;
    return 0;

fail:
    core_worker_stop_all(rt);
    return rc;
}
