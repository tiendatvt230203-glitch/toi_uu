#include "../../../inc/core/runtime/worker.h"
#include "../../../inc/core/interface/interface.h"
#include "../../../inc/core/dataplane/bypass.h"
#include "../../../inc/core/dataplane/tx.h"
#include "../../../inc/core/dataplane/wan.h"

#include <errno.h>
#include <netinet/in.h>
#include <string.h>

/* Same sticky flow-set layout as MTU-1500-old/crypto_route.c. */
static struct core_flow_route
    g_flow_routes[CORE_FLOW_ROUTE_SETS][CORE_FLOW_ROUTE_WAYS];
static struct core_flow_route
    g_tx_routes[CORE_FLOW_ROUTE_SETS][CORE_FLOW_ROUTE_WAYS];
static uint64_t g_worker_flow_count[CORE_CRYPTO_WORKERS];
static uint64_t g_tx_flow_count[CORE_TX_WORKERS];
static pthread_mutex_t g_flow_route_lock = PTHREAD_MUTEX_INITIALIZER;

int core_worker_start_all()
{

}

void core_worker_stop_all()
{
    
}

int core_worker_pin_cpu()
{

}

static int select_flow_core(const uint8_t *pkt, uint32_t len,
                            enum core_worker_role role)
{
    const uint8_t *cpus = role == CORE_WORKER_TX ? CORE_CPU_TX : CORE_CPU_CRYPTO;
    uint32_t count = role == CORE_WORKER_TX ? CORE_TX_WORKERS : CORE_CRYPTO_WORKERS;
    uint64_t *flow_count = role == CORE_WORKER_TX ? g_tx_flow_count : g_worker_flow_count;
    uint32_t src_ip, dst_ip, hash, tmp_ip;
    uint16_t src_port = 0, dst_port = 0, tmp_port;
    uint32_t ihl, l4_off;
    uint8_t proto;
    struct core_flow_route *set;
    int empty = -1, chosen = 0;

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
        /* Echo request/reply share one identifier and therefore one core. */
        if (pkt[l4_off] == 8 || pkt[l4_off] == 0)
            src_port = dst_port =
                ((uint16_t)pkt[l4_off + 4] << 8) | pkt[l4_off + 5];
    } else if (proto != IPPROTO_OSPF_VAL) {
        return -EAFNOSUPPORT;
    }
    if (src_ip > dst_ip || (src_ip == dst_ip && src_port > dst_port)) {
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

    set = role == CORE_WORKER_TX
        ? g_tx_routes[hash & (CORE_FLOW_ROUTE_SETS - 1u)]
        : g_flow_routes[hash & (CORE_FLOW_ROUTE_SETS - 1u)];
    for (unsigned int way = 0; way < CORE_FLOW_ROUTE_WAYS; way++) {
        if (atomic_load_explicit(&set[way].valid, memory_order_acquire) &&
            set[way].ip_a == src_ip && set[way].ip_b == dst_ip &&
            set[way].port_a == src_port && set[way].port_b == dst_port &&
            set[way].protocol == proto)
            return set[way].worker_idx;
    }

    pthread_mutex_lock(&g_flow_route_lock);
    for (unsigned int way = 0; way < CORE_FLOW_ROUTE_WAYS; way++) {
        if (!atomic_load_explicit(&set[way].valid, memory_order_acquire)) {
            if (empty < 0)
                empty = way;
        } else if (set[way].ip_a == src_ip && set[way].ip_b == dst_ip &&
                   set[way].port_a == src_port && set[way].port_b == dst_port &&
                   set[way].protocol == proto) {
            chosen = set[way].worker_idx;
            pthread_mutex_unlock(&g_flow_route_lock);
            return chosen;
        }
    }
    /* Never evict a live flow: doing so could move later packets to another core. */
    if (empty < 0) {
        pthread_mutex_unlock(&g_flow_route_lock);
        return -ENOSPC;
    }
    for (uint32_t core = 1; core < count; core++) {
        if (flow_count[core] < flow_count[chosen] ||
            (flow_count[core] == flow_count[chosen] && cpus[core] < cpus[chosen]))
            chosen = core;
    }
    set[empty].ip_a = src_ip;
    set[empty].ip_b = dst_ip;
    set[empty].port_a = src_port;
    set[empty].port_b = dst_port;
    set[empty].protocol = proto;
    set[empty].worker_idx = (uint8_t)chosen;
    flow_count[chosen]++;
    atomic_store_explicit(&set[empty].valid, 1, memory_order_release);
    pthread_mutex_unlock(&g_flow_route_lock);
    return chosen;
}

int core_worker_select_encrypt_core(const uint8_t *pkt, uint32_t len)
{
    return select_flow_core(pkt, len, CORE_WORKER_CRYPTO);
}

int core_worker_select_tx_core(const uint8_t *pkt, uint32_t len)
{
    return select_flow_core(pkt, len, CORE_WORKER_TX);
}

int core_worker_select_decrypt_core(const uint8_t *pkt, uint32_t len)
{
    if (!pkt || len < 16)
        return -EINVAL;
    /* BPF already sends only the four fake EtherTypes to WAN RX. */
    if (pkt[15] >= CORE_CRYPTO_WORKERS)
        return -EINVAL;
    return pkt[15];
}

int core_worker_rx_submit(struct core_runtime *rt, const struct ne_packet *pkt)
{
    const uint8_t *data;
    const struct crypto_policy *policy = NULL;
    struct ne_packet job;
    uint8_t cfg_wan_idx;
    int core_id, tx_slot;

    if (!rt || !pkt || pkt->addr >= rt->pair.bufsize ||
        pkt->len > rt->pair.bufsize - pkt->addr)
        return -EINVAL;
    data = ne_packet_data(&rt->pair, pkt->addr);
    if (!data)
        return -EINVAL;
    if (pkt->dir == NE_DIR_LOCAL) {
        if (core_tx_match_out(&rt->config, data, pkt->len, &policy) <= 0)
            return -EACCES;
        if (policy->action == POLICY_ACTION_BYPASS) {
            int dp_idx = 0;

            if (core_bypass_handle_lan_wan(&rt->config, data, pkt->len,
                                           &cfg_wan_idx) != 0)
                return -EACCES;
            for (int i = 0; i < cfg_wan_idx; i++)
                if (rt->config.wans[i].dataplane)
                    dp_idx++;
            job = *pkt;
            job.dir = NE_DIR_WAN;
            job.wan_idx = (uint8_t)dp_idx;
            tx_slot = core_worker_select_tx_core(data, pkt->len);
            if (tx_slot < 0)
                return tx_slot;
            job.tx_slot = (uint8_t)tx_slot;
            return ne_ring_try_push(&rt->to_wan_tx[dp_idx][job.tx_slot], &job);
        }
        core_id = core_worker_select_encrypt_core(data, pkt->len);
        if (core_id < 0)
            return core_id;
        tx_slot = core_worker_select_tx_core(data, pkt->len);
        if (tx_slot < 0)
            return tx_slot;
        job = *pkt;
        job.tx_slot = (uint8_t)tx_slot;
        return ne_ring_try_push(&rt->local_to_crypto[core_id], &job);
    }
    if (pkt->dir == NE_DIR_WAN) {
        if (pkt->len >= 14 && data[12] == 0x08 && data[13] == 0x00) {
            int local_idx = -1, wan_cfg_idx = -1, dp_idx = 0;
            uint32_t len = pkt->len;

            if (core_bypass_handle_wan_lan(&rt->config, (uint8_t *)data,
                                           &len) != 0)
                return -EACCES;
            for (int i = 0; i < rt->config.wan_count; i++) {
                if (!rt->config.wans[i].dataplane)
                    continue;
                if (dp_idx++ == pkt->wan_idx) {
                    wan_cfg_idx = i;
                    break;
                }
            }
            if (wan_cfg_idx < 0)
                return -ENOENT;
            for (int i = 0; i < rt->config.bridge_count; i++) {
                const struct bridge_config *bridge = &rt->config.bridges[i];

                if (bridge->wan_slot != wan_cfg_idx)
                    continue;
                if (bridge->local_slot < 0 ||
                    bridge->local_slot >= rt->config.local_count)
                    return -EINVAL;
                if (local_idx >= 0 && local_idx != bridge->local_slot)
                    return -EOPNOTSUPP;
                local_idx = bridge->local_slot;
            }
            if (local_idx < 0)
                return -ENOENT;
            job = *pkt;
            job.dir = NE_DIR_LOCAL;
            job.local_idx = (uint8_t)local_idx;
            tx_slot = core_worker_select_tx_core(data, pkt->len);
            if (tx_slot < 0)
                return tx_slot;
            job.tx_slot = (uint8_t)tx_slot;
            return ne_ring_try_push(&rt->to_lan_tx[local_idx][job.tx_slot],
                                    &job);
        }
        core_id = core_worker_select_decrypt_core(data, pkt->len);
        return core_id < 0 ? core_id :
            ne_ring_try_push(&rt->wan_to_crypto[core_id], pkt);
    }
    return -EINVAL;
}

int core_worker_crypto_step(struct core_runtime *rt, struct ne_packet *pkt,
                            int worker_idx)
{
    uint8_t *data;
    uint32_t len;
    int rc, local_idx = -1, wan_cfg_idx = -1, dp_idx = 0;

    if (!rt || !pkt || pkt->dir != NE_DIR_WAN ||
        worker_idx < 0 || worker_idx >= (int)CORE_CRYPTO_WORKERS ||
        pkt->addr >= rt->pair.bufsize ||
        pkt->len > rt->pair.bufsize - pkt->addr)
        return -EINVAL;
    data = ne_packet_data(&rt->pair, pkt->addr);
    if (!data)
        return -EINVAL;
    len = pkt->len;
    rc = core_wan_process(&rt->config, data, &len, rt->pair.frame_size);
    if (rc != 0)
        return rc;
    pkt->len = len;
    for (int i = 0; i < rt->config.wan_count; i++) {
        if (!rt->config.wans[i].dataplane)
            continue;
        if (dp_idx++ == pkt->wan_idx) {
            wan_cfg_idx = i;
            break;
        }
    }
    if (wan_cfg_idx < 0)
        return -ENOENT;
    for (int i = 0; i < rt->config.bridge_count; i++) {
        const struct bridge_config *bridge = &rt->config.bridges[i];

        if (bridge->wan_slot != wan_cfg_idx)
            continue;
        if (bridge->local_slot < 0 || bridge->local_slot >= rt->config.local_count)
            return -EINVAL;
        if (local_idx >= 0 && local_idx != bridge->local_slot)
            return -EOPNOTSUPP;
        local_idx = bridge->local_slot;
    }
    if (local_idx < 0)
        return -ENOENT;
    pkt->dir = NE_DIR_LOCAL;
    pkt->local_idx = (uint8_t)local_idx;
    rc = core_worker_select_tx_core(data, len);
    if (rc < 0)
        return rc;
    pkt->tx_slot = (uint8_t)rc;
    return ne_ring_try_push(&rt->to_lan_tx[local_idx][pkt->tx_slot], pkt);
}

int core_worker_tx_step()
{
    /* Khung nối TX:
     * ne_ring_try_pop() -> ne_tx_drain_all() -> ne_cq_drain_slot()
     *                   -> ne_frame_free().
     */
}
