#include "../../../inc/core/runtime/worker.h"
#include "../../../inc/core/interface/interface.h"

#include <errno.h>
#include <netinet/in.h>
#include <string.h>

/* Same sticky flow-set layout as MTU-1500-old/crypto_route.c. */
static struct core_flow_route
    g_flow_routes[CORE_FLOW_ROUTE_SETS][CORE_FLOW_ROUTE_WAYS];
static uint64_t g_worker_flow_count[CORE_CRYPTO_WORKERS];
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

int core_worker_select_encrypt_core(const uint8_t *pkt, uint32_t len)
{
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

    set = g_flow_routes[hash & (CORE_FLOW_ROUTE_SETS - 1u)];
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
    for (int core = 1; core < CORE_CRYPTO_WORKERS; core++) {
        if (g_worker_flow_count[core] < g_worker_flow_count[chosen])
            chosen = core;
    }
    set[empty].ip_a = src_ip;
    set[empty].ip_b = dst_ip;
    set[empty].port_a = src_port;
    set[empty].port_b = dst_port;
    set[empty].protocol = proto;
    set[empty].worker_idx = (uint8_t)chosen;
    g_worker_flow_count[chosen]++;
    atomic_store_explicit(&set[empty].valid, 1, memory_order_release);
    pthread_mutex_unlock(&g_flow_route_lock);
    return chosen;
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
    int core_id;

    if (!rt || !pkt || pkt->addr >= rt->pair.bufsize ||
        pkt->len > rt->pair.bufsize - pkt->addr)
        return -EINVAL;
    data = ne_packet_data(&rt->pair, pkt->addr);
    if (!data)
        return -EINVAL;
    if (pkt->dir == NE_DIR_LOCAL) {
        core_id = core_worker_select_encrypt_core(data, pkt->len);
        return core_id < 0 ? core_id :
            ne_ring_try_push(&rt->local_to_crypto[core_id], pkt);
    }
    if (pkt->dir == NE_DIR_WAN) {
        core_id = core_worker_select_decrypt_core(data, pkt->len);
        return core_id < 0 ? core_id :
            ne_ring_try_push(&rt->wan_to_crypto[core_id], pkt);
    }
    return -EINVAL;
}

int core_worker_crypto_step()
{
    /* Khung nối core RX -> xử lý -> core TX:
     * ne_ring_try_pop() -> core_lan_process() / core_wan_process()
     *                   -> ne_ring_try_push().
     * LAN chọn TCP/UDP/PING/OSPF sau match OUT.
     * WAN chọn bằng fake EtherType, giải mã rồi match IN.
     */
}

int core_worker_tx_step()
{
    /* Khung nối TX:
     * ne_ring_try_pop() -> ne_tx_drain_all() -> ne_cq_drain_slot()
     *                   -> ne_frame_free().
     */
}
