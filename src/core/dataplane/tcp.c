#include "../../../inc/core/dataplane/tcp.h"
#include "../../../inc/core/crypto/crypto.h"
#include "../../../inc/core/crypto/key_manager.h"
#include "../../../inc/core/dataplane/tx.h"
#include <errno.h>
#include <string.h>
#include <limits.h>

static int core_tcp_decrypt(uint8_t *pkt, uint32_t *len, const uint8_t key[32]);
static int core_tcp_encrypt(uint8_t *pkt, uint32_t *len, uint32_t capacity,
                            uint8_t policy_id, uint8_t core_id,
                            const uint8_t key[32]);


int core_tcp_handle_lan_wan(const struct app_config *cfg, uint8_t *pkt,
                            uint32_t *len, uint32_t capacity,
                            uint8_t policy_id, uint8_t core_id,
                            uint8_t *wan_idx)
{
    uint8_t key[32];
    uint8_t selected;
    int rc = core_tcp_per_packet(cfg, pkt, len ? *len : 0, &selected);
    if (rc != 0)
        return rc;
    rc = core_key_get(policy_id, key, sizeof(key));
    if (rc != 0)
        return rc;
    rc = core_tcp_encrypt(pkt, len, capacity, policy_id, core_id, key);
    memset(key, 0, sizeof(key));
    if (rc >= 0 && wan_idx)
        *wan_idx = selected;
    return rc;
}
int core_tcp_handle_wan_lan(const struct app_config *cfg, uint8_t *pkt,
                            uint32_t *len, uint32_t capacity)
{
    uint8_t key[32];
    uint8_t policy_id;
    int rc;

    if (!pkt || !len || *len < 16 || *len > capacity)
        return -EINVAL;
    policy_id = pkt[14];
    rc = core_key_get(policy_id, key, sizeof(key));
    if (rc != 0)
        return rc;
    rc = core_tcp_decrypt(pkt, len, key);
    memset(key, 0, sizeof(key));
    if (rc != 0)
        return rc;
    return core_tx_match_in(cfg, pkt, *len, policy_id) ? 0 : -EACCES;
}

int core_tcp_clamp_mss(uint8_t *pkt, uint32_t len)
{
    uint8_t *ip, *tcp;
    uint32_t ihl, thl, pos, cap;

    if (!pkt || len < 54 || pkt[12] != 0x08 || pkt[13] != 0x00)
        return -EINVAL;
    ip = pkt + 14;
    ihl = (ip[0] & 15u) * 4u;
    if ((ip[0] >> 4) != 4 || ip[9] != 6 || ihl < 20 ||
        len < 14u + ihl + 20u)
        return -EINVAL;
    if ((ip[6] & 0x1fu) || ip[7])
        return 0;
    tcp = ip + ihl;
    if (!(tcp[13] & 0x02))
        return 0;
    thl = (tcp[12] >> 4) * 4u;
    if (thl < 20 || len < 14u + ihl + thl)
        return -EINVAL;
    cap = PATH_MTU - 14u - ihl - 20u - 30u;
    for (pos = 20; pos < thl;) {
        uint8_t kind = tcp[pos], size;
        uint16_t old, hc;
        uint32_t sum;
        if (kind == 0)
            break;
        if (kind == 1) {
            pos++;
            continue;
        }
        if (pos + 1 >= thl || (size = tcp[pos + 1]) < 2 || pos + size > thl)
            return -EINVAL;
        if (kind == 2 && size == 4) {
            old = ((uint16_t)tcp[pos + 2] << 8) | tcp[pos + 3];
            if (old > cap) {
                hc = ((uint16_t)tcp[16] << 8) | tcp[17];
                sum = (uint32_t)(~hc & 0xffffu) +
                      (uint32_t)(~old & 0xffffu) + cap;
                while (sum >> 16)
                    sum = (sum & 0xffffu) + (sum >> 16);
                hc = (uint16_t)~sum;
                tcp[16] = (uint8_t)(hc >> 8);
                tcp[17] = (uint8_t)hc;
                tcp[pos + 2] = (uint8_t)(cap >> 8);
                tcp[pos + 3] = (uint8_t)cap;
            }
            break;
        }
        pos += size;
    }
    return 0;
}

static int core_tcp_encrypt(uint8_t *pkt, uint32_t *len, uint32_t capacity,
                            uint8_t policy_id, uint8_t core_id,
                            const uint8_t key[32])
{
    int rc = core_tcp_clamp_mss(pkt, *len);
    if (rc != 0)
        return rc;
    return core_l2_pqc_encrypt(pkt, len, capacity, NE_L2_TCP_ETHERTYPE,
                               policy_id, core_id, key);
}

static int core_tcp_decrypt(uint8_t *pkt, uint32_t *len, const uint8_t key[32])
{
    return core_l2_pqc_decrypt(pkt, len, *len, NE_L2_TCP_ETHERTYPE, key);
}

static _Thread_local struct core_wan_flow
    g_tcp_wan_flows[CORE_WAN_FLOW_SETS][CORE_WAN_FLOW_WAYS];
static _Thread_local uint64_t g_tcp_wan_clock;
static _Thread_local int64_t g_tcp_wan_current[MAX_INTERFACES];
static _Thread_local int g_tcp_wan_weights[MAX_INTERFACES];

static int core_tcp_pick_wan(const struct app_config *cfg)
{
    int best = -1, changed = 0;
    int64_t total = 0, largest = INT64_MIN;

    for (int i = 0; i < MAX_INTERFACES; i++) {
        int weight = i < cfg->wan_count && cfg->wans[i].dataplane
            ? cfg->wans[i].bandwidth_weight : 0;
        if (weight < 0)
            weight = 0;
        if (weight != g_tcp_wan_weights[i]) {
            g_tcp_wan_weights[i] = weight;
            changed = 1;
        }
    }
    if (changed)
        memset(g_tcp_wan_current, 0, sizeof(g_tcp_wan_current));
    for (int i = 0; i < MAX_INTERFACES; i++) {
        int weight = g_tcp_wan_weights[i];
        if (weight == 0)
            continue;
        g_tcp_wan_current[i] += weight;
        total += weight;
        if (g_tcp_wan_current[i] > largest) {
            largest = g_tcp_wan_current[i];
            best = i;
        }
    }
    if (best >= 0)
        g_tcp_wan_current[best] -= total;
    else
        for (int i = 0; i < cfg->wan_count && i < MAX_INTERFACES; i++)
            if (cfg->wans[i].dataplane)
                return i;
    return best;
}

static int core_tcp_route(const struct app_config *cfg, const uint8_t *pkt,
                          uint32_t len, uint8_t *wan_idx, uint16_t window)
{
    struct core_wan_flow *set, *slot = NULL;
    uint32_t ihl, hash = 2166136261u;
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    int victim = 0, selected;

    if (!cfg || !pkt || !wan_idx || len < 54 || pkt[12] != 8 || pkt[13] != 0 ||
        (pkt[14] >> 4) != 4 || pkt[23] != IPPROTO_TCP_VAL)
        return -EINVAL;
    ihl = (uint32_t)(pkt[14] & 15u) * 4u;
    if (ihl < 20 || len < 14u + ihl + 4u)
        return -EINVAL;
    memcpy(&src_ip, pkt + 26, sizeof(src_ip));
    memcpy(&dst_ip, pkt + 30, sizeof(dst_ip));
    src_port = ((uint16_t)pkt[14 + ihl] << 8) | pkt[15 + ihl];
    dst_port = ((uint16_t)pkt[16 + ihl] << 8) | pkt[17 + ihl];
    for (uint32_t i = 26; i < 34; i++)
        hash = (hash ^ pkt[i]) * 16777619u;
    for (uint32_t i = 14 + ihl; i < 18 + ihl; i++)
        hash = (hash ^ pkt[i]) * 16777619u;
    set = g_tcp_wan_flows[hash & (CORE_WAN_FLOW_SETS - 1u)];
    for (int way = 0; way < (int)CORE_WAN_FLOW_WAYS; way++) {
        if (set[way].valid && set[way].src_ip == src_ip &&
            set[way].dst_ip == dst_ip && set[way].src_port == src_port &&
            set[way].dst_port == dst_port) {
            slot = &set[way];
            break;
        }
        if (!set[way].valid || set[way].stamp < set[victim].stamp)
            victim = way;
    }
    if (!slot)
        slot = &set[victim];
    if (!slot->valid || slot->src_ip != src_ip || slot->dst_ip != dst_ip ||
        slot->src_port != src_port || slot->dst_port != dst_port ||
        slot->wan_idx >= cfg->wan_count ||
        !cfg->wans[slot->wan_idx].dataplane ||
        cfg->wans[slot->wan_idx].bandwidth_weight <= 0 ||
        (window && slot->packet_count == 0)) {
        selected = core_tcp_pick_wan(cfg);
        if (selected < 0)
            return -ENETUNREACH;
        slot->src_ip = src_ip;
        slot->dst_ip = dst_ip;
        slot->src_port = src_port;
        slot->dst_port = dst_port;
        slot->wan_idx = (uint8_t)selected;
        slot->packet_count = 0;
        slot->valid = 1;
    }
    slot->stamp = ++g_tcp_wan_clock;
    *wan_idx = slot->wan_idx;
    if (window) {
        slot->packet_count++;
        if (slot->packet_count >= window)
            slot->packet_count = 0;
    }
    return 0;
}

int core_tcp_per_flow(const struct app_config *cfg, const uint8_t *pkt,
                      uint32_t len, uint8_t *wan_idx)
{
    return core_tcp_route(cfg, pkt, len, wan_idx, 0);
}

int core_tcp_per_packet(const struct app_config *cfg, const uint8_t *pkt,
                        uint32_t len, uint8_t *wan_idx)
{
    return core_tcp_route(cfg, pkt, len, wan_idx,
                          CORE_TCP_WAN_PACKET_WINDOW);
}

int core_tcp_retry()
{
    
}
