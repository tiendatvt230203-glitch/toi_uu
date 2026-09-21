#include "../../../inc/core/dataplane/bypass.h"
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <string.h>

static _Thread_local struct core_wan_flow
    g_bypass_flows[CORE_WAN_FLOW_SETS][CORE_WAN_FLOW_WAYS];
static _Thread_local uint64_t g_bypass_clock;
static _Thread_local int64_t g_bypass_current[MAX_INTERFACES];
static _Thread_local int g_bypass_weights[MAX_INTERFACES];

static int core_bypass_pick_wan(const struct app_config *cfg)
{
    int best = -1, changed = 0;
    int64_t total = 0, largest = INT64_MIN;

    for (int i = 0; i < MAX_INTERFACES; i++) {
        int weight = i < cfg->wan_count && cfg->wans[i].dataplane
            ? cfg->wans[i].bandwidth_weight : 0;
        if (weight < 0)
            weight = 0;
        if (weight != g_bypass_weights[i]) {
            g_bypass_weights[i] = weight;
            changed = 1;
        }
    }
    if (changed)
        memset(g_bypass_current, 0, sizeof(g_bypass_current));
    for (int i = 0; i < MAX_INTERFACES; i++) {
        int weight = g_bypass_weights[i];
        if (weight == 0)
            continue;
        g_bypass_current[i] += weight;
        total += weight;
        if (g_bypass_current[i] > largest) {
            largest = g_bypass_current[i];
            best = i;
        }
    }
    if (best >= 0)
        g_bypass_current[best] -= total;
    else
        for (int i = 0; i < cfg->wan_count && i < MAX_INTERFACES; i++)
            if (cfg->wans[i].dataplane)
                return i;
    return best;
}

static int core_bypass_route(const struct app_config *cfg, const uint8_t *pkt,
                             uint32_t len, uint8_t *wan_idx, int per_packet)
{
    struct core_wan_flow *set, *slot = NULL;
    uint32_t ihl, hash = 2166136261u;
    uint32_t src_ip, dst_ip;
    uint16_t src_port = 0, dst_port = 0, window = 0;
    uint8_t protocol;
    int victim = 0, selected;

    if (!cfg || !pkt || !wan_idx || len < 34 || pkt[12] != 8 || pkt[13] != 0 ||
        (pkt[14] >> 4) != 4)
        return -EINVAL;
    ihl = (uint32_t)(pkt[14] & 15u) * 4u;
    if (ihl < 20 || len < 14u + ihl)
        return -EINVAL;
    protocol = pkt[23];
    if (protocol == IPPROTO_TCP_VAL || protocol == IPPROTO_UDP_VAL) {
        if (len < 14u + ihl + 4u)
            return -EINVAL;
        src_port = ((uint16_t)pkt[14 + ihl] << 8) | pkt[15 + ihl];
        dst_port = ((uint16_t)pkt[16 + ihl] << 8) | pkt[17 + ihl];
        window = protocol == IPPROTO_TCP_VAL
            ? CORE_TCP_WAN_PACKET_WINDOW : CORE_UDP_WAN_PACKET_WINDOW;
    } else if (protocol == IPPROTO_ICMP_VAL && len >= 14u + ihl + 8u &&
               (pkt[14 + ihl] == 0 || pkt[14 + ihl] == 8)) {
        src_port = dst_port = ((uint16_t)pkt[18 + ihl] << 8) | pkt[19 + ihl];
        window = 1;
    } else {
        window = 1;
    }
    memcpy(&src_ip, pkt + 26, sizeof(src_ip));
    memcpy(&dst_ip, pkt + 30, sizeof(dst_ip));
    for (uint32_t i = 26; i < 34; i++)
        hash = (hash ^ pkt[i]) * 16777619u;
    hash = (hash ^ protocol) * 16777619u;
    hash = (hash ^ src_port) * 16777619u;
    hash = (hash ^ dst_port) * 16777619u;
    set = g_bypass_flows[hash & (CORE_WAN_FLOW_SETS - 1u)];
    for (int way = 0; way < (int)CORE_WAN_FLOW_WAYS; way++) {
        if (set[way].valid && set[way].src_ip == src_ip &&
            set[way].dst_ip == dst_ip && set[way].src_port == src_port &&
            set[way].dst_port == dst_port && set[way].protocol == protocol) {
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
        slot->protocol != protocol || slot->wan_idx >= cfg->wan_count ||
        !cfg->wans[slot->wan_idx].dataplane ||
        cfg->wans[slot->wan_idx].bandwidth_weight <= 0 ||
        (per_packet && slot->packet_count == 0)) {
        selected = core_bypass_pick_wan(cfg);
        if (selected < 0)
            return -ENETUNREACH;
        slot->src_ip = src_ip;
        slot->dst_ip = dst_ip;
        slot->src_port = src_port;
        slot->dst_port = dst_port;
        slot->protocol = protocol;
        slot->wan_idx = (uint8_t)selected;
        slot->packet_count = 0;
        slot->valid = 1;
    }
    slot->stamp = ++g_bypass_clock;
    *wan_idx = slot->wan_idx;
    if (per_packet) {
        slot->packet_count++;
        if (slot->packet_count >= window)
            slot->packet_count = 0;
    }
    return 0;
}

int core_bypass_per_flow(const struct app_config *cfg, const uint8_t *pkt,
                         uint32_t len, uint8_t *wan_idx)
{
    return core_bypass_route(cfg, pkt, len, wan_idx, 0);
}

int core_bypass_per_packet(const struct app_config *cfg, const uint8_t *pkt,
                           uint32_t len, uint8_t *wan_idx)
{
    return core_bypass_route(cfg, pkt, len, wan_idx, 1);
}

int core_bypass_handle_lan_wan(const struct app_config *cfg,
                               const uint8_t *pkt, uint32_t len,
                               uint8_t *wan_idx)
{
    return core_bypass_per_packet(cfg, pkt, len, wan_idx);
}

int core_bypass_handle_wan_lan(const struct app_config *cfg,
                               uint8_t *pkt, uint32_t *len)
{
    const struct crypto_policy *best = NULL;
    uint32_t src_ip, dst_ip, ihl;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto;

    if (!cfg || !cfg->enabled || cfg->policy_count < 0 ||
        cfg->policy_count > MAX_CRYPTO_POLICIES || !pkt || !len || *len < 34 ||
        pkt[12] != 0x08 || pkt[13] != 0x00 || (pkt[14] >> 4) != 4)
        return -EACCES;
    ihl = (uint32_t)(pkt[14] & 15u) * 4u;
    if (ihl < 20 || *len < 14u + ihl)
        return -EACCES;
    memcpy(&src_ip, pkt + 26, sizeof(src_ip));
    memcpy(&dst_ip, pkt + 30, sizeof(dst_ip));
    proto = pkt[23];
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        if (*len < 14u + ihl + 4u)
            return -EACCES;
        src_port = ((uint16_t)pkt[14 + ihl] << 8) | pkt[15 + ihl];
        dst_port = ((uint16_t)pkt[16 + ihl] << 8) | pkt[17 + ihl];
    }
    for (int i = 0; i < cfg->policy_count;) {
        const struct crypto_policy *base = &cfg->policies[i];
        int proto_ok = base->protocol == POLICY_PROTO_ANY ||
            base->protocol == proto ||
            (base->protocol == POLICY_PROTO_TCP_UDP &&
             (proto == IPPROTO_TCP || proto == IPPROTO_UDP));
        int src_seen = 0, dst_seen = 0, src_ok = 0, dst_ok = 0;
        int src_neg_ok = 1, dst_neg_ok = 1, src_port_ok = 0;
        int dst_port_ok = 0, any_ok = 0, j = i;

        for (; j < cfg->policy_count &&
               cfg->policies[j].db_id == base->db_id; j++) {
            const struct crypto_policy *cp = &cfg->policies[j];
            int src_in = cp->src_any ||
                ((dst_ip & cp->src_mask) == (cp->src_net & cp->src_mask));
            int dst_in = cp->dst_any ||
                ((src_ip & cp->dst_mask) == (cp->dst_net & cp->dst_mask));
            int sp = cp->src_port_from < 0 || cp->src_port_to < 0 ||
                ((int)dst_port >= cp->src_port_from &&
                 (int)dst_port <= cp->src_port_to);
            int dp = cp->dst_port_from < 0 || cp->dst_port_to < 0 ||
                ((int)src_port >= cp->dst_port_from &&
                 (int)src_port <= cp->dst_port_to);

            if (!base->src_negate && !base->dst_negate) {
                any_ok |= proto_ok && src_in && dst_in && sp && dp;
                continue;
            }
            if (cp->src_negate)
                src_neg_ok &= !src_in;
            else {
                src_seen = 1;
                src_ok |= src_in;
            }
            if (cp->dst_negate)
                dst_neg_ok &= !dst_in;
            else {
                dst_seen = 1;
                dst_ok |= dst_in;
            }
            src_port_ok |= sp;
            dst_port_ok |= dp;
        }
        if ((base->src_negate || base->dst_negate
                 ? proto_ok && (!src_seen || src_ok) && src_neg_ok &&
                   (!dst_seen || dst_ok) && dst_neg_ok &&
                   src_port_ok && dst_port_ok
                 : any_ok) &&
            (!best || base->priority < best->priority ||
             (base->priority == best->priority && base->id < best->id)))
            best = base;
        i = j;
    }
    return best && best->action == POLICY_ACTION_BYPASS ? 0 : -EACCES;
}
