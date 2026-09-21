#include "../../../inc/core/dataplane/udp.h"
#include "../../../inc/core/crypto/crypto.h"
#include "../../../inc/core/crypto/key_manager.h"
#include "../../../inc/core/dataplane/tx.h"
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <limits.h>

static _Thread_local struct core_wan_flow *g_udp_pending_wan_flow;
static _Thread_local uint8_t g_udp_pending_fragments;

static int core_udp_fragment(uint8_t *pkt, uint32_t *len, uint32_t capacity,
                            uint8_t policy_id, uint8_t core_id,
                            uint8_t *second, uint32_t *second_len,
                            const uint8_t key[32]);
static int core_udp_reassemble(uint8_t *pkt, uint32_t *len,
                              uint32_t capacity, uint8_t policy_id,
                              uint8_t core_id);

static int core_udp_decrypt(uint8_t *pkt, uint32_t *len, const uint8_t key[32]);
static int core_udp_encrypt(uint8_t *pkt, uint32_t *len, uint32_t capacity,
                            uint8_t policy_id, uint8_t core_id,
                            const uint8_t key[32]);

int core_udp_handle_lan_wan(const struct app_config *cfg, uint8_t *pkt,
                            uint32_t *len, uint32_t capacity,
                            uint8_t policy_id, uint8_t core_id,
                            uint8_t *second, uint32_t *second_len,
                            uint8_t *wan_idx)
{
    uint8_t key[32];
    uint8_t selected;
    int rc;
    if (!pkt || !len || !second_len || *len > capacity)
        return -EINVAL;
    *second_len = 0;
    rc = core_udp_per_packet(cfg, pkt, *len, &selected);
    if (rc != 0)
        return rc;
    rc = core_key_get(policy_id, key, sizeof(key));
    if (rc != 0) {
        g_udp_pending_wan_flow = NULL;
        g_udp_pending_fragments = 0;
        return rc;
    }
    if (*len + 30u > PATH_MTU)
        rc = core_udp_fragment(pkt, len, capacity, policy_id, core_id,
                             second, second_len, key);
    else
        rc = core_udp_encrypt(pkt, len, capacity, policy_id, core_id, key);
    memset(key, 0, sizeof(key));
    if (rc < 0) {
        g_udp_pending_wan_flow = NULL;
        g_udp_pending_fragments = 0;
    } else {
        g_udp_pending_fragments = rc == 1 ? 2u : 1u;
    }
    if (rc >= 0 && wan_idx)
        *wan_idx = selected;
    return rc;
}

void core_udp_packet_complete(uint8_t enqueued_fragments)
{
    if (g_udp_pending_wan_flow && g_udp_pending_fragments != 0 &&
        enqueued_fragments == g_udp_pending_fragments &&
        ++g_udp_pending_wan_flow->packet_count >=
            CORE_UDP_WAN_PACKET_WINDOW)
        g_udp_pending_wan_flow->packet_count = 0;
    g_udp_pending_wan_flow = NULL;
    g_udp_pending_fragments = 0;
}

int core_udp_handle_wan_lan(const struct app_config *cfg, uint8_t *pkt,
                            uint32_t *len, uint32_t capacity)
{
    uint8_t key[32];
    uint8_t policy_id;
    uint8_t core_id;
    int rc;

    if (!pkt || !len || *len < 16 || *len > capacity)
        return -EINVAL;
    policy_id = pkt[14];
    core_id = pkt[15];
    rc = core_key_get(policy_id, key, sizeof(key));
    if (rc != 0)
        return rc;
    rc = core_udp_decrypt(pkt, len, key);
    memset(key, 0, sizeof(key));
    if (rc != 0)
        return rc;
    rc = core_udp_reassemble(pkt, len, capacity, policy_id, core_id);
    if (rc != 0)
        return rc;
    return core_tx_match_in(cfg, pkt, *len, policy_id) ? 0 : -EACCES;
}


#define FRAG_SLOTS 256u
static struct core_fragment_slot g_frag_slots[FRAG_SLOTS];
static pthread_mutex_t g_frag_lock = PTHREAD_MUTEX_INITIALIZER;
static atomic_uint_fast32_t g_frag_next = ATOMIC_VAR_INIT(1u);

static uint32_t core_udp_get32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void core_udp_put32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static void core_udp_write_frag(uint8_t *p, uint8_t kind,
                               uint32_t epoch, uint32_t seq)
{
    p[0] = 0x5b;
    p[1] = 'U';
    p[2] = 'D';
    p[3] = 1;
    p[4] = (uint8_t)(0x10u | kind);
    core_udp_put32(p + 5, epoch);
    core_udp_put32(p + 9, seq);
    core_udp_put32(p + 13, seq);
}

static uint64_t core_udp_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int core_udp_fragment(uint8_t *pkt, uint32_t *len, uint32_t capacity,
                            uint8_t policy_id, uint8_t core_id,
                            uint8_t *second, uint32_t *second_len,
                            const uint8_t key[32])
{
    uint32_t first_size = PATH_MTU - 14u - 17u - 30u;
    uint32_t ip_size = *len - 14u;
    uint32_t tail_size, first_wire, tail_wire;
    uint32_t seq, epoch;
    struct timespec ts;
    int rc;

    if (!second || !second_len || capacity < PATH_MTU ||
        *len > capacity || *len < 34 || ip_size <= first_size ||
        ip_size - first_size > first_size || pkt[12] != 0x08 ||
        pkt[13] != 0x00 || (pkt[14] >> 4) != 4 ||
        pkt[23] != 17)
        return -EMSGSIZE;
    tail_size = ip_size - first_size;
    seq = (uint32_t)atomic_fetch_add(&g_frag_next, 1u);
    clock_gettime(CLOCK_REALTIME, &ts);
    epoch = (uint32_t)ts.tv_sec ^ (uint32_t)ts.tv_nsec;

    memcpy(second, pkt, 14);
    memcpy(second + 31, pkt + 14 + first_size, tail_size);
    core_udp_write_frag(second + 14, 1, epoch, seq);
    tail_wire = 31u + tail_size;
    rc = core_l2_pqc_encrypt(second, &tail_wire, capacity,
                             NE_L2_UDP_ETHERTYPE,
                             policy_id, core_id, key);
    if (rc != 0)
        return rc;

    memmove(pkt + 31, pkt + 14, first_size);
    core_udp_write_frag(pkt + 14, 0, epoch, seq);
    first_wire = 31u + first_size;
    rc = core_l2_pqc_encrypt(pkt, &first_wire, capacity,
                             NE_L2_UDP_ETHERTYPE,
                             policy_id, core_id, key);
    if (rc != 0)
        return rc;
    *len = first_wire;
    *second_len = tail_wire;
    return 1;
}

static int core_udp_reassemble(uint8_t *pkt, uint32_t *len,
                              uint32_t capacity, uint8_t policy_id,
                              uint8_t core_id)
{
    uint8_t kind;
    uint32_t epoch, datagram;
    uint64_t id, now;
    uint32_t base;
    int selected = -1, oldest = -1;
    uint64_t oldest_time = UINT64_MAX;
    struct core_fragment_slot *slot;

    if (*len >= 34 && (pkt[14] >> 4) == 4)
        return pkt[23] == 17 ? 0 : -EBADMSG;
    if (*len < 32 || pkt[14] != 0x5b || pkt[15] != 'U' ||
        pkt[16] != 'D' || pkt[17] != 1 ||
        (pkt[18] >> 4) != 1 || (kind = pkt[18] & 15u) > 1)
        return -EBADMSG;
    epoch = core_udp_get32(pkt + 19);
    datagram = core_udp_get32(pkt + 27);
    if (core_udp_get32(pkt + 23) != datagram || !datagram)
        return -EBADMSG;
    id = ((uint64_t)epoch << 32) | datagram;
    now = core_udp_now_ns();
    base = (uint32_t)(id ^ (id >> 32) ^ (policy_id * 0x9e3779b9u) ^
                      core_id) & (FRAG_SLOTS - 1u);
    pthread_mutex_lock(&g_frag_lock);
    for (uint32_t n = 0; n < 8; n++) {
        int index = (base + n) & (FRAG_SLOTS - 1u);
        struct core_fragment_slot *candidate = &g_frag_slots[index];
        if (candidate->seen &&
            now - candidate->seen_ns > 200000000ull)
            candidate->seen = 0;
        if (candidate->seen && candidate->id == id &&
            candidate->policy_id == policy_id &&
            candidate->core_id == core_id) {
            selected = index;
            break;
        }
        if (!candidate->seen && selected < 0)
            selected = index;
        if (candidate->seen && candidate->seen_ns < oldest_time) {
            oldest_time = candidate->seen_ns;
            oldest = index;
        }
    }
    if (selected < 0)
        selected = oldest;
    slot = &g_frag_slots[selected];
    if (!slot->seen || slot->id != id || slot->policy_id != policy_id ||
        slot->core_id != core_id) {
        slot->seen = 0;
        slot->id = id;
        slot->policy_id = policy_id;
        slot->core_id = core_id;
    }
    slot->seen_ns = now;
    if (kind == 0) {
        slot->first_len = (uint16_t)(*len - 31u);
        memcpy(slot->first, pkt + 31, slot->first_len);
        memcpy(slot->eth, pkt, 14);
    } else {
        slot->second_len = (uint16_t)(*len - 31u);
        memcpy(slot->second, pkt + 31, slot->second_len);
    }
    slot->seen |= (uint8_t)(1u << kind);
    if (slot->seen != 3) {
        *len = 0;
        pthread_mutex_unlock(&g_frag_lock);
        return -EINPROGRESS;
    }
    if ((uint32_t)slot->first_len + slot->second_len + 14u > capacity ||
        slot->first_len < 20 ||
        (slot->first[0] >> 4) != 4 ||
        slot->first[9] != 17) {
        slot->seen = 0;
        pthread_mutex_unlock(&g_frag_lock);
        return -EBADMSG;
    }
    *len = 14u + slot->first_len + slot->second_len;
    memcpy(pkt, slot->eth, 14);
    memcpy(pkt + 14, slot->first, slot->first_len);
    memcpy(pkt + 14 + slot->first_len, slot->second, slot->second_len);
    slot->seen = 0;
    pthread_mutex_unlock(&g_frag_lock);
    return 0;
}


static int core_udp_encrypt(uint8_t *pkt, uint32_t *len, uint32_t capacity,
                            uint8_t policy_id, uint8_t core_id,
                            const uint8_t key[32])
{
    return core_l2_pqc_encrypt(pkt, len, capacity, NE_L2_UDP_ETHERTYPE,
                               policy_id, core_id, key);
}

static int core_udp_decrypt(uint8_t *pkt, uint32_t *len, const uint8_t key[32])
{
    return core_l2_pqc_decrypt(pkt, len, *len, NE_L2_UDP_ETHERTYPE, key);
}

static _Thread_local struct core_wan_flow
    g_udp_wan_flows[CORE_WAN_FLOW_ROWS][CORE_WAN_FLOW_SLOTS_PER_ROW];
static _Thread_local uint64_t g_udp_wan_clock;
static _Thread_local int64_t g_udp_wan_current[MAX_INTERFACES];
static _Thread_local int g_udp_wan_weights[MAX_INTERFACES];

static int core_udp_pick_wan(const struct app_config *cfg)
{
    int best = -1, changed = 0;
    int64_t total = 0, largest = INT64_MIN;

    for (int i = 0; i < MAX_INTERFACES; i++) {
        int weight = i < cfg->wan_count && cfg->wans[i].dataplane
            ? cfg->wans[i].bandwidth_weight : 0;
        if (weight < 0)
            weight = 0;
        if (weight != g_udp_wan_weights[i]) {
            g_udp_wan_weights[i] = weight;
            changed = 1;
        }
    }
    if (changed)
        memset(g_udp_wan_current, 0, sizeof(g_udp_wan_current));
    for (int i = 0; i < MAX_INTERFACES; i++) {
        int weight = g_udp_wan_weights[i];
        if (weight == 0)
            continue;
        g_udp_wan_current[i] += weight;
        total += weight;
        if (g_udp_wan_current[i] > largest) {
            largest = g_udp_wan_current[i];
            best = i;
        }
    }
    if (best >= 0)
        g_udp_wan_current[best] -= total;
    else
        for (int i = 0; i < cfg->wan_count && i < MAX_INTERFACES; i++)
            if (cfg->wans[i].dataplane)
                return i;
    return best;
}

static int core_udp_route(const struct app_config *cfg, const uint8_t *pkt,
                          uint32_t len, uint8_t *wan_idx, uint16_t window)
{
    struct core_wan_flow *set, *slot = NULL;
    uint32_t ihl, hash = 2166136261u;
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    int victim = 0, selected;

    if (!cfg || !pkt || !wan_idx || len < 42 || pkt[12] != 8 || pkt[13] != 0 ||
        (pkt[14] >> 4) != 4 || pkt[23] != IPPROTO_UDP_VAL)
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
    set = g_udp_wan_flows[hash & (CORE_WAN_FLOW_ROWS - 1u)];
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return -errno;
    uint64_t now_ns = (uint64_t)now.tv_sec * 1000000000ULL + now.tv_nsec;
    for (int way = 0; way < (int)CORE_WAN_FLOW_SLOTS_PER_ROW; way++) {
        /* Hết hạn: xóa ô, valid trở về 0 để dùng lại. */
        if (set[way].valid &&
            now_ns - set[way].last_seen_ns >= CORE_ROUTE_IDLE_NS)
            memset(&set[way], 0, sizeof(set[way]));

        if (set[way].valid && set[way].src_ip == src_ip &&
            set[way].dst_ip == dst_ip && set[way].src_port == src_port &&
            set[way].dst_port == dst_port) {
            slot = &set[way];
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
        selected = core_udp_pick_wan(cfg);
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
    slot->stamp = ++g_udp_wan_clock;
    slot->last_seen_ns = now_ns;
    *wan_idx = slot->wan_idx;
    g_udp_pending_wan_flow = window ? slot : NULL;
    return 0;
}

int core_udp_per_flow(const struct app_config *cfg, const uint8_t *pkt,
                      uint32_t len, uint8_t *wan_idx)
{
    return core_udp_route(cfg, pkt, len, wan_idx, 0);
}

int core_udp_per_packet(const struct app_config *cfg, const uint8_t *pkt,
                        uint32_t len, uint8_t *wan_idx)
{
    return core_udp_route(cfg, pkt, len, wan_idx,
                          CORE_UDP_WAN_PACKET_WINDOW);
}

int core_udp_reorder()
{
    
}
