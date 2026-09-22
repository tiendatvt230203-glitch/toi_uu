#include "../../../inc/dataplane/bypass.h"
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <string.h>
#include <time.h>


int core_bypass_handle_lan_wan(const struct app_config *cfg,
                               const uint8_t *pkt, uint32_t len,
                               uint8_t *wan_idx)
{
    (void)pkt;
    (void)len;
    if (!wan_idx)
        return -EINVAL;
    if (!cfg || cfg->wan_count != 1 || !cfg->wans[0].dataplane)
        return -ENODEV;
    *wan_idx = 0;
    return 0;
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
