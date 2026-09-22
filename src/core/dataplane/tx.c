#include "../../../inc/dataplane/tx.h"
#include <netinet/in.h>
#include <string.h>


static int read_flow(const uint8_t *pkt, uint32_t len, uint32_t *sip,
                     uint32_t *dip, uint16_t *sport, uint16_t *dport,
                     uint8_t *proto)
{
    uint32_t off = 14, ihl;

    if (!pkt || len < off + 20)
        return 0;
    if (pkt[12] != 0x08 || pkt[13] != 0x00 || (pkt[off] >> 4) != 4)
        return 0;
    ihl = (uint32_t)(pkt[off] & 15u) * 4u;
    if (ihl < 20 || len < off + ihl)
        return 0;
    memcpy(sip, pkt + off + 12, sizeof(*sip));
    memcpy(dip, pkt + off + 16, sizeof(*dip));
    *proto = pkt[off + 9];
    *sport = *dport = 0;
    if (*proto == IPPROTO_TCP || *proto == IPPROTO_UDP) {
        off += ihl;
        if (len < off + 4)
            return 0;
        *sport = ((uint16_t)pkt[off] << 8) | pkt[off + 1];
        *dport = ((uint16_t)pkt[off + 2] << 8) | pkt[off + 3];
    }
    return 1;
}

static int port_ok(int from, int to, uint16_t port)
{
    return from < 0 || to < 0 || ((int)port >= from && (int)port <= to);
}



static int group_ok(const struct app_config *cfg, int first, int *next,
                    uint32_t sip, uint32_t dip, uint16_t sport,
                    uint16_t dport, uint8_t proto)
{
    const struct crypto_policy *base = &cfg->policies[first];
    int spos_seen = 0, dpos_seen = 0, spos_ok = 0, dpos_ok = 0;
    int sneg_ok = 1, dneg_ok = 1, sp_ok = 0, dp_ok = 0, any_ok = 0;
    int proto_ok = base->protocol == POLICY_PROTO_ANY ||
                   base->protocol == proto ||
                   (base->protocol == POLICY_PROTO_TCP_UDP &&
                    (proto == IPPROTO_TCP || proto == IPPROTO_UDP));
    int j;

    for (j = first; j < cfg->policy_count; j++) {
        const struct crypto_policy *cp = &cfg->policies[j];
        int src_in, dst_in;

        if (cp->db_id != base->db_id)
            break;
        src_in = cp->src_any ||
            ((sip & cp->src_mask) == (cp->src_net & cp->src_mask));
        dst_in = cp->dst_any ||
            ((dip & cp->dst_mask) == (cp->dst_net & cp->dst_mask));
        if (!base->src_negate && !base->dst_negate) {
            any_ok |= proto_ok && src_in && dst_in &&
                port_ok(cp->src_port_from, cp->src_port_to, sport) &&
                port_ok(cp->dst_port_from, cp->dst_port_to, dport);
            continue;
        }
        if (cp->src_negate)
            sneg_ok &= !src_in;
        else {
            spos_seen = 1;
            spos_ok |= src_in;
        }
        if (cp->dst_negate)
            dneg_ok &= !dst_in;
        else {
            dpos_seen = 1;
            dpos_ok |= dst_in;
        }
        sp_ok |= port_ok(cp->src_port_from, cp->src_port_to, sport);
        dp_ok |= port_ok(cp->dst_port_from, cp->dst_port_to, dport);
    }
    *next = j;
    if (!base->src_negate && !base->dst_negate)
        return any_ok;
    return proto_ok && (!spos_seen || spos_ok) && sneg_ok &&
           (!dpos_seen || dpos_ok) && dneg_ok && sp_ok && dp_ok;
}

int core_tx_match_out(const struct app_config *cfg, const uint8_t *pkt,
                      uint32_t len, const struct crypto_policy **policy_out)
{
    const struct crypto_policy *best = NULL;
    uint32_t sip, dip;
    uint16_t sport, dport;
    uint8_t proto;

    if (policy_out)
        *policy_out = NULL;
    if (!cfg || !cfg->enabled || cfg->policy_count < 0 ||
        cfg->policy_count > MAX_CRYPTO_POLICIES ||
        !read_flow(pkt, len, &sip, &dip, &sport, &dport, &proto))
        return 0;
    for (int i = 0; i < cfg->policy_count;) {
        const struct crypto_policy *cp = &cfg->policies[i];
        int next = i + 1;
        if (group_ok(cfg, i, &next, sip, dip, sport, dport, proto) &&
            (cp->action == POLICY_ACTION_BYPASS ||
             cp->action == POLICY_ACTION_ENCRYPT_L2) &&
            (!best || cp->priority < best->priority ||
             (cp->priority == best->priority && cp->id < best->id)))
            best = cp;
        i = next;
    }
    if (policy_out)
        *policy_out = best;
    return best != NULL;
}

int core_tx_match_in(const struct app_config *cfg, const uint8_t *pkt,
                     uint32_t len, uint8_t wire_policy_id)
{
    uint32_t sip, dip;
    uint16_t sport, dport;
    uint8_t proto;

    if (!cfg || !cfg->enabled || cfg->policy_count < 0 ||
        cfg->policy_count > MAX_CRYPTO_POLICIES ||
        !read_flow(pkt, len, &sip, &dip, &sport, &dport, &proto))
        return 0;
    for (int i = 0; i < cfg->policy_count;) {
        const struct crypto_policy *cp = &cfg->policies[i];
        int next = i + 1;
        int matched = group_ok(cfg, i, &next, dip, sip, dport, sport, proto);
        if (cp->action == POLICY_ACTION_ENCRYPT_L2 &&
            cp->id == (int)wire_policy_id && matched)
            return 1;
        i = next;
    }
    return 0;
}
