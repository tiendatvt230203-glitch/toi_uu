#include "../../../inc/dataplane/udp.h"
#include "../../../inc/crypto/crypto.h"
#include "../../../inc/crypto/key_manager.h"
#include "../../../inc/dataplane/tx.h"
#include "../../../inc/interface/interface.h"
#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static atomic_uint_fast64_t g_udp_log_second[5];

static void udp_error_log(unsigned stage, int rc)
{
    uint64_t now = (uint64_t)time(NULL);
    uint64_t seen = atomic_load_explicit(&g_udp_log_second[stage - 1u],
                                         memory_order_relaxed);
    if (seen != now && atomic_compare_exchange_strong_explicit(
            &g_udp_log_second[stage - 1u], &seen, now,
            memory_order_relaxed, memory_order_relaxed))
        fprintf(stderr, "9:%u:%d\n", stage, rc);
}

int core_udp_handle_lan_wan(const struct app_config *cfg,
    struct ne_pair *pair, struct ne_packet *pkt, uint8_t policy_id,
    uint8_t core_id, struct core_packet_batch *out)
{
    uint8_t key[32];
    if (!cfg || cfg->wan_count != 1 || !cfg->wans[0].dataplane)
        return -ENODEV;
    int rc = core_key_get(policy_id, key, sizeof(key));
    if (!rc)
        rc = core_l2_pqc_fragment(pair, pkt, NE_L2_UDP_ETHERTYPE,
                                  policy_id, core_id, key, out);
    memset(key, 0, sizeof(key));
    return rc;
}

int core_udp_handle_wan_lan(const struct app_config *cfg,
    struct ne_pair *pair, struct ne_packet *pkt)
{
    uint8_t key[32];
    uint8_t policy_id;
    int rc = core_l2_pqc_reassemble(pair, pkt, NE_L2_UDP_ETHERTYPE);
    if (rc) {
        if (rc != 1)
            udp_error_log(1, rc);
        return rc;
    }
    if (ne_packet_read(pair, pkt, pkt->total_len - 1u, &policy_id, 1)) {
        udp_error_log(2, -EINVAL);
        return -EINVAL;
    }
    rc = core_key_get(policy_id, key, sizeof(key));
    if (rc) {
        udp_error_log(3, rc);
        memset(key, 0, sizeof(key));
        return rc;
    }
    rc = core_l2_pqc_decrypt(pair, pkt, NE_L2_UDP_ETHERTYPE, key);
    memset(key, 0, sizeof(key));
    if (rc) {
        udp_error_log(4, rc);
        return rc;
    }
    uint32_t contiguous;
    uint8_t *data = ne_packet_at(pair, pkt, 0, &contiguous);
    if (!data || contiguous < 34 ||
        core_tx_match_in(cfg, data, pkt->total_len, policy_id) <= 0) {
        udp_error_log(5, -EACCES);
        return -EACCES;
    }
    return 0;
}
