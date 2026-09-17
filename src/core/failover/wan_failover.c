#include "../../../inc/core/failover/wan_failover.h"
#include "../../../inc/core/failover/cfm_diag.h"
#include "../../../inc/core/forwarder/forwarder.h"
#include "../../../inc/core/dataplane/arp_bridge.h"

static void wan_failover_state_changed(int wan_dp, const char *ifname,
                                       int old_state, int new_state,
                                       void *user)
{
    (void)ifname;
    (void)old_state;
    (void)user;
    arp_bridge_link_state_changed(wan_dp,
                                  new_state == CFM_LINK_STATE_UP);
}

int wan_failover_enabled(void)
{
    return FAILOVER_ENABLE != 0;
}

int wan_failover_start(struct forwarder *fwd)
{
    if (!fwd || !fwd->cfg)
        return -1;

    if (!wan_failover_enabled())
        return 0;

    arp_bridge_failover_reset();
    cfm_set_state_callback(wan_failover_state_changed, fwd);

    if (cfm_init(fwd->cfg) != 0)
        return -1;
    return 0;
}

void wan_failover_on_cfg(struct forwarder *fwd)
{
    if (!fwd || !fwd->cfg)
        return;
    if (!wan_failover_enabled())
        return;

    arp_bridge_failover_reset();
    cfm_set_state_callback(wan_failover_state_changed, fwd);
    (void)cfm_init(fwd->cfg);
}

void wan_failover_stop(void)
{
    if (!wan_failover_enabled())
        return;
    cfm_set_state_callback(NULL, NULL);
    cfm_cleanup();
    arp_bridge_failover_reset();
}

int wan_failover_dp_excluded(int wan_dp)
{
    if (!wan_failover_enabled())
        return 0;
    /* CFM-managed WANs that are DOWN are kept out of the profile pool. */
    return cfm_link_is_down(wan_dp) ? 1 : 0;
}
