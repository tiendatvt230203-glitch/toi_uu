#ifndef CORE_INTERFACE_H
#define CORE_INTERFACE_H

#include "../core_types.h"

int core_interface_open(struct core_interfaces *, const struct app_config *);
void core_interface_close(struct core_interfaces *);

int ne_pair_local_live(const struct ne_pair *p, int pair_local_idx);
int ne_pair_wan_live(const struct ne_pair *p, int dp_slot);
int ne_pair_plumb_local(struct ne_pair *p, const struct app_config *cfg,
                        int cfg_local_idx, int pair_li);
int ne_pair_plumb_wan_dp(struct ne_pair *p, const struct app_config *cfg,
                         int cfg_wan_idx, int dp_slot);
void ne_pair_unplumb_local(struct ne_pair *p, int pair_li);
void ne_pair_unplumb_wan_dp(struct ne_pair *p, int dp_slot);
int ne_pair_teardown_live(struct ne_pair *p);

int ne_ring_init(struct ne_ring *r, uint32_t cap, int mpsc_pop);
void ne_ring_destroy(struct ne_ring *r);
int ne_ring_try_push(struct ne_ring *r, const struct ne_packet *pkt);
int ne_ring_try_push_pair(struct ne_ring *r, const struct ne_packet *first,
                          const struct ne_packet *second);
int ne_ring_try_pop(struct ne_ring *r, struct ne_packet *pkt);
uint32_t ne_ring_try_pop_batch(struct ne_ring *r, struct ne_packet *pkts,
                               uint32_t max_n);
uint32_t ne_ring_count(const struct ne_ring *r);

int ne_pair_open(struct ne_pair *p, const struct app_config *cfg);
void ne_pair_close(struct ne_pair *p, const struct app_config *cfg);
void ne_pair_delete_local_xsks(struct ne_pair *p, int pair_li);
void ne_pair_delete_wan_xsks(struct ne_pair *p, int dp_slot);

int ne_recv_local_slot(struct ne_pair *p, int rx_slot,
                       struct ne_packet *out, uint32_t max);
int ne_recv_wan_slot(struct ne_pair *p, int rx_slot,
                     struct ne_packet *out, uint32_t max);
void ne_recv_release_local_slot(struct ne_pair *p, int rx_slot);
void ne_recv_release_wan_slot(struct ne_pair *p, int rx_slot);
void ne_drain_cq_local(struct ne_pair *p, int tx_slot);
void ne_drain_cq_wan(struct ne_pair *p, int tx_slot);
void ne_refill_fq_local_slot(struct ne_pair *p, int rx_slot);
void ne_refill_fq_wan_slot(struct ne_pair *p, int rx_slot);
void ne_dp_tx_ctx(const char *dir, int tx_slot);
void ne_dp_warn_rx(const char *dir, int cpu, int batch_rcvd);
void ne_dp_warn_rx_drop(const char *dir, int cpu, int worker, uint32_t q_depth);
void ne_dp_warn_crypto(int cpu, int worker, uint32_t lan_q, uint32_t wan_q);
int ne_tx_drain_local_all(struct ne_pair *p, struct ne_ring *srcs[],
                          int src_count, int local_idx, int tx_slot);
int ne_tx_drain_wan_all(struct ne_pair *p, struct ne_ring *srcs[],
                        int src_count, int wan_idx, int tx_slot);

void *ne_packet_data(struct ne_pair *p, uint64_t addr);
int ne_frame_alloc(struct ne_pair *p, uint64_t *addr_out);
uint32_t ne_frame_alloc_batch(struct ne_pair *p, uint64_t *addrs_out,
                              uint32_t max_n);
void ne_frame_free(struct ne_pair *p, uint64_t addr);
uint32_t ne_pool_free_count(struct ne_pair *p);

void interface_reset_redirect_maps(void);
void interface_promisc_off_config(const struct app_config *cfg);
int interface_set_queue_count(const char *ifname, int desired_count);
int interface_get_queue_count(const char *ifname);
int ne_rx_lan_slots_for(int local_queue_total);
int ne_rx_wan_slots_for(int wan_queue_total);
int ne_rx_local_fds(struct ne_pair *p, int rx_slot, int *fds, int max);
int ne_rx_wan_fds(struct ne_pair *p, int rx_slot, int *fds, int max);
int ne_tx_local_fds(struct ne_pair *p, int tx_slot, int *fds, int max);
int ne_tx_wan_fds(struct ne_pair *p, int tx_slot, int *fds, int max);
int ne_tx_fds(struct ne_pair *p, int tx_slot, int *fds, int max);
void ne_kick_fq_local_slot(struct ne_pair *p, int rx_slot);
void ne_kick_fq_wan_slot(struct ne_pair *p, int rx_slot);
#endif
