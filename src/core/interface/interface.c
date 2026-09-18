#include "../../../inc/core/interface/interface.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

int ne_ring_init(struct ne_ring *r, uint32_t cap, int mpsc_pop)
{
    if (!r || cap == 0 || (cap & (cap - 1u)) != 0)
        return -EINVAL;
    memset(r, 0, sizeof(*r));
    r->buf = calloc(cap, sizeof(*r->buf));
    if (!r->buf)
        return -ENOMEM;
    r->cap = cap;
    r->mask = cap - 1u;
    r->mpsc_pop = mpsc_pop ? 1 : 0;
    if (pthread_spin_init(&r->push_lock, PTHREAD_PROCESS_PRIVATE) != 0) {
        free(r->buf);
        memset(r, 0, sizeof(*r));
        return -1;
    }
    if (r->mpsc_pop &&
        pthread_spin_init(&r->pop_lock, PTHREAD_PROCESS_PRIVATE) != 0) {
        pthread_spin_destroy(&r->push_lock);
        free(r->buf);
        memset(r, 0, sizeof(*r));
        return -1;
    }
    return 0;
}

void ne_ring_destroy(struct ne_ring *r)
{
    if (!r || !r->buf)
        return;
    if (r->mpsc_pop)
        pthread_spin_destroy(&r->pop_lock);
    pthread_spin_destroy(&r->push_lock);
    free(r->buf);
    memset(r, 0, sizeof(*r));
}

int ne_ring_try_push(struct ne_ring *r, const struct ne_packet *pkt)
{
    uint32_t head;
    uint32_t tail;
    if (!r || !r->buf || !pkt)
        return -EINVAL;
    pthread_spin_lock(&r->push_lock);
    head = __atomic_load_n(&r->head, __ATOMIC_RELAXED);
    tail = __atomic_load_n(&r->tail, __ATOMIC_ACQUIRE);
    if (head - tail >= r->cap) {
        pthread_spin_unlock(&r->push_lock);
        return -ENOSPC;
    }
    r->buf[head & r->mask] = *pkt;
    __atomic_store_n(&r->head, head + 1u, __ATOMIC_RELEASE);
    pthread_spin_unlock(&r->push_lock);
    return 0;
}

int ne_ring_try_push_pair(struct ne_ring *r, const struct ne_packet *first,
                          const struct ne_packet *second)
{
    uint32_t head;
    uint32_t tail;
    if (!r || !r->buf || !first || !second || r->cap < 2)
        return -EINVAL;
    pthread_spin_lock(&r->push_lock);
    head = __atomic_load_n(&r->head, __ATOMIC_RELAXED);
    tail = __atomic_load_n(&r->tail, __ATOMIC_ACQUIRE);
    if (head - tail > r->cap - 2u) {
        pthread_spin_unlock(&r->push_lock);
        return -ENOSPC;
    }
    r->buf[head & r->mask] = *first;
    r->buf[(head + 1u) & r->mask] = *second;
    __atomic_store_n(&r->head, head + 2u, __ATOMIC_RELEASE);
    pthread_spin_unlock(&r->push_lock);
    return 0;
}

int ne_ring_try_pop(struct ne_ring *r, struct ne_packet *pkt)
{
    uint32_t head;
    uint32_t tail;
    if (!r || !r->buf || !pkt)
        return -EINVAL;
    if (r->mpsc_pop)
        pthread_spin_lock(&r->pop_lock);
    tail = __atomic_load_n(&r->tail, __ATOMIC_RELAXED);
    head = __atomic_load_n(&r->head, __ATOMIC_ACQUIRE);
    if (tail == head) {
        if (r->mpsc_pop)
            pthread_spin_unlock(&r->pop_lock);
        return 0;
    }
    *pkt = r->buf[tail & r->mask];
    __atomic_store_n(&r->tail, tail + 1u, __ATOMIC_RELEASE);
    if (r->mpsc_pop)
        pthread_spin_unlock(&r->pop_lock);
    return 1;
}

uint32_t ne_ring_try_pop_batch(struct ne_ring *r, struct ne_packet *pkts,
                               uint32_t max_n)
{
    uint32_t n = 0;
    if (!r || !pkts)
        return 0;
    while (n < max_n && ne_ring_try_pop(r, &pkts[n]) > 0)
        n++;
    return n;
}

uint32_t ne_ring_count(const struct ne_ring *r)
{
    if (!r || !r->buf)
        return 0;
    return __atomic_load_n(&r->head, __ATOMIC_ACQUIRE) -
           __atomic_load_n(&r->tail, __ATOMIC_ACQUIRE);
}

int ne_pair_local_live(const struct ne_pair *p, int pair_local_idx)
{
    return p && pair_local_idx >= 0 && pair_local_idx < p->local_count &&
           pair_local_idx < MAX_INTERFACES && p->local_live[pair_local_idx];
}

int ne_pair_wan_live(const struct ne_pair *p, int dp_slot)
{
    return p && dp_slot >= 0 && dp_slot < p->wan_count &&
           dp_slot < MAX_INTERFACES && p->wan_live[dp_slot];
}

int ne_pair_plumb_local(struct ne_pair *p, const struct app_config *cfg,
                        int cfg_local_idx, int pair_li)
{
    (void)p; (void)cfg; (void)cfg_local_idx; (void)pair_li;
    return -ENOSYS;
}

int ne_pair_plumb_wan_dp(struct ne_pair *p, const struct app_config *cfg,
                         int cfg_wan_idx, int dp_slot)
{
    (void)p; (void)cfg; (void)cfg_wan_idx; (void)dp_slot;
    return -ENOSYS;
}

void ne_pair_unplumb_local(struct ne_pair *p, int pair_li)
{
    (void)p; (void)pair_li;
}

void ne_pair_unplumb_wan_dp(struct ne_pair *p, int dp_slot)
{
    (void)p; (void)dp_slot;
}

int ne_pair_teardown_live(struct ne_pair *p)
{
    (void)p;
    return -ENOSYS;
}

int ne_pair_open(struct ne_pair *p, const struct app_config *cfg)
{
    (void)p; (void)cfg;
    return -ENOSYS;
}

void ne_pair_close(struct ne_pair *p, const struct app_config *cfg)
{
    (void)p; (void)cfg;
}

void ne_pair_delete_local_xsks(struct ne_pair *p, int pair_li)
{
    (void)p; (void)pair_li;
}

void ne_pair_delete_wan_xsks(struct ne_pair *p, int dp_slot)
{
    (void)p; (void)dp_slot;
}

int ne_recv_local_slot(struct ne_pair *p, int rx_slot,
                       struct ne_packet *out, uint32_t max)
{
    (void)p; (void)rx_slot; (void)out; (void)max;
    return -ENOSYS;
}

int ne_recv_wan_slot(struct ne_pair *p, int rx_slot,
                     struct ne_packet *out, uint32_t max)
{
    (void)p; (void)rx_slot; (void)out; (void)max;
    return -ENOSYS;
}

void ne_recv_release_local_slot(struct ne_pair *p, int rx_slot)
{
    (void)p; (void)rx_slot;
}

void ne_recv_release_wan_slot(struct ne_pair *p, int rx_slot)
{
    (void)p; (void)rx_slot;
}

void ne_drain_cq_local(struct ne_pair *p, int tx_slot)
{
    (void)p; (void)tx_slot;
}

void ne_drain_cq_wan(struct ne_pair *p, int tx_slot)
{
    (void)p; (void)tx_slot;
}

void ne_refill_fq_local_slot(struct ne_pair *p, int rx_slot)
{
    (void)p; (void)rx_slot;
}

void ne_refill_fq_wan_slot(struct ne_pair *p, int rx_slot)
{
    (void)p; (void)rx_slot;
}

void ne_dp_tx_ctx(const char *dir, int tx_slot)
{
    (void)dir; (void)tx_slot;
}

void ne_dp_warn_rx(const char *dir, int cpu, int batch_rcvd)
{
    (void)dir; (void)cpu; (void)batch_rcvd;
}

void ne_dp_warn_rx_drop(const char *dir, int cpu, int worker, uint32_t q_depth)
{
    (void)dir; (void)cpu; (void)worker; (void)q_depth;
}

void ne_dp_warn_crypto(int cpu, int worker, uint32_t lan_q, uint32_t wan_q)
{
    (void)cpu; (void)worker; (void)lan_q; (void)wan_q;
}

int ne_tx_drain_local_all(struct ne_pair *p, struct ne_ring *srcs[],
                          int src_count, int local_idx, int tx_slot)
{
    (void)p; (void)srcs; (void)src_count; (void)local_idx; (void)tx_slot;
    return -ENOSYS;
}

int ne_tx_drain_wan_all(struct ne_pair *p, struct ne_ring *srcs[],
                        int src_count, int wan_idx, int tx_slot)
{
    (void)p; (void)srcs; (void)src_count; (void)wan_idx; (void)tx_slot;
    return -ENOSYS;
}

void *ne_packet_data(struct ne_pair *p, uint64_t addr)
{
    if (!p || !p->bufs || addr >= p->bufsize)
        return NULL;
    return xsk_umem__get_data(p->bufs, addr);
}

int ne_frame_alloc(struct ne_pair *p, uint64_t *addr_out)
{
    (void)p; (void)addr_out;
    return -ENOSYS;
}

uint32_t ne_frame_alloc_batch(struct ne_pair *p, uint64_t *addrs_out,
                              uint32_t max_n)
{
    (void)p; (void)addrs_out; (void)max_n;
    return 0;
}

void ne_frame_free(struct ne_pair *p, uint64_t addr)
{
    (void)p; (void)addr;
}

uint32_t ne_pool_free_count(struct ne_pair *p)
{
    (void)p;
    return 0;
}

void interface_reset_redirect_maps(void)
{
}

void interface_promisc_off_config(const struct app_config *cfg)
{
    (void)cfg;
}

int interface_set_queue_count(const char *ifname, int desired_count)
{
    (void)ifname; (void)desired_count;
    return -ENOSYS;
}

int interface_get_queue_count(const char *ifname)
{
    (void)ifname;
    return -ENOSYS;
}

int ne_rx_lan_slots_for(int local_queue_total)
{
    (void)local_queue_total;
    return -ENOSYS;
}

int ne_rx_wan_slots_for(int wan_queue_total)
{
    (void)wan_queue_total;
    return -ENOSYS;
}

int ne_rx_local_fds(struct ne_pair *p, int rx_slot, int *fds, int max)
{
    (void)p; (void)rx_slot; (void)fds; (void)max;
    return -ENOSYS;
}

int ne_rx_wan_fds(struct ne_pair *p, int rx_slot, int *fds, int max)
{
    (void)p; (void)rx_slot; (void)fds; (void)max;
    return -ENOSYS;
}

int ne_tx_local_fds(struct ne_pair *p, int tx_slot, int *fds, int max)
{
    (void)p; (void)tx_slot; (void)fds; (void)max;
    return -ENOSYS;
}

int ne_tx_wan_fds(struct ne_pair *p, int tx_slot, int *fds, int max)
{
    (void)p; (void)tx_slot; (void)fds; (void)max;
    return -ENOSYS;
}

int ne_tx_fds(struct ne_pair *p, int tx_slot, int *fds, int max)
{
    (void)p; (void)tx_slot; (void)fds; (void)max;
    return -ENOSYS;
}

void ne_kick_fq_local_slot(struct ne_pair *p, int rx_slot)
{
    (void)p; (void)rx_slot;
}

void ne_kick_fq_wan_slot(struct ne_pair *p, int rx_slot)
{
    (void)p; (void)rx_slot;
}
