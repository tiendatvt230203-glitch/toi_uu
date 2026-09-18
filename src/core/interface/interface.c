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

int ne_pair_open(struct ne_pair *p, const struct app_config *cfg)
{
    (void)p; (void)cfg;
    return -ENOSYS;
}

void ne_pair_close(struct ne_pair *p, const struct app_config *cfg)
{
    (void)p; (void)cfg;
}

int ne_fill_slot(struct ne_pair *p, enum ne_packet_dir dir, int rx_slot)
{
    (void)p; (void)dir; (void)rx_slot;
    return -ENOSYS;
}

int ne_recv_slot(struct ne_pair *p, enum ne_packet_dir dir, int rx_slot,
                 struct ne_packet *out, uint32_t max)
{
    (void)p; (void)dir; (void)rx_slot; (void)out; (void)max;
    return -ENOSYS;
}

int ne_tx_drain_all(struct ne_pair *p, enum ne_packet_dir dir,
                    struct ne_ring *srcs[], int src_count,
                    int iface_idx, int tx_slot)
{
    (void)p; (void)dir; (void)srcs; (void)src_count;
    (void)iface_idx; (void)tx_slot;
    return -ENOSYS;
}

int ne_cq_drain_slot(struct ne_pair *p, enum ne_packet_dir dir, int tx_slot)
{
    (void)p; (void)dir; (void)tx_slot;
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

void ne_frame_free(struct ne_pair *p, uint64_t addr)
{
    (void)p; (void)addr;
}
