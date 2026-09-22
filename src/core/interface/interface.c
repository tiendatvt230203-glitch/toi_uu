#include "../../../inc/core/interface/interface.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <linux/if_link.h>
#include "../../../inc/core/interface/xdp.h"

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

static struct ne_xsk_queue *pair_queues(struct ne_pair *p, int dir, int *count)
{
    if (dir == NE_DIR_LOCAL) {
        *count = p->config->locals[0].queue_count;
        return p->config->locals[0].queues;
    }
    *count = p->config->wans[0].queue_count;
    return p->config->wans[0].queues;
}

int ne_frame_alloc(struct ne_pair *p, uint64_t *addr_out)
{
    pthread_spin_lock(&p->pool.lock);
    if (p->pool.head == p->pool.tail) {
        pthread_spin_unlock(&p->pool.lock);
        return -ENOSPC;
    }
    *addr_out = p->pool.buf[p->pool.tail++ & p->pool.mask] + NE_XDP_PACKET_HEADROOM;
    pthread_spin_unlock(&p->pool.lock);
    return 0;
}

void ne_frame_free(struct ne_pair *p, uint64_t addr)
{
    pthread_spin_lock(&p->pool.lock);
    p->pool.buf[p->pool.head++ & p->pool.mask] = addr & ~((uint64_t)p->frame_size - 1u);
    pthread_spin_unlock(&p->pool.lock);
}

void *ne_packet_data(struct ne_pair *p, uint64_t addr)
{
    return p && p->bufs && addr < p->bufsize ? xsk_umem__get_data(p->bufs, addr) : NULL;
}

void ne_packet_free(struct ne_pair *p, const struct ne_packet *pkt)
{
    ne_frame_free(p, pkt->addr);
    for (unsigned i = 1; i < pkt->segment_count; i++)
        ne_frame_free(p, pkt->continuation_addr[i - 1]);
}

int ne_packet_copy(struct ne_pair *p, const struct ne_packet *pkt,
                    uint8_t *out, uint32_t capacity)
{
    unsigned segments = pkt->segment_count ? pkt->segment_count : 1;
    uint32_t copied = 0;
    if (segments > NE_PACKET_MAX_SEGMENTS) return -EMSGSIZE;
    for (unsigned i = 0; i < segments; i++) {
        uint64_t addr = i ? pkt->continuation_addr[i - 1] : pkt->addr;
        uint32_t len = i ? pkt->continuation_len[i - 1] : pkt->len;
        if (addr >= p->bufsize || len > p->bufsize - addr ||
            len > capacity - copied) return -EMSGSIZE;
        memcpy(out + copied, ne_packet_data(p, addr), len);
        copied += len;
    }
    return copied;
}

int ne_packet_store(struct ne_pair *p, const uint8_t *data, uint32_t len,
                     struct ne_packet *pkt)
{
    memset(pkt, 0, sizeof(*pkt));
    if (!len || len > ETH_FRAME_MAX) return -EMSGSIZE;
    uint32_t offset = 0;
    while (offset < len) {
        uint64_t addr;
        int rc = ne_frame_alloc(p, &addr);
        if (rc) {
            if (pkt->segment_count) ne_packet_free(p, pkt);
            return rc;
        }
        uint32_t take = len - offset;
        if (take > NE_FRAME_DATA_MAX) take = NE_FRAME_DATA_MAX;
        memcpy(ne_packet_data(p, addr), data + offset, take);
        unsigned i = pkt->segment_count++;
        if (!i) { pkt->addr = addr; pkt->len = take; }
        else { pkt->continuation_addr[i-1] = addr; pkt->continuation_len[i-1] = take; }
        offset += take;
    }
    pkt->total_len = len;
    return 0;
}

static int queue_count(const char *ifname)
{
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%s/queues", ifname);
    DIR *dir = opendir(path);
    if (!dir) return -errno;
    struct dirent *entry;
    int count = 0;
    while ((entry = readdir(dir)))
        if (!strncmp(entry->d_name, "rx-", 3)) count++;
    closedir(dir);
    return count;
}

int ne_pair_open(struct ne_pair *p, struct app_config *cfg)
{
    if (!p || !cfg || cfg->local_count != 1 || cfg->wan_count != 1 ||
        !cfg->wans[0].dataplane) return -EINVAL;
    memset(p, 0, sizeof(*p));
    p->config = cfg;
    p->frame_size = NE_FRAME;
    p->n_frames = NE_N_FRAMES;
    p->bufsize = (size_t)p->frame_size * p->n_frames;
    p->local_count = p->wan_count = 1;
    int rc = 0;
    for (int dir = 0; dir < 2; dir++) {
        const char *name = dir ? cfg->wans[0].ifname : cfg->locals[0].ifname;
        int n = queue_count(name);
        if (n < (int)CORE_TX_WORKERS || n > MAX_QUEUES) return -ENOSPC;
        if (dir) cfg->wans[0].queue_count = n;
        else cfg->locals[0].queue_count = n;
    }
    p->pool.buf = calloc(p->n_frames, sizeof(uint64_t));
    if (!p->pool.buf) return -ENOMEM;
    rc = pthread_spin_init(&p->pool.lock, PTHREAD_PROCESS_PRIVATE);
    if (rc) { free(p->pool.buf); p->pool.buf = NULL; return -rc; }
    p->pool.cap = p->n_frames;
    p->pool.mask = p->n_frames - 1;
    p->pool.head = p->n_frames;
    for (unsigned i = 0; i < p->n_frames; i++) p->pool.buf[i] = (uint64_t)i * p->frame_size;
    p->bufs = mmap(NULL, p->bufsize, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p->bufs == MAP_FAILED) { p->bufs = NULL; rc = -errno; goto fail; }
    struct xsk_umem_config uc = {
        .fill_size = CORE_RING_CAPACITY, .comp_size = CORE_RING_CAPACITY,
        .frame_size = NE_FRAME, .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM
    };
    rc = xsk_umem__create(&p->umem, p->bufs, p->bufsize,
        &cfg->locals[0].queues[0].fq, &cfg->locals[0].queues[0].cq, &uc);
    if (rc) goto fail;
    struct xsk_socket_config sc = {
        .rx_size = CORE_RING_CAPACITY, .tx_size = CORE_RING_CAPACITY,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = XDP_FLAGS_DRV_MODE,
        .bind_flags = XDP_COPY | XDP_USE_NEED_WAKEUP | XDP_USE_SG
    };
    for (int dir = 0; dir < 2; dir++) {
        int count;
        struct ne_xsk_queue *q = pair_queues(p, dir, &count);
        const char *name = dir ? cfg->wans[0].ifname : cfg->locals[0].ifname;
        for (int i = 0; i < count; i++) {
            rc = xsk_socket__create_shared(&q[i].xsk, name, i, p->umem,
                &q[i].rx, &q[i].tx, &q[i].fq, &q[i].cq, &sc);
            if (rc) goto fail;
        }
        if (dir) p->wan_queue_total = count;
        else p->local_queue_total = count;
        rc = ne_fill_slot(p, dir, 0);
        if (rc < 0) goto fail;
    }
    rc = core_xdp_attach(p);
    if (rc) goto fail;
    p->local_live[0] = p->wan_live[0] = 1;
    return 0;
fail:
    ne_pair_close(p, cfg);
    return rc;
}

void ne_pair_close(struct ne_pair *p, const struct app_config *cfg)
{
    (void)cfg;
    if (!p || !p->config) return;
    core_xdp_detach(p);
    /* Shared UMEM socket must be deleted last. */
    for (int pass = 0; pass < 2; pass++)
        for (int dir = 0; dir < 2; dir++) {
            int count;
            struct ne_xsk_queue *q = pair_queues(p, dir, &count);
            for (int i = 0; i < count; i++) {
                if (!q[i].xsk) continue;
                int owner = p->umem && xsk_socket__fd(q[i].xsk) == xsk_umem__fd(p->umem);
                if (owner != pass) continue;
                xsk_socket__delete(q[i].xsk);
                memset(&q[i], 0, sizeof(q[i]));
            }
        }
    if (p->umem) xsk_umem__delete(p->umem);
    if (p->bufs) munmap(p->bufs, p->bufsize);
    if (p->pool.buf) { pthread_spin_destroy(&p->pool.lock); free(p->pool.buf); }
    memset(p, 0, sizeof(*p));
}

int ne_fill_slot(struct ne_pair *p, enum ne_packet_dir dir, int rx_slot)
{
    if (!p || !p->config || rx_slot != 0) return -EINVAL;
    int count, supplied = 0;
    struct ne_xsk_queue *q = pair_queues(p, dir, &count);
    for (int i = 0; i < count; i++) {
        struct ne_xsk_queue *slot = &q[i];
        if (!slot->xsk) continue;
        for (unsigned n = 0; n < NE_FQ_REFILL_BUDGET; n++) {
            uint32_t free_slots = xsk_prod_nb_free(&slot->fq, slot->fq.size);
            if (slot->fq.size - free_slots >= NE_FQ_PREFILL) break;
            uint64_t addr;
            if (ne_frame_alloc(p, &addr)) break;
            uint32_t idx;
            if (xsk_ring_prod__reserve(&slot->fq, 1, &idx) != 1) {
                ne_frame_free(p, addr); break;
            }
            *xsk_ring_prod__fill_addr(&slot->fq, idx) = addr - NE_XDP_PACKET_HEADROOM;
            xsk_ring_prod__submit(&slot->fq, 1);
            supplied++;
        }
        if (xsk_ring_prod__needs_wakeup(&slot->fq))
            (void)recvfrom(xsk_socket__fd(slot->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
    }
    return supplied;
}

int ne_recv_slot(struct ne_pair *p, enum ne_packet_dir dir, int rx_slot,
                 struct ne_packet *out, uint32_t max)
{
    if (!p || !p->config || !out || rx_slot != 0) return -EINVAL;
    static _Thread_local unsigned cursor;
    int count;
    struct ne_xsk_queue *queues = pair_queues(p, dir, &count);
    uint32_t produced = 0;
    for (int off = 0; off < count && produced < max; off++) {
        struct ne_xsk_queue *q = &queues[(cursor + off) % count];
        uint32_t idx, consumed = 0;
        uint32_t n = xsk_ring_cons__peek(&q->rx, (max - produced) * NE_PACKET_MAX_SEGMENTS, &idx);
        while (consumed < n && produced < max) {
            struct ne_packet pkt = {0};
            uint32_t start = consumed;
            int complete = 0;
            while (consumed < n && pkt.segment_count < NE_PACKET_MAX_SEGMENTS) {
                const struct xdp_desc *d = xsk_ring_cons__rx_desc(&q->rx, idx + consumed++);
                unsigned i = pkt.segment_count++;
                if (!i) { pkt.addr = d->addr; pkt.len = d->len; }
                else { pkt.continuation_addr[i-1] = d->addr; pkt.continuation_len[i-1] = d->len; }
                pkt.total_len += d->len;
                if (!(d->options & XDP_PKT_CONTD)) { complete = 1; break; }
            }
            if (!complete) { consumed = start; break; }
            pkt.dir = dir;
            out[produced++] = pkt;
        }
        if (n > consumed) xsk_ring_cons__cancel(&q->rx, n - consumed);
        if (consumed) xsk_ring_cons__release(&q->rx, consumed);
    }
    cursor = (cursor + 1u) % count;
    return produced;
}

int ne_cq_drain_slot(struct ne_pair *p, enum ne_packet_dir dir, int tx_slot)
{
    int count, total = 0;
    struct ne_xsk_queue *q = pair_queues(p, dir, &count);
    for (int i = tx_slot; i < count; i += CORE_TX_WORKERS) {
        uint32_t idx, n;
        while ((n = xsk_ring_cons__peek(&q[i].cq, NE_BATCH_SIZE, &idx))) {
            for (unsigned j = 0; j < n; j++)
                ne_frame_free(p, *xsk_ring_cons__comp_addr(&q[i].cq, idx + j));
            xsk_ring_cons__release(&q[i].cq, n);
            total += n;
        }
    }
    return total;
}

int ne_tx_drain_all(struct ne_pair *p, enum ne_packet_dir dir,
                    struct ne_ring *srcs[], int src_count, int iface_idx, int tx_slot)
{
    if (iface_idx != 0 || tx_slot < 0 || tx_slot >= (int)CORE_TX_WORKERS) return -EINVAL;
    int count, sent = 0;
    struct ne_xsk_queue *q = pair_queues(p, dir, &count);
    if (count <= tx_slot) return -ENOSPC;
    struct ne_xsk_queue *slot = &q[tx_slot];
    for (int s = 0; s < src_count; s++) {
        struct ne_ring *ring = srcs[s];
        for (unsigned batch = 0; batch < NE_BATCH_SIZE; batch++) {
            uint32_t tail = __atomic_load_n(&ring->tail, __ATOMIC_RELAXED);
            uint32_t head = __atomic_load_n(&ring->head, __ATOMIC_ACQUIRE);
            if (tail == head) break;
            struct ne_packet first = ring->buf[tail & ring->mask];
            unsigned group = first.jumbo_fragment_count > 1 ? first.jumbo_fragment_count : 1;
            if (group > NE_PACKET_MAX_SEGMENTS || head - tail < group) break;
            unsigned needed = 0;
            for (unsigned j = 0; j < group; j++) {
                struct ne_packet *pkt = &ring->buf[(tail+j) & ring->mask];
                needed += pkt->segment_count ? pkt->segment_count : 1;
            }
            uint32_t idx;
            if (xsk_ring_prod__reserve(&slot->tx, needed, &idx) != needed) break;
            unsigned written = 0;
            for (unsigned j = 0; j < group; j++) {
                struct ne_packet *pkt = &ring->buf[(tail+j) & ring->mask];
                unsigned segments = pkt->segment_count ? pkt->segment_count : 1;
                for (unsigned i = 0; i < segments; i++) {
                    struct xdp_desc *d = xsk_ring_prod__tx_desc(&slot->tx, idx + written++);
                    d->addr = i ? pkt->continuation_addr[i-1] : pkt->addr;
                    d->len = i ? pkt->continuation_len[i-1] : pkt->len;
                    d->options = i + 1 < segments ? XDP_PKT_CONTD : 0;
                }
            }
            __atomic_store_n(&ring->tail, tail + group, __ATOMIC_RELEASE);
            xsk_ring_prod__submit(&slot->tx, needed);
            sent += group;
        }
    }
    if (xsk_ring_prod__needs_wakeup(&slot->tx))
        (void)sendto(xsk_socket__fd(slot->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    return sent;
}
