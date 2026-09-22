#ifndef CORE_INTERFACE_H
#define CORE_INTERFACE_H

#include "../core_types.h"

int ne_ring_init(struct ne_ring *r, uint32_t cap, int mpsc_pop);
void ne_ring_destroy(struct ne_ring *r);
int ne_ring_try_push(struct ne_ring *r, const struct ne_packet *pkt);
int ne_ring_try_push_pair(struct ne_ring *r, const struct ne_packet *first,
                          const struct ne_packet *second);
int ne_ring_try_pop(struct ne_ring *r, struct ne_packet *pkt);
uint32_t ne_ring_try_pop_batch(struct ne_ring *r, struct ne_packet *pkts,
                               uint32_t max_n);
uint32_t ne_ring_count(const struct ne_ring *r);

int ne_pair_open(struct ne_pair *p, struct app_config *cfg);
void ne_pair_close(struct ne_pair *p, const struct app_config *cfg);


int ne_fill_slot(struct ne_pair *p, enum ne_packet_dir dir, int rx_slot);
int ne_recv_slot(struct ne_pair *p, enum ne_packet_dir dir, int rx_slot,
                 struct ne_packet *out, uint32_t max);
int ne_tx_drain_all(struct ne_pair *p, enum ne_packet_dir dir,
                    struct ne_ring *srcs[], int src_count,
                    int iface_idx, int tx_slot);
int ne_cq_drain_slot(struct ne_pair *p, enum ne_packet_dir dir, int tx_slot);

void *ne_packet_data(struct ne_pair *p, uint64_t addr);
int ne_frame_alloc(struct ne_pair *p, uint64_t *addr_out);
void ne_frame_free(struct ne_pair *p, uint64_t addr);
void ne_packet_free(struct ne_pair *p, const struct ne_packet *pkt);
int ne_packet_copy(struct ne_pair *p, const struct ne_packet *pkt,
                    uint8_t *out, uint32_t capacity);
int ne_packet_store(struct ne_pair *p, const uint8_t *data, uint32_t len,
                     struct ne_packet *pkt);
#endif
