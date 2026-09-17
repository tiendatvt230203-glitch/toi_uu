#ifndef CRYPTO_OPTION_H
#define CRYPTO_OPTION_H

#include <stdint.h>
#include <stddef.h>

#include "../core/util/config.h"
#include "packet_crypto.h"

/* L2-PQC wire envelope. Protocol-specific TCP/UDP/ARP handling stays in its
 * owning dataplane module; these APIs only identify the encrypted envelope. */
#define CRYPTO_L2_PQC_ETHERTYPE      0x104Au
#define CRYPTO_L2_PQC_UDP_ETHERTYPE  0x104Bu
#define CRYPTO_L2_PQC_ARP_ETHERTYPE  0x1048u
/* Existing wire constants used by the XDP loader and profile configuration. */
#define NE_L2_FAKE_ETHERTYPE      CRYPTO_L2_PQC_ETHERTYPE
#define NE_L2_FAKE_ETHERTYPE_UDP  CRYPTO_L2_PQC_UDP_ETHERTYPE
#define NE_L2_FAKE_ETHERTYPE_ARP  CRYPTO_L2_PQC_ARP_ETHERTYPE

int crypto_l2_pqc_is_wire(const uint8_t *packet, size_t packet_len);
int crypto_l2_pqc_is_arp_wire(const uint8_t *packet, size_t packet_len);
int crypto_l2_pqc_read_policy_id(const uint8_t *packet, uint32_t packet_len,
                                 uint8_t *policy_id_out);
int crypto_l2_pqc_frag_tag_offset(const uint8_t *packet, size_t packet_len,
                                  int nonce_size);
int crypto_l2_pqc_read_worker_idx(const uint8_t *packet, uint32_t packet_len,
                                  uint8_t *worker_idx_out);

/* --- worker bind (forwarder sets once per crypto thread) --- */

void crypto_option_bind_worker_idx(uint8_t worker_idx);
uint8_t crypto_option_worker_idx(void);

struct ne_pair;
void crypto_l2_pqc_bind_pair(struct ne_pair *p);
void crypto_l2_pqc_reasm_set_addr(uint64_t addr);
int crypto_l2_pqc_reasm_held(void);
uint64_t crypto_l2_pqc_reasm_out_addr(void);

/* --- option router --- */

typedef enum {
    CRYPTO_OPT_L2_PQC = 0,
    CRYPTO_OPT_COUNT
} crypto_option_id;

typedef enum {
    CRYPTO_PROTO_TCP = 0,
    CRYPTO_PROTO_UDP,
    CRYPTO_PROTO_ICMP,
    CRYPTO_PROTO_OSPF,
    CRYPTO_PROTO_OTHER,
    CRYPTO_PROTO_ARP,
    CRYPTO_PROTO_COUNT
} crypto_proto_class;

crypto_proto_class crypto_proto_classify(uint8_t ip_proto);

struct crypto_option_ops {
    int (*need_split)(uint32_t pkt_len);
    int (*split)(struct packet_crypto_ctx *ctx, uint8_t *pkt_data, uint32_t pkt_len,
                 size_t frag0_max, uint32_t *frag0_len,
                 uint8_t *frag1, size_t frag1_max, uint32_t *frag1_len);
    int (*encrypt)(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len);
    int (*decrypt)(struct packet_crypto_ctx *ctx, uint8_t *pkt, uint32_t *pkt_len);
    int (*is_fragment)(const struct app_config *cfg, const uint8_t *pkt_data,
                       uint32_t pkt_len, uint16_t *pkt_id, uint8_t *frag_index);
    int (*reasm)(int profile_slot, int worker_idx, struct packet_crypto_ctx *ctx,
                 uint8_t *pkt_data, uint32_t *pkt_len, uint8_t *out_buf, uint32_t *out_len);
    void (*frag_gc)(int profile_slot, int worker_idx, uint64_t now_ns);
};

const struct crypto_option_ops *crypto_option_ops(crypto_option_id id, crypto_proto_class proto);

int crypto_l2_pqc_encrypt_tcp_l3(struct packet_crypto_ctx *ctx,
                                 uint8_t *pkt, uint32_t *pkt_len,
                                 int l3_off, int bond_active);

int crypto_option_need_split(crypto_option_id id, crypto_proto_class proto, uint32_t pkt_len);
int crypto_option_split(crypto_option_id id, crypto_proto_class proto,
                        struct packet_crypto_ctx *ctx,
                        uint8_t *pkt_data, uint32_t pkt_len,
                        size_t frag0_max, uint32_t *frag0_len,
                        uint8_t *frag1, size_t frag1_max, uint32_t *frag1_len);
int crypto_option_encrypt(crypto_option_id id, crypto_proto_class proto,
                          struct packet_crypto_ctx *ctx,
                          uint8_t *pkt, uint32_t *pkt_len);
int crypto_option_decrypt(crypto_option_id id, crypto_proto_class proto,
                          struct packet_crypto_ctx *ctx,
                          uint8_t *pkt, uint32_t *pkt_len);
int crypto_option_is_fragment(crypto_option_id id, crypto_proto_class proto,
                              const struct app_config *cfg,
                              const uint8_t *pkt_data, uint32_t pkt_len,
                              uint16_t *pkt_id, uint8_t *frag_index);
int crypto_option_reassemble(crypto_option_id id, crypto_proto_class proto,
                             int profile_slot, int worker_idx,
                             struct packet_crypto_ctx *ctx,
                             uint8_t *pkt_data, uint32_t *pkt_len,
                             uint8_t *out_buf, uint32_t *out_len);
void crypto_option_frag_gc(crypto_option_id id, crypto_proto_class proto,
                           int profile_slot, int worker_idx, uint64_t now_ns);
void crypto_option_frag_gc_all(int profile_slot, int worker_idx, uint64_t now_ns);

#endif
