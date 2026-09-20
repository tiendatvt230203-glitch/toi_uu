#ifndef CORE_TYPES_H
#define CORE_TYPES_H

#define MAX_INTERFACES 16
#define MAX_QUEUES 64
#define MAX_CRYPTO_POLICIES 128
#define MAX_BRIDGES_PER_PROFILE 16
#define PQC_PEER_PUB_MAX 8192
#define MAC_LEN 6
#define NE_PROFILE_SLOTS 1
#define POLICY_PROTO_ANY 0
#define POLICY_PROTO_TCP_UDP 254
#define NE_L2_TCP_ETHERTYPE  0x1054u
#define NE_L2_UDP_ETHERTYPE  0x1055u
#define NE_L2_PING_ETHERTYPE 0x1056u
#define NE_L2_OSPF_ETHERTYPE 0x1059u
#define CORE_MAX_WORKERS 64
#define CORE_CRYPTO_WORKERS 6
#define CORE_TX_WORKERS 4
#define CORE_RING_CAPACITY 16384u
#define CORE_KEY_LIFETIME_SEC (30u * 24u * 60u * 60u)
#define CORE_FLOW_ROUTE_SETS 8192u
#define CORE_FLOW_ROUTE_WAYS 8u
#define NE_FRAME 2048u
#define NE_N_FRAMES 1048576u
#define NE_BATCH_SIZE 64u
#define NE_FQ_PREFILL 16384u

/* Shared core and XDP constants. */
#define IPPROTO_ICMP_VAL 1
#define IPPROTO_TCP_VAL 6
#define IPPROTO_UDP_VAL 17
#define IPPROTO_OSPF_VAL 89
#define ETH_P_NE_ARP_ENC 0x1048
#define ETH_P_CFM 0x8902
#define ETH_P_ARP_VAL 0x0806
#define PATH_MTU 1500
#define ETH_FRAME_MAX (14 + PATH_MTU)

#ifndef NE_BPF
#include <net/if.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <xdp/xsk.h>

enum policy_action {
    POLICY_ACTION_BYPASS = 0,
    POLICY_ACTION_ENCRYPT_L2 = 2
};

enum ne_packet_dir {
    NE_DIR_LOCAL = 0,
    NE_DIR_WAN = 1
};

enum core_worker_role {
    CORE_WORKER_LAN_RX = 1,
    CORE_WORKER_WAN_RX = 2,
    CORE_WORKER_CRYPTO = 3,
    CORE_WORKER_TX = 4
};

struct crypto_policy {
    int id;
    int db_id;
    int priority;
    int action;
    uint8_t protocol;
    int src_port_from;
    int src_port_to;
    int dst_port_from;
    int dst_port_to;
    int src_any;
    int dst_any;
    int src_negate;
    int dst_negate;
    uint32_t src_net;
    uint32_t src_mask;
    uint32_t dst_net;
    uint32_t dst_mask;
};

struct bridge_config {
    char ifname[IF_NAMESIZE];
    int local_slot;
    int wan_slot;
};

struct pqc_profile_config {
    char local_identity_fingerprint[16];
    char peer_fingerprint[16];
    int is_initiator;
    int has_pqc_identity;
    char peer_public_key[PQC_PEER_PUB_MAX];
};

struct local_config {
    char ifname[IF_NAMESIZE];
    int ifindex;
    int queue_count;
    struct {
        struct xsk_socket *xsk;
        struct xsk_ring_cons rx;
        struct xsk_ring_prod tx;
        struct xsk_ring_prod fq;
        struct xsk_ring_cons cq;
        uint32_t rx_pending;
    } queues[MAX_QUEUES];
    uint64_t tx_no_free;
    uint32_t xdp_flags;
};

struct wan_config {
    char ifname[IF_NAMESIZE];
    uint8_t src_mac[MAC_LEN];
    uint8_t dst_mac[MAC_LEN];
    int dataplane;
    int bandwidth_weight;
    int ifindex;
    int queue_count;
    struct {
        struct xsk_socket *xsk;
        struct xsk_ring_cons rx;
        struct xsk_ring_prod tx;
        struct xsk_ring_prod fq;
        struct xsk_ring_cons cq;
        uint32_t rx_pending;
    } queues[MAX_QUEUES];
    uint64_t tx_no_free;
    uint32_t xdp_flags;
};

struct app_config {
    int profile_id;
    char profile_name[64];
    int enabled;
    struct local_config locals[MAX_INTERFACES];
    int local_count;
    struct wan_config wans[MAX_INTERFACES];
    int wan_count;
    struct bridge_config bridges[MAX_BRIDGES_PER_PROFILE];
    int bridge_count;
    struct pqc_profile_config pqc;
    char bpf_lan_file[256];
    char bpf_wan_file[256];
    int crypto_enabled;
    struct crypto_policy policies[MAX_CRYPTO_POLICIES];
    int policy_count;
};

struct ne_packet {
    uint64_t addr;
    uint32_t len;
    uint16_t wire_ethertype;
    uint8_t dir;
    uint8_t wan_idx;
    uint8_t local_idx;
    uint8_t tx_slot;
};

struct ne_ring {
    struct ne_packet *buf;
    uint32_t cap;
    uint32_t mask;
    __attribute__((aligned(64))) volatile uint32_t head;
    __attribute__((aligned(64))) volatile uint32_t tail;
    pthread_spinlock_t push_lock;
    pthread_spinlock_t pop_lock;
    uint8_t mpsc_pop;
};

struct ne_pool {
    uint64_t *buf;
    uint32_t cap;
    uint32_t mask;
    uint32_t head;
    uint32_t tail;
    pthread_spinlock_t lock;
};

struct bpf_object;

struct ne_pair {
    void *bufs;
    size_t bufsize;
    uint32_t frame_size;
    uint32_t n_frames;
    struct xsk_umem *umem;
    int umem_fq_li;
    int umem_fq_q;
    int local_count;
    int wan_count;
    int local_queue_total;
    int wan_queue_total;
    struct ne_pool pool;
    struct bpf_object *bpf_locals[MAX_INTERFACES];
    struct bpf_object *bpf_wans[MAX_INTERFACES];
    uint8_t xdp_local_on[MAX_INTERFACES];
    uint8_t xdp_wan_on[MAX_INTERFACES];
    uint8_t local_live[MAX_INTERFACES];
    uint8_t wan_live[MAX_INTERFACES];
    uint32_t xdp_flags;
};

struct core_worker {
    pthread_t thread;
    enum core_worker_role role;
    int cpu_id;
    int running;
    void *context;
};

struct core_flow_route {
    uint32_t ip_a;
    uint32_t ip_b;
    uint16_t port_a;
    uint16_t port_b;
    uint8_t protocol;
    uint8_t worker_idx;
    atomic_uchar valid;
};

struct core_runtime {
    struct app_config config;
    struct ne_pair pair;
    struct ne_ring local_to_crypto[CORE_CRYPTO_WORKERS];
    struct ne_ring wan_to_crypto[CORE_CRYPTO_WORKERS];
    struct ne_ring crypto_to_lan[MAX_INTERFACES][CORE_CRYPTO_WORKERS];
    struct ne_ring crypto_to_wan[MAX_INTERFACES][CORE_CRYPTO_WORKERS];
    struct core_worker workers[CORE_MAX_WORKERS];
    int worker_count;
    int initialized;
    int running;
    int stop_requested;
};

#endif /* NE_BPF */
#endif /* CORE_TYPES_H */
