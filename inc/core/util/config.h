#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <net/if.h>

#define MAX_INTERFACES 16
#define MAC_LEN 6
#define NE_PROFILE_SLOTS 1
#define MAX_BRIDGES_PER_PROFILE MAX_INTERFACES
#define MAX_CRYPTO_POLICIES 128
#define PQC_PEER_PUB_MAX 8192
#define POLICY_PROTO_ANY 0
#define POLICY_PROTO_TCP_UDP 254

#ifndef CRYPTO_POLICY_MATCH_IP_ONLY
#define CRYPTO_POLICY_MATCH_IP_ONLY 0
#endif

enum policy_action {
    POLICY_ACTION_BYPASS = 0,
    POLICY_ACTION_ENCRYPT_L2 = 2
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
};

struct wan_config {
    int db_id;
    char ifname[IF_NAMESIZE];
    uint32_t dst_ip;
    uint8_t src_mac[MAC_LEN];
    uint8_t dst_mac[MAC_LEN];
    int dataplane;
    int bandwidth_weight;
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
    uint16_t fake_ethertype_ipv4;
    struct crypto_policy policies[MAX_CRYPTO_POLICIES];
    int policy_count;
};

int config_wan_profile_weight(const struct app_config *cfg, int wan_idx);
int config_wan_live(const struct app_config *cfg, int wan_idx);
int config_wan_live_in_cfg(const struct app_config *cfg, const char *ifname);
int config_count_dataplane_wans(const struct app_config *cfg);
int config_wan_cfg_to_dp(const struct app_config *cfg, int cfg_idx);
int config_wan_dp_to_cfg(const struct app_config *cfg, int dp_idx);

int parse_ip_cidr_pub(const char *str, uint32_t *ip, uint32_t *netmask, uint32_t *network);
int parse_hex_bytes_pub(const char *str, uint8_t *out, int expected_len);
int config_validate(struct app_config *cfg);
int config_local_ifname_in_cfg(const struct app_config *cfg, const char *ifname);
int config_policy_db_id_taken(const struct app_config *cfg, int db_id);
const struct crypto_policy *config_select_crypto_policy(struct app_config *cfg,
                                                        uint32_t src_ip, uint32_t dst_ip,
                                                        uint16_t src_port, uint16_t dst_port,
                                                        uint8_t protocol);
void config_refresh_policy_in_table(struct app_config *cfg);
int config_policy_in_ok(const struct app_config *cfg,
                        uint8_t wire_policy_id,
                        uint32_t src_ip, uint32_t dst_ip,
                        uint16_t src_port, uint16_t dst_port,
                        uint8_t protocol);
#endif
