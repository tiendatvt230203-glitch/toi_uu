#ifndef PQC_HANDSHAKE_H
#define PQC_HANDSHAKE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <net/if.h>

enum {
    PQC_ROLE_DYNAMIC = 0,
    PQC_ROLE_INITIATOR = 1,
    PQC_ROLE_RESPONDER = 2
};

#define PQC_USE_DYNAMIC_ROLE 1

struct pqc_policy_input {
    int policy_id;
    int profile_id;
    int role_mode;
    bool is_tunnel;
    char peer_ip[64];
    char wan_ifname[IF_NAMESIZE];
    char key_id[64];
    char local_fingerprint[64];
    char peer_fingerprint[64];
    char local_private_key[8192];
    char local_public_key[8192];
    char peer_public_key[8192];
};

#define PQC_POLICY_KEY_SIZE 32u

struct pqc_policy_key {
    int policy_id;
    uint8_t bytes[PQC_POLICY_KEY_SIZE];
};



int sig_pqc_handshake_policy(const struct pqc_policy_input *input,
                             struct pqc_policy_key *key_out);

#endif
