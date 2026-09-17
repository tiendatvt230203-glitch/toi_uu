#include "../../../inc/core/dataplane/ospf.h"
#include "../../../inc/core/crypto/crypto.h"

int core_ospf_handle(struct core_runtime *runtime, void *packet,
                     uint32_t *packet_length)
{
    (void)runtime;
    (void)packet;
    (void)packet_length;
    return 0;
}

int core_ospf_encrypt(struct core_runtime *runtime, int policy_id,
                      void *packet, uint32_t *packet_length)
{
    (void)runtime;
    return core_l2_pqc_encrypt(policy_id, packet, packet_length);
}

int core_ospf_decrypt(struct core_runtime *runtime, int policy_id,
                      void *packet, uint32_t *packet_length)
{
    (void)runtime;
    return core_l2_pqc_decrypt(policy_id, packet, packet_length);
}
