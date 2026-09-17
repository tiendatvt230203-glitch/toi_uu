#ifndef CORE_OSPF_H
#define CORE_OSPF_H

#include <stdint.h>
#include "../core_types.h"

int core_ospf_handle(struct core_runtime *, void *packet,
                     uint32_t *packet_length);
int core_ospf_encrypt(struct core_runtime *, int policy_id,
                      void *packet, uint32_t *packet_length);
int core_ospf_decrypt(struct core_runtime *, int policy_id,
                      void *packet, uint32_t *packet_length);

#endif
