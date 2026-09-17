#include "../../../inc/core/crypto/crypto.h"

#include <errno.h>

int core_l2_pqc_encrypt(int policy_id, void *ethernet_frame,
                        uint32_t *frame_length)
{
    (void)policy_id;
    (void)ethernet_frame;
    (void)frame_length;
    return -ENOSYS;
}

int core_l2_pqc_decrypt(int policy_id, void *ethernet_frame,
                        uint32_t *frame_length)
{
    (void)policy_id;
    (void)ethernet_frame;
    (void)frame_length;
    return -ENOSYS;
}
