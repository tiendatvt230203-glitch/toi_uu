#include "pqc_handshake.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

int sig_pqc_handshake_policy(const struct pqc_policy_input *input,
                             struct pqc_policy_key *key_out)
{
#if PQC_FIXED_TEST_KEY
    if (!input || !key_out || input->policy_id <= 0 || input->policy_id > 255)
        return -EINVAL;
    key_out->policy_id = input->policy_id;
    memset(key_out->bytes, 0x5a, sizeof(key_out->bytes));
    fprintf(stderr, "[PQC-TEST] Fixed 256-bit test key for policy %d; no handshake\n",
            input->policy_id);
    return 0;
#else
    (void)input;
    (void)key_out;
    return -ENOSYS;
#endif
}
