#include "pqc_handshake.h"

#include <errno.h>

int sig_pqc_handshake_policy(const struct pqc_policy_input *input,
                             struct pqc_policy_key *key_out)
{
    (void)input;
    (void)key_out;
    return -ENOSYS;
}
