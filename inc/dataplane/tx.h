#ifndef CORE_TX_H
#define CORE_TX_H
#include <stdint.h>
#include "../core_types.h"

int core_tx_match_out(const struct app_config *cfg, const uint8_t *pkt,
                      uint32_t len, const struct crypto_policy **policy_out);
int core_tx_match_in(const struct app_config *cfg, const uint8_t *pkt,
                     uint32_t len, uint8_t wire_policy_id);
#endif
