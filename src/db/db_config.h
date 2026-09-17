#ifndef DB_CONFIG_H
#define DB_CONFIG_H

#include "core/core_types.h"

int config_load_from_db(struct app_config *cfg, int ne_profile_id,
                        const char *conn_str);
int config_apply_crypto_from_policies(struct app_config *cfg);
int config_policy_db_id_taken(const struct app_config *cfg, int db_id);
int config_wan_cfg_to_dp(const struct app_config *cfg, int cfg_idx);
int config_validate(struct app_config *cfg);
int parse_ip_cidr_pub(const char *str, uint32_t *ip,
                      uint32_t *netmask, uint32_t *network);

struct pqc_policy_input;
int db_config_load_pqc_policy(void *pg_conn, int policy_id, int profile_id,
                              struct pqc_policy_input *out);

#endif
