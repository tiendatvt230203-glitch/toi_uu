#include "db_runtime.h"

#include "db_config.h"
#include "db_env.h"

#include <libpq-fe.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

int ne_profile_id_exists(int profile_id) {
    if (profile_id <= 0) return -EINVAL;
    struct ne_postgres_conn pg;
    if (ne_postgres_conn_fill(&pg) != 0)
        return -1;

    PGconn *conn = PQconnectdbParams(pg.keywords, pg.values, 0);
    if (!conn) return -ENOMEM;
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "[DB] connection failed: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return -EIO;
    }

    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", profile_id);
    const char *params[1] = { id_str };

    PGresult *res = PQexecParams(conn,
                                 "SELECT 1 FROM ne_profiles WHERE id = $1",
                                 1, NULL, params, NULL, NULL, 0);
    int rc = -EIO;
    if (res && PQresultStatus(res) == PGRES_TUPLES_OK)
        rc = PQntuples(res) > 0 ? 0 : -ENOENT;
    else
        fprintf(stderr, "[DB] profile lookup failed: %s", PQerrorMessage(conn));

    PQclear(res);
    PQfinish(conn);
    return rc;
}

int load_active_profile_config(struct app_config *out_cfg, int profile_id)
{
    if (!out_cfg || profile_id <= 0)
        return -EINVAL;

    int rc = config_load_from_db(out_cfg, profile_id, NULL);
    if (rc != 0) {
        memset(out_cfg, 0, sizeof(*out_cfg));
        return rc;
    }
    fprintf(stderr, "[DB] loaded profile=%d LAN=%d WAN=%d policy_rows=%d\n",
            out_cfg->profile_id, out_cfg->local_count,
            out_cfg->wan_count, out_cfg->policy_count);
    return 0;
}
