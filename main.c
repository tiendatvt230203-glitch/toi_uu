#include "runtime/runtime.h"

#include "db_env.h"

#include <libpq-fe.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static int daemon_load_environment(void)
{








    if (load_ne_env() != 0) {
        fprintf(stderr, "[MAIN] failed to load environment\n");
        return -1;
    }

    return 0;
}


static PGconn *daemon_check_database(void)
{
    struct ne_postgres_conn pg;
    PGconn *conn;

    if (ne_postgres_conn_fill(&pg) != 0) {
        fprintf(stderr, "[MAIN] invalid PostgreSQL configuration\n");
        return NULL;
    }

    conn = PQconnectdbParams(pg.keywords, pg.values, 0);
    if (!conn) {
        fprintf(stderr, "[MAIN] failed to create PostgreSQL connection\n");
        return NULL;
    }

    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr,
                "[MAIN] PostgreSQL connection failed: %s",
                PQerrorMessage(conn));

        PQfinish(conn);
        return NULL;
    }

    fprintf(stderr, "[DB] OK\n");

    return conn;
}


static int daemon_setup_core(struct core_runtime *runtime)
{









    if (core_runtime_init(runtime) != 0) {
        fprintf(stderr, "[MAIN] core runtime init failed\n");
        return -1;
    }

    return 0;
}


static int daemon_run(struct core_runtime *runtime)
{















    return core_runtime_run(runtime);
}


static void daemon_cleanup(struct core_runtime *runtime)
{
    core_runtime_stop(runtime);
    core_runtime_cleanup(runtime);
}


int main(int argc, char **argv)
{
    static struct core_runtime runtime;
    int rc;
    int profile_id = 0;
    if (argc != 1) {
        if (argc != 3 || (strcmp(argv[1], "-id") && strcmp(argv[1], "-del"))) {
            fprintf(stderr, "Usage: %s [-id PROFILE | -del PROFILE]\n", argv[0]);
            return argc == 2 && !strcmp(argv[1], "--help") ? 0 : 1;
        }
        char *end;
        errno = 0;
        long value = strtol(argv[2], &end, 10);
        if (errno || end == argv[2] || *end || value <= 0 || value > INT_MAX)
            return 1;
        profile_id = (int)value;
    }

    rc = daemon_load_environment();
    if (rc != 0)
        return 1;

    PGconn *conn = daemon_check_database();
    if (!conn)
        return 1;

    if (profile_id) {
        char payload[64];
        snprintf(payload, sizeof(payload), "%s:%d",
                 !strcmp(argv[1], "-del") ? "del" : "load", profile_id);
        const char *params[] = { payload };
        PGresult *res = PQexecParams(conn, "SELECT pg_notify('xdp_start', $1)",
                                     1, NULL, params, NULL, NULL, 0);
        int ok = res && PQresultStatus(res) == PGRES_TUPLES_OK;
        if (!ok) fprintf(stderr, "[MAIN] notify failed: %s\n", PQerrorMessage(conn));
        else fprintf(stderr, "[MAIN] sent %s; daemon will apply profile\n", payload);
        PQclear(res);
        PQfinish(conn);
        return ok ? 0 : 1;
    }
    PQfinish(conn);

    rc = daemon_setup_core(&runtime);
    if (rc != 0) {
        daemon_cleanup(&runtime);
        return 1;
    }

    rc = daemon_run(&runtime);

    daemon_cleanup(&runtime);

    return rc == 0 ? 0 : 1;
}
