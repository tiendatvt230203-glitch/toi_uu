#include "../../../inc/runtime/runtime.h"
#include "../../../inc/runtime/worker.h"
#include "../../../inc/interface/interface.h"
#include "../../../inc/profile/profile_load.h"
#include "../../../inc/crypto/key_manager.h"
#include "db_env.h"

#include <errno.h>
#include <limits.h>
#include <libpq-fe.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile sig_atomic_t g_shutdown;

static void runtime_signal(int signal_number)
{
    (void)signal_number;
    g_shutdown = 1;
}

int core_runtime_init(struct core_runtime *runtime)
{
    if (!runtime) return -EINVAL;
    if (runtime->initialized) return 0;
    memset(runtime, 0, sizeof(*runtime));
    int rc = pthread_rwlock_init(&runtime->config_lock, NULL);
    if (rc) return -rc;
    atomic_init(&runtime->stop_requested, 0);
    runtime->initialized = 1;
    g_shutdown = 0;
    return 0;
}

int core_runtime_run(struct core_runtime *runtime)
{
    if (!runtime || !runtime->initialized) return -EINVAL;
    struct sigaction action = {0}, old_int, old_term;
    action.sa_handler = runtime_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, &old_int)) return -errno;
    if (sigaction(SIGTERM, &action, &old_term)) {
        int rc = -errno;
        sigaction(SIGINT, &old_int, NULL);
        return rc;
    }
    PGconn *conn = NULL;
    int rc = 0;
    while (!g_shutdown) {
        if (!conn) {
            struct ne_postgres_conn pg;
            if (ne_postgres_conn_fill(&pg)) { rc = -EINVAL; break; }
            conn = PQconnectdbParams(pg.keywords, pg.values, 0);
            if (!conn || PQstatus(conn) != CONNECTION_OK) {
                if (conn) PQfinish(conn);
                conn = NULL;
                poll(NULL, 0, 1000);
                continue;
            }
            PGresult *result = PQexec(conn, "LISTEN xdp_start");
            int ok = result && PQresultStatus(result) == PGRES_COMMAND_OK;
            PQclear(result);
            if (!ok) {
                PQfinish(conn);
                conn = NULL;
                poll(NULL, 0, 1000);
                continue;
            }
            fprintf(stderr, "[DAEMON] waiting for profile: ./network-encryptor -id <ID>\n");
        }
        struct pollfd fd = { .fd = PQsocket(conn), .events = POLLIN };
        int ready = poll(&fd, 1, 500);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0 || (fd.revents & (POLLERR | POLLHUP | POLLNVAL)) ||
            (ready > 0 && !PQconsumeInput(conn))) {
            PQfinish(conn);
            conn = NULL;
            continue;
        }
        PGnotify *event;
        while (!g_shutdown && (event = PQnotifies(conn))) {
            const char *payload = event->extra;
            int remove_profile = !strncmp(payload, "del:", 4);
            if (remove_profile) payload += 4;
            else if (!strncmp(payload, "load:", 5)) payload += 5;
            char *end;
            errno = 0;
            long id = strtol(payload, &end, 10);
            if (errno || end == payload || *end || id <= 0 || id > INT_MAX) {
                fprintf(stderr, "[PROFILE] invalid event ignored\n");
            } else if (remove_profile) {
                if (runtime->config.profile_id == id) {
                    core_profile_unload(runtime);
                    fprintf(stderr, "[PROFILE] removed %ld; waiting for next profile\n", id);
                }
            } else {
                int apply = core_profile_load(runtime, (int)id);
                if (apply) fprintf(stderr, "[PROFILE] load/edit %ld failed: %d\n", id, apply);
            }
            PQfreemem(event);
        }
    }
    if (conn) PQfinish(conn);
    core_worker_stop_all(runtime);
    sigaction(SIGINT, &old_int, NULL);
    sigaction(SIGTERM, &old_term, NULL);
    return rc;
}

void core_runtime_stop(struct core_runtime *runtime)
{
    if (!runtime || !runtime->initialized) return;
    g_shutdown = 1;
    atomic_store_explicit(&runtime->stop_requested, 1, memory_order_release);
}

void core_runtime_cleanup(struct core_runtime *runtime)
{
    if (!runtime || !runtime->initialized) return;
    core_runtime_stop(runtime);
    core_worker_stop_all(runtime);
    ne_pair_close(&runtime->pair, &runtime->config);
    for (int id = 1; id < 256; id++) core_key_remove(id);
    pthread_rwlock_destroy(&runtime->config_lock);
    memset(runtime, 0, sizeof(*runtime));
}
