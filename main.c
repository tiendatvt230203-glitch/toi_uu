#include "core/runtime/runtime.h"

static int handle_cli_command(int argc, char **argv)
{

}

static int daemon_connect_vault(void)
{

}

static int daemon_load_db_account(void)
{

}

static int daemon_login_db(void)
{

}

static int daemon_load_profile_id(int *profile_id)
{

}

static int daemon_setup_core_once(struct core_runtime *runtime,
                                  int profile_id)
{

}

static int daemon_run(struct core_runtime *runtime)
{

}

static void daemon_cleanup(struct core_runtime *runtime)
{

}

int main(int argc, char **argv)
{
    struct core_runtime runtime = {0};
    int profile_id = 0;
    int rc;

    rc = handle_cli_command(argc, argv);
    if (rc != 0)
        return rc;

    rc = daemon_connect_vault();
    if (rc != 0)
        return rc;

    rc = daemon_load_db_account();
    if (rc != 0)
        return rc;

    rc = daemon_login_db();
    if (rc != 0)
        return rc;

    rc = daemon_load_profile_id(&profile_id);
    if (rc != 0)
        return rc;

    rc = daemon_setup_core_once(&runtime, profile_id);
    if (rc != 0)
        return rc;

    rc = daemon_run(&runtime);
    daemon_cleanup(&runtime);
    return rc;
}
