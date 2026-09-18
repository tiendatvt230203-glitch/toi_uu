#include "../../../inc/core/dataplane/ping.h"
#include "../../../inc/core/crypto/crypto.h"

int core_ping_handle_lan_wan()
{
    core_ping_fragment();
    core_ping_encrypt();
    core_ping_per_flow();
}

int core_ping_handle_wan_lan()
{
    core_ping_reassemble();
    core_ping_decrypt();
}

int core_ping_fragment()
{
    
}

int core_ping_reassemble()
{
   
}

int core_ping_encrypt()
{
    
}

int core_ping_decrypt()
{
    
}

int core_ping_per_flow()
{
    
}
