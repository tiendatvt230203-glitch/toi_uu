#include "../../../inc/core/dataplane/tcp.h"
#include "../../../inc/core/crypto/crypto.h"

int core_tcp_handle_lan_wan()
{
    core_tcp_clamp_mss();
    core_tcp_encrypt();
    core_tcp_per_flow();
    core_tcp_per_packet();
}
int core_tcp_handle_wan_lan()
{
    core_tcp_decrypt();
    core_tcp_retry();
}

int core_tcp_clamp_mss()
{
    
}

int core_tcp_encrypt()
{
    
}

int core_tcp_decrypt()
{
    
}

int core_tcp_per_flow()
{
    
}

int core_tcp_per_packet()
{
    
}

int core_tcp_retry()
{
    
}
