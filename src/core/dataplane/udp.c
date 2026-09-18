#include "../../../inc/core/dataplane/udp.h"
#include "../../../inc/core/crypto/crypto.h"

int core_udp_handle_lan_wan()
{
    core_udp_fragment();
    core_udp_encrypt();
    core_udp_per_flow();
    core_udp_per_packet();
}

int core_udp_handle_wan_lan()
{
    core_udp_decrypt();
    core_udp_reassemble();
    core_udp_reorder();
}

int core_udp_fragment()
{
    
}

int core_udp_reassemble()
{
    
}

int core_udp_encrypt()
{
    
}

int core_udp_decrypt()
{

}

int core_udp_per_flow()
{
    
}

int core_udp_per_packet()
{
    
}

int core_udp_reorder()
{
    
}
