#include "../../../inc/core/dataplane/ospf.h"
#include "../../../inc/core/crypto/crypto.h"

int core_ospf_handle_lan_wan()
{
    core_ospf_encrypt();
}

int core_ospf_handle_wan_lan()
{
    core_ospf_decrypt();
}

int core_ospf_fragment()
{
}

int core_ospf_reassemble()
{
}

int core_ospf_encrypt()
{
}

int core_ospf_decrypt()
{
}

int core_ospf_per_flow()
{
}
