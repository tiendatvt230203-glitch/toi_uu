#ifndef CORE_XDP_H
#define CORE_XDP_H
int core_xdp_attach(const char *ifname);
void core_xdp_detach(const char *ifname);
#endif
