#ifndef CORE_XDP_H
#define CORE_XDP_H
#include "../core_types.h"
int core_xdp_attach(struct ne_pair *p);
void core_xdp_detach(struct ne_pair *p);
#endif
