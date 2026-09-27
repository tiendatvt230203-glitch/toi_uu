#include "../../../inc/interface/xdp.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <errno.h>
extern struct bpf_program *bpf_object__next_program(
    const struct bpf_object *obj, struct bpf_program *prog);
extern int bpf_program__set_flags(struct bpf_program *prog, __u32 flags);
extern int bpf_xdp_query_id(int ifindex, int flags, __u32 *prog_id);



int core_xdp_attach(struct ne_pair *p)
{
    struct app_config *cfg = p->config;
    for (int wan = 0; wan < 2; wan++) {
        const char *path = wan ? cfg->bpf_wan_file : cfg->bpf_lan_file;
        const char *name = wan ? cfg->wans[0].ifname : cfg->locals[0].ifname;
        struct ne_xsk_queue *queues = wan ? cfg->wans[0].queues : cfg->locals[0].queues;
        int count = wan ? p->wan_queue_total : p->local_queue_total;
        struct bpf_object *obj = bpf_object__open_file(
            *path ? path : (wan ? "lib/wan.o" : "lib/lan.o"), NULL);
        int rc = (int)libbpf_get_error(obj);
        if (rc) { core_xdp_detach(p); return rc; }
        if (wan) p->bpf_wans[0] = obj;
        else p->bpf_locals[0] = obj;
        struct bpf_program *prog = bpf_object__next_program(obj, NULL);
        if (!prog) {
            core_xdp_detach(p);
            return -EOPNOTSUPP;
        }
        bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);
        rc = bpf_program__set_flags(prog, 1u << 5);
        if (!rc) rc = bpf_object__load(obj);
        if (rc) { core_xdp_detach(p); return rc; }
        int map = bpf_object__find_map_fd_by_name(obj, wan ? "wan_xsks_map" : "xsks_map");
        if (map < 0) { core_xdp_detach(p); return map; }
        for (int q = 0; q < count; q++) {
            int fd = xsk_socket__fd(queues[q].xsk);
            if (bpf_map_update_elem(map, &q, &fd, BPF_ANY)) {
                rc = -errno; core_xdp_detach(p); return rc;
            }
        }
        int ifindex = if_nametoindex(name);
        rc = bpf_xdp_attach(ifindex, bpf_program__fd(prog),
                                XDP_FLAGS_DRV_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
        if (rc) { core_xdp_detach(p); return rc; }
        if (wan) { cfg->wans[0].ifindex = ifindex; p->xdp_wan_on[0] = 1; }
        else { cfg->locals[0].ifindex = ifindex; p->xdp_local_on[0] = 1; }
    }
    return 0;
}

void core_xdp_detach(struct ne_pair *p)
{
    for (int wan = 0; wan < 2; wan++) {
        struct bpf_object *obj = wan ? p->bpf_wans[0] : p->bpf_locals[0];
        if (!obj) continue;
        int attached = wan ? p->xdp_wan_on[0] : p->xdp_local_on[0];
        int ifindex = wan ? p->config->wans[0].ifindex : p->config->locals[0].ifindex;
        struct bpf_prog_info info = {0};
        __u32 size = sizeof(info), current = 0;
        struct bpf_program *prog = bpf_object__next_program(obj, NULL);
        if (attached && prog &&
            !bpf_obj_get_info_by_fd(bpf_program__fd(prog), &info, &size) &&
            !bpf_xdp_query_id(ifindex, XDP_FLAGS_DRV_MODE, &current) &&
            current == info.id)
            bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
        bpf_object__close(obj);
        if (wan) { p->bpf_wans[0] = NULL; p->xdp_wan_on[0] = 0; }
        else { p->bpf_locals[0] = NULL; p->xdp_local_on[0] = 0; }
    }
}
