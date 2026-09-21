#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../inc/core/core_types.h"

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, int);
    __type(value, int);
} wan_xsks_map SEC(".maps");

SEC("xdp")
int xdp_wan_redirect_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 proto = eth->h_proto;

    /* CFM failover — luôn vào kernel stack cho AF_PACKET raw socket. */
    if (proto == bpf_htons(ETH_P_CFM))
        return XDP_PASS;

    /* ARP is temporarily owned by the kernel, not this dataplane. */
    if (proto == bpf_htons(ETH_P_ARP) ||
        proto == bpf_htons(ETH_P_NE_ARP_ENC))
        return XDP_PASS;

    if (proto == bpf_htons(0x0800)) {
        struct iphdr *ip = (void *)(eth + 1);

        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        if (ip->protocol == IPPROTO_TCP_VAL ||
            ip->protocol == IPPROTO_UDP_VAL ||
            ip->protocol == IPPROTO_ICMP_VAL ||
            ip->protocol == IPPROTO_OSPF_VAL)
            goto redirect;
        return XDP_PASS;
    }

    if (proto == bpf_htons(NE_L2_TCP_ETHERTYPE) ||
        proto == bpf_htons(NE_L2_UDP_ETHERTYPE) ||
        proto == bpf_htons(NE_L2_PING_ETHERTYPE) ||
        proto == bpf_htons(NE_L2_OSPF_ETHERTYPE)) {
        goto redirect;
    }

    return XDP_PASS;

redirect:
    ;
    __u32 qid = ctx->rx_queue_index;
    return bpf_redirect_map(&wan_xsks_map, qid, 0);
}

char _license[] SEC("license") = "GPL";
