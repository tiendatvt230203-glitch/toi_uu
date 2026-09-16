#include "core/dataplane/tcp_bond_reorder.h"
#include "core/dataplane/udp_reorder.h"
#include <stdio.h>

static unsigned udp_next[512], udp_count, udp_drops;
static unsigned tcp_next[2] = {1, 1}, tcp_count[2], tcp_drops;

static int udp_emit(void *ctx, struct dp_udp_reorder_item *item)
{
    unsigned flow = (unsigned)item->packet.addr;
    (void)ctx;
    if (flow >= 512 || item->packet.len != udp_next[flow]++)
        return -1;
    udp_count++;
    return 0;
}

static void udp_drop(void *ctx, struct dp_udp_reorder_item *item)
{ (void)ctx; (void)item; udp_drops++; }

static int tcp_emit(void *ctx, struct dp_tcp_bond_item *item)
{
    unsigned worker = (unsigned)item->packet.addr;
    (void)ctx;
    if (worker >= 2 || item->packet.len != tcp_next[worker]++)
        return -1;
    tcp_count[worker]++;
    return 0;
}

static void tcp_drop(void *ctx, struct dp_tcp_bond_item *item)
{ (void)ctx; (void)item; tcp_drops++; }

static void send_udp(unsigned flow, unsigned seq, uint64_t now,
                     const struct dp_udp_reorder_ops *ops)
{
    struct dp_udp_reorder_key key = {
        .src_ip = flow + 1u, .dst_ip = 2u,
        .src_port = (uint16_t)(1000u + flow), .dst_port = 9000u,
    };
    struct dp_udp_reorder_item item = {0};
    item.packet.addr = flow;
    item.packet.len = seq;
    dp_udp_reorder_submit(0, &key, 77u, seq, &item, now, ops);
}

static void send_tcp(unsigned worker, unsigned seq, uint64_t now,
                     const struct dp_tcp_bond_ops *ops)
{
    struct dp_tcp_bond_item item = {0};
    item.packet.addr = worker;
    item.packet.len = seq;
    dp_tcp_bond_reorder_submit(8, (int)worker, 321u, seq, &item, now, ops);
}

int main(void)
{
    const uint64_t start = 1000000000ULL;
    const struct dp_udp_reorder_ops uops = {.emit = udp_emit, .drop = udp_drop};
    const struct dp_tcp_bond_ops tops = {.emit = tcp_emit, .drop = tcp_drop};

    dp_udp_reorder_configure_from_env();
    dp_tcp_bond_reorder_configure_from_env();
    for (unsigned flow = 0; flow < 512; flow++) {
        send_udp(flow, 0, start, &uops);
        send_udp(flow, 2, start, &uops);
    }
    for (unsigned flow = 0; flow < 512; flow++)
        send_udp(flow, 1, start + 900000ULL, &uops);
    if (udp_count != 1536u || udp_drops)
        return 1;
    send_tcp(0, 2, start, &tops);
    send_tcp(1, 1, start, &tops);
    if (tcp_count[0] != 0 || tcp_count[1] != 1)
        return 2;
    send_tcp(0, 1, start + 900000ULL, &tops);
    if (tcp_count[0] != 2 || tcp_drops)
        return 3;
    dp_udp_reorder_reset_worker(0, &uops);
    dp_tcp_bond_reorder_reset(0, &tops);
    dp_tcp_bond_reorder_reset(1, &tops);
    puts("UDP 512 flows at 0.9ms; TCP worker isolation: ok");
    return 0;
}
