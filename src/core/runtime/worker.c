#include "../../../inc/core/runtime/worker.h"

#include <errno.h>

int core_worker_start_all()
{

}

void core_worker_stop_all()
{
    
}

int core_worker_pin_cpu()
{

}

int core_worker_rx_submit()
{
    /* Khung nối RX, chưa truyền packet/slot:
     * ne_fill_slot() -> ne_recv_slot() -> ne_ring_try_push().
     * LAN RX và WAN RX cùng dùng đường này, khác ring đích.
     */
}

int core_worker_crypto_step()
{
    /* Khung nối core RX -> xử lý -> core TX:
     * ne_ring_try_pop() -> core_lan_process() / core_wan_process()
     *                   -> ne_ring_try_push().
     * LAN chọn TCP/UDP/PING/OSPF sau match OUT.
     * WAN chọn bằng fake EtherType, giải mã rồi match IN.
     */
}

int core_worker_tx_step()
{
    /* Khung nối TX:
     * ne_ring_try_pop() -> ne_tx_drain_all() -> ne_cq_drain_slot()
     *                   -> ne_frame_free().
     */
}
