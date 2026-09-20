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

int core_worker_select_encrypt_core()
{
    /* LAN -> WAN: hash 5-tuple de chon crypto worker. */
    return -ENOSYS;
}

int core_worker_select_decrypt_core()
{
    /* WAN -> LAN: core ID tren goi tin chon crypto worker giai ma. */
    return -ENOSYS;
}

int core_worker_rx_submit()
{
    /* Khung nối RX, chưa truyền packet/slot:
     * ne_fill_slot() -> ne_recv_slot()
     * LAN: core_worker_select_encrypt_core() -> local_to_crypto[worker].
     * WAN: core_worker_select_decrypt_core() -> wan_to_crypto[worker].
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
