#include "../../../inc/core/dataplane/tx.h"

int core_tx_match_in()
{
    /* Chưa có bộ lọc: chặn chiều IN thay vì cho qua ngẫu nhiên. */
    return 0;
}

int core_tx_match_out()
{
    return 0;
}
