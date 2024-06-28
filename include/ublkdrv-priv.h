#ifndef UBLKDRV_PRIV_H
#define UBLKDRV_PRIV_H

#include <linux/workqueue.h>

void ublkdrv_req_copy_work_h(struct work_struct *work);
void ublkdrv_req_finish_work_h(struct work_struct *work);

#endif /* UBLKDRV_PRIV_H */
