#ifndef UBLKDRV_PRIV_H
#define UBLKDRV_PRIV_H

#include <linux/workqueue.h>
#include <linux/blk_types.h>

#define KiB_SHIFT 10
#define MiB_SHIFT 20
#define GiB_SHIFT 30

static inline u32 ublkdrv_sectors_to_bytes(u32 sectors)
{
	return sectors << SECTOR_SHIFT;
}

void ublkdrv_req_copy_work_h(struct work_struct *work);
void ublkdrv_req_finish_work_h(struct work_struct *work);

#endif /* UBLKDRV_PRIV_H */
