#ifndef UBLKDRV_H
#define UBLKDRV_H

#include <linux/types.h>

#include "ublkdrv-dev.h"

struct ublkdrv_dev *ublkdrv_dev_create(char const *disk_name,
				       u64 capacity_sectors, bool read_only,
				       int nid);
void ublkdrv_dev_destroy(struct ublkdrv_dev *ubd);

#endif /* UBLKDRV_H */
