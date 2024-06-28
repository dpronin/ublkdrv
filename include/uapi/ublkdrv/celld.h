#ifndef UBLKDRV_UAPI_CELLD_H
#define UBLKDRV_UAPI_CELLD_H

#include <linux/types.h>

struct ublkdrv_celld {
	__u32 offset;
	__u32 data_sz;
	__u32 ncelld;
};

#endif /* UBLKDRV_UAPI_CELLD_H */
