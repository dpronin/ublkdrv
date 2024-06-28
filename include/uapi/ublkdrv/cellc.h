#ifndef UBLKDRV_UAPI_CELLC_H
#define UBLKDRV_UAPI_CELLC_H

#include <linux/types.h>

#include "celld.h"

struct ublkdrv_cellc {
	__u32 cellds_len;
	__u8 cmdb_head __attribute__((aligned(64)));
	__u8 cmdb_ack_head __attribute__((aligned(64)));
	struct ublkdrv_celld cellds[] __attribute__((aligned(64)));
};

#endif /* UBLKDRV_UAPI_CELLC_H */
