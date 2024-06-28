#ifndef UBLKDRV_UAPI_CMDB_TEMPLATE_H
#define UBLKDRV_UAPI_CMDB_TEMPLATE_H

#include <linux/types.h>

#define UBLKDRV_CMDB_DECLARE(cmdb_struct_name, cmd_type)      \
	struct cmdb_struct_name {                             \
		__u8 cmds_len;                                \
		__u8 tail __attribute__((aligned(64)));       \
		cmd_type cmds[] __attribute__((aligned(64))); \
	}

#endif /* UBLKDRV_UAPI_CMDB_TEMPLATE_H */
