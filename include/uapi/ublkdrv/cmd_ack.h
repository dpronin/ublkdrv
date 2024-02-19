#ifndef UBLKDRV_UAPI_CMD_ACK_H
#define UBLKDRV_UAPI_CMD_ACK_H

#include <linux/types.h>

struct ublkdrv_cmd_ack {
    __u8 id;
    __u8 err;
};

static inline __u8 ublkdrv_cmd_ack_get_id(struct ublkdrv_cmd_ack const* pcmd) { return pcmd->id; }
static inline void ublkdrv_cmd_ack_set_id(struct ublkdrv_cmd_ack* pcmd, __u8 v) { pcmd->id = v; }

static inline __u8 ublkdrv_cmd_ack_get_err(struct ublkdrv_cmd_ack const* pcmd) { return pcmd->err; }
static inline void ublkdrv_cmd_ack_set_err(struct ublkdrv_cmd_ack* pcmd, __u8 v) { pcmd->err = v; }

#endif /* UBLKDRV_UAPI_CMD_ACK_H */
