#ifndef UBLKDRV_UAPI_CMD_H
#define UBLKDRV_UAPI_CMD_H

#include <linux/types.h>

enum ublkdrv_cmd_op {
	UBLKDRV_CMD_OP_READ = 0b000,
	UBLKDRV_CMD_OP_WRITE = 0b001,
	UBLKDRV_CMD_OP_FLUSH = 0b010,
	UBLKDRV_CMD_OP_DISCARD = 0b011,
	UBLKDRV_CMD_OP_WRITE_ZEROES = 0b100,
	//
	UBLKDRV_CMD_OP_MAX = UBLKDRV_CMD_OP_WRITE_ZEROES,
};

#define UBLKDRV_CMD_OP_SHIFT 0
#define UBLKDRV_CMD_OP_BITS 3
#define UBLKDRV_CMD_OP_MASK ((1u << UBLKDRV_CMD_OP_BITS) - 1)

#define UBLKDRV_CMD_FL_SHIFT UBLKDRV_CMD_OP_BITS
#define UBLKDRV_CMD_FL_MASK ~(UBLKDRV_CMD_OP_MASK)
#define UBLKDRV_CMD_FL_BITS (8 - UBLKDRV_CMD_OP_BITS)

struct ublkdrv_cmd_read {
	__u64 offset;
	__u32 fcdn;
	__u16 cds_nr;
};

struct ublkdrv_cmd_write {
	__u64 offset;
	__u32 fcdn;
	__u16 cds_nr;
};

struct ublkdrv_cmd_flush {};

struct ublkdrv_cmd_discard {
	__u64 offset;
	__u32 sz;
};

struct ublkdrv_cmd_write_zeros {
	__u64 offset;
	__u32 sz;
};

struct ublkdrv_cmd {
	__u8 id;
	__u8 opfl;
	union {
		struct ublkdrv_cmd_read r;
		struct ublkdrv_cmd_write w;
		struct ublkdrv_cmd_flush f;
		struct ublkdrv_cmd_discard d;
		struct ublkdrv_cmd_write_zeros wz;
	} u;
};

static inline __u8 ublkdrv_cmd_get_id(struct ublkdrv_cmd const *pcmd)
{
	return pcmd->id;
}
static inline void ublkdrv_cmd_set_id(struct ublkdrv_cmd *pcmd, __u8 v)
{
	pcmd->id = v;
}

static inline __u32 ublkdrv_cmd_get_op(struct ublkdrv_cmd const *pcmd)
{
	return (pcmd->opfl & UBLKDRV_CMD_OP_MASK) >> UBLKDRV_CMD_OP_SHIFT;
}

static inline void ublkdrv_cmd_set_op(struct ublkdrv_cmd *pcmd, __u32 op)
{
	pcmd->opfl &= ~UBLKDRV_CMD_OP_MASK;
	pcmd->opfl |= ((op & UBLKDRV_CMD_OP_MASK) << UBLKDRV_CMD_OP_SHIFT);
}

static inline __u32 ublkdrv_cmd_get_fl(struct ublkdrv_cmd const *pcmd)
{
	return (pcmd->opfl & UBLKDRV_CMD_FL_MASK) >> UBLKDRV_CMD_FL_SHIFT;
}

static inline void ublkdrv_cmd_set_fl(struct ublkdrv_cmd *pcmd, __u32 fl)
{
	pcmd->opfl &= ~UBLKDRV_CMD_FL_MASK;
	pcmd->opfl |= (fl << UBLKDRV_CMD_FL_SHIFT);
}

static inline __u16
ublkdrv_cmd_read_get_cds_nr(struct ublkdrv_cmd_read const *pcmd)
{
	return pcmd->cds_nr;
}
static inline void ublkdrv_cmd_read_set_cds_nr(struct ublkdrv_cmd_read *pcmd,
					       __u16 v)
{
	pcmd->cds_nr = v;
}

static inline __u32
ublkdrv_cmd_read_get_fcdn(struct ublkdrv_cmd_read const *pcmd)
{
	return pcmd->fcdn;
}
static inline void ublkdrv_cmd_read_set_fcdn(struct ublkdrv_cmd_read *pcmd,
					     __u32 v)
{
	pcmd->fcdn = v;
}

static inline __u64
ublkdrv_cmd_read_get_offset(struct ublkdrv_cmd_read const *pcmd)
{
	return pcmd->offset;
}
static inline void ublkdrv_cmd_read_set_offset(struct ublkdrv_cmd_read *pcmd,
					       __u64 off)
{
	pcmd->offset = off;
}

static inline __u16
ublkdrv_cmd_write_get_cds_nr(struct ublkdrv_cmd_write const *pcmd)
{
	return pcmd->cds_nr;
}
static inline void ublkdrv_cmd_write_set_cds_nr(struct ublkdrv_cmd_write *pcmd,
						__u16 v)
{
	pcmd->cds_nr = v;
}

static inline __u32
ublkdrv_cmd_write_get_fcdn(struct ublkdrv_cmd_write const *pcmd)
{
	return pcmd->fcdn;
}
static inline void ublkdrv_cmd_write_set_fcdn(struct ublkdrv_cmd_write *pcmd,
					      __u32 v)
{
	pcmd->fcdn = v;
}

static inline __u64
ublkdrv_cmd_write_get_offset(struct ublkdrv_cmd_write const *pcmd)
{
	return pcmd->offset;
}
static inline void ublkdrv_cmd_write_set_offset(struct ublkdrv_cmd_write *pcmd,
						__u64 off)
{
	pcmd->offset = off;
}

static inline __u32
ublkdrv_cmd_discard_get_offset(struct ublkdrv_cmd_discard const *pcmd)
{
	return pcmd->offset;
}
static inline void
ublkdrv_cmd_discard_set_offset(struct ublkdrv_cmd_discard *pcmd, __u64 off)
{
	pcmd->offset = off;
}

static inline __u32
ublkdrv_cmd_discard_get_sz(struct ublkdrv_cmd_discard const *pcmd)
{
	return pcmd->sz;
}
static inline void ublkdrv_cmd_discard_set_sz(struct ublkdrv_cmd_discard *pcmd,
					      __u32 sz)
{
	pcmd->sz = sz;
}

static inline __u32
ublkdrv_cmd_write_zeros_get_sz(struct ublkdrv_cmd_write_zeros const *pcmd)
{
	return pcmd->sz;
}
static inline void
ublkdrv_cmd_write_zeros_set_sz(struct ublkdrv_cmd_write_zeros *pcmd, __u32 sz)
{
	pcmd->sz = sz;
}

static inline __u32
ublkdrv_cmd_write_zeros_get_offset(struct ublkdrv_cmd_write_zeros const *pcmd)
{
	return pcmd->offset;
}
static inline void
ublkdrv_cmd_write_zeros_set_offset(struct ublkdrv_cmd_write_zeros *pcmd,
				   __u64 off)
{
	pcmd->offset = off;
}

#endif /* UBLKDRV_UAPI_CMD_H */
