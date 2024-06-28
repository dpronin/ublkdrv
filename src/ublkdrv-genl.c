#include "ublkdrv-genl.h"

#include <linux/blkdev.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/skbuff.h>
#include <linux/topology.h>

#include <net/genetlink.h>
#include <net/netlink.h>

#include "uapi/ublkdrv/def.h"
#include "uapi/ublkdrv/genl.h"

#include "ublkdrv.h"

#define UBLKDRV_GENL_VERSION 0x01

#define UBLKDRV_DEVICES_MAX 4

static struct ublkdrv_dev *devices[UBLKDRV_DEVICES_MAX];
static int devs_nr;

static const struct nla_policy nl_policy[UBLKDRV_GENL_BDEV_ATTRS_QTY] = {
	[UBLKDRV_GENL_BDEV_ATTR_NAME_SUFFIX] = { .type = NLA_STRING,
						 .len = DISK_NAME_LEN -
							strlen(UBLKDRV_PREFIX) },
	[UBLKDRV_GENL_BDEV_ATTR_NODE] = { .type = NLA_U32 },
	[UBLKDRV_GENL_BDEV_ATTR_CAPACITY_SECTORS] = { .type = NLA_U64 },
	[UBLKDRV_GENL_BDEV_ATTR_READ_ONLY] = { .type = NLA_FLAG },
};

static int ublkdrv_genl_bdev_cmd_create(struct sk_buff *skb,
					struct genl_info *info);
static int ublkdrv_genl_bdev_cmd_destroy(struct sk_buff *skb,
					 struct genl_info *info);

static const struct genl_small_ops ublkdrv_genl_ops[] = {
	{
		.cmd = UBLKDRV_GENL_BDEV_CMD_CREATE,
		.doit = ublkdrv_genl_bdev_cmd_create,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
	},
	{
		.cmd = UBLKDRV_GENL_BDEV_CMD_DESTROY,
		.doit = ublkdrv_genl_bdev_cmd_destroy,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
	},
};

static struct genl_family nl_genl_family __ro_after_init = {
	.module = THIS_MODULE,
	.hdrsize = 0,
	.name = UBLKDRV_GENL_NAME,
	.version = UBLKDRV_GENL_VERSION,
	.small_ops = ublkdrv_genl_ops,
	.n_small_ops = ARRAY_SIZE(ublkdrv_genl_ops),
	.parallel_ops = false,
	.resv_start_op = UBLKDRV_GENL_BDEV_CMDS_QTY,
	.policy = nl_policy,
	.netnsok = true,
	.maxattr = UBLKDRV_GENL_BDEV_ATTRS_QTY - 1,
};

static int ublkdrv_genl_bdev_cmd_create(struct sk_buff *skb,
					struct genl_info *info)
{
	char disk_name[DISK_NAME_LEN] = UBLKDRV_PREFIX;
	int nid = numa_mem_id();
	bool read_only = false;
	u64 capacity;

	if (!(devs_nr < UBLKDRV_DEVICES_MAX))
		return -ENOSPC;

	if (!info->attrs[UBLKDRV_GENL_BDEV_ATTR_NAME_SUFFIX])
		return -EINVAL;

	if (!info->attrs[UBLKDRV_GENL_BDEV_ATTR_CAPACITY_SECTORS])
		return -EINVAL;

	if (info->attrs[UBLKDRV_GENL_BDEV_ATTR_NODE])
		nid = nla_get_u32(info->attrs[UBLKDRV_GENL_BDEV_ATTR_NODE]);

	if (info->attrs[UBLKDRV_GENL_BDEV_ATTR_READ_ONLY])
		read_only = nla_get_flag(
			info->attrs[UBLKDRV_GENL_BDEV_ATTR_READ_ONLY]);

	nla_strscpy(disk_name + strlen(UBLKDRV_PREFIX),
		    info->attrs[UBLKDRV_GENL_BDEV_ATTR_NAME_SUFFIX],
		    DISK_NAME_LEN - strlen(UBLKDRV_PREFIX));
	capacity = nla_get_u64(
		info->attrs[UBLKDRV_GENL_BDEV_ATTR_CAPACITY_SECTORS]);

	devices[devs_nr] =
		ublkdrv_dev_create(disk_name, capacity, read_only, nid);
	if (IS_ERR_OR_NULL(devices[devs_nr]))
		return devices[devs_nr] ? PTR_ERR(devices[devs_nr]) : -ENOMEM;

	pr_info("bdev %s (disk %s) registered\n", devices[devs_nr]->name,
		devices[devs_nr]->disk->disk_name);

	++devs_nr;

	return 0;
}

static int ublkdrv_genl_bdev_cmd_destroy(struct sk_buff *skb,
					 struct genl_info *info)
{
	int i;

	char disk_name[DISK_NAME_LEN] = UBLKDRV_PREFIX;

	if (!devs_nr)
		return 0;

	if (!info->attrs[UBLKDRV_GENL_BDEV_ATTR_NAME_SUFFIX])
		return -EINVAL;

	nla_strscpy(disk_name + strlen(UBLKDRV_PREFIX),
		    info->attrs[UBLKDRV_GENL_BDEV_ATTR_NAME_SUFFIX],
		    DISK_NAME_LEN - strlen(UBLKDRV_PREFIX));

	for (i = 0; i < devs_nr; ++i) {
		struct ublkdrv_dev *ubd = devices[i];
		if (!strncmp(ubd->disk->disk_name, disk_name,
			     sizeof(disk_name))) {
			pr_info("unregister bdev %s (disk %s)\n", ubd->name,
				ubd->disk->disk_name);
			devices[i] = devices[--devs_nr];
			devices[devs_nr] = NULL;
			ublkdrv_dev_destroy(ubd);
			break;
		}
	}

	return 0;
}

int ublkdrv_genl_init(void)
{
	return genl_register_family(&nl_genl_family);
}

void ublkdrv_genl_deinit(void)
{
	while (devs_nr--) {
		struct ublkdrv_dev *ubd = devices[devs_nr];
		pr_info("unregister bdev %s (disk %s)\n", ubd->name,
			ubd->disk->disk_name);
		devices[devs_nr] = NULL;
		ublkdrv_dev_destroy(ubd);
	}
	genl_unregister_family(&nl_genl_family);
}
