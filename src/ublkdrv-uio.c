#include "ublkdrv-uio.h"

#include <asm/barrier.h>

#include <linux/bio.h>
#include <linux/bitops.h>
#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/compiler.h>
#include <linux/container_of.h>
#include <linux/gfp_types.h>
#include <linux/kernel.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "uapi/ublkdrv/cellc.h"
#include "uapi/ublkdrv/celld.h"
#include "uapi/ublkdrv/cmd.h"
#include "uapi/ublkdrv/cmd_ack.h"
#include "uapi/ublkdrv/cmdb.h"
#include "uapi/ublkdrv/cmdb_ack.h"
#include "uapi/ublkdrv/mapping.h"

#include "ublkdrv-cfq.h"
#include "ublkdrv-dev.h"
#include "ublkdrv-ku-gate.h"
#include "ublkdrv-mapping.h"
#include "ublkdrv-priv.h"
#include "ublkdrv-req.h"
#include "ublkdrv-uk-gate.h"

static void ublkdrv_uio_vma_open(struct vm_area_struct* vma);
static void ublkdrv_uio_vma_close(struct vm_area_struct* vma);
static vm_fault_t ublkdrv_uio_vma_fault(struct vm_fault* vmf);

static const struct vm_operations_struct ublkdrv_vm_ops = {
    .open  = ublkdrv_uio_vma_open,
    .close = ublkdrv_uio_vma_close,
    .fault = ublkdrv_uio_vma_fault,
};

struct ublkdrv_cmd_complete_work {
    struct work_struct work;
    struct ublkdrv_dev* ubd;
    u32 cmds;
};

static int ublkdrv_uio_open(struct uio_info* uio, struct inode* inode)
{
    pr_debug("uio %s, open()\n", uio->name);
    return 0;
}

static int ublkdrv_uio_release(struct uio_info* uio, struct inode* inode)
{
    pr_debug("uio %s, release()\n", uio->name);
    return 0;
}

static void
ublkdrv_cfq_pop_work_h(struct work_struct* work)
{
    struct ublkdrv_cmd_complete_work* ccw = container_of(work, struct ublkdrv_cmd_complete_work, work);
    struct ublkdrv_dev* ubd               = ccw->ubd;
    struct ublkdrv_ctx* ctx               = ubd->ctx;

    for (u32 cmds = ccw->cmds; cmds--;) {
        struct ublkdrv_cmdb_ack* cmdb_ack;
        struct ublkdrv_cellc* cellc;
        struct ublkdrv_cmd_ack cmd_ack;
        struct ublkdrv_req* req;
        struct ublkdrv_uk_gate* uk_gate;
        u8 cmd_id;

    retry:
        rcu_read_lock();

        uk_gate = rcu_dereference(ubd->uk_gate);
        if (unlikely(!uk_gate)) {
            rcu_read_unlock();
            break;
        }

        cmdb_ack = uk_gate->cmdb_ack;
        cellc    = uk_gate->cellc;

        if (unlikely(!ublkdrv_cfq_ack_pop(cmdb_ack->cmds, cmdb_ack->cmds_len, &cellc->cmdb_ack_head, &cmdb_ack->tail, &cmd_ack))) {
            rcu_read_unlock();
            schedule();
            goto retry;
        }

        req    = NULL;
        cmd_id = ublkdrv_cmd_ack_get_id(&cmd_ack);

        spin_lock(&ctx->ku_state_ctx->lock);

        if (likely(0 == dynamic_bitmap_semaphore_post(ctx->ku_state_ctx->cmds_ids, cmd_id))) {
            BUG_ON(!ctx->ku_state_ctx->reqs_pending[cmd_id]);
            req                                     = ctx->ku_state_ctx->reqs_pending[cmd_id];
            ctx->ku_state_ctx->reqs_pending[cmd_id] = NULL;
        }

        spin_unlock(&ctx->ku_state_ctx->lock);

        rcu_read_unlock();

        if (likely(req)) {
            void (*nwh)(struct work_struct*);
            struct workqueue_struct* nwq;

            req->err = -(int)ublkdrv_cmd_ack_get_err(&cmd_ack);
            if (!req->err && UBLKDRV_CMD_OP_READ == ublkdrv_cmd_get_op(&req->cmd)) {
                nwh = ublkdrv_req_copy_work_h;
                nwq = ubd->wqs[UBLKDRV_COPY_WQ];
            } else {
                nwh = ublkdrv_req_finish_work_h;
                nwq = ubd->wqs[UBLKDRV_FIN_WQ];
            }

            ublkdrv_req_submit(req, nwq, nwh);
        }
    }
}

static int ublkdrv_uio_irq_cmd_handled(struct uio_info* info, s32 irq_on)
{
    struct ublkdrv_uio* uio     = info->priv;
    struct ublkdrv_dev* ubd     = uio->priv;
    struct ublkdrv_ctx* ctx     = ubd->ctx;
    struct ublkdrv_cellc* cellc = ctx->cellc;
    struct ublkdrv_cmdb* cmdb   = ctx->cmdb;

    irq_on %= cmdb->cmds_len;

    if (likely(irq_on)) {
        u8 ph = smp_load_acquire(&cellc->cmdb_head);
        typeof(ph) ph_old;
        do {
            ph_old = ph;
            cpu_relax();
        } while (ph_old != (ph = cmpxchg_relaxed(&cellc->cmdb_head, ph, (ph + irq_on) % cmdb->cmds_len)));
    }

    return 0;
}

static int ublkdrv_uio_irq_cmd_complete(struct uio_info* info, s32 irq_on)
{
    struct ublkdrv_uio* uio = info->priv;
    struct ublkdrv_dev* ubd = uio->priv;

    struct ublkdrv_cmd_complete_work ccw = {
        .ubd  = ubd,
        .cmds = irq_on,
    };

    INIT_WORK_ONSTACK(&ccw.work, ublkdrv_cfq_pop_work_h);
    queue_work(ubd->wqs[UBLKDRV_CFQ_POP_WQ], &ccw.work);
    flush_work(&ccw.work);
    destroy_work_on_stack(&ccw.work);

    return 0;
}

static void ublkdrv_uio_vma_open(struct vm_area_struct* vma)
{
    struct ublkdrv_uio* uio = vma->vm_private_data;
    struct ublkdrv_dev* ubd = uio->priv;
    u32 const mem_id        = vma->vm_pgoff;
    pr_debug("%s: vma_open(), mi %u", ubd->name, mem_id);
    ubd->ops->acquire(ubd);
}

static void ublkdrv_uio_vma_close(struct vm_area_struct* vma)
{
    struct ublkdrv_uio* uio = vma->vm_private_data;
    struct ublkdrv_dev* ubd = uio->priv;
    u32 const mem_id        = vma->vm_pgoff;

    pr_debug("%s: vma_close(), mi %u", ubd->name, mem_id);

    /* clang-format off */
    if (test_and_clear_bit(mem_id, &uio->flags)
        && !smp_load_acquire(&ubd->uios[UBLKDRV_UIO_DIR_KERNEL_TO_USER]->flags)
        && !smp_load_acquire(&ubd->uios[UBLKDRV_UIO_DIR_USER_TO_KERNEL]->flags)) {
        /* clang-format on */

        u32 celldn;
        int i;
        struct ublkdrv_ku_gate* ku_gate;
        struct ublkdrv_uk_gate* uk_gate;

        struct ublkdrv_ctx* ctx = ubd->ctx;

        ku_gate = rcu_replace_pointer(ubd->ku_gate, NULL, true);
        synchronize_rcu();
        kfree(ku_gate);
        flush_workqueue(ubd->wqs[UBLKDRV_CFQ_PUSH_WQ]);

        ctx->cmdb->tail = 0;
        memset(ctx->cmdb->cmds, 0, sizeof(ctx->cmdb->cmds[0]) * ctx->cmdb->cmds_len);
        ctx->cellc->cmdb_head = 0;

        uk_gate = rcu_replace_pointer(ubd->uk_gate, NULL, true);
        synchronize_rcu();
        kfree(uk_gate);
        flush_workqueue(ubd->wqs[UBLKDRV_CFQ_POP_WQ]);

        ctx->cmdb_ack->tail = 0;
        memset(ctx->cmdb_ack->cmds, 0, sizeof(ctx->cmdb_ack->cmds[0]) * ctx->cmdb_ack->cmds_len);
        ctx->cellc->cmdb_ack_head = 0;

        for (i = 0; i < ctx->cmdb->cmds_len - 1; ++i) {
            struct ublkdrv_req* req = ctx->ku_state_ctx->reqs_pending[i];
            if (req) {
                BUG_ON(dynamic_bitmap_semaphore_post(ctx->ku_state_ctx->cmds_ids, i));
                ctx->ku_state_ctx->reqs_pending[i] = NULL;
                req->err                           = -ENOLINK;
                ublkdrv_req_cells_free(req, ctx);
                ublkdrv_req_endio(req, BLK_STS_TRANSPORT);
            }
        }

        for (celldn = 0; celldn < ctx->cellc->cellds_len; ++celldn) {
            struct ublkdrv_celld* celld = &ctx->cellc->cellds[celldn];

            celld->data_sz = 0;
            celld->ncelld  = ctx->cellc->cellds_len;
        }
        memset(ctx->cells, 0, ctx->cells_sz);
    }

    ubd->ops->release(ubd);
}

static vm_fault_t ublkdrv_uio_vma_fault(struct vm_fault* vmf)
{
    unsigned long off;
    void* addr;
    struct page* page;

    struct vm_area_struct* vma = vmf->vma;
    struct ublkdrv_uio* uio    = vma->vm_private_data;
    u32 const mem_id           = vma->vm_pgoff;

    if (unlikely(!(mem_id < uio->mems_len)))
        return VM_FAULT_SIGBUS;

    off  = (vmf->pgoff - mem_id) << PAGE_SHIFT;
    addr = (void*)(u64)uio->uio.mem[mem_id].addr + off;

    if (unlikely(!(off < (u64)uio->uio.mem[mem_id].size)))
        return VM_FAULT_SIGBUS;

    page = uio->uio.mem[mem_id].memtype == UIO_MEM_LOGICAL ? virt_to_page(addr) : vmalloc_to_page(addr);

    get_page(page);
    vmf->page = page;

    return 0;
}

static int ublkdrv_uio_mmap(struct uio_info* info, struct vm_area_struct* vma)
{
    struct ublkdrv_uio* uio = info->priv;
    struct ublkdrv_dev* ubd = uio->priv;

    u32 const mem_id = vma->vm_pgoff;

    vm_flags_t vm_flags = VM_DONTEXPAND;

    pr_debug("%s: uio_mmap(), mi %u", ubd->name, mem_id);

    /* clang-format off */
    if (!(vma->vm_flags & VM_SHARED)
        || (vma->vm_flags & (VM_EXEC | VM_MAYEXEC))
        || mem_id >= uio->mems_len) {

        return -EINVAL;
    }
    /* clang-format on */

    if (uio == ubd->uios[UBLKDRV_UIO_DIR_KERNEL_TO_USER]) {
        switch (mem_id) {
            case UBLKDRV_UIO_MEM_CMDB:
            case UBLKDRV_UIO_MEM_CELLC:
                if (vma->vm_flags & VM_WRITE)
                    return -EINVAL;
                break;
            default:
                break;
        }
    }

    if (test_and_set_bit(mem_id, &uio->flags))
        return -EBUSY;

    if (UBLKDRV_UIO_MEM_CELLS == mem_id)
        vm_flags |= VM_DONTDUMP;

    vm_flags_set(vma, vm_flags);
    vma->vm_ops          = &ublkdrv_vm_ops;
    vma->vm_private_data = uio;

    ublkdrv_uio_vma_open(vma);

    /* clang-format off */
    if (uio == ubd->uios[UBLKDRV_UIO_DIR_KERNEL_TO_USER]
        && UBLKDRV_UIO_MEM_CMDB == mem_id
        && !rcu_access_pointer(ubd->ku_gate)) {
        /* clang-format on */

        struct ublkdrv_ku_gate* ku_gate = kzalloc_node(sizeof(*ku_gate), GFP_KERNEL, ubd->nid);
        BUG_ON(!ku_gate);

        ku_gate->cmdb  = ubd->ctx->cmdb;
        ku_gate->cellc = ubd->ctx->cellc;

        rcu_assign_pointer(ubd->ku_gate, ku_gate);
        synchronize_rcu();
    }

    /* clang-format off */
    if (uio == ubd->uios[UBLKDRV_UIO_DIR_USER_TO_KERNEL]
        && UBLKDRV_UIO_MEM_CMDB == mem_id
        && !rcu_access_pointer(ubd->uk_gate)) {
        /* clang-format on */

        struct ublkdrv_uk_gate* uk_gate = kzalloc_node(sizeof(*uk_gate), GFP_KERNEL, ubd->nid);
        BUG_ON(!uk_gate);

        uk_gate->cmdb_ack = ubd->ctx->cmdb_ack;
        uk_gate->cellc    = ubd->ctx->cellc;

        rcu_assign_pointer(ubd->uk_gate, uk_gate);
        synchronize_rcu();
    }

    return 0;
}

static int ublkdrv_uio_kern_to_user_register(struct ublkdrv_dev* ubd, struct ublkdrv_uio* uio)
{
    struct uio_info* info;
    char* uio_name;

    int ret = -ENOMEM;

    info = &uio->uio;

    info->version = "7.0.0";

    info->mem[UBLKDRV_UIO_MEM_CMDB].name    = UBLKDRV_UIO_MEM_CMDB_NAME;
    info->mem[UBLKDRV_UIO_MEM_CMDB].addr    = (phys_addr_t)ubd->ctx->cmdb;
    info->mem[UBLKDRV_UIO_MEM_CMDB].size    = ubd->ctx->cmdb_sz;
    info->mem[UBLKDRV_UIO_MEM_CMDB].memtype = UIO_MEM_LOGICAL;

    info->mem[UBLKDRV_UIO_MEM_CELLC].name    = UBLKDRV_UIO_MEM_CELLC_NAME;
    info->mem[UBLKDRV_UIO_MEM_CELLC].addr    = (phys_addr_t)ubd->ctx->cellc;
    info->mem[UBLKDRV_UIO_MEM_CELLC].size    = ubd->ctx->cellc_sz;
    info->mem[UBLKDRV_UIO_MEM_CELLC].memtype = UIO_MEM_LOGICAL;

    info->mem[UBLKDRV_UIO_MEM_CELLS].name    = UBLKDRV_UIO_MEM_CELLS_NAME;
    info->mem[UBLKDRV_UIO_MEM_CELLS].addr    = (phys_addr_t)ubd->ctx->cells;
    info->mem[UBLKDRV_UIO_MEM_CELLS].size    = ubd->ctx->cells_sz;
    info->mem[UBLKDRV_UIO_MEM_CELLS].memtype = UIO_MEM_VIRTUAL;

    uio->mems_len = UBLKDRV_UIO_MEM_CELLS + 1;

    uio_name = kzalloc(strlen(ubd->name) + strlen(UBLKDRV_UIO_KERNEL_TO_USER_DIR_SUFFIX) + 1, GFP_KERNEL);
    if (!uio_name)
        goto err;

    strcat(strcpy(uio_name, ubd->name), UBLKDRV_UIO_KERNEL_TO_USER_DIR_SUFFIX);

    info->priv       = uio;
    info->irqcontrol = ublkdrv_uio_irq_cmd_handled;
    info->irq        = UIO_IRQ_CUSTOM;
    info->name       = uio_name;
    info->mmap       = ublkdrv_uio_mmap;
    info->open       = ublkdrv_uio_open;
    info->release    = ublkdrv_uio_release;

    ret = uio_register_device(&ubd->disk->part0->bd_device, info);
    if (ret)
        goto free_uio_name;

    uio->name = uio_name;

    return 0;

free_uio_name:
    kfree(uio_name);

err:
    return ret;
}

static int ublkdrv_uio_user_to_kernel_register(struct ublkdrv_dev* ubd, struct ublkdrv_uio* uio)
{
    struct uio_info* info;
    char* uio_name;

    int ret = -ENOMEM;

    info = &uio->uio;

    info->version = "3.0.0";

    info->mem[UBLKDRV_UIO_MEM_CMDB].name    = UBLKDRV_UIO_MEM_CMDB_NAME;
    info->mem[UBLKDRV_UIO_MEM_CMDB].addr    = (phys_addr_t)ubd->ctx->cmdb_ack;
    info->mem[UBLKDRV_UIO_MEM_CMDB].size    = ubd->ctx->cmdb_ack_sz;
    info->mem[UBLKDRV_UIO_MEM_CMDB].memtype = UIO_MEM_LOGICAL;

    uio->mems_len = UBLKDRV_UIO_MEM_CMDB + 1;

    uio_name = kzalloc(strlen(ubd->name) + strlen(UBLKDRV_UIO_USER_TO_KERNEL_DIR_SUFFIX) + 1, GFP_KERNEL);
    if (!uio_name)
        goto err;

    strcat(strcpy(uio_name, ubd->name), UBLKDRV_UIO_USER_TO_KERNEL_DIR_SUFFIX);

    info->priv       = uio;
    info->irqcontrol = ublkdrv_uio_irq_cmd_complete;
    info->irq        = UIO_IRQ_CUSTOM;
    info->name       = uio_name;
    info->mmap       = ublkdrv_uio_mmap;
    info->open       = ublkdrv_uio_open;
    info->release    = ublkdrv_uio_release;

    ret = uio_register_device(&ubd->disk->part0->bd_device, info);
    if (ret)
        goto free_uio_name;

    uio->name = uio_name;

    return 0;

free_uio_name:
    kfree(uio_name);

err:
    return ret;
}

static void ublkdrv_uio_unregister(struct ublkdrv_uio* uio)
{
    uio_unregister_device(&uio->uio);
}

int ublkdrv_uios_register(struct ublkdrv_dev* ubd)
{
    int i, j;

    static int (*f[])(struct ublkdrv_dev*, struct ublkdrv_uio*) = {
        [UBLKDRV_UIO_DIR_KERNEL_TO_USER] = ublkdrv_uio_kern_to_user_register,
        [UBLKDRV_UIO_DIR_USER_TO_KERNEL] = ublkdrv_uio_user_to_kernel_register,
    };
    static_assert(ARRAY_SIZE(f) == ARRAY_SIZE(ubd->uios));

    int ret = 0;

    for (i = 0; i < ARRAY_SIZE(f); ++i) {
        ubd->uios[i] = kzalloc_node(sizeof(*ubd->uios[i]), GFP_KERNEL, ubd->nid);
        if (!ubd->uios[i]) {
            ret = -ENOMEM;
            goto err;
        }

        ubd->uios[i]->priv = ubd;

        ret = f[i](ubd, ubd->uios[i]);
        if (ret)
            goto err;
    }

    return 0;

err:
    for (j = i - 1; !(j < 0); --j) {
        struct ublkdrv_uio* uio = ubd->uios[j];
        ubd->uios[j]            = NULL;
        ublkdrv_uio_unregister(uio);
        kfree_const(uio->name);
        kfree(uio);
    }

    return ret;
}

void ublkdrv_uios_unregister(struct ublkdrv_dev* ubd)
{
    int i;

    for (i = ARRAY_SIZE(ubd->uios) - 1; !(i < 0); --i) {
        if (ubd->uios[i])
            ublkdrv_uio_unregister(ubd->uios[i]);
    }
}
