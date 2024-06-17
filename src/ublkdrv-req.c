#include "ublkdrv-req.h"

#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/math64.h>
#include <linux/minmax.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/types.h>

void ublkdrv_req_from_bio_to_cells_copy(struct ublkdrv_cellc const* cellc, void* cells, struct bio const* bio, u32 celldn)
{
    unsigned int bv_len, bv_offset;
    struct bio_vec bv;
    struct bvec_iter iter;
    u32 cp_sz;
    u32 data_sz;
    void const* bv_page;

    u32 cell_offset                   = 0;
    struct ublkdrv_celld const* celld = &cellc->cellds[celldn];

    if (unlikely(!(celldn < cellc->cellds_len)))
        return;

    data_sz = celld->data_sz;
    bio_for_each_segment(bv, bio, iter)
    {
        bv_len    = bv.bv_len;
        bv_offset = bv.bv_offset;
        bv_page   = page_to_virt(bv.bv_page);
        for (cp_sz = min(data_sz, bv_len);
             bv_len;
             bv_offset += cp_sz, bv_len -= cp_sz, cp_sz = min(data_sz, bv_len)) {

            char* to         = &((char*)(cells))[celld->offset + cell_offset];
            char const* from = &((char const*)(bv_page))[bv_offset];

            memcpy(to, from, cp_sz);
            might_sleep();

            data_sz -= cp_sz;
            cell_offset += cp_sz;

            if (!data_sz) {
                celldn = celld->ncelld;
                celld  = &cellc->cellds[celldn];
                if (unlikely(!(celldn < cellc->cellds_len)))
                    return;

                data_sz     = celld->data_sz;
                cell_offset = 0;
            }
        }
    }
}

void ublkdrv_req_from_cells_to_bio_copy(struct ublkdrv_cellc const* cellc, struct bio* bio, void const* cells, u32 celldn)
{
    unsigned int bv_len, bv_offset;
    struct bvec_iter iter;
    struct bio_vec bv;
    u32 cp_sz;
    void* bv_page;

    u32 data_sz;
    u32 cell_offset;

    struct ublkdrv_celld const* celld = &cellc->cellds[celldn];

    for (; celldn < cellc->cellds_len && !celld->data_sz; celldn = celld->ncelld, celld = &cellc->cellds[celldn])
        ;

    if (unlikely(!(celldn < cellc->cellds_len)))
        return;

    data_sz     = celld->data_sz;
    cell_offset = 0;
    bio_for_each_segment(bv, bio, iter)
    {
        bv_len    = bv.bv_len;
        bv_offset = bv.bv_offset;
        bv_page   = page_to_virt(bv.bv_page);
        for (cp_sz = min(data_sz, bv_len);
             bv_len;
             bv_offset += cp_sz, bv_len -= cp_sz, cp_sz = min(data_sz, bv_len)) {

            char* to         = &((char*)(bv_page))[bv_offset];
            char const* from = &((char const*)(cells))[celld->offset + cell_offset];

            memcpy(to, from, cp_sz);
            might_sleep();

            data_sz -= cp_sz;
            cell_offset += cp_sz;

            if (!data_sz) {
                do {
                    celldn = celld->ncelld;
                    celld  = &cellc->cellds[celldn];
                } while (celldn < cellc->cellds_len && !celld->data_sz);

                if (unlikely(!(celldn < cellc->cellds_len)))
                    return;

                data_sz     = celld->data_sz;
                cell_offset = 0;
            }
        }
    }
}
