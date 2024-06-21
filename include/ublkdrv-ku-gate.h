#ifndef UBLKDRV_KU_GATE_H
#define UBLKDRV_KU_GATE_H

#include "uapi/ublkdrv/cellc.h"
#include "uapi/ublkdrv/cmdb.h"

struct ublkdrv_ku_gate {
    struct ublkdrv_cmdb* cmdb;
    struct ublkdrv_cellc* cellc;
};

#endif /* UBLKDRV_KU_GATE_H */
