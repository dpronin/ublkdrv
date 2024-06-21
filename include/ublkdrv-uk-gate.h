#ifndef UBLKDRV_UK_GATE_H
#define UBLKDRV_UK_GATE_H

#include "uapi/ublkdrv/cellc.h"
#include "uapi/ublkdrv/cmdb_ack.h"

struct ublkdrv_uk_gate {
    struct ublkdrv_cellc* cellc;
    struct ublkdrv_cmdb_ack* cmdb_ack;
};

#endif /* UBLKDRV_UK_GATE_H */
