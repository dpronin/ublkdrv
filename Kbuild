ccflags-y = -I$(src)/include/ -I$(src)/include/uapi/

obj-m := ublkdrv.o

ublkdrv-y += \
  src/ublkdrv-main.o \
  src/ublkdrv-req.o \
  src/ublkdrv-uio.o \
  src/ublkdrv-dev.o \
  src/ublkdrv-genl.o
