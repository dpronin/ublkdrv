KDIR ?= /lib/modules/$(shell uname -r)/build
INSTALL_PATH ?= /lib/modules/$(shell uname -r)/misc
INSTALL_HDR_PATH ?= /usr/include/linux

kbuild:
	make -C $(KDIR) M=$(PWD)

install:
	@echo "installing ublkdrv.ko in $(INSTALL_PATH)"
	install -m644 -vD ublkdrv.ko $(INSTALL_PATH)/ublkdrv.ko

headers_install:
	@echo "installing headers in $(INSTALL_HDR_PATH)"
	mkdir -p $(INSTALL_HDR_PATH) && cp -r include/uapi/* $(INSTALL_HDR_PATH)

clean:
	make -C $(KDIR) M=$(PWD) clean

.PHONY: kbuild install headers_install clean
