export KDIR ?= /lib/modules/$(shell uname -r)/build

module := rvm

all: build

build:
	$(MAKE) -C $(KDIR) M=$(PWD)
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

insmod: rmmod
	sudo dmesg -C
	sudo insmod $(module).ko
	sudo chown root:kvm /dev/rvm
	sudo chmod 660 /dev/rvm
	dmesg

rmmod:
ifneq ($(shell lsmod | grep rvm),)
	sudo rmmod $(module)
endif

test: rmmod
	sudo dmesg -C
	sudo insmod $(module).ko
	sudo rmmod $(module).ko
	dmesg
