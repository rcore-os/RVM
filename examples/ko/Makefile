export KDIR ?= /lib/modules/$(shell uname -r)/build

module := rvm

ccflags-y := -I$(src)/include
obj-m += rvm.o

all: build

build:
	$(MAKE) -C $(KDIR) M=$(PWD) CC=$(CC)

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) CC=$(CC) clean

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
