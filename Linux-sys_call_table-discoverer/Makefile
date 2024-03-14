obj-m += the_usctm.o
the_usctm-objs += usctm.o ./lib/vtpmo.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules 

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

remote-build:
	 make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/Linux-sys_call_table-discoverer modules

remote-insmod:
	 sudo insmod Linux-sys_call_table-discoverer/the_usctm.ko

remote-clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/Linux-sys_call_table-discoverer  clean
remote-rmmod:
	sudo rmmod the_usctm.ko
