obj-m := reference_monitor_main.o
reference_monitor_main-objs := reference_monitor.o ./utils/rcu_list.o

A := $(shell cat /sys/module/the_usctm/parameters/sys_call_table_address)
array_free_entries := $(shell cat /sys/module/the_usctm/parameters/free_entries) 
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
remote-build:
	 make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/FSReferenceMonitor modules
remote-insmod:
	 sudo insmod FSReferenceMonitor/reference_monitor_main.ko systemcall_table=$(A) free_entries=$(array_free_entries)
remote-clean:
	 make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/FSReferenceMonitor clean
remote-rmmod:
	sudo rmmod reference_monitor_main.ko 
