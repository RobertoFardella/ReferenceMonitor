obj-m += reference_monitor_main.o
reference_monitor_main-objs += reference_monitor.o lib/scth.o ./utility/utils.o

A:= $(shell cat /sys/module/the_usctm/parameters/sys_call_table_address)
array_free_entries:= $(shell cat /sys/module/the_usctm/parameters/free_entries) 

EXTRA_CFLAGS := -I$(PWD)/include -w

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

insmod:
	@echo "$(A)"
	@echo "$(array_free_entries)"
	@read -p "Select a password: " password; \
	insmod reference_monitor_main.ko password="$$password" systemcall_table=$(A) 
