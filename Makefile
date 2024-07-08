MAKE = make -C

all:
	$(MAKE) /lib/modules/$(shell uname -r)/build M=$(PWD)/Linux-sys_call_table-discoverer modules
	$(MAKE) /lib/modules/$(shell uname -r)/build M=$(PWD)/FSReferenceMonitor modules
	$(MAKE) /lib/modules/$(shell uname -r)/build M=$(PWD)/Single_fs modules
clean:
	$(MAKE) Linux-sys_call_table-discoverer/ clean
	$(MAKE) FSReferenceMonitor/ clean
	$(MAKE) commands/ clean
	$(MAKE) Single_fs/ clean
mount:
	$(MAKE) Single_fs/ load-FS-driver
	$(MAKE) Single_fs/ create-fs
	$(MAKE) Single_fs/ mount-fs
	$(MAKE) Linux-sys_call_table-discoverer/ insmod
	$(MAKE) FSReferenceMonitor/ insmod

unmount:
	rmmod the_usctm
	rmmod reference_monitor_main
	rmmod singlefilefs
	
#command to run the test cases

init_blacklist: 
	make -f test/Makefile init_blacklist
	
switch_state:
	make -f test/Makefile switch_state

add_path_blacklist:
	make -e path=$(path) -f test/Makefile add_path_blacklist

rm_path_blacklist:	
	make  -e path=$(path) -f test/Makefile rm_path_blacklist

print_blacklist:
	make -f test/Makefile print_blacklist

write_test:
	make -e path=$(path) text=$(text) -f test/Makefile write_test

mkdir_test:
	make -e path=$(path) -f test/Makefile mkdir_test

rmdir_test:
	make -e path=$(path) -f test/Makefile rmdir_test

mknod_test:
	make -e path=$(path) -f test/Makefile mknod_test

setattr_test:
	make -e path=$(path) -f test/Makefile setattr_test

rename_test:
	make -e old_path=$(old_path) new_path=$(new_path) -f test/Makefile rename_test

symblink_test:
	make -e path=$(path) sym_path=$(sym_path) -f test/Makefile symblink_test

unlink_test:
	make -e path=$(path) -f test/Makefile unlink_test

link_test:
	make -e path=$(path) hl_path=$(hl_path) -f test/Makefile link_test

create_test:
	make -e path=$(path) -f test/Makefile create_test