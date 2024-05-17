all:
	if [ -z "$$PW" ]; then echo "Please set the PW variable"; exit 1; fi
	@echo "the password is $(PW)" 
	make  -f Single_fs/Makefile remote-all						    ###module build			
	make  -f Linux-sys_call_table-discoverer/Makefile remote-build
	make  -f FSReferenceMonitor/Makefile remote-build
	make  -f Single_fs/Makefile ex-create-fs 							###filesystem setup
	sudo make -f Single_fs/Makefile ex-mount-fs
	sudo make -f Linux-sys_call_table-discoverer/Makefile remote-insmod ###module insmod
	sudo make -e PW=$(PW) -f FSReferenceMonitor/Makefile remote-insmod 
	
clean:
	make -f FSReferenceMonitor/Makefile remote-clean
	make -f Linux-sys_call_table-discoverer/Makefile remote-clean
	make -f Single_fs/Makefile remote-clean
	make -f test/Makefile clean
	
insmod:
	make -f Single_fs/Makefile remote-insmod
	sudo make -f Linux-sys_call_table-discoverer/Makefile remote-insmod
	sudo make -f FSReferenceMonitor/Makefile remote-insmod
rmmod:
	sudo make -f Linux-sys_call_table-discoverer/Makefile remote-rmmod
	sudo make -f FSReferenceMonitor/Makefile remote-rmmod
	make -f Single_fs/Makefile remote-destroy-fs
	make -f Single_fs/Makefile remote-rmmod
	
#command to run the test cases

init_blacklist: 
	sudo make -f test/Makefile init_blacklist
	
switch_state:
	sudo make -f test/Makefile switch_state

add_path_blacklist:
	sudo make -e path=$(path) -f test/Makefile add_path_blacklist

rm_path_blacklist:	
	sudo make  -e path=$(path) -f test/Makefile rm_path_blacklist

print_blacklist:
	sudo make -f test/Makefile print_blacklist

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

# filesystem commands

filesystem-setup:
	make -f Single_fs/Makefile ex-create-fs
	sudo make -f Single_fs/Makefile ex-mount-fs

filesystem-destroy:
	umount ./mount
