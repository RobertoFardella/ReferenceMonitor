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
insmod:
	make -f Single_fs/Makefile remote-insmod
	sudo make -f Linux-sys_call_table-discoverer/Makefile remote-insmod
	sudo make -f FSReferenceMonitor/Makefile remote-insmod
rmmod:
	make -f Single_fs/Makefile remote-destroy-fs
	make -f Single_fs/Makefile remote-rmmod
	sudo make -f Linux-sys_call_table-discoverer/Makefile remote-rmmod
	sudo make -f FSReferenceMonitor/Makefile remote-rmmod
	
test:
	sudo make -f user/Makefile all
switch_state:
	sudo make -f user/Makefile switch_state

filesystem-setup:
	make -f Single_fs/Makefile ex-create-fs
	sudo make -f Single_fs/Makefile ex-mount-fs

filesystem-destroy:
	umount ./mount
