all:
	make -f Linux-sys_call_table-discoverer/Makefile remote-build
	make -f FSReferenceMonitor/Makefile remote-build
	sudo make -f Linux-sys_call_table-discoverer/Makefile remote-insmod
	sudo make -f FSReferenceMonitor/Makefile remote-insmod
	#make -f Single_fs/Makefile remote-build
	#sudo make -f Single_fs/Makefile remote-insmod
clean:
	make -f FSReferenceMonitor/Makefile remote-clean
	make -f Linux-sys_call_table-discoverer/Makefile remote-clean
	make -f Single_fs/Makefile remote-clean
insmod:
	sudo make -f Linux-sys_call_table-discoverer/Makefile remote-insmod
	sudo make -f FSReferenceMonitor/Makefile remote-insmod
	#make -f Single_fs/Makefile remote-insmod
rmmod:
	sudo make -f Linux-sys_call_table-discoverer/Makefile remote-rmmod
	sudo make -f FSReferenceMonitor/Makefile remote-rmmod
	#make -f Single_fs/Makefile remote-rmmod
test:
	sudo make -f user/Makefile all

filesystem-setup:
	make -f Single_fs/Makefile ex-create-fs
	sudo make -f Single_fs/Makefile ex-mount-fs

filesystem-destroy:
	umount ./mount
