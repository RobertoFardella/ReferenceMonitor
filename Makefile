all:
	make -f Linux-sys_call_table-discoverer/Makefile remote-build
	sudo make -f Linux-sys_call_table-discoverer/Makefile remote-insmod
	make -f FSReferenceMonitor/Makefile remote-build
	sudo make -f FSReferenceMonitor/Makefile remote-insmod
clean:
	make -f FSReferenceMonitor/Makefile remote-clean
	make -f Linux-sys_call_table-discoverer/Makefile remote-clean
insmod:
	sudo make -f Linux-sys_call_table-discoverer/Makefile remote-insmod
	sudo make -f FSReferenceMonitor/Makefile remote-insmod
rmmod:
	sudo make -f FSReferenceMonitor/Makefile remote-rmmod
	sudo make -f Linux-sys_call_table-discoverer/Makefile remote-rmmod
test:
	sudo make -f user/Makefile all
