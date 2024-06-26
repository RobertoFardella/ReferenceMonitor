## Makefile for testing the file system - is called from the root Makefile

switch_state:
	gcc test/switch_state.c -o ./test/switch_state
	sudo ./test/switch_state

init_blacklist:
	gcc test/add_path_blacklist.c -o ./test/add_path_blacklist
	sudo ./test/add_path_blacklist "/etc/passwd"
	sudo ./test/add_path_blacklist "/home/ciao"
	sudo ./test/add_path_blacklist "/etc/shadow"

add_path_blacklist:
	gcc test/add_path_blacklist.c -o ./test/add_path_blacklist
	sudo ./test/add_path_blacklist $$path
rm_path_blacklist:
	gcc test/rm_path_blacklist.c -o ./test/rm_path_blacklist
	sudo ./test/rm_path_blacklist $$path

print_blacklist:
	gcc test/print_blacklist.c -o ./test/print_blacklist
	./test/print_blacklist

write_test:
	gcc test/write_test.c -o ./test/write_test
	./test/write_test $$path $$text

mkdir_test:
	gcc test/mkdir_test.c -o ./test/mkdir_test
	./test/mkdir_test $$path

mknod_test:
	gcc test/mknod_test.c -o ./test/mknod_test
	./test/mknod_test $$path

setattr_test:
	gcc test/setattr_test.c -o ./test/setattr_test
	./test/setattr_test $$path

rename_test:
	gcc test/rename_test.c -o ./test/rename_test
	./test/rename_test $$old_path $$new_path

rmdir_test:
	gcc test/rmdir_test.c -o ./test/rmdir_test
	./test/rmdir_test $$path

symblink_test:
	gcc test/symlink_test.c -o ./test/symlink_test
	./test/symlink_test $$path $$sym_path

unlink_test:
	gcc test/unlink_test.c -o ./test/unlink_test
	./test/unlink_test $$path

link_test:
	gcc test/link_test.c -o ./test/link_test
	./test/link_test $$path $$hl_path

create_test:
	gcc test/create_test.c -o ./test/create_test
	./test/create_test $$path

clean:
	rm -f ./test/write_test
	rm -f ./test/switch_state
	rm -f ./test/init_blacklist
	rm -f ./test/add_path_blacklist
	rm -f ./test/rm_path_blacklist
	rm -f ./test/print_blacklist
	rm -f ./test/mkdir_test
	rm -f ./test/mknod_test
	rm -f ./test/setattr_test
	rm -f ./test/rename_test
	rm -f ./test/rmdir_test
	rm -f ./test/symlink_test
	rm -f ./test/unlink_test
	rm -f ./test/link_test
	rm -f ./test/create_test

