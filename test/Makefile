## Makefile for testing the file system - is called from the root Makefile
all:
	gcc test/write_test.c -o ./test/write_test
	#gcc test/rename_test.c -o ./test/rename_test
	#gcc test/setattr_test.c -o ./test/setattr_test
	#gcc test/mknod_test.c -o ./test/mknod_test
	#gcc test/mkdir_test.c -o ./test/mkdir_test
	sudo ./test/write_test "/home/zudelino/Musica/a.txt" "Hello World" 

switch_state:
	gcc test/switch_state.c -o ./test/switch_state
	sudo ./test/switch_state

init_blacklist:
	gcc test/init_blacklist.c -o ./test/init_blacklist
	sudo ./test/init_blacklist

add_path_blacklist:
	gcc test/add_path_blacklist.c -o ./test/add_path_blacklist
	sudo ./test/add_path_blacklist "/home/zudelino/Musica/a.txt"

rm_path_blacklist:
	gcc test/rm_path_blacklist.c -o ./test/rm_path_blacklist
	sudo ./test/rm_path_blacklist "/home/zudelino/Musica/a.txt"

print_blacklist:
	gcc test/print_blacklist.c -o ./test/print_blacklist
	sudo ./test/print_blacklist

write_test:
	gcc test/write_test.c -o ./test/write_test
	sudo ./test/write_test /home/zudelino/Musica/a.txt Hello_World

mkdir_test:
	gcc test/mkdir_test.c -o ./test/mkdir_test
	sudo ./test/mkdir_test /home/zudelino/Musica/asas/dir

mknod_test:
	gcc test/mknod_test.c -o ./test/mknod_test
	sudo ./test/mknod_test /home/zudelino/Musica/asas ##########################################################

setattr_test:
	gcc test/setattr_test.c -o ./test/setattr_test
	sudo ./test/setattr_test /home/zudelino/Musica/asas 

rename_test:
	gcc test/rename_test.c -o ./test/rename_test
	sudo ./test/rename_test /home/zudelino/Musica/asas /home/zudelino/Musica/asas2

rmdir_test:
	gcc test/rmdir_test.c -o ./test/rmdir_test
	sudo ./test/rmdir_test /home/zudelino/Musica/asas

symblink_test:
	gcc test/symlink_test.c -o ./test/symlink_test
	sudo ./test/symlink_test /home/zudelino/Musica/a.txt /home/zudelino/Musica/asas/b.txt

unlink_test:
	gcc test/unlink_test.c -o ./test/unlink_test
	sudo ./test/unlink_test /home/zudelino/Musica/a.txt

link_test:
	gcc test/link_test.c -o ./test/link_test
	sudo ./test/link_test /home/zudelino/Musica/asas /home/zudelino/Musica/asas2

create_test:
	gcc test/create_test.c -o ./test/create_test
	sudo ./test/create_test /home/zudelino/Musica/asas/ciaone.txt

