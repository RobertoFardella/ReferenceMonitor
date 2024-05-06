obj-m += singlefilefs.o
singlefilefs-objs += singlefilefs_src.o file.o dir.o

all:
	gcc singlefilemakefs.c -o singlefilemakefs
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	sudo insmod singlefilefs.ko

load-FS-driver:
	sudo insmod singlefilefs.ko

unload-FS-driver:
	sudo rmmod singlefilefs.ko

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	


create-fs:
	dd bs=4096 count=100 if=/dev/zero of=image
	./singlefilemakefs image
	mkdir mount
	
mount-fs:
	sudo mount -o loop -t singlefilefs image ./mount/

destroy-fs:
	sudo umount ./mount

remote-all:
	gcc Single_fs/singlefilemakefs.c -o ./Single_fs/singlefilemakefs
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/Single_fs modules
	sudo insmod Single_fs/singlefilefs.ko

remote-build:
	gcc Single_fs/singlefilemakefs.c -o ./Single_fs/singlefilemakefs
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/Single_fs modules

remote-insmod:
	 sudo insmod Single_fs/singlefilefs.ko

remote-clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/Single_fs  clean
remote-rmmod:
	sudo rmmod Single_fs/singlefilefs.ko

ex-create-fs:
	dd bs=4096 count=100 if=/dev/zero of=./Single_fs/image
	 ./Single_fs/singlefilemakefs ./Single_fs/image 
	 -f mkdir ./Single_fs/mount
	
ex-mount-fs:
	 sudo mount -o loop -t singlefilefs ./Single_fs/image ./Single_fs/mount/


#digitare lsblk per vedere i dispositivi montati e i loro path 

