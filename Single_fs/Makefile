obj-m += singlefilefs.o
singlefilefs-objs += singlefilefs_src.o file.o dir.o

EXTRA_CFLAGS := -I$(PWD)/include -w

all:
	gcc singlefilemakefs.c -o singlefilemakefs
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules


load-FS-driver:
	insmod singlefilefs.ko

unload-FS-driver:
	rmmod singlefilefs.ko

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

mount-fs: 
	mount -o loop -t singlefilefs image ./mount
 
umount-fs:
	umount ./mount
	rmdir ./mount
create-fs:
	dd bs=4096 count=100 if=/dev/zero of=image
	./singlefilemakefs image
	mkdir mount