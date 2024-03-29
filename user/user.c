#include <unistd.h>
#include <stdio.h>
#include <syscall.h>
#include <string.h>

/**
comando df o lsblk per visualizzare i filesystem
coon cat /proc/filesystems vedo quelli che sono supportati dal mio kernel
*/

int main(int argc, char** argv){

	/*if(argc < 2){
                printf("usage: prog syscall-num [nsg-body]\n");
                return EXIT_FAILURE;
        }*/
	int ret ;
	char *pw  ;
	int syscall_index[5] = {134,156};
	int add = 1;
	pw = "carabiniere_a_cavallo";
	size_t size = strlen(pw);

	//ret = syscall(134,state, pw , size);
	//printf("\n il valore tornato dalla system call %d e': %d \n", syscall_index[0], ret);
	ret = syscall(syscall_index[1], "ciao", 0 );
	ret = syscall(syscall_index[1], "ciao2", 0 );  
	ret = syscall(syscall_index[1], "elimino", 1 ); 
	ret = syscall(syscall_index[1], "ricerca", 2 );

	return 0;
}

