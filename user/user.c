#include <unistd.h>
#include <stdio.h>
#include <syscall.h>
#include </home/zudel/Documents/ReferenceMonitor/FSReferenceMonitor/referenceMonitor.h>

int main(int argc, char** argv){
	int ret ;
	int syscall_index[5] = {134,156};
	enum rm_state state;
	state = ON;
	ret = syscall(134,state,"ciao");
	printf("il valore tornato dalla system call %d e': %d \n", syscall_index[0], ret);
	return 0;
}