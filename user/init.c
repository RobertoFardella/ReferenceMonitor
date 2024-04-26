#include "./include/client.h"

int main(int argc, char** argv){
	int ret ;
	char* pw;
	enum rm_state state;

	int syscall_index[5] = {134,156};

	ret = syscall(syscall_index[1], "/home/zudelino/Documenti/GitHub/ReferenceMonitor/FSReferenceMonitor/utility/rcu_list.c", 0 ); 
	ret = syscall(syscall_index[1], "/home/zudelino/Musica", 0 ); 
	ret = syscall(syscall_index[1], "", 2 );
	ret = syscall(syscall_index[1], "/home/zudelino/Musica", 0 );
	ret = syscall(syscall_index[1], "", 2 );
	return 0;
}