#include "./include/client.h"

int main(int argc, char** argv){
	int ret ;
	char* pw;
	enum rm_state state;

	int syscall_index[5] = {134,156};

	/*if (argc != 2) {
		fprintf(stderr, "Usage: %s <path file>\n", argv[0]);
		return 1;
	}*/

	//ret = syscall(syscall_index[1], "/home/zudelino/Musica", 0 ); 
	ret = syscall(syscall_index[1], "/home/zudelino/Musica/a.txt", 0 );
	if(ret < 0) {
		printf("1");
		}
	ret = syscall(syscall_index[1], "/home/zudelino/Musica/asas", 0 );
	if(ret < 0) {
		printf("13");
		}
	ret = syscall(syscall_index[1], "", 2 );
	if(ret < 0) {
		printf("12");}
	return 0;
}