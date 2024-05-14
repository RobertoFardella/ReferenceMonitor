#include "./include/client.h"
/* remove a path to the blacklist*/

int main(int argc, char** argv){
	int ret ;
	char* pw;
	enum rm_state state;

	int syscall_index = 156;
    if (argc != 2) {
		fprintf(stderr, "Usage: %s <path file>\n", argv[0]);
		return 1;
	}
    ret = syscall(syscall_index, argv[1], 1 );
    if(ret < 0){
        printf("error in removing path\n");
        return -1;
    }
	return 0;
}