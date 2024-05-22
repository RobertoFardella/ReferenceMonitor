#include "./include/client.h"
/* print all paths of the blacklist*/
int main(int argc, char** argv){
	int ret ;
	char* pw;
	enum rm_state state;

	int syscall_index = 156;
    ret = syscall(syscall_index, NULL,0,NULL,0, 2 );
	if(ret < 0) {
        printf("error print\n");
		return -1;
    }

	return 0;
}