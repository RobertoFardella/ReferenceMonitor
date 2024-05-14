#include "./include/client.h"

int main(int argc, char** argv){
	int ret;

    if (argc != 2) {
		fprintf(stderr, "Usage: %s <path file>\n", argv[0]);
		return 1;
	}
    ret = rmdir(argv[1]);
    if(ret){
        printf("rmdir failed\n");
        return -1;
    }

    printf("rmdir %s executed\n", argv[1]);
	return 0;
}