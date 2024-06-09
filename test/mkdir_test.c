#include "./include/client.h"

int main(int argc, char** argv){
	int ret;

    if (argc != 2) {
		fprintf(stderr, "Usage: %s path=<path of directory>\n", argv[0]);
		return 1;
	}
    ret = mkdir(argv[1], 0777);
    if(ret){
        printf("mkdir failed\n");
        return -1;
    }
	return 0;
}