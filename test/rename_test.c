#include "./include/client.h"
/*rename - change the name or location of a file*/
int main(int argc, char** argv){

    int ret;
    if (argc != 3) {
		fprintf(stderr, "Usage: %s old_path=<old path> new_path=<new path>\n", argv[0]);
		return 1;
	}

    ret = rename(argv[1], argv[2]);
    if(ret){
        printf("rename error\n");
        return -1;
    }
    printf("the name of a file is changed\n");
    return 0;
}