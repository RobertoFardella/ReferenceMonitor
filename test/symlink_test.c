#include "./include/client.h"

/*symlink() creates a symbolic link named newpath which contains the string oldpath.*/
int main(int argc, char** argv){

    if (argc != 3) {
		fprintf(stderr, "Usage: %s path= <path> sym_path=<sym path>\n", argv[0]);
		return 1;
	}

    int ret;

    ret = symlink(argv[1], argv[2]);
    if(ret){
        printf("symlink error\n");
        return -1;
    }

    printf("symlink created\n");


    return 0;
}