#include "./include/client.h"

/*link() creates a new link (also known as a hard link) to an existing file.*/

int main(int argc, char** argv){
    int ret;
    if (argc != 3) {
		fprintf(stderr, "Usage: %s old_path=<old path> new_path=<new path>\n", argv[0]);
		return 1;
	}

    ret = link(argv[1], argv[2]);
    if(ret){
        printf("link error\n");
        return -1;
    }

    return 0;
}