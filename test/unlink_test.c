#include "./include/client.h"
/*unlink - delete a name and possibly the file it refers to*/

int main(int argc, char** argv){
    int ret;
    if (argc != 2) {
		fprintf(stderr, "Usage: %s <pathname>\n", argv[0]);
		return 1;
	}
    ret = unlink(argv[1]);
    if(ret){
        printf("unlink error\n");
        return -1;
    }

    return 0;
}