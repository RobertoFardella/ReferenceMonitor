#include "./include/client.h"

/*The chmod function is then used to change the file's permissions to 644 (read and write for the owner, read for the group, and read for others).*/
int main(int argc, char** argv){
    int ret;
    mode_t permissions = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH; // Esempio: permessi 644
    if (argc != 2) {
		fprintf(stderr, "Usage: %s path=<path file>\n", argv[0]);
		return 1;
	}
    ret = chmod(argv[1], permissions);
    if(ret){
        printf("chmod error\n");
        return -1;
    }
    return 0;
}