#include "./include/client.h"

/*The program expects one command-line argument, which is the pathname for the FIFO. 
It checks if the correct number of arguments is provided and displays a usage message if not. 
The `mknod` function is then used to create the FIFO .*/
int main(int argc, char** argv){
    int ret;
    mode_t permissions = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH; 
    
    if (argc != 2) {
		fprintf(stderr, "Usage: %s <pathname>\n", argv[0]);
		return 1;
	}
    ret = mknod(argv[1], S_IFIFO | 0666 ,0); //// FIFO (named pipe) con permessi 666
    if(ret){
        printf("mknod error\n");
        return -1;
    }

    printf("mknod %s executed\n", argv[1]);
    return 0;
}