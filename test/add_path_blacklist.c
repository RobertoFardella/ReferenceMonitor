#include "./include/client.h"
/* add a path to the blacklist*/

int main(int argc, char** argv){
	int ret ;
	char pw[256];
	int pw_size;
	int path_len;

	int syscall_index = 156;
    if (argc != 2) {
		fprintf(stderr, "Usage: %s path=<path file>\n", argv[0]);
		return 1;
	}
	printf("enter a password:");
	scanf("%s", pw);
	// Rimuovi il newline dalla fine della stringa
	
	pw_size = strlen(pw);
	path_len = strlen(argv[1]);
    ret = syscall(syscall_index, argv[1],path_len, pw, pw_size);
    if(ret < 0){
        printf("error in adding path\n");
        return -1;
    }
	return 0;
}