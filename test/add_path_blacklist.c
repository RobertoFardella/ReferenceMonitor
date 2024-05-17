#include "./include/client.h"
/* add a path to the blacklist*/

int main(int argc, char** argv){
	int ret ;
	char* pw= malloc(sizeof(char)*64);
	enum rm_state state;

	int syscall_index = 156;
    if (argc != 2) {
		fprintf(stderr, "Usage: %s <path file>\n", argv[0]);
		return 1;
	}
	printf("enter a password:");
	scanf("%s", pw);
	// Rimuovi il newline dalla fine della stringa
	pw[strcspn(pw, "\n")] = '\0';
    ret = syscall(syscall_index, argv[1], pw, 0 );
    if(ret < 0){
        printf("error in adding path\n");
        return -1;
    }
	return 0;
}