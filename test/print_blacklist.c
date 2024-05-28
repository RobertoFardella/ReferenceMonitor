#include "./include/client.h"
/* print all paths of the blacklist*/
int main(int argc, char** argv){
	int ret ;
	char* pw= malloc(256);
	int pw_size;
	int syscall_index = 177;

	printf("enter a password:");
	scanf("%s", pw);
	
	// Rimuovi il newline dalla fine della stringa
	pw[strcspn(pw, "\n")] = '\0';
	pw_size = strlen(pw);
	printf("%s, %d", pw, pw_size);
    ret = syscall(syscall_index, pw, pw_size);
	if(ret < 0) {
        printf("error print\n");
		return -1;
    }

	return 0;
}