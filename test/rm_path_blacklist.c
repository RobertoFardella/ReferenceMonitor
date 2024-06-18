#include "./include/client.h"
/* remove a path to the blacklist*/

int main(int argc, char** argv){
	int ret ;
	char pw[256];
	int pw_size;
    int len_path;

	int syscall_index = 174;
    if (argc != 2) {
		fprintf(stderr, "Usage: %s path=<path file>\n", argv[0]);
		return 1;
	}
	printf("enter a password:");
    scanf("%s", pw);
    // Rimuovi il newline dalla fine della stringa
    pw[strcspn(pw, "\n")] = '\0';
    argv[1][strcspn(argv[1], "\n")] = '\0';
    pw_size = strlen(pw);
    len_path= strlen(argv[1]);
    ret = syscall(syscall_index, argv[1],len_path, pw, pw_size);
    if(ret < 0){
        printf("error in removing path\n");
        return -1;
    }
	return 0;
}