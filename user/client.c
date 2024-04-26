#include "./include/client.h"
/**
comando df o lsblk per visualizzare i filesystem
coon cat /proc/filesystems vedo quelli che sono supportati dal mio kernel
*/



void displayMenu() {
    printf("\nMenu, digitare:\n");
    printf("1. Stato ON\n");
    printf("2. Stato OFF\n");
    printf("3. Stato REC_ON\n");
    printf("4. Stato REC_OFF\n");
    printf("0. Esci\n");
}

int read_file(char *path) {
    int fd;
    char buffer[1024];
    ssize_t bytes_read;

    fd = open(path, O_RDONLY);
    if (fd == -1) {
        printf("Errore durante l'apertura del file %s\n", path);
        return 1;
    }

    // Legge i dati dal file nel buffer
    bytes_read = read(fd, buffer, sizeof(buffer));
    if (bytes_read == -1) {
        printf("Errore durante la lettura dal file %s\n", path);
        close(fd);
        return 1;
    }

    close(fd);
    printf("Dati letti dal file %s:\n%s\n", path, buffer);

    return 0;
}

int write_file(char *path){

	int fd;
    ssize_t bytes_written;

    // Apre il file in modalità scrittura (O_CREAT crea il file se non esiste)
    fd = open(path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        printf("Errore durante l'apertura del file %s \n", path);
        return 1;
    }

    bytes_written = write(fd, "data", sizeof("data") - 1);  // sizeof(data) include il terminatore '\0'

    if (bytes_written == -1) {
        printf("Errore durante la scrittura nel file %s \n", path);
        close(fd);
        return 1;
    }
    close(fd);
    printf("Scrittura completata con successo.\n");
    return 0;
}

int main(int argc, char** argv){

	/*if(argc < 2){
                printf("usage: prog syscall-num [nsg-body]\n");
                return EXIT_FAILURE;
        }*/
        
	int ret ;
    int choose;
	char *pw = malloc(sizeof(char)*64);
	int syscall_index[5] = {134,156};
	int add = 1;
	size_t size_pw ;
	enum rm_state state  = ON;

    displayMenu();
    printf("selezionare un input valido\n");
init:
    scanf("%d", &choose);
    if(choose < 0 || choose > 4){ 
        printf("selezionare un input valido,riprova\n");
        goto init;
    }
    while(1){   
        displayMenu();
        printf("enter a password: \n");
        fgets(pw,64, stdin);
        // Rimuovi il newline dalla fine della stringa
        pw[strcspn(pw, "\n")] = '\0';
        size_pw = strlen(pw);
        ret = syscall(syscall_index[0], state, pw, size_pw);
        
        if(ret == -1){
            perror("Errore nella syscall_switch_state");
            switch (errno)
            {
            case -EPERM:
                printf("livello di privilegi insufficiente\n");
                break;
            case -EINVAL:
                printf("lo stato inserito e' quello corrente\n");
                break;
            case -ENOEXEC:
                printf("password sbagliata, riprova\n");
                break;
            default:
                break;
            }
        }
    }
	return 0;
}

