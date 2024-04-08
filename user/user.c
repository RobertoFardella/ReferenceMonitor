#include <unistd.h>
#include <stdio.h>
#include <syscall.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

/**
comando df o lsblk per visualizzare i filesystem
coon cat /proc/filesystems vedo quelli che sono supportati dal mio kernel
*/
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
	char *pw  ;
	int syscall_index[5] = {134,156};
	int add = 1;
	pw = "carabiniere_a_cavallo";
	size_t size = strlen(pw);
	//enum rm_state state;

	ret = syscall(syscall_index[1], "/home/zudelino/Documenti/GitHub/ReferenceMonitor/FSReferenceMonitor/utility/rcu_list.c", 0 );  
	ret = syscall(syscall_index[1], "/home/zudelino/Musica", 0 ); 
	ret = syscall(syscall_index[1], "", 2 );
	ret = syscall(syscall_index[1], "/home/zudelino/Musica", 0 );
	ret = syscall(syscall_index[1], "", 2 );
	write_file("/home/zudelino/Documenti/GitHub/ReferenceMonitor/FSReferenceMonitor/utility/rcu_list.c");
    read_file("/home/zudelino/Documenti/GitHub/ReferenceMonitor/FSReferenceMonitor/utility/rcu_list.c");
	return 0;
}

