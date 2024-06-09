#include "./include/client.h"

int main(int argc, char** argv) {
    int fd;

    if (argc != 2) {
		fprintf(stderr, "Usage: %s path=<path file>\n", argv[0]);
		return 1;
	}
    // Creazione del file se non esiste, con permessi di scrittura
    fd = open(argv[1], O_CREAT | O_WRONLY, 0666);
    if (fd == -1) {
        perror("Errore nella creazione del file");
        return 1;
    }

    printf("File %s creato con successo.\n", argv[1]);
    close(fd);

    return 0;
}