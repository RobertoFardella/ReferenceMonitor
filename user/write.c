#include <stdio.h>

int main() {
    FILE *file_ptr;
    char text[] = "Questo è un esempio di testo da scrivere nel file.\n";
    const char *file_name =  "/home/zudelino/Musica/a.txt";

    // Apre il file in modalità scrittura ("w")
    file_ptr = fopen(file_name, "w");
    if (file_ptr == NULL) {
        printf("Errore nell'apertura del file!\n");
        return 1;
    }

    // Scrive il testo nel file
    fprintf(file_ptr, "%s", text);

    // Chiude il file
    fclose(file_ptr);

    printf("Testo scritto correttamente nel file '%s'\n", file_name);
    return 0;
}
