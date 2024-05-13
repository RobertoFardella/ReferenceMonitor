#include <stdio.h>
/**
 * this program write into a file  
*/
int main() {
    FILE *file_ptr;
    char text[] = "ciao a tutti\n";
    const char *file_name =  "/home/zudelino/Musica/a.txt";

    
    file_ptr = fopen(file_name, "w");
    if (file_ptr == NULL) {
        printf("Errore nell'apertura del file!\n");
        return 0;
    }

    
    fprintf(file_ptr, "%s", text);

    fclose(file_ptr);

    printf("Testo scritto correttamente nel file '%s'\n", file_name);
    return 0;
}
