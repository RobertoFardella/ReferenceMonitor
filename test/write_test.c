#include <stdio.h>
/**
 * this program write into a file  
*/
int main(int argc, char** argv) {


    FILE *file_ptr;


    if (argc != 3) {
		fprintf(stderr, "Usage: %s <path file> <text>\n", argv[0]);
		return 1;
	}

    file_ptr = fopen(argv[1], "w");
    if (file_ptr == NULL) {
        printf("Errore nell'apertura del file!\n");
        return 0;
    }
    
    fprintf(file_ptr, "%s", argv[2]);

    fclose(file_ptr);

    printf("Testo scritto correttamente nel file '%s'\n", argv[1]);
    return 0;
}
