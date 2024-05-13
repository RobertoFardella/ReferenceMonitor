#include "./include/client.h"


enum rm_state displayMenuAndGetChoice() {
    printf("Seleziona uno stato:\n");
    printf("1. ON\n");
    printf("2. OFF\n");
    printf("3. REC-ON\n");
    printf("4. REC-OFF\n");

    char choice[8];
    scanf("%s", choice);
  
    if (strcmp(choice, "ON") == 0) {
        printf("Stato selezionato: ON\n");
        return ON;
    } else if (strcmp(choice, "OFF") == 0) {
        printf("Stato selezionato: OFF\n");
        return OFF;
    } else if (strcmp(choice, "REC-ON") == 0) {
        printf("Stato selezionato: REC-ON\n");
        return REC_ON;
    } else if (strcmp(choice, "REC-OFF") == 0) {
        printf("Stato selezionato: REC-OFF\n");
        return REC_OFF;
    } else {
        return -1;
        printf("Stato non riconosciuto.\n");
    }
}
int main(int argc, char** argv){     
	int ret ;
	char *pw = malloc(sizeof(char)*64);
	int syscall_index[5] = {134,156};
	size_t size_pw ;
	enum rm_state state;


init:
    state = displayMenuAndGetChoice();
    if(state == -1){ 
        printf("selezionare un input valido,riprova\n");
        goto init;
    }  
        printf("enter a password:");
        scanf("%s", pw);
        // Rimuovi il newline dalla fine della stringa
        pw[strcspn(pw, "\n")] = '\0';
        size_pw = strlen(pw);
        ret = syscall(syscall_index[0], state, pw);
        free(pw);
        if(ret == -1){
            perror("\nErrore nella syscall_switch_state");
            switch (errno)
            {
            case -EPERM:
                break;
            case -EINVAL:
                goto init;
                break;
            case -ENOEXEC:
                printf("\npassword sbagliata, riprova");
                break;
            default:
                printf("\nerrore generico invocando system call switch_state");
                break;
            } 
        }

	return 0;
}


