#include "./include/client.h"


enum rm_state displayMenuAndGetChoice(char* choice) {
    printf("Seleziona uno stato:\n");
    printf("1. ON\n");
    printf("2. OFF\n");
    printf("3. REC-ON\n");
    printf("4. REC-OFF\n");

    
    scanf("%s", choice);
    if(strlen(choice) >= 8) return -1;
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
	char pw[256];
	int syscall_index = 134;
	int size_pw ;
	enum rm_state state;
    char *choice;
    choice = malloc(sizeof(char)*64);
init:
    state = displayMenuAndGetChoice(choice);
    if(state == -1){ 
        printf("selezionare un input valido,riprova\n");
        goto init;
    }  
        free(choice);
        printf("enter a password:");
        scanf("%s", pw);
        size_pw= strlen(pw);
        ret = syscall(syscall_index, state, pw,size_pw);
        if(ret == -1){
            perror("\nErrore nella syscall_switch_state");
        }

	return 0;
}


