#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/unistd.h> // Include per geteuid()
#include <linux/cred.h>
#include <linux/key.h>
#include "referenceMonitor.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Roberto Fardella <roberto.fard@gmail.com>");
MODULE_DESCRIPTION("my first module");

#define MODNAME "REFERENCE-MONITOR"

static ref_mon rm;

int check_password(char* pw){
    int ret;
    
    return ret;
}

/*sys_switch_state: cambiamento dello stato del reference monitor*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2,_switch_state, enum rm_state, state, char*, pw){
#else
asmlinkage int sys_switch_state(enum state, char* pw){
#endif
    const struct cred *cred = current_cred();
    printk(KERN_INFO "%s: system call switch state invocata correttamente con parametro %d", MODNAME, state);
    /**
     * changing the current state of the reference monitor requires that the thread that is running this operation needs 
     * to be marked with effective-user-id set to root, and additionally the reconfiguration requires in input a password 
     * that is reference-monitor specific. This means that the encrypted version of 
     * the password is maintained at the level of the reference monitor architecture for performing the required checks.
     *  
    */
   printk("effective-user-id del thread corrente: %d", cred->euid);
   // Ottenere l'UID effettivo (euid) corrente
    kuid_t current_euid = current_cred()->euid;
   
    if (!uid_eq(current_euid, GLOBAL_ROOT_UID)){ // Verifica se l'UID effettivo è root
        printk(KERN_INFO "Solo l'UID effettivo root può cambiare lo stato.\n");
        return -EPERM; // Restituisci errore di permesso negato
    }

    printk("privilegi sufficienti per cambiare lo stato (siamo user root)");

   
    if (!check_password(pw)) {  // Verifica della password (da implementare)
        printk(KERN_INFO "Password non valida.\n");
        return -EINVAL; // Restituisci errore di input non valido
    }

    if(rm.state == state) {
        printk("lo stato inserito e' gia' quello corrente");
        return -1;
    }
    
    switch (state)
    {
      case ON:
        printk(KERN_INFO  "lo stato inserito e' ON");
        rm.state = ON;
        break;
    case OFF:
        printk(KERN_INFO  "lo stato inserito e' OFF");
        rm.state = OFF;
        break;
    case REC_ON:
        printk(KERN_INFO  "lo stato inserito e' REC_ON");
        rm.state = REC_ON;
        break;
    case REC_OFF:    
        printk(KERN_INFO "lo stato inserito e' REC_OFF");
        rm.state = REC_OFF;
        break;
    default:
        printk(KERN_INFO "lo stato inserito non e' valido");
        break;
    }

    return rm.state;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
static unsigned long sys_switch_state = (unsigned long) __x64_sys_switch_state;	
#endif


unsigned long systemcall_table=0x0;
module_param(systemcall_table,ulong,0660);
int free_entries[15];
module_param_array(free_entries,int,NULL,0660);

unsigned long cr0;

static inline void write_cr0_forced(unsigned long val){
    unsigned long __force_order;

    /* __asm__ __volatile__( */
    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
}

static inline void protect_memory(void){
    write_cr0_forced(cr0);
}

static inline void unprotect_memory(void){
    write_cr0_forced(cr0 & ~X86_CR0_WP);
}
unsigned long * nisyscall;

// INIT MODULE
int init_module(void) {


    unsigned long ** sys_call_table;
    rm.state = OFF;//parto nello stato OFF


    if(systemcall_table!=0){
        cr0 = read_cr0();
        unprotect_memory();
        sys_call_table = (void*) systemcall_table; 
        nisyscall = sys_call_table[free_entries[0]]; //mi serve poi nel cleanup
        sys_call_table[free_entries[0]] = (unsigned long*)sys_switch_state;
        protect_memory();
    }else{
        printk("%s: system call table non trovata\n", MODNAME);
        return -1;
    }

    
        return 0;

}


void cleanup_module(void) {
        
    unsigned long ** sys_call_table;
    cr0 = read_cr0();
    unprotect_memory();
    sys_call_table = (void*) systemcall_table; 
    sys_call_table[free_entries[0]] = nisyscall;
    protect_memory();                  

    printk("%s: shutting down\n",MODNAME);
       
}

