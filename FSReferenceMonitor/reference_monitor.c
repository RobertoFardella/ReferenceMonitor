#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include "referenceMonitor.h"



MODULE_LICENSE("GPL");
MODULE_AUTHOR("Roberto Fardella <roberto.fard@gmail.com>");
MODULE_DESCRIPTION("my first module");

#define MODNAME "REFERENCE-MONITOR"

static ref_mon rm;


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(1,_switch_state, enum rm_state, state){
#else
asmlinkage int sys_switch_state(enum state){
#endif
    printk(KERN_INFO "%s: system call switch state invocata correttamente con parametro %d", MODNAME, state);
    //qui va inserito la protezione con pw del cambio di stato
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

    rm.state = OFF;//parto nello stato OFF
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

