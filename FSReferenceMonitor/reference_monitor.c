#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Roberto Fardella <roberto.fard@gmail.com>");
MODULE_DESCRIPTION("my first module");

#define MODNAME "REFERENCE-MONITOR"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(1,_hello, int, A){
#else
asmlinkage int sys_hello(int A){
#endif
        printk("hello func");
        return A;
    
}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
static unsigned long sys_hello = (unsigned long) __x64_sys_hello;	
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


int init_module(void) {


    int ret;
    unsigned long ** sys_call_table;
    
    if(systemcall_table!=0){
        cr0 = read_cr0();
        unprotect_memory();
        sys_call_table = (void*) systemcall_table; 
        nisyscall = sys_call_table[free_entries[0]]; //mi serve poi nel cleanup
        sys_call_table[free_entries[0]] = (unsigned long*)sys_hello;
        protect_memory();
        printk("la system call table si trova a %p", systemcall_table);
    }else{
        printk("%s: systemcall Table non trovata\n", MODNAME);
        return -1;
    }
        return 0;

}


void cleanup_module(void) {
        
         int  ret;
    unsigned long ** sys_call_table;
    cr0 = read_cr0();
    unprotect_memory();
    sys_call_table = (void*) systemcall_table; 
    sys_call_table[free_entries[0]] = nisyscall;
    protect_memory();                  

    printk("%s: shutting down\n",MODNAME);
       
}

