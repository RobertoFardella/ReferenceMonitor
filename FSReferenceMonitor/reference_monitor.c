#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <linux/unistd.h> // Include per geteuid()
#include <linux/cred.h>
#include <linux/kprobes.h>
#include <linux/key.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/hash.h>
#include <linux/errno.h>
#include "referenceMonitor.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Roberto Fardella <roberto.fard@gmail.com>");
MODULE_DESCRIPTION("my first module");

#define MODNAME "reference_monitor"
unsigned long cr0;
#define PERMS 0644
#define SHA256_DIGEST_SIZE 16
#define MAX_PW_SIZE 64
#define KEY_DESC "my_password_key"
static ref_mon *rm;
static struct task_struct *thread;
static spinlock_t lock;
static spinlock_t lock_sys_write;
#define FILE_PATH "./pw.txt" // Definisci il percorso del file
    node * node_ptr ;
    struct list_head* new_node;
    struct list_head *ptr;

#define target_func "do_sys_open" //you should modify this depending on the kernel version

int write_to_file(char * content, char * filepath ) {
    struct file *file;
    int ret = 0;
    size_t len = strlen(content);
    // Apre il file per la scrittura
    file = filp_open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (IS_ERR(file)) {
        printk(KERN_ERR "Impossibile aprire il file per la scrittura\n");
        return -1;
    }

    // Scrive l'hash sul file
    ret = kernel_write(file, content, len, &file->f_pos);
    if (ret < 0) {
        printk(KERN_ERR "Errore durante la scrittura sul file\n");
    }

    // Chiude il file
    filp_close(file, NULL);

    return ret;
}

// Funzione per calcolare l'hash della password
int calculate_hash(const char *content, unsigned char* hash)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    int ret = -ENOMEM;
    
    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);

    desc = kmalloc(sizeof(*desc), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return ret;
    }
    desc->tfm = tfm;
    ret = crypto_shash_digest(desc, content, strlen(content), hash);//return 0 if the message digest creation was successful; < 0 if an error occurred
    
    kfree(desc);
    crypto_free_shash(tfm);

    return ret;
}

/*sys_switch_state: cambiamento dello stato del reference monitor*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(3,_switch_state, enum rm_state, state, char* , pw, size_t, size){
#else
asmlinkage int sys_switch_state(enum state, char*  pw, size_t size){
#endif
    int ret;
    const struct cred *cred = current_cred();
        unsigned char * hash_digest = kmalloc(SHA256_DIGEST_SIZE*2 + 1, GFP_KERNEL); // GFP_KERNEL specifica che l'allocazione avviene in contesto di kernel
    printk(KERN_INFO "%s: system call switch state invocata correttamente con parametri state %d, pw %s, taglia %d", MODNAME, state, pw, (int)size);
   
   
    if (!uid_eq(cred->euid, GLOBAL_ROOT_UID)){ // Verifica se l'UID effettivo è root
        printk(KERN_INFO "Solo l'UID effettivo root può cambiare lo stato.\n");
        return -EPERM; // Restituisci errore di permesso negato
    }

	
    char pw_buffer[MAX_PW_SIZE];
    void *addr;
    if(size >= (MAX_PW_SIZE -1)) return -EINVAL;

    addr = (void*)get_zeroed_page(GFP_KERNEL);
    
    if (addr == NULL) return -ENOMEM;

    ret = copy_from_user((char*)addr, pw, (int) size);
    
    memcpy(pw_buffer,(char*)addr,size-ret);
    
    pw_buffer[size - ret] = '\0';
    free_pages((unsigned long)addr,0);

    if (calculate_hash(pw_buffer, hash_digest)  < 0) {  // Verifica della password (da implementare)
        printk(KERN_INFO "%s: Password non valida.\n", MODNAME);
        return -EINVAL; // Restituisci errore di input non valido
    }
        int i, offset = 0;
        char buffer[SHA256_DIGEST_SIZE * 2 + 1]; // Il buffer per contenere l'output esadecimale dei byte più il terminatore di stringa
    
    for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
        offset += snprintf(buffer + offset, sizeof(buffer) - offset, "%02x", hash_digest[i]); // Formattare due caratteri esadecimali per ogni byte
    }

    buffer[offset] = '\0'; // Aggiungi il terminatore di stringa
    printk(KERN_INFO "\nHash della password formattato :  %s", buffer);

    size_t hash_len = sizeof(buffer); // Lunghezza dell'hash della password

    write_to_file(buffer, hash_len); // Chiamata alla funzione per scrivere
    
    /*
    struct key *keyring_alloc(const char *description, uid_t uid, gid_t gid,
                          const struct cred *cred,
                          key_perm_t perm,
                          struct key_restriction *restrict_link,
                          unsigned long flags,
                          struct key *dest);
    */
    //key_ref_t password_key;
    //struct key *key;
    //key = kmalloc(sizeof(struct key), GFP_KERNEL);
    //validate_key(keyring_alloc("referenceMonitor", (kuid_t)0, (kgid_t)0, cred, KEY_POS_VIEW | KEY_POS_READ | KEY_POS_SEARCH, NULL, KEY_ALLOC_BYPASS_RESTRICTION,  key));

    //password_key = make_key_ref(key,true);
    // Crea una chiave logon per memorizzare l'hash della password
    /*password_key =  key_create_or_update(password_key, "logon", "password_key", hash, sizeof(hash), KEY_POS_VIEW | KEY_POS_READ | KEY_POS_SEARCH, 0);
    if (password_key == NULL) {
        printk(KERN_ERR "Failed to create key: %ld\n", -1);
        ret = -1;
        kfree(hash);
        return ret;
    }*/

    printk(KERN_INFO "%s: Password hash key created\n", MODNAME);
 
    if(rm->state == state) {
        printk("lo stato inserito e' gia' quello corrente");
        return -1;
    }
    
    switch (state)
    {
      case ON:
        printk(KERN_INFO  "lo stato inserito e' ON");
        rm->state = ON;
        break;
    case OFF:
        printk(KERN_INFO  "lo stato inserito e' OFF");
        rm->state = OFF;
        break;
    case REC_ON:
        printk(KERN_INFO  "lo stato inserito e' REC_ON");
        rm->state = REC_ON;
        break;
    case REC_OFF:    
        printk(KERN_INFO "lo stato inserito e' REC_OFF");
        rm->state = REC_OFF;
        break;
    default:
        printk(KERN_INFO "lo stato inserito non e' valido");
        break;
    }

    return rm->state;
}

/*sys_add_or_remove_link: aggiunta o rimozione del path all'insieme da protezioni aperture in modalità scrittura*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2,_manage_link, char*, path, int, op){
#else
asmlinkage int sys_manage_link(char* path,int op){
#endif

    int ret;
    
    const struct cred *cred = current_cred();
    struct file *file;
    int  nbytes;
    //ssize_t ret;
    loff_t offset;
    
    printk(KERN_INFO "%s: system call sys_manage_link invocata correttamente con parametri %s %d ", MODNAME, path, op);
    if(rm->state == OFF || rm->state == ON){
        printk("%s: passare allo stato di REC-ON oppure REC-OFF per poter eseguire l'attivita' di inserimento/eliminazione del path", MODNAME);
        return -EPERM;    
    }
    
    if (!uid_eq(cred->euid, GLOBAL_ROOT_UID)){ // Verifica se l'UID effettivo è root
        printk(KERN_INFO "Solo l'UID effettivo root può eseguire l'attivita' di inserimento/eliminazione del path.\n");
        return -EPERM; // Restituisci errore di permesso negato
    }
    
    
    if(op == 0){ //path da aggiungere alla lista
            spin_lock(&lock);
            
            
            new_node = kmalloc(sizeof(struct list_head),GFP_KERNEL);
            if (new_node == NULL) {
                printk("allocation of new node into the list failed/n");
                return -ENOMEM;
            }
            node_ptr = list_entry(new_node, node, list); 
            node_ptr->path = path;
            list_add_tail(new_node, &rm->paths.list);  // Aggiunta del nuovo nodo alla lista
            spin_unlock(&lock);
        
    }
    else if(op == 1){ //path da rimuovere dalla lista
        if(list_empty(&rm->paths.list)){
            printk("%s: the set of paths to protect is empty \n", MODNAME);
            return -EFAULT;
        }

        list_for_each(ptr, &rm->paths.list) {
            node_ptr = list_entry(ptr, node, list); //utilizza internamente container_of()
            if(strcmp(node_ptr->path , path) == 0){ //qui andrebbe il path dato dall'utente
                list_del(ptr);
                printk("%s: path removed correctly \n", MODNAME);
                return 0;
            }           
        }
        printk("%s: path to remove not found \n", MODNAME);
        return -EINVAL;

    }
    else{ //visualizzo la lista dei path da proteggere da
        if(list_empty(&rm->paths.list)){
            printk("%s: the set of paths to protect is empty \n", MODNAME);
            return -EFAULT;
        }

        printk("%s: lista dei path che non sono accessibili in scrittura", MODNAME);

        list_for_each(ptr, &rm->paths.list) {
            node_ptr = list_entry(ptr, node, list); //utilizza internamente container_of()
                       
            printk(KERN_ALERT "(list %p, value %s, prev = %p, next = %p) \n",ptr,node_ptr->path, ptr->prev, ptr->next); 
                        
        }
    }

return 0;

}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
static unsigned long sys_switch_state = (unsigned long) __x64_sys_switch_state;	
static unsigned long sys_manage_link = (unsigned long) __x64_sys_manage_link;	
#endif


unsigned long systemcall_table=0x0;
module_param(systemcall_table,ulong,0660);
int free_entries[15];
module_param_array(free_entries,int,NULL,0660);



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

static int sys_open_wrapper(struct kprobe *ri, struct pt_regs *regs){
        //where to look at when searching system call parmeters
    printk("filp_open \n ");
    if(rm->state == OFF || rm->state == REC_OFF){
        goto reject;
    }
    list_for_each(ptr, &rm->paths.list) {
            node_ptr = list_entry(ptr, node, list);
            //if(strcmp("/home/zudelino/Documenti/GitHub/ReferenceMonitor/FSReferenceMonitor/utils/test.txt", node_ptr->path) == 0){
                write_to_file("file test in utils aperto", "./test.txt");
                return 0;
            //}
    }

    return 0;
reject:
    regs->di = NULL;
    return 0;
}

unsigned long * nisyscall;

/*static struct kprobe kp = {
        .symbol_name =  target_func,
        .pre_handler = sys_open_wrapper,
};*/

static struct kretprobe retprobe;

int init_module(void) {
    unsigned long ** sys_call_table;
    int ret = 0;
     int  nbytes;
     char * buffer;
    loff_t offset = 0;
     size_t count1;
    rm =  kmalloc(sizeof(ref_mon), GFP_KERNEL);

    retprobe.kp.symbol_name = target_func;
	retprobe.handler = (kretprobe_handler_t) NULL;
	retprobe.entry_handler = (kretprobe_handler_t)sys_open_wrapper;
	retprobe.maxactive = -1; //lets' go for the default number of active kretprobes manageable by the kernel

	ret = register_kretprobe(&retprobe);
	if (ret < 0) {
		printk("%s: hook init failed , returned %d\n", MODNAME, ret);
		return ret;
	}
    
    INIT_LIST_HEAD(&rm->paths.list); //inizializzo la struttura list_head in rm
    rm->state = REC_ON;//parto nello stato OFF
    
    /*buffer = kzalloc(sizeof(char)*500, GFP_ATOMIC);
    rm->log_file = filp_open("./Single_fs/mount/the-file", O_RDWR, 0);
	if (IS_ERR(rm->log_file)) {
    printk(KERN_ERR "%s: Failed to open file\n", MODNAME);
    return PTR_ERR(rm->log_file);
    }

    ret = rm->log_file->f_op->write(rm->log_file,buffer,count1,rm->log_file->f_pos);
    if(IS_ERR(ret)){
        printk(KERN_ERR "%s: Failed to read file: %d\n", MODNAME, ret);
    return PTR_ERR(rm->log_file);
    }
    printk(KERN_INFO "ret %d write data to file: %s\n", ret, buffer);

    // Chiudi il file
    filp_close(rm->log_file, NULL);*/


    /*nbytes = strlen("file_body");
	//ret = vfs_write(rm->log_file, "file_body", nbytes, 0);
    // Scrivi dati sul file utilizzando la funzione di scrittura del tuo file system
    ret = rm->log_file->f_op->write(rm->log_file,"file_body", nbytes, rm->log_file->f_pos);
    if (ret != nbytes) {
		printk("Writing file has failed.\n");
		return -1;
	}

     printk("%s: log file written with success\n", MODNAME);*/

    //if(!try_module_get(THIS_MODULE)) return -1;
    if(systemcall_table!=0){
        cr0 = read_cr0();
        unprotect_memory();
        sys_call_table = (void*) systemcall_table; 
        nisyscall = sys_call_table[free_entries[0]]; //mi serve poi nel cleanup
        sys_call_table[free_entries[0]] = (unsigned long*)sys_switch_state;
        sys_call_table[free_entries[1]] = (unsigned long*)sys_manage_link;
        protect_memory();
    }else{
        printk("%s: system call table non trovata\n", MODNAME);
        return -1;
    }
    
   
    //ret = register_kprobe(&kp);
    
        printk("%s: module correctly mounted\n", MODNAME);    
        return ret;

}

void cleanup_module(void) {
    int ret;
    unsigned long ** sys_call_table;
    //module_put(THIS_MODULE);

    /*restore system call table*/
    cr0 = read_cr0();
    unprotect_memory();
    sys_call_table = (void*) systemcall_table; 
    sys_call_table[free_entries[0]] = nisyscall;
    sys_call_table[free_entries[1]] = nisyscall;
    protect_memory();   

    
    //unregister kprobe
    //unregister_kprobe(&kp); 
     unregister_kretprobe(&retprobe);
    
    
    kfree(rm);

    printk("%s: shutting down\n",MODNAME);

}
  

  