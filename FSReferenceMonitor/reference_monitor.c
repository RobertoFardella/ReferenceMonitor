#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/module.h>
#include<linux/mount.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <linux/unistd.h> // Include per geteuid()
#include <linux/cred.h>
#include <linux/namei.h> //kern_path()
#include <linux/path.h>


#include "referenceMonitor.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Roberto Fardella <roberto.fard@gmail.com>");
MODULE_DESCRIPTION("Linux Security Module (LSM) for file protection");

#define MODNAME "reference_monitor"
#define PERMS 0644
#define SHA256_DIGEST_SIZE 16
#define MAX_PW_SIZE 64


/* The kernel functions we want to hooks: */

const char* do_filp_open_func = "do_filp_open";
const char* security_inode_create_hook_name = "security_inode_create";
const char* security_inode_link_hook_name = "security_inode_link";
const char* security_inode_unlink_hook_name = "security_inode_unlink";
const char* security_inode_symlink_hook_name = "security_inode_symlink";
const char* security_inode_rmdir_hook_name = "security_inode_rmdir";
const char* security_inode_mknod_hook_name = "security_inode_mknod";
const char* security_inode_mkdir_hook_name = "security_inode_mkdir" ;
const char* security_inode_rename_hook_name = "security_inode_rename";
static int set_pw = 0;

unsigned long *nisyscall;
unsigned long cr0;

static int the_hook(struct kretprobe_instance  *ri, struct pt_regs *regs);
static int do_filp_open_hook(struct kretprobe_instance  *ri, struct pt_regs *regs);
static int inode_create_pre_hook(struct kretprobe_instance  *ri, struct pt_regs *regs);
static int inode_link_pre_hook(struct kretprobe_instance  *ri, struct pt_regs *regs);
static int inode_unlink_pre_hook(struct kretprobe_instance  *ri, struct pt_regs *regs);
static int inode_symlink_pre_hook(struct kretprobe_instance  *ri, struct pt_regs *regs);
static int inode_mkdir_pre_hook(struct kretprobe_instance  *ri, struct pt_regs *regs);
static int inode_rmdir_pre_hook(struct kretprobe_instance  *ri, struct pt_regs *regs);
static int inode_mknod_pre_hook(struct kretprobe_instance  *ri, struct pt_regs *regs);
static int inode_rename_pre_hook(struct kretprobe_instance  *ri, struct pt_regs *regs);

// Utility function to initialize a kretprobe data
#define declare_kretprobe(NAME, ENTRY_CALLBACK, EXIT_CALLBACK, DATA_SIZE) \
static struct kretprobe NAME = {                                          \
 .handler = (kretprobe_handler_t) EXIT_CALLBACK,                           \
 .entry_handler = (kretprobe_handler_t) ENTRY_CALLBACK,      \
 .data_size = DATA_SIZE,       \
 .maxactive = -1,       \
};

// Utility function to register a kretprobe with error handling
#define set_kretprobe(KPROBE)                                                       \
do {                                                                                \
    if(register_kretprobe(KPROBE)) {                                                \
        printk(KERN_ERR "%s: unable to register a probe\n", MODNAME);                        \
        return -EINVAL;                                                             \
    }                                                                               \
} while(0)

declare_kretprobe(do_filp_open_probe, NULL, do_filp_open_hook, 0);
declare_kretprobe(security_inode_create_probe, inode_create_pre_hook, the_hook, 0);
declare_kretprobe(security_inode_link_probe, inode_link_pre_hook, the_hook, 0);
declare_kretprobe(security_inode_unlink_probe, inode_unlink_pre_hook, the_hook, 0);
declare_kretprobe(security_inode_symlink_probe, inode_symlink_pre_hook, the_hook, 0);
declare_kretprobe(security_inode_rmdir_probe, inode_rmdir_pre_hook, the_hook, 0);
declare_kretprobe(security_inode_mkdir_probe, inode_mkdir_pre_hook, the_hook, 0);
declare_kretprobe(security_inode_mknod_probe, inode_mknod_pre_hook, the_hook, 0);
declare_kretprobe(security_inode_rename_probe, inode_rename_pre_hook, the_hook, 0);

/*sys_switch_state: cambiamento dello stato del reference monitor*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(4,_switch_state, enum rm_state, state, char* , pw, size_t, size, int, init_pw){
#else
asmlinkage int sys_switch_state(enum state, char*  pw, size_t size, int init_pw){
#endif
    int ret, i, offset = 0;
    const struct cred *cred = current_cred();
    char pw_buffer[MAX_PW_SIZE];
    char buffer[SHA256_DIGEST_SIZE * 2 + 1]; // Il buffer per contenere l'output esadecimale dei byte più il terminatore di stringa
    void *addr;
    unsigned char* hash_digest = kmalloc(SHA256_DIGEST_SIZE*2 + 1, GFP_KERNEL); 

    if (!uid_eq(cred->euid, GLOBAL_ROOT_UID)){ // Verifica se l'UID effettivo è root
        printk(KERN_INFO "Solo l'UID effettivo root può cambiare lo stato.\n");
        return -EPERM; // Restituisci errore di permesso negato (-1)
    }
    
    if(size >= (MAX_PW_SIZE -1) || size <= 0) { //check passwrd size
        printk("%s: invalid pw size!\n", MODNAME);
        return -EINVAL; 
    }

    addr = (void*)get_zeroed_page(GFP_KERNEL);
    if (!addr) {
        printk("allocation failed\n");
        return -ENOMEM;
    }

    if((set_pw == 1 && init_pw == 1) || (set_pw == 0 && init_pw == 0)) {
        printk("%s: initialize pw failed\n", MODNAME);
        return -EINVAL;} //la pw deve ancora essere settata oppure è stata già settata

    ret = copy_from_user((char*)addr, pw, (int) size);
    memcpy(pw_buffer,(char*)addr,size-ret);
    pw_buffer[size - ret] = '\0';
    
    free_pages((unsigned long)addr,0);

    if (calculate_hash(pw_buffer, hash_digest)  < 0) {  // calcolo dell'hash della password
        printk(KERN_INFO "%s: pw's hash failed.\n", MODNAME);
        return -ERANGE;	/* Math result not representable 34*/
    }
        
    for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
        offset += snprintf(buffer + offset, sizeof(buffer) - offset, "%02x", hash_digest[i]); // Formattare due caratteri esadecimali per ogni byte
    }

    buffer[offset] = '\0'; // Aggiungi il terminatore di stringa
    
    if(set_pw == 0) {
        strcpy(rm->pw_hash, buffer);
        set_pw = 1;
    }
    printk(KERN_INFO "\nHash della password :  %s", rm->pw_hash);
    if(init_pw != 0) return rm->state;
    
    if( strcmp(rm->pw_hash, buffer)!= 0 ) 
    {   
        printk("%s: mismatch della password \n", MODNAME);
        return -ENOEXEC;  /* Exec format error */
        }
        
    if(rm->state == state) {
        printk("lo stato inserito e' gia' quello corrente \n");
        return -EINVAL;
    }

    switch (state)
    {
      case ON:
        printk(KERN_INFO  "lo stato inserito e' ON ");
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
        return -EINVAL;
    }
    return rm->state;
}

/*sys_add_or_remove_link: aggiunta o rimozione del path all'insieme da protezioni aperture in modalità scrittura*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2,_manage_link, char*, pathname, int, op){
#else
asmlinkage int sys_manage_link(char* pathname,int op){
#endif

    int ret;
    const struct cred *cred = current_cred();
    struct inode *inode;
    node * node_ptr;
    struct list_head *ptr;
    struct path struct_path;
    //printk(KERN_INFO "%s: system call sys_manage_link invocata correttamente con parametri %s %d \n ", MODNAME, pathname, op);
    
    if (!uid_eq(cred->euid, GLOBAL_ROOT_UID)){ // Verifica se l'UID effettivo è root
        printk(KERN_INFO "Solo l'UID effettivo root può eseguire l'attivita' di inserimento/eliminazione del path.\n");
        return -EPERM; // Restituisci errore di permesso negato
    }

    if(rm->state == OFF || rm->state == ON){
        printk("%s: passare allo stato di REC-ON oppure REC-OFF per poter eseguire l'attivita' di inserimento/eliminazione del path \n", MODNAME);
        return -EINVAL;    
    }

    if(!rm->pw_hash) {  
        return -EINVAL; //la pw deve ancora essere settata
        printk("%s: password not initiliazed\n" , MODNAME);
    }

    if(op == 0){ //path da aggiungere alla lista
            spin_lock(&rm->lock);
            struct list_head * new_node_lh = kmalloc(sizeof(struct list_head), GFP_KERNEL);
            if (new_node_lh == NULL) {
                spin_unlock(&rm->lock);
                printk("allocation of new node into the list failed \n");
                return -ENOMEM;
            }
            
            node_ptr = list_entry(new_node_lh, node, elem); 
            node_ptr->path = pathname;
            if(kern_path(pathname, LOOKUP_RCU , &struct_path ) != 0 ){
                 spin_unlock(&rm->lock);
                 printk("kern_path failed, the file or directory doesn't exists \n");
                 return -ENOMEM;
            }
            
            inode =  struct_path.dentry->d_inode; //retrieve inode from kern_path
            //check if inode is already present 
            node *node_ptr_aux;
            list_for_each(ptr, &rm->blk_head_node.elem) {
                node_ptr_aux = list_entry(ptr, node, elem);
                
                if(node_ptr_aux->inode_cod == inode->i_ino){
                    printk("inode %lu is already present that belongs to %s  \n", node_ptr->inode_cod, node_ptr->path);
                    spin_unlock(&rm->lock);
                    return -EINVAL;
                }
            }
            node_ptr->inode_cod = inode->i_ino;
            node_ptr->inode_blk = inode;
            node_ptr->dentry_blk = struct_path.dentry;
            list_add_tail(new_node_lh, &rm->blk_head_node.elem);  // Aggiunta del nuovo nodo alla lista

            spin_unlock(&rm->lock);
    }
    
    else if(op == 1){ //ELIMINAZIONE
        spin_lock(&rm->lock);
        if(list_empty(&rm->blk_head_node.elem)){
            spin_unlock(&rm->lock);
            return -EFAULT;
        }
        list_for_each(ptr, &rm->blk_head_node.elem) {
            node_ptr = list_entry(ptr, node, elem);
            if(strcmp(node_ptr->path , pathname) == 0){ //qui andrebbe il path dato dall'utente
                
                list_del(ptr);
                spin_unlock(&rm->lock);
                printk("%s: path removed correctly \n", MODNAME);
                return 0;
            }           
        }
        spin_unlock(&rm->lock);
        printk("%s: path to remove not found \n", MODNAME);
        return -EINVAL;
    }
    else{ //ENUMERAZIONE
        spin_lock(&rm->lock);
        if(list_empty(&rm->blk_head_node.elem)){
            spin_unlock(&rm->lock);
            printk("%s: the set of blk_head_node to protect is empty \n", MODNAME);
            return -EFAULT;
        }

        printk("%s: blacklist:\n", MODNAME);
        list_for_each(ptr, &rm->blk_head_node.elem) {
            node_ptr = list_entry(ptr, node, elem); 
            printk(KERN_ALERT "(address element %p, inode->i_ino %lu, path %s, inode %p, dentry %p, prev = %p, next = %p) \n",ptr, node_ptr->inode_cod, node_ptr->path, node_ptr->inode_blk, node_ptr->dentry_blk, ptr->prev, ptr->next); 
                        
        }
        spin_unlock(&rm->lock);
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

/* int security_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
Parameters
struct inode *dir - the parent directory
struct dentry *dentry - the file being created
umode_t mode - requested file mode
Description
Check permission to create a regular file. 
dir contains inode structure of the parent of the new file. 
dentry contains the dentry structure for the file to be created.
 mode contains the file mode of the file to be created.
Returns 0 if permission is granted.

*/
int inode_create_pre_hook(struct kretprobe_instance  *ri, struct pt_regs *regs){
    struct inode* parent_inode = regs->di;
    struct dentry* dentry_created = regs->si;
    struct dentry* parent_dentry;
    node* node_ptr_h;
    struct list_head* ptr_h;

      spin_lock(&rm->lock);
      if(list_empty(&rm->blk_head_node.elem) || ((rm->state == REC_OFF || rm->state == OFF ))) goto leave;
        parent_dentry = d_find_alias(parent_inode);
        list_for_each(ptr_h, &rm->blk_head_node.elem) {
            node_ptr_h = (node*)list_entry(ptr_h, node, elem);
            if(!node_ptr_h) goto leave;
            if((parent_inode->i_ino == node_ptr_h->inode_cod)|| (is_subdir(parent_dentry,node_ptr_h->dentry_blk))){
                        printk("%s: vfs_create denied\n ", MODNAME);
                        spin_unlock(&rm->lock);
                        return 0;
            }
         }
leave:
    spin_unlock(&rm->lock);
    return 1; 
}

/*int security_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry);
   called in vfs_link - create a new link
 * @old_dentry:	object to be linked
 * @mnt_userns:	the user namespace of the mount
 * @dir:	new parent
 * @new_dentry:	where to create the new link
 * @delegated_inode: returns inode needing a delegation break
 * 
 * @description: Check permission before creating a new hard link to a file. 
 * old_dentry contains the dentry structure for an existing link to the file. 
 * dir contains the inode structure of the parent directory of the new link. 
 * new_dentry contains the dentry structure for the new link. 
 * */

int inode_link_pre_hook(struct kretprobe_instance  *ri, struct pt_regs *regs){
    struct dentry* old_dentry = regs->di; //dentry structure for an existing link to the file
    struct inode* parent_inode = regs->si; //parent inode dir of the new link
    //struct dentry* new_dentry = regs->dx; // dentry structure for the new link
    //struct inode* inode = old_dentry->d_inode;
    node* node_ptr_h;
    struct list_head* ptr_h;
    spin_lock(&rm->lock);
    if(list_empty(&rm->blk_head_node.elem) || ((rm->state == REC_OFF || rm->state == OFF ))) goto leave;
    struct dentry* parent_dentry = d_find_alias(parent_inode);
    list_for_each(ptr_h, &rm->blk_head_node.elem) {
            node_ptr_h = (node*)list_entry(ptr_h, node, elem);
            if(!node_ptr_h) goto leave;
            if(node_ptr_h->inode_cod == old_dentry->d_inode->i_ino || (is_subdir(parent_dentry,node_ptr_h->dentry_blk))){
                        printk("%s: vfs_link denied\n ", MODNAME);
                        spin_unlock(&rm->lock);
                        return 0;
            }
         }
leave:
    spin_unlock(&rm->lock);
    return 1;
}
/*int security_inode_unlink(struct inode *dir, struct dentry *dentry) 
 * called in vfs_unlink - unlink a filesystem object
 * @dir:	parent directory
 * @dentry:	victim
 * 
 * @description: Check the permission to remove a hard link to a file. 
 * dir contains the inode structure of parent directory of the file. 
 * dentry contains the dentry structure for file to be unlinked.
 *  Return 0 if permission is granted.
 * */
int inode_unlink_pre_hook(struct kretprobe_instance  *ri, struct pt_regs *regs){
        struct inode* parent_inode = regs->di; //parent inode dir 
        struct dentry* dentry = regs->si; //dentry for file to be unlinked
         node* node_ptr_h;
        struct list_head* ptr_h;
        spin_lock(&rm->lock);
        if(list_empty(&rm->blk_head_node.elem) || ((rm->state == REC_OFF || rm->state == OFF ))) goto leave;
        struct dentry* parent_dentry = d_find_alias(parent_inode); //dentry structure for an existing link to the file
        list_for_each(ptr_h, &rm->blk_head_node.elem) {
            node_ptr_h = (node*)list_entry(ptr_h, node, elem);
            
            if((dentry->d_inode->i_ino == node_ptr_h->inode_cod) || (is_subdir(parent_dentry,node_ptr_h->dentry_blk))){
                        printk("%s: vfs_unlink denied\n ", MODNAME);
                        spin_unlock(&rm->lock);
                        return 0;
            }
         }

leave:
    spin_unlock(&rm->lock);
    return 1;
}
/* int security_inode_symlink(struct inode *dir, struct dentry *dentry, const char *old_name)

 * called in vfs_symlink - create symlink
 * @dir:	inode of @dentry
 * @dentry:	pointer to dentry of the base directory
 * @oldname:	name of the file to link to
 *
 * @description: Check the permission to create a symbolic link to a file. 
 * dir contains the inode structure of parent directory of the symbolic link. 
 * dentry contains the dentry structure of the symbolic link. 
 * old_name contains the pathname of file. Return 0 if permission is granted.
*/
int inode_symlink_pre_hook(struct kretprobe_instance  *ri, struct pt_regs *regs){
    struct inode* parent_inode = (struct inode*)regs->di;
    struct dentry* dentry = (struct dentry*)regs->si;
    char* old_name = (char*)regs->dx;
    node* node_ptr_h;
    struct list_head* ptr_h;
    
    spin_lock(&rm->lock);
    if(list_empty(&rm->blk_head_node.elem) || ((rm->state == REC_OFF || rm->state == OFF ))) goto leave;
    
    list_for_each(ptr_h, &rm->blk_head_node.elem) {
        node_ptr_h = (node*)list_entry(ptr_h, node, elem);
        if(!node_ptr_h) goto leave;
        if(parent_inode->i_ino == (get_parent_inode(node_ptr_h->inode_blk))->i_ino || is_subdir(d_find_alias(parent_inode), node_ptr_h->dentry_blk) ){
                    printk("%s: vfs_symlink denied\n ", MODNAME);
                    spin_unlock(&rm->lock);
                    return 0;
        }
        }
leave:
    spin_unlock(&rm->lock);
    return 1;
}
/* int security_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode) */
/**
 * called in vfs_mkdir - create directory
 * @dir:	inode of @dentry
 * @dentry:	pointer to dentry of the base directory
 *
 * @description:Check permissions to create a new directory in the existing directory associated with inode structure dir. 
 * dir contains the inode structure of parent of the directory to be created. 
 * dentry contains the dentry structure of new directory. 
 * mode contains the mode of new directory. Return 0 if permission is granted.
 * 
 * */
int inode_mkdir_pre_hook(struct kretprobe_instance  *ri, struct pt_regs *regs){
    struct inode* parent_inode = (struct inode*)regs->di;
    struct dentry* dentry = (struct dentry*)regs->si;
    node* node_ptr_h;
    struct list_head* ptr_h;
    spin_lock(&rm->lock);
    if(list_empty(&rm->blk_head_node.elem) || ((rm->state == REC_OFF || rm->state == OFF ))) goto leave;
    struct dentry* parent_dentry= d_find_alias(parent_inode);
    list_for_each(ptr_h, &rm->blk_head_node.elem) {
            node_ptr_h = (node*)list_entry(ptr_h, node, elem);
            if(!node_ptr_h) goto leave;
            if((parent_dentry->d_inode->i_ino == (get_parent_inode(node_ptr_h->inode_blk))->i_ino) || (is_subdir(parent_dentry,node_ptr_h->dentry_blk))){
                        printk("%s: vfs_mkdir denied\n ", MODNAME);
                        spin_unlock(&rm->lock);
                        return 0;
            }
         }
leave:
    spin_unlock(&rm->lock);
    return 1;
}
/*int security_inode_rmdir(struct inode *dir, struct dentry *dentry) 
 * called in vfs_rmdir - remove directory
 * @dir:	inode of @dentry
 * @dentry:	pointer to dentry of the base directory
 *
 * @description:Check the permission to remove a directory. 
 * dir contains the inode structure of parent of the directory to be removed. 
 * dentry contains the dentry structure of directory to be removed. 
 * Return 0 if permission is granted.
 * 
*/
int inode_rmdir_pre_hook(struct kretprobe_instance  *ri, struct pt_regs *regs){
    struct inode* parent_inode = (struct inode*)regs->di;
    struct dentry* dentry = (struct dentry*)regs->si;
    node* node_ptr_h;
    struct list_head* ptr_h;
    spin_lock(&rm->lock);
    if(list_empty(&rm->blk_head_node.elem) || ((rm->state == REC_OFF || rm->state == OFF ))) goto leave;

     list_for_each(ptr_h, &rm->blk_head_node.elem) {
            node_ptr_h = (node*)list_entry(ptr_h, node, elem);
            if(!node_ptr_h) goto leave;
            if(dentry->d_inode->i_ino == node_ptr_h->inode_cod || (is_subdir(dentry,node_ptr_h->dentry_blk))){
                        printk("%s: vfs_rmdir denied\n ", MODNAME);
                        spin_unlock(&rm->lock);
                        return 0;
            }
         }

leave:
    spin_unlock(&rm->lock);
    return 1;
}

/* int security_inode_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)*/
/**
 * called into vfs_mknod - create device node or file
 * @dir:	inode of @dentry
 * @dentry:	pointer to dentry of the base directory
 * @mode:	mode of the new device node or file
 * @dev:	device number of device to create
 * @description: Check permissions when creating a special file (or a socket or a fifo file created via the mknod system call). 
 * Note that if mknod operation is being done for a regular file, then the create hook will be called and not this hook. 
 * dir contains the inode structure of parent of the new file. dentry contains the dentry structure of the new file. 
 * mode contains the mode of the new file. 
 * dev contains the device number. Return 0 if permission is granted.
 */
int inode_mknod_pre_hook(struct kretprobe_instance  *ri, struct pt_regs *regs){
    struct inode* inode = regs->di;
    node* node_ptr_h;
    struct list_head* ptr_h;
    spin_lock(&rm->lock);
    if(list_empty(&rm->blk_head_node.elem) || ((rm->state == REC_OFF || rm->state == OFF ))) goto leave;

     list_for_each(ptr_h, &rm->blk_head_node.elem) {
            node_ptr_h = (node*)list_entry(ptr_h, node, elem);
            if(!node_ptr_h) goto leave;
            if(inode->i_ino == node_ptr_h->inode_cod || (is_subdir(d_find_alias(inode),node_ptr_h->dentry_blk))){
                        printk("%s: vfs_rmdir denied\n ", MODNAME);
                        spin_unlock(&rm->lock);
                        return 0;
            }
         }


leave:
    spin_unlock(&rm->lock);
    return 1;
}
/*int security_inode_rename(struct inode *old_dir, struct dentry *old_dentry,struct inode *new_dir, struct dentry *new_dentry, unsigned int flags) 
 * called in vfs_rename - rename a filesystem object
 * @description: Check for permission to rename a file or directory. 
 * old_dir contains the inode structure for parent of the old link. 
 * old_dentry contains the dentry structure of the old link. 
 * new_dir contains the inode structure for parent of the new link. 
 * new_dentry contains the dentry structure of the new link. Return 0 if permission is granted.
 * */
int inode_rename_pre_hook(struct kretprobe_instance  *ri, struct pt_regs *regs){
    struct  dentry* old_dentry = (struct dentry*)regs->si;
    //struct dentry* new_dentry = (struct dentry*)regs->cx;
    struct inode* old_inode = old_dentry->d_inode;
    //struct inode* new_inode = new_dentry->d_inode;
    node* node_ptr_h;
    struct list_head* ptr_h;

    spin_lock(&rm->lock);
    if(list_empty(&rm->blk_head_node.elem) || ((rm->state == REC_OFF || rm->state == OFF ))) goto leave;
     list_for_each(ptr_h, &rm->blk_head_node.elem) {
            node_ptr_h = (node*)list_entry(ptr_h, node, elem);
            if(!node_ptr_h) goto leave;
            if(old_inode->i_ino == node_ptr_h->inode_cod){
                        printk("%s: vfs_rename denied\n ", MODNAME);
                        spin_unlock(&rm->lock);
                        return 0;
                 
            }
         }
leave:
    spin_unlock(&rm->lock);
    return 1;
}


int do_filp_open_hook(struct kretprobe_instance  *ri, struct pt_regs *regs){
        struct file * filp = (struct file*) regs_return_value(regs);
        node * node_ptr_h;
        struct list_head *ptr_h;
        
        if(IS_ERR(filp) || !filp) return 0;      
                                        
        spin_lock(&rm->lock);
        if(list_empty(&rm->blk_head_node.elem) || ((rm->state == REC_OFF || rm->state == OFF ))) goto leave;
        unsigned int f_flags = filp->f_flags;    
        /*list_for_each(ptr_h, &rm->blk_head_node.elem) {
            node_ptr_h = (node*)list_entry(ptr_h, node, elem);
            if(!node_ptr_h) goto leave;
            if((node_ptr_h->inode_cod  == filp->f_inode->i_ino) &&  !(f_flags & O_RDONLY)){  
                    spin_unlock(&rm->lock);
                    regs->ax = -EACCES;
                    return 0;
            }
        }*/
leave:
        spin_unlock(&rm->lock);
         return 0;
         //TODO: scrivere la funzione che in deferred work scrive sul file di log
}

/* The_hook function is the exit handler shared among all the kretprobes.
It blocks any attempt to write access and performs deferred work to write 
various log information to a file.
*/
int the_hook(struct kretprobe_instance  *ri, struct pt_regs *regs){
         regs->ax = -EACCES; 
         return 0;
         //TODO: scrivere la funzione che in deferred work scrive sul file di log
}

void logger_handler(struct work_struct *data){ //dovrei farla static?

    return;
}


int init_module(void) {
    unsigned long ** sys_call_table;
    int ret = 0;
    
    rm =  kmalloc(sizeof(ref_mon), GFP_KERNEL); //alloc memory and setup reference monitor struct
    rm->pw_hash = kmalloc(sizeof(char)*MAX_PW_SIZE, GFP_KERNEL);
    rm->state = REC_ON;// init state of reference monitor
    INIT_LIST_HEAD(&rm->blk_head_node.elem); 
    rm->packed_work.queue = alloc_workqueue("HELLOWORLD", WQ_UNBOUND, 1); 
    INIT_WORK(&rm->packed_work.work, logger_handler); 
    queue_work(rm->packed_work.queue, &rm->packed_work.work);

    do_filp_open_probe.kp.symbol_name = do_filp_open_func;
    security_inode_create_probe.kp.symbol_name = security_inode_create_hook_name;
    security_inode_link_probe.kp.symbol_name = security_inode_link_hook_name;
    security_inode_unlink_probe.kp.symbol_name = security_inode_unlink_hook_name;
    security_inode_symlink_probe.kp.symbol_name = security_inode_symlink_hook_name;
    security_inode_rmdir_probe.kp.symbol_name = security_inode_rmdir_hook_name;
    security_inode_mkdir_probe.kp.symbol_name = security_inode_mkdir_hook_name;
    security_inode_mknod_probe.kp.symbol_name = security_inode_mknod_hook_name;
    security_inode_rename_probe.kp.symbol_name = security_inode_rename_hook_name;

    //set_kretprobe(&retprobe);
    set_kretprobe(&do_filp_open_probe);
    set_kretprobe(&security_inode_create_probe);
    set_kretprobe(&security_inode_link_probe);
    set_kretprobe(&security_inode_unlink_probe);
    set_kretprobe(&security_inode_symlink_probe);
    set_kretprobe(&security_inode_rmdir_probe);
    set_kretprobe(&security_inode_mkdir_probe);
    set_kretprobe(&security_inode_mknod_probe);
    set_kretprobe(&security_inode_rename_probe);


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
        printk("%s: system call table not avalaible\n", MODNAME);
        return -1;
    }
    
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

    unregister_kretprobe(&do_filp_open_probe);
    unregister_kretprobe(&security_inode_create_probe);
    unregister_kretprobe(&security_inode_link_probe);
    unregister_kretprobe(&security_inode_unlink_probe);
    unregister_kretprobe(&security_inode_symlink_probe);
    unregister_kretprobe(&security_inode_rmdir_probe);
    unregister_kretprobe(&security_inode_mkdir_probe);
    unregister_kretprobe(&security_inode_mknod_probe);
    unregister_kretprobe(&security_inode_rename_probe);
    
    destroy_workqueue(rm->packed_work.queue); 
    kfree(rm);

    printk("%s: shutting down\n",MODNAME);
}
  

  /*setattr
called by the VFS to set attributes for a file. This method is called by chmod(2) and related system calls*/