#include <linux/key.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/hash.h>
#include <linux/unistd.h> 
#include "./../referenceMonitor.h"

int write_to_file(char * content, char * filepath ) {
    struct file *file;
    int ret = 0;
    size_t len = strlen(content);

    file = filp_open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (IS_ERR(file)) {
        printk(KERN_ERR "Impossibile aprire il file per la scrittura\n");
        return -1;
    }
    ret = kernel_write(file, content, len, &file->f_pos);
    if (ret < 0) {
        printk(KERN_ERR "Errore durante la scrittura sul file\n");
    }
    filp_close(file, NULL);

    return ret;
}

int calculate_hash(const char *content, unsigned char* hash) 
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    int ret;
    
    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);

    desc = kmalloc(sizeof(desc), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }
    desc->tfm = tfm;
    ret = crypto_shash_digest(desc, content, strlen(content), hash);//return 0 if the message digest creation was successful; < 0 if an error occurred
    
    kfree(desc);
    crypto_free_shash(tfm);

    return ret;
}

struct inode *get_parent_inode(struct inode *file_inode) {
    struct dentry *dentry;
    struct inode *parent_inode = NULL;

    dentry = d_find_alias(file_inode);
    if (!dentry)   return NULL;

    if (dentry->d_parent) {
        parent_inode = dentry->d_parent->d_inode;
        dput(dentry);
    }
    return parent_inode;
}

void password_setup(ref_mon *rm){
    int ret;
    char *pw;

}

/*
node* lookup_path_node_blacklist(char* pathname){
    node * node_ptr ;
    struct list_head *ptr;
    list_for_each(ptr, &rm->paths.list) {
            node_ptr = list_entry(ptr, node, list); //utilizza internamente container_of()
            if(strcmp(node_ptr->path , pathname) == 0){ //qui andrebbe il path dato dall'utente
                return node_ptr;
            }           
        }
    return NULL;
}

node* lookup_inode_node_blacklist(struct inode* inode, struct list_head* head){
     node* node_ptr;
     struct list_head* ptr;
    list_for_each(ptr, head) {
            node_ptr = list_entry(ptr, node, elem);
            if(node_ptr->inode_cod == inode->i_ino){                
                return node_ptr;
            }
    }
    return NULL;
}
*/
/*
void logging_information(ref_mon* rm, struct log_info* log_info){
    packed_work pkd_work;
    struct work_struct work;
    const struct cred *cred;
    cred = current_cred();
    printk("ok\n" );
    pkd_work.log_info.real_uid = cred->uid;
    pkd_work.log_info.effect_uid = cred->euid;
    pkd_work.log_info.tid = current->pid;
    pkd_work.log_info.tgid = current->tgid;
    pkd_work.log_info.pathname =log_info->pathname;
    printk("ok\n" );
    INIT_WORK(&work, deferred_logger_handler);
    queue_work(rm->queue_work, &work);
    printk("ok\n" );
    return;
}*/

char *get_path_from_dentry(struct dentry *dentry) {

	char *buffer, *full_path;

        buffer = (char *)__get_free_page(GFP_KERNEL);
        if (!buffer)
                return NULL;

        full_path = dentry_path_raw(dentry, buffer, PATH_MAX);
        if (IS_ERR(full_path)) {
                printk("dentry_path_raw failed\n");
                free_page((unsigned long)buffer);
                return NULL;
        } 

        free_page((unsigned long)buffer);
        return full_path;
}

 

    /*qui provavo a fa la scrittura sul vfs cust
    */

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
