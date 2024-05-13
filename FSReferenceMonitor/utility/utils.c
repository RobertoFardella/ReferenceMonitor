#include <linux/key.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include "./../referenceMonitor.h"

int calculate_crypto_hash(const char *content, unsigned char* hash) 
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    int ret;

    if(!content || ! hash) return -EINVAL;
    
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

char *file_content_fingerprint(char *pathname) {
        struct crypto_shash *hash_tfm;
        struct file *file;
        struct shash_desc *desc;
        unsigned char *digest;
        char *result = NULL;
        loff_t pos = 0;
        int ret, i;

        hash_tfm = crypto_alloc_shash("sha256", 0, 0); // hash sha256 allocation
        if (IS_ERR(hash_tfm)) {
                pr_err("Failed to allocate hash transform\n");
                return NULL;
        }

        file = filp_open(pathname, O_RDONLY, 0);
        if (IS_ERR(file)) {
                printk("%s: file not opened correctly, hash failed\n", MODNAME);
                crypto_free_shash(hash_tfm);
                return NULL;
        }

        /* hash descriptor allocation */
        desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(hash_tfm), GFP_KERNEL);
        if (!desc) {
                printk("Failed to allocate hash descriptor\n");
                goto out;
        }
        desc->tfm = hash_tfm;

        /* digest allocation */
        digest = kmalloc(32, GFP_KERNEL);
        if (!digest) {
                printk("Failed to allocate hash buffer\n");
                goto out;
        }

        /* hash computation */
        crypto_shash_init(desc);
        while (1) {
                char buf[512];
                ret = kernel_read(file, buf, sizeof(buf), &pos);
                if (ret <= 0)
                break;
                crypto_shash_update(desc, buf, ret);
        }
        crypto_shash_final(desc, digest);

        /* result allocation */
        result = kmalloc(2 * 32 + 1, GFP_KERNEL);
        if (!result) {
                printk("Failed to allocate memory for result\n");
                goto out;
        }

        for (i = 0; i < 32; i++)
                sprintf(&result[i * 2], "%02x", digest[i]);
                
out:
        if (digest)
                kfree(digest);
        if (desc)
                kfree(desc);
        if (file)
                filp_close(file, NULL);
        if (hash_tfm)
                crypto_free_shash(hash_tfm);

        return result;
}

struct inode *get_parent_inode(struct inode *file_inode) {
    struct dentry *dentry;
    struct inode *parent_inode = NULL;

    if(!file_inode) return NULL;

    dentry = d_find_alias(file_inode);
    if(!dentry)   return NULL;

    if (dentry->d_parent) {
        parent_inode = dentry->d_parent->d_inode;
        dput(dentry);
    }
    return parent_inode;
}

char* password_hash(char* pw){
    unsigned char *pw_digest = kmalloc(sizeof(SHA256_DIGEST_SIZE * 2 + 1), GFP_KERNEL); 
    char buffer[SHA256_DIGEST_SIZE * 2 + 1];
    int ret,i, offset = 0;
    
    printk("pw inserita dall'utente: %s", pw);
    //encryption password phase

    ret = calculate_crypto_hash(pw, pw_digest);

    if(ret < 0){
        printk("%s: crypto digest not computed\n", MODNAME);
        kfree(pw_digest);
        return NULL;
    }

    for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
        offset += snprintf(buffer + offset, sizeof(buffer) - offset, "%02x", pw_digest[i]); 
    }

    buffer[offset] = '\0'; 
    
    kfree(pw_digest);
    return kstrdup(buffer, GFP_KERNEL);
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

void logging_information(ref_mon* rm, struct log_info* log_info){
    static packed_work pkd_work;
    const struct cred *cred;
    cred = current_cred();

    pkd_work.log_info.real_uid = cred->uid;
    pkd_work.log_info.effect_uid = cred->euid;
    pkd_work.log_info.tid = current->pid;
    pkd_work.log_info.tgid = current->tgid;
    pkd_work.log_info.pathname =log_info->pathname;
    
    INIT_WORK(&pkd_work.work, deferred_logger_handler);
    queue_work(rm->queue_work, &pkd_work.work);
    return;
}

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



char *safe_copy_from_user(char* src_buffer){
    int ret;
    void *addr;
    char* pw_buffer;
    int size;
    size = strlen(src_buffer);

    addr = (void*)get_zeroed_page(GFP_KERNEL);
    if (!addr) {
        printk("%s: kernel page allocation failed\n", MODNAME);
        return NULL;
    }

    ret = copy_from_user((char*)addr, src_buffer,size);
    pw_buffer = kstrndup((char*)addr, size - ret, GFP_KERNEL);
    if(!pw_buffer) {
        printk("%s: kernel memory allocation failed\n", MODNAME);
        return NULL;
    }
    pw_buffer[size - ret] = '\0';

    printk("%s", pw_buffer);
    

    /*if(size == 0){
        printk("%s:user buffer is empty\n", MODNAME);
        return NULL;
    }*/
    
    free_pages((unsigned long)addr,0);

    return pw_buffer;
}