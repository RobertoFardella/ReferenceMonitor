

#include "referenceMonitor.h"

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

int calculate_hash(const char *content, unsigned char* hash) // Funzione per calcolare l'hash della password
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
