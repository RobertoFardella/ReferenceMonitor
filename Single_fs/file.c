#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/timekeeping.h>
#include <linux/time.h>
#include <linux/buffer_head.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/blk_types.h>
#include <linux/uio.h>
#include <linux/mutex.h>
#include "singlefilefs.h"


#define MODNAME "Single-fs"

#define LOG_FILE_PATH "./mount/the-file"
static DEFINE_MUTEX(offset_mutex); //*off can be changed concurrently 

ssize_t onefilefs_read(struct file * filp, char __user * buf, size_t len, loff_t * off) {

    struct buffer_head *bh = NULL;
    uint64_t file_size;
    int ret;
    loff_t offset;
    int block_to_read;//index of the block to be read from device
     
     if(IS_ERR(filp)){
        printk("%s: error in input file\n",MOD_NAME);
        return len;
     }

     mutex_lock(&offset_mutex);
     file_size = filp->f_inode->i_size;
    //check that *off is within boundaries
    if (*off >= file_size){
        mutex_unlock(&offset_mutex);
        return 0;
    }
    else if (*off + len > file_size)
        len = file_size - *off;

    //determine the block level offset for the operation
    offset = *off % DEFAULT_BLOCK_SIZE; 
    //just read stuff in a single block - residuals will be managed at the applicatin level
    if (offset + len > DEFAULT_BLOCK_SIZE)
        len = DEFAULT_BLOCK_SIZE - offset;

    //compute the actual index of the the block to be read from device
    block_to_read = *off / DEFAULT_BLOCK_SIZE + 2; //the value 2 accounts for superblock and file-inode on device

    bh = (struct buffer_head *)sb_bread(filp->f_path.dentry->d_inode->i_sb, block_to_read);
    if(!bh){
        mutex_unlock(&offset_mutex);
	    return -EIO;
    }
    ret = copy_to_user(buf,bh->b_data + offset, len);  
                                                       
    *off += (len - ret); //incremento di quanti byte effettivamente ho scritto sul file
    brelse(bh);
    mutex_unlock(&offset_mutex);
    
    
    return len - ret;

}

ssize_t onefilefs_write_iter(struct kiocb *iocb, struct iov_iter *from) {
  	struct file *file;
	struct inode *filp_inode;
	loff_t blk_offset, size_file;
    int blk_to_write;
    struct block_device *bdev; 
    struct buffer_head *bh;
	ssize_t ret;
    int start = 0;
    int payload_size; //lunghezza del buffer da scrivere
    char* buffer_data;

    file = iocb->ki_filp;
    payload_size = from->count;

    if(IS_ERR(file)){
        printk("%s: file not open correctly\n",MOD_NAME);
        return payload_size;
     }

     if (!iov_iter_count(from)){ //Check if there is data to write
        printk("%s: no data to write into log file\n", MOD_NAME);
        return payload_size;
    }
    
    buffer_data = kmalloc(payload_size, GFP_KERNEL);
    if(!buffer_data) { 
        printk("%s: memory allocation failed\n", MOD_NAME);
        return -ENOMEM;
    }
    
    ret = copy_from_iter((void*)buffer_data, (size_t) payload_size, from);
    if(ret != payload_size){
        kfree(buffer_data);
        return ret;
    }
    mutex_lock(&offset_mutex);
    filp_inode = file->f_inode; //retrieve the inode of the file
    size_file = i_size_read(filp_inode); //determine the size of the file
    
    blk_offset = size_file % DEFAULT_BLOCK_SIZE;    //determine the block level offset for the operation
    blk_to_write = size_file / DEFAULT_BLOCK_SIZE + 2; //determine the block to write, the value 2 accounts for superblock and file-inode on device

    if(payload_size > DEFAULT_BLOCK_SIZE - blk_offset){ //se la dimensione del buffer da scrivere è superiore allo spazio vuoto all'intenro di un blocco
        bh = (struct buffer_head *)sb_bread(file->f_path.dentry->d_inode->i_sb, blk_to_write);
        if(!bh){
            mutex_unlock(&offset_mutex);
            kfree(buffer_data);
            return -EIO;
        }

        bdev = bh->b_bdev;  /* device where block resides */
        if (bdev->bd_read_only){
            brelse(bh);
            mutex_unlock(&offset_mutex);
            kfree(buffer_data);
            return -EPERM;

        }

        memcpy(bh->b_data + blk_offset, buffer_data,  DEFAULT_BLOCK_SIZE - blk_offset);
        i_size_write(filp_inode, size_file + DEFAULT_BLOCK_SIZE - blk_offset);
        payload_size -= DEFAULT_BLOCK_SIZE - blk_offset;
        start = DEFAULT_BLOCK_SIZE - blk_offset;
        mark_buffer_dirty(bh);
        brelse(bh);
        size_file = i_size_read(filp_inode); 
        blk_offset = 0;
        blk_to_write++;
    }
    
    bh = (struct buffer_head *)sb_bread(file->f_path.dentry->d_inode->i_sb, blk_to_write);
    if(!bh){
        mutex_unlock(&offset_mutex);
        kfree(buffer_data);
	    return -EIO;
    }

    bdev = bh->b_bdev;  /* device where block resides */
    if (bdev->bd_read_only){
        brelse(bh);
        mutex_unlock(&offset_mutex);
		kfree(buffer_data);
        return -EPERM;

    }
    
    if(start == 0)
        memcpy(bh->b_data + blk_offset, buffer_data , payload_size);
        
    else
        memcpy(bh->b_data + blk_offset, buffer_data + start , payload_size);

    i_size_write(filp_inode, size_file + payload_size);
    mark_buffer_dirty(bh);
    brelse(bh);
    mutex_unlock(&offset_mutex);
    kfree(buffer_data);
	return ret;    
}



struct dentry *onefilefs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags) {

    struct onefilefs_inode *FS_specific_inode;
    struct super_block *sb = parent_inode->i_sb;
    struct buffer_head *bh = NULL;
    struct inode *the_inode = NULL;

    if(!strcmp(child_dentry->d_name.name, UNIQUE_FILE_NAME)){
	
	    //get a locked inode from the cache 
        the_inode = iget_locked(sb, 1);
        if (!the_inode)
       		 return ERR_PTR(-ENOMEM);

	    //already cached inode - simply return successfully
        if(!(the_inode->i_state & I_NEW)){
            return child_dentry;
        }
        //this work is done if the inode was not already cached
    #if LINUX_VERSION_CODE <= KERNEL_VERSION(5,12,0)
        inode_init_owner(the_inode, NULL, S_IFREG);
    #elif LINUX_VERSION_CODE < KERNEL_VERSION(6,3,0)
        inode_init_owner(&init_user_ns,the_inode, NULL, S_IFREG);
    #elif LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
        inode_init_owner(&nop_mnt_idmap,the_inode, NULL, S_IFREG);
    #endif
        
        the_inode->i_mode = S_IFREG | S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IXUSR | S_IXGRP | S_IXOTH;
        the_inode->i_fop = &onefilefs_file_operations;
        the_inode->i_op = &onefilefs_inode_ops;

        //just one link for this file
        set_nlink(the_inode,1);

        //now we retrieve the file size via the FS specific inode, putting it into the generic inode
        bh = (struct buffer_head *)sb_bread(sb, SINGLEFILEFS_INODES_BLOCK_NUMBER );
        if(!bh){
            iput(the_inode); // decrementare il contatore dei riferimenti dell'inode specificato
            return ERR_PTR(-EIO);
        }
        FS_specific_inode = (struct onefilefs_inode*)bh->b_data;
        the_inode->i_size = FS_specific_inode->file_size;
        brelse(bh);

        d_add(child_dentry, the_inode);
        dget(child_dentry);

        //unlock the inode to make it usable 
            unlock_new_inode(the_inode);

        return child_dentry;
    }

    return NULL;

}

//look up goes in the inode operations
const struct inode_operations onefilefs_inode_ops = {
    .lookup = onefilefs_lookup,
};

const struct file_operations onefilefs_file_operations = {
    .owner = THIS_MODULE,
    .read = onefilefs_read,
    .write_iter = onefilefs_write_iter, //kernel side
};
