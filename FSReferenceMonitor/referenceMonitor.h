#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/workqueue.h>
static enum rm_state {
    ON,
    OFF,
    REC_ON,
    REC_OFF
};

typedef struct _node{
    struct list_head elem; 
    char* path;
	unsigned long inode_cod;
	struct inode* inode_blk;
	struct dentry* dentry_blk;

} node;

typedef struct _packed_work{
    struct workqueue_struct *queue = NULL; 
    struct work_struct work;
} packed_work;

typedef struct referenceMonitor
{
    enum rm_state state; //possible state (ON, OFF, REC-ON, REC-OFF)
    node blk_head_node; //head node della blacklist
	struct file *log_file;
	char* pw_hash;
	spinlock_t lock; //accessing in concurrently manner in blacklist list_head structure
    packed_work packed_work; 
}ref_mon;

static ref_mon *rm;

//functions defined in ./utility/utils.c
extern int calculate_hash(const char *content, unsigned char* hash);
extern int write_to_file(char * content, char * filepath );
extern struct inode *get_parent_inode(struct inode *file_inode);
extern char *get_path_from_dentry(struct dentry *dentry);
//extern node* lookup_inode_node_blacklist(struct inode* inode,struct list_head* ptr);
//extern node* lookup_path_node_blacklist(char* pathname);

