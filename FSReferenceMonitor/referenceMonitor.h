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

struct log_info {
    kuid_t effect_uid;
    kuid_t real_uid;
    pid_t tid;
    pid_t tgid;
    char* pathname;
    char* file_content_hash;
};

typedef struct _packed_work{
    struct work_struct work;
    struct log_info log_info;
    char* buffer;
} packed_work;

typedef struct referenceMonitor
{
    enum rm_state state; //possible state (ON, OFF, REC-ON, REC-OFF)
    node blk_head_node; //blacklist head node 
	struct file *log_file;
    struct workqueue_struct *queue_work;
	char* pw_hash;
	spinlock_t lock; //accessing in concurrently manner in blacklist list_head structure
     
}ref_mon;


//functions defined in ./utility/utils.c
//extern void logging_information(ref_mon* rm, struct log_info* log_info);
extern int calculate_hash(const char *content, unsigned char* hash);
extern int write_to_file(char * content, char * filepath );
extern struct inode *get_parent_inode(struct inode *file_inode);
extern char *get_path_from_dentry(struct dentry *dentry);
//extern void deferred_logger_handler(struct work_struct* data);
//extern node* lookup_inode_node_blacklist(struct inode* inode,struct list_head* ptr);
//extern node* lookup_path_node_blacklist(char* pathname);

