#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/fs.h>
static enum rm_state {
    ON,
    OFF,
    REC_ON,
    REC_OFF
};

//this defines the RCU house keeping period
#ifndef PERIOD
#define PERIOD 1
#endif
#define EPOCHS (2)

typedef struct _node{
    struct list_head list;
    char* path;
	unsigned long inode_cod;
} node;

typedef struct _rcu__paths_list{
	unsigned long standing[EPOCHS];	//you can further optimize putting these values
					//on different cache lines
	unsigned long epoch; //a different cache line for this can also help
	int next_epoch_index;
	spinlock_t write_lock;

} __attribute__((packed)) rcu_list;

typedef rcu_list  __attribute__((aligned(64)));


//RCU versions
extern void rcu_list_init(rcu_list * l, struct task_struct *thread);

extern int rcu_list_search(rcu_list *l, long key);

extern int rcu_list_insert(rcu_list *l, long key);

extern int rcu_list_remove(rcu_list *l, long key);

typedef struct referenceMonitor
{
    enum rm_state state;
     node paths;
	 struct file *log_file;
	//struct shash_alg hash_algo;  //synchronous message digest definition

}ref_mon;


extern int calculate_hash(const char *content, unsigned char* hash);
extern int write_to_file(char * content, char * filepath );


#ifndef _ONEFILEFS_H
#define _ONEFILEFS_H

#define MOD_NAME "SINGLE FILE FS"

#define MAGIC 0x42424242
#define DEFAULT_BLOCK_SIZE 4096
#define SB_BLOCK_NUMBER 0
#define DEFAULT_FILE_INODE_BLOCK 1

#define FILENAME_MAXLEN 255

#define SINGLEFILEFS_ROOT_INODE_NUMBER 10
#define SINGLEFILEFS_FILE_INODE_NUMBER 1

#define SINGLEFILEFS_INODES_BLOCK_NUMBER 1

#define UNIQUE_FILE_NAME "the-file"

//inode definition
struct onefilefs_inode {
	mode_t mode;//not exploited
	uint64_t inode_no;
	uint64_t data_block_number;//not exploited

	union {
		uint64_t file_size;
		uint64_t dir_children_count;
	};
};

//dir definition (how the dir datablock is organized)
struct onefilefs_dir_record {
	char filename[FILENAME_MAXLEN];
	uint64_t inode_no;
};


//superblock definition
struct onefilefs_sb_info {
	uint64_t version;
	uint64_t magic;
	uint64_t block_size;
	uint64_t inodes_count;//not exploited
	uint64_t free_blocks;//not exploited

	//padding to fit into a single block
	char padding[ (4 * 1024) - (5 * sizeof(uint64_t))];
};


// file.c
extern const struct inode_operations onefilefs_inode_ops;
extern const struct file_operations onefilefs_file_operations;

// dir.c
extern const struct file_operations onefilefs_dir_operations;


#endif

