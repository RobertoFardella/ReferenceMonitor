#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/fs.h>
static enum rm_state {
    ON,
    OFF,
    REC_ON,
    REC_OFF
};

typedef struct _node{
    struct list_head elem; //se faccio la modifica a rm, allora questo lo chiamerei + list_head_elem
    char* path;
	unsigned long inode_cod;
	struct inode* inode_blk;
	struct dentry* dentry_blk;
} node;

typedef struct referenceMonitor
{
    enum rm_state state; //possible state (ON, OFF, REC-ON, REC-OFF)
    node blk_head_node; //head node della blacklist
	struct file *log_file;
	char* pw_hash;

}ref_mon;

static ref_mon *rm;

//functions defined in ./utility/utils.c
extern int calculate_hash(const char *content, unsigned char* hash);
extern int write_to_file(char * content, char * filepath );
extern struct inode *get_parent_inode(struct inode *file_inode);
//extern node* lookup_inode_node_blacklist(struct inode* inode,struct list_head* ptr);
//extern node* lookup_path_node_blacklist(char* pathname);


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

