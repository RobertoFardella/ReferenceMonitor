


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

typedef struct _path{        //element of a list that maintain the set of path of the dir/file to protect they from write operations
	struct _element * next;
	long key;
} path;

typedef struct _rcu__paths_list{
	unsigned long standing[EPOCHS];	//you can further optimize putting these values
					//on different cache lines
	unsigned long epoch; //a different cache line for this can also help
	int next_epoch_index;
	//pthread_spinlock_t write_lock;
	path * head;
} __attribute__((packed)) rcu_paths_list;

typedef rcu_paths_list list __attribute__((aligned(64)));

typedef struct referenceMonitor
{
    enum rm_state state;
    rcu_paths_list paths;
	//struct shash_alg hash_algo;  //synchronous message digest definition

}ref_mon;



