#include <linux/spinlock.h>

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
    unsigned long key;
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
	//struct shash_alg hash_algo;  //synchronous message digest definition

}ref_mon;

