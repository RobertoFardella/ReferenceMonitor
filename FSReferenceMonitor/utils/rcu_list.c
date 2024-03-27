#include "./../referenceMonitor.h"
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/sched.h>
int  house_keeper(void * the_list);

void rcu_list_init(rcu_list * l, struct task_struct *thread){

	int i;
	l->epoch = 0x0;
	l->next_epoch_index = 0x1;
	for(i=0;i<EPOCHS;i++){
		l->standing[i] = 0x0;
	}

	l->head = NULL;
        
	printk(KERN_INFO "%s: daemon thread sta eseguendo house_keeper");
    // Creazione del nuovo thread kernel
    thread = kthread_create(house_keeper, (void *)l, "house_keeper_thread");
    if (IS_ERR(thread)) {
        printk(KERN_ERR "Errore durante la creazione del thread house_keeper\n");
        return ;
    }
	wake_up_process(thread);

}

int rcu_list_search(rcu_list *l, long key){

	unsigned long * epoch = &(l->epoch);
	unsigned long my_epoch;
	node *p;
	int index;

	my_epoch = __sync_fetch_and_add(epoch,1);
	
	//actual list traversal		
	p = l->head;
	while(p!=NULL){
		if ( p->key == key){
			break;
		}
		p = p->next;
	}

	#define MASK 0x8000000000000000
	index = (my_epoch & MASK) ? 1 : 0; 
	__sync_fetch_and_add(&l->standing[index],1);

	if (p) return 1;//here we return out of the RCU-read phase - the structure
			//can be changed to have RCU-read lock/unlock 
			//out of the actual read phase

	return 0;

}

int rcu_list_insert(rcu_list *l, long key){

	node * p;

	p = kmalloc(sizeof(node), GFP_KERNEL);

	if(!p){
		printk(KERN_ERR "Impossibile allocare memoria per il nodo\n");
    	return -ENOMEM; 
	}

	p->key = key;
	p->next = NULL;

	
	printk("insertion: waiting for lock\n");

	//pthread_spin_lock(&(l->write_lock));

	//traverse and insert
	p->next = l->head;
	asm volatile("mfence");
	l->head = p;
	asm volatile("mfence");
	

	while(p){
		printk("elem %d\n",p->key);
		p = p->next;
	}

	//pthread_spin_unlock(&l->write_lock);
	
	return 1;

}

int rcu_list_remove(rcu_list *l, long key){

	node * p, *removed = NULL;
	int grace_epoch;
	unsigned long last_epoch;
	unsigned long updated_epoch;
	unsigned long grace_period_threads;
	int index;
	

	//pthread_spin_lock(&l->write_lock);

	//traverse and delete
	p = l->head;

	if(p != NULL && p->key == key){
		removed = p;
		l->head = removed->next;
		asm volatile("mfence");//make it visible to readers
	}
	else{
		while(p != NULL){
			if ( p->next != NULL && p->next->key == key){
				removed = p->next;
				p->next = p->next->next;
				asm volatile("mfence");//make it visible to readers
				break;
			}	
			p = p->next;	
		}
	}
	//move to a new epoch - still under write lock
	updated_epoch = (l->next_epoch_index) ? MASK : 0;

    	l->next_epoch_index += 1;
		l->next_epoch_index %= 2;	

	last_epoch = __atomic_exchange_n (&(l->epoch), updated_epoch, __ATOMIC_SEQ_CST); 
	index = (last_epoch & MASK) ? 1 : 0; 
	grace_period_threads = last_epoch & (~MASK); 	
	printk("deletion: waiting grace-full period (target value is %d)\n",grace_period_threads);
	while(l->standing[index] < grace_period_threads);
	l->standing[index] = 0;
	
	//pthread_spin_unlock(&l->write_lock);

	if(removed){
		kfree(removed);
		return 1;
	}
	
	return 0;

}


int  house_keeper(void * the_list){

	int grace_epoch;
	unsigned long last_epoch;
	unsigned long updated_epoch;
	unsigned long grace_period_threads;
	int index;

	rcu_list * l = (rcu_list*) the_list;

redo:

	//pthread_spin_lock(&l->write_lock);
	spin_lock(&(l->write_lock));
	updated_epoch = (l->next_epoch_index) ? MASK : 0;
	//printk(KERN_INFO "next epoch index is %d - next epoch is %p\n",l->next_epoch_index,updated_epoch);

    l->next_epoch_index += 1;
	l->next_epoch_index %= 2;	

	last_epoch = __atomic_exchange_n (&(l->epoch), updated_epoch, __ATOMIC_SEQ_CST); 
	index = (last_epoch & MASK) ? 1 : 0; 
	grace_period_threads = last_epoch & (~MASK); 

	
	//printk(KERN_INFO "house keeping: waiting grace-full period (target value is %d)\n",grace_period_threads);
	while(l->standing[index] < grace_period_threads);
	l->standing[index] = 0;
	spin_unlock(&(l->write_lock));
	//pthread_spin_unlock(&l->write_lock);

	goto redo;

	return 1;
}