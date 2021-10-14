#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>

#include "mm_trace.h"
#include "klist.h"

typedef struct mm_info_s{
	char task_name[32];
	unsigned long pid;  //process ID
	unsigned long tid;  //thread ID
	const char *func;
	unsigned long line;
	unsigned long size;
	void *addr;
}mm_info_t;

typedef struct mm_node_s{
	struct list_head list;
	mm_info_t info;
}mm_node_t;

pthread_mutex_t mm_mutex = PTHREAD_MUTEX_INITIALIZER;
static LIST_HEAD(mm_list);


void *mm_malloc(const char *func,unsigned long line,unsigned long size)
{
	void *addr = NULL;
	mm_node_t *node = NULL;
	pthread_t thread_id = 0;
	addr = malloc(size);
	assert(addr);
	node = malloc(sizeof(*node));
	assert(node);
	thread_id = pthread_self();
	pthread_getname_np(thread_id,node->info.task_name,sizeof(node->info.task_name));
	node->info.tid = (unsigned long)thread_id;
	node->info.pid = (unsigned long)gettid();
	node->info.func = func;
	node->info.line = line;
	node->info.size = size;
	node->info.addr = addr;

	pthread_mutex_lock(&mm_mutex);
	list_add_tail(&node->list, &mm_list);
	pthread_mutex_unlock(&mm_mutex);
	
	return addr;
}


void mm_free(void *addr)
{
	mm_node_t *node = NULL,*tmp = NULL;
	if(addr)
	{
		list_for_each_entry_safe(node, tmp,&mm_list, list) {
			if(node->info.addr == addr)
			{
				list_del(&node->list);
				free(node);
				break;
			}
		}
		free(addr);
		addr = NULL;
	}
}

void mm_show(void)
{
	mm_node_t *node = NULL,*tmp = NULL;
	printf("\n\n=========================================== mm_show ===========================================\n");
	printf("%-15s %-15s %-15s %-32s %-15s %-15s %-15s\n",
	"[task]","[tid]","[pid]","[function]","[line]","[addr]","[size]");
	list_for_each_entry_safe(node, tmp,&mm_list, list) {
		printf("%-15s %-15u %-15u %-32s %-15d %-15p %-15d\n",
		node->info.task_name,node->info.tid,node->info.pid,
		node->info.func,node->info.line,
		node->info.addr,node->info.size);
	}
}

void task_name_mm_show(const char *name)
{
	mm_node_t *node = NULL,*tmp = NULL;
	unsigned long sum = 0;
	printf("\n\n=========================================== task_mm_show ===========================================\n");
	printf("%-20s%-20s%-20s%-20s\n","[function]","[line]","[addr]","[size]");
	list_for_each_entry_safe(node, tmp,&mm_list, list) {
		if(0 == strcmp(name,node->info.task_name))
		{
			printf("%-20s %-20d %-20p %-20d \n",
			node->info.func,node->info.line,
			node->info.addr,node->info.size);
			sum += node->info.size;
		}
	}
	printf(">>>>>> sum:%u \n\n",sum);
}

void task_id_mm_show(unsigned long id)
{
	mm_node_t *node = NULL,*tmp = NULL;
	
	unsigned long sum = 0;
	printf("\n\n=========================================== task_mm_show2 ===========================================\n");
	printf("%-20s %-20s %-20s %-20s\n","[function]","[line]","[addr]","[size]");
	list_for_each_entry_safe(node, tmp,&mm_list, list) {
		if(id == node->info.tid)
		{
			printf("%-20s %-20d %-20p %-20d \n",
			node->info.func,node->info.line,
			node->info.addr,node->info.size);
			sum += node->info.size;
		}
	}
	printf(">>>>>> sum:%u \n\n",sum);
}


void task_mm_show(void)
{
	mm_node_t *node = NULL,*tmp = NULL;

	char cmd[1024] = {0,};
	FILE *fp = NULL;
    char buf[1024] = {0,};
    char *pResult = NULL;
    unsigned long task_pid = 0;
	int i = 0;
	unsigned long mem_size = 0;
	const char *task_name = NULL;
	pid_t pid = getpid();
	memset(cmd,0,sizeof(cmd));
    snprintf(cmd,sizeof(cmd),"ls /proc/%d/task/ | xargs",pid);
    fp = popen (cmd, "r");
    assert(fp);
	memset(buf,0,sizeof(buf));
	pResult = fgets (buf, sizeof (buf), fp);
    assert(pResult);
    fclose(fp);
    fp = NULL;
    //printf("%s\n",buf);
    
	printf("\n\n=========================================== task_mm_show ===========================================\n");
	printf("%-20s %-20s %-20s\n","[task]","[task_pid]","[size]");
	
    char *sub = NULL,*str = NULL;
	str = buf;
	do {
		sub = strtok(str," ");
		if(NULL == sub)
			break;
		sscanf(str,"%u",&task_pid);
		//printf("task_pid: %d\n",task_pid);
		str += (strlen(sub)+1);

		///////////////////////////////
		mem_size = 0;
		list_for_each_entry_safe(node, tmp,&mm_list, list) {
			if(task_pid == node->info.pid)
			{
				mem_size += node->info.size;
				task_name = node->info.task_name;
			}
		}
		printf("%-20s %-20u %-20u\n",task_name,task_pid,mem_size);
	} while(1);
	
    #if 0
	printf("\n\n=========================================== mm_show ===========================================\n");
	printf("%-20s %-20s %-20s\n","[task]","[id]","[size]");
	list_for_each_entry_safe(node, tmp,&mm_list, list) {
		if(0 != strcmp(task_name,node->info.task_name))
		{
			task_name = node->info.task_name;
			printf("%-20s 0x%-20x %-20u\n",node->info.task_name,
			node->info.task_id,node->info.task_total_size);
		}
	}
	#endif
}

