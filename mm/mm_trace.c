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


const char *task_name_get(unsigned long ppid,unsigned long pid,char *buf,unsigned int buf_size)
{
#define TASK_NAME_CMD "cat /proc/%d/task/%d/status | grep Name | xargs | sed 's/Name: \\(.*\\)/\\1/g'"
	char cmd[1024] = {0,};
	FILE *fp = NULL;
	char *p_ret = NULL;
	memset(cmd,0,sizeof(cmd));
    snprintf(cmd,sizeof(cmd),TASK_NAME_CMD,ppid,pid);
    //printf("+++ %s\n",cmd);
    fp = popen (cmd, "r");
    assert(fp);
	memset(buf,0,buf_size);
	p_ret = fgets (buf, buf_size, fp);
    assert(p_ret);
    fclose(fp);
    fp = NULL;
    buf[strlen(buf)-1] = 0;  //去掉最后换行符.
    //printf(">>> %s (%d)\n",buf,strlen(buf));
    return buf;
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
    unsigned long task_pid = 0,task_tid = 0;
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
	printf("%-20s %-20s %-20s\n","[task]","[task_pid]","[task_tid]","[size]");
	
    char *sub = NULL,*str = NULL;
	str = buf;
	do {
		sub = strtok(str," ");
		if(NULL == sub)
			break;
		sscanf(str,"%u",&task_pid);
		//printf("pid=%d, task_pid: %d\n",pid,task_pid);
		str += (strlen(sub)+1);

		///////////////////////////////
		mem_size = 0;
		task_name = NULL;
		list_for_each_entry_safe(node, tmp,&mm_list, list) {
			if(task_pid == node->info.pid)
			{
				mem_size += node->info.size;
				task_name = node->info.task_name;
				task_tid = node->info.tid;
			}
		}
		//printf("mem_size: %d\n",mem_size);
		if(0 == mem_size)
		{
			char tname[64] = {0,};
			memset(tname,0,sizeof(tname));
			task_name = task_name_get(pid,task_pid,tname,sizeof(tname));
			task_tid = (unsigned long)-1;
		}
		printf("%-20s %-20u %-20x %-20u\n",task_name,task_pid,task_tid,mem_size);
	} while(1);
	
}

