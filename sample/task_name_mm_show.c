#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>
#include <sys/prctl.h>

#include "mm_trace.h"


static void *task_routine_no1(void *arg)
{
	prctl(PR_SET_NAME,"task_no1");
	int cnt = 0;
	void *p = NULL;
	while (1)
	{
		p = MALLOC((cnt+1)*16);
		sleep(1);
		cnt++;
		if(0 == cnt%3)
		{
			FREE(p);
		}
	}
	return NULL;
}

static void *task_routine_no2(void *arg)
{
	prctl(PR_SET_NAME,"task_no2");
	int cnt = 0;
	void *p = NULL;
	while (1)
	{
		p = MALLOC((cnt+1)*512);
		sleep(1);
		cnt++;
		if(0 == cnt%2)
		{
			FREE(p);
		}
	}
	return NULL;
}




int main(void)
{
	void *p1,*p2,*p3;
	int cnt = 0;
	p1 = MALLOC(10);
	assert(p1);
	p2 = MALLOC(20);
	assert(p1);
	p3 = MALLOC(30);
	assert(p1);

	
	pthread_t thread_id1,thread_id2;
	int ret = -1;
	
	ret = pthread_create(&thread_id1, NULL, task_routine_no1, (void *)NULL);
	assert(0 == ret);
	pthread_detach(thread_id1);
	
	ret = pthread_create(&thread_id2, NULL, task_routine_no2, (void *)NULL);
	assert(0 == ret);
	pthread_detach(thread_id2);
	
	while(1)
	{
		task_name_mm_show("task_no2");
		sleep(1);
		system("clear");
	}
	
	return 0;
}

