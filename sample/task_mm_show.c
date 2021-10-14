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
	}
	return NULL;
}


static void *task_routine_normal(void *arg)
{
	prctl(PR_SET_NAME,"task_normal");
	int cnt = 0;
	void *p = NULL;
	while (1)
	{
		p = MALLOC((cnt+1)*2048);
		cnt++;
		FREE(p);
		sleep(1);
	}
	return NULL;
}


static void *task_routine_dummy(void *arg)
{
	prctl(PR_SET_NAME,"task_dummy");
	int cnt = 0;
	void *p = NULL;
	while (1)
	{
		p = MALLOC((cnt+1)*64);
		cnt++;
		sleep(1);
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
	pthread_t thread_id3,thread_id4;
	int ret = -1;
	
	ret = pthread_create(&thread_id1, NULL, task_routine_no1, (void *)NULL);
	assert(0 == ret);
	pthread_detach(thread_id1);
	
	ret = pthread_create(&thread_id2, NULL, task_routine_no2, (void *)NULL);
	assert(0 == ret);
	pthread_detach(thread_id2);

	
	ret = pthread_create(&thread_id3, NULL, task_routine_normal, (void *)NULL);
	assert(0 == ret);
	pthread_detach(thread_id3);

	
	ret = pthread_create(&thread_id4, NULL, task_routine_dummy, (void *)NULL);
	assert(0 == ret);
	pthread_detach(thread_id4);
	
	while(1)
	{
		system("clear");
		task_mm_show();
		usleep(1000*1000);

		if(cnt++ == 10)
		{
			FREE(p1);
			FREE(p2);
			FREE(p3);
		}
	}
	
	return 0;
}

