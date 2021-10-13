#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>

#include "mm_trace.h"

int main(void)
{
	void *p1,*p2,*p3;
	p1 = MALLOC(10);
	assert(p1);
	p2 = MALLOC(20);
	assert(p1);
	p3 = MALLOC(30);
	assert(p1);
	mm_show();

	task_name_mm_show("mm_trace");
	///////////////
	FREE(p3);
	mm_show();
	FREE(p2);
	mm_show();
	FREE(p1);
	mm_show();
	
	return 0;
}

