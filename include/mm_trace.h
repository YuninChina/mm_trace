#ifndef __MM_TRACE_H
#define __MM_TRACE_H

void *mm_malloc(const char *func,unsigned long line,unsigned long size);
void mm_free(void *addr);
void mm_show(void);

#define MALLOC(size)	mm_malloc(__func__,__LINE__,size)
#define FREE(addr)		mm_free(addr)

#endif
