#ifndef __D0_H__
#define __D0_H__

#include <stdlib.h> // size_t

#define WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#define BOOL int

extern void *(*d0_malloc)(size_t len);
extern void (*d0_free)(void *p);

#endif
