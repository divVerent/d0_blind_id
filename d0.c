#include "d0.h"

#include <stdlib.h>

void *(*d0_malloc)(size_t len) = malloc;
void (*d0_free)(void *p) = free;
