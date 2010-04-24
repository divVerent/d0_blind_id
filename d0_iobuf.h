#ifndef __D0_IOBUF_H__
#define __D0_IOBUF_H__

#include "d0.h"

typedef struct d0_iobuf_s d0_iobuf_t;

WARN_UNUSED_RESULT d0_iobuf_t *d0_iobuf_open_read(const void *buf, size_t len); // note: can read AND write!
WARN_UNUSED_RESULT d0_iobuf_t *d0_iobuf_open_write(void *buf, size_t len); // note: can read AND write!
WARN_UNUSED_RESULT BOOL d0_iobuf_conv_base64_in(d0_iobuf_t *buf);
WARN_UNUSED_RESULT BOOL d0_iobuf_conv_base64_out(d0_iobuf_t *buf);
BOOL d0_iobuf_close(d0_iobuf_t *buf, size_t *len); // don't warn
WARN_UNUSED_RESULT size_t d0_iobuf_write_raw(d0_iobuf_t *buf, const void *s, size_t n);
WARN_UNUSED_RESULT size_t d0_iobuf_read_raw(d0_iobuf_t *buf, void *s, size_t n);
WARN_UNUSED_RESULT BOOL d0_iobuf_write_packet(d0_iobuf_t *buf, const void *s, size_t n);
WARN_UNUSED_RESULT BOOL d0_iobuf_read_packet(d0_iobuf_t *buf, void *s, size_t *n);

#endif
