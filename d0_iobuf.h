/*
 * FILE:	d0_iobuf.h
 * AUTHOR:	Rudolf Polzer - divVerent@xonotic.org
 * 
 * Copyright (c) 2010, Rudolf Polzer
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTOR(S) ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTOR(S) BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Format:commit %H$
 * $Id$
 */

#ifndef __D0_IOBUF_H__
#define __D0_IOBUF_H__

#include "d0.h"

typedef struct d0_iobuf_s d0_iobuf_t;

D0_WARN_UNUSED_RESULT d0_iobuf_t *d0_iobuf_open_read(const void *buf, size_t len); // note: can read AND write!
D0_WARN_UNUSED_RESULT d0_iobuf_t *d0_iobuf_open_write(void *buf, size_t len); // note: can read AND write!
D0_WARN_UNUSED_RESULT D0_BOOL d0_iobuf_conv_base64_in(d0_iobuf_t *buf);
D0_WARN_UNUSED_RESULT D0_BOOL d0_iobuf_conv_base64_out(d0_iobuf_t *buf);
D0_BOOL d0_iobuf_close(d0_iobuf_t *buf, size_t *len); // don't warn
D0_WARN_UNUSED_RESULT size_t d0_iobuf_write_raw(d0_iobuf_t *buf, const void *s, size_t n);
D0_WARN_UNUSED_RESULT size_t d0_iobuf_read_raw(d0_iobuf_t *buf, void *s, size_t n);
D0_WARN_UNUSED_RESULT D0_BOOL d0_iobuf_write_packet(d0_iobuf_t *buf, const void *s, size_t n);
D0_WARN_UNUSED_RESULT D0_BOOL d0_iobuf_read_packet(d0_iobuf_t *buf, void *s, size_t *n);

#endif
