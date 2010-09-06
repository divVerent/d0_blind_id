/*
 * FILE:	d0_bignum.h
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

#ifndef __D0_BIGNUM_H__
#define __D0_BIGNUM_H__

#include "d0.h"
#include "d0_iobuf.h"

typedef struct d0_bignum_s d0_bignum_t;

D0_WARN_UNUSED_RESULT D0_BOOL d0_iobuf_write_bignum(d0_iobuf_t *buf, const d0_bignum_t *bignum); // byte 0: 01=+ 11=- 00=0, rest = big endian number
D0_WARN_UNUSED_RESULT d0_bignum_t *d0_iobuf_read_bignum(d0_iobuf_t *buf, d0_bignum_t *bignum);
D0_WARN_UNUSED_RESULT ssize_t d0_bignum_export_unsigned(const d0_bignum_t *bignum, void *buf, size_t bufsize); // big endian, return value = number of significant bytes (or -1 on error)
D0_WARN_UNUSED_RESULT d0_bignum_t *d0_bignum_import_unsigned(d0_bignum_t *bignum, const void *buf, size_t bufsize);

D0_WARN_UNUSED_RESULT D0_BOOL d0_bignum_INITIALIZE(void);
void d0_bignum_SHUTDOWN(void);

D0_WARN_UNUSED_RESULT d0_bignum_t *d0_bignum_new(void);
void d0_bignum_free(d0_bignum_t *a);
void d0_bignum_init(d0_bignum_t *b);
void d0_bignum_clear(d0_bignum_t *a);
D0_WARN_UNUSED_RESULT size_t d0_bignum_size(const d0_bignum_t *r);
D0_WARN_UNUSED_RESULT int d0_bignum_cmp(const d0_bignum_t *a, const d0_bignum_t *b);
D0_WARN_UNUSED_RESULT d0_bignum_t *d0_bignum_rand_range(d0_bignum_t *r, const d0_bignum_t *min, const d0_bignum_t *max);
D0_WARN_UNUSED_RESULT d0_bignum_t *d0_bignum_rand_bit_atmost(d0_bignum_t *r, size_t n);
D0_WARN_UNUSED_RESULT d0_bignum_t *d0_bignum_rand_bit_exact(d0_bignum_t *r, size_t n);
D0_WARN_UNUSED_RESULT d0_bignum_t *d0_bignum_zero(d0_bignum_t *r);
D0_WARN_UNUSED_RESULT d0_bignum_t *d0_bignum_one(d0_bignum_t *r);
D0_WARN_UNUSED_RESULT d0_bignum_t *d0_bignum_int(d0_bignum_t *r, int n);
D0_WARN_UNUSED_RESULT d0_bignum_t *d0_bignum_mov(d0_bignum_t *r, const d0_bignum_t *a);
D0_WARN_UNUSED_RESULT d0_bignum_t *d0_bignum_neg(d0_bignum_t *r, const d0_bignum_t *a);
D0_WARN_UNUSED_RESULT d0_bignum_t *d0_bignum_shl(d0_bignum_t *r, const d0_bignum_t *a, ssize_t n);
D0_WARN_UNUSED_RESULT d0_bignum_t *d0_bignum_add(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *b);
D0_WARN_UNUSED_RESULT d0_bignum_t *d0_bignum_sub(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *b);
D0_WARN_UNUSED_RESULT d0_bignum_t *d0_bignum_mul(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *b);
D0_WARN_UNUSED_RESULT d0_bignum_t *d0_bignum_divmod(d0_bignum_t *q, d0_bignum_t *m, const d0_bignum_t *a, const d0_bignum_t *b); // only do mod if both are NULL
D0_WARN_UNUSED_RESULT d0_bignum_t *d0_bignum_mod_add(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *b, const d0_bignum_t *m);
D0_WARN_UNUSED_RESULT d0_bignum_t *d0_bignum_mod_mul(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *b, const d0_bignum_t *m);
D0_WARN_UNUSED_RESULT d0_bignum_t *d0_bignum_mod_pow(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *b, const d0_bignum_t *m);
D0_WARN_UNUSED_RESULT D0_BOOL d0_bignum_mod_inv(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *m);
D0_WARN_UNUSED_RESULT int d0_bignum_isprime(d0_bignum_t *r, int param);
D0_WARN_UNUSED_RESULT d0_bignum_t *d0_bignum_gcd(d0_bignum_t *r, d0_bignum_t *s, d0_bignum_t *t, const d0_bignum_t *a, const d0_bignum_t *b);

D0_WARN_UNUSED_RESULT char *d0_bignum_tostring(const d0_bignum_t *x, unsigned int base); // allocates!

#endif
