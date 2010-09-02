/*
Blind-ID library for user identification using RSA blind signatures
Copyright (C) 2010  Rudolf Polzer

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "d0_bignum.h"

#include <openssl/bn.h>

struct d0_bignum_s
{
	BIGNUM z;
};

static d0_bignum_t temp;
static BN_CTX ctx;

#include <time.h>
#include <stdio.h>

WARN_UNUSED_RESULT BOOL d0_bignum_INITIALIZE(void)
{
	BN_CTX_init(&ctx);
	d0_bignum_init(&temp);
	return 1;
}

void d0_bignum_SHUTDOWN(void)
{
	d0_bignum_clear(&temp);
	BN_CTX_free(&ctx);
}

BOOL d0_iobuf_write_bignum(d0_iobuf_t *buf, const d0_bignum_t *bignum)
{
	static unsigned char numbuf[65536];
	size_t count = 0;
	numbuf[0] = BN_is_zero(&bignum->z) ? 0 : BN_is_negative(&bignum->z) ? 3 : 1;
	if((numbuf[0] & 3) != 0) // nonzero
	{
		count = BN_num_bytes(&bignum->z);
		if(count > sizeof(numbuf) - 1)
			return 0;
		BN_bn2bin(numbuf+1, &bignum->z);
	}
	return d0_iobuf_write_packet(buf, numbuf, count + 1);
}

d0_bignum_t *d0_iobuf_read_bignum(d0_iobuf_t *buf, d0_bignum_t *bignum)
{
	static unsigned char numbuf[65536];
	size_t count = sizeof(numbuf);
	if(!d0_iobuf_read_packet(buf, numbuf, &count))
		return NULL;
	if(count < 1)
		return NULL;
	if(!bignum) bignum = d0_bignum_new(); if(!bignum) return NULL;
	if(numbuf[0] & 3) // nonzero
	{
		BN_bin2bn(numbuf+1, count-1, &bignum->z);
		if(numbuf[0] & 2) // negative
			BN_set_negative(&bignum->z, 1);
	}
	else // zero
	{
		BN_zero(&bignum->z);
	}
	return bignum;
}

ssize_t d0_bignum_export_unsigned(const d0_bignum_t *bignum, void *buf, size_t bufsize)
{
	size_t count;
	count = BN_num_bytes(&bignum->z);
	if(count > bufsize)
		return -1;
	if(bufsize > count)
	{
		// pad from left (big endian numbers!)
		memset(buf, 0, bufsize - count);
		buf += bufsize - count;
	}
	BN_bn2bin(&bignum->z, buf);
	return bufsize;
}

d0_bignum_t *d0_bignum_import_unsigned(d0_bignum_t *bignum, const void *buf, size_t bufsize)
{
	size_t count;
	if(!bignum) bignum = d0_bignum_new(); if(!bignum) return NULL;
	BN_bin2bn(buf, bufsize, &bignum->z);
	return bignum;
}

d0_bignum_t *d0_bignum_new(void)
{
	d0_bignum_t *b = d0_malloc(sizeof(d0_bignum_t));
	BN_init(&b->z);
	return b;
}

void d0_bignum_free(d0_bignum_t *a)
{
	BN_free(&a->z);
	d0_free(a);
}

void d0_bignum_init(d0_bignum_t *b)
{
	BN_init(&b->z);
}

void d0_bignum_clear(d0_bignum_t *a)
{
	BN_free(&a->z);
}

size_t d0_bignum_size(const d0_bignum_t *r)
{
	return BN_num_bits(&r->z);
}

int d0_bignum_cmp(const d0_bignum_t *a, const d0_bignum_t *b)
{
	return BN_cmp(&a->z, &b->z);
}

d0_bignum_t *d0_bignum_rand_range(d0_bignum_t *r, const d0_bignum_t *min, const d0_bignum_t *max)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	BN_sub(&temp.z, &max->z, &min->z);
	BN_rand_range(&r->z, &temp.z);
	BN_add(&r->z, &r->z, &min->z);
	return r;
}

d0_bignum_t *d0_bignum_rand_bit_atmost(d0_bignum_t *r, size_t n)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	BN_rand(&r->z, n, -1, 0);
	return r;
}

d0_bignum_t *d0_bignum_rand_bit_exact(d0_bignum_t *r, size_t n)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	BN_rand(&r->z, n, 0, 0);
	return r;
}

d0_bignum_t *d0_bignum_zero(d0_bignum_t *r)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	BN_zero(&r->z);
	return r;
}

d0_bignum_t *d0_bignum_one(d0_bignum_t *r)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	BN_one(&r->z);
	return r;
}

d0_bignum_t *d0_bignum_int(d0_bignum_t *r, int n)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	BN_set_word(&r->z, n);
	return r;
}

d0_bignum_t *d0_bignum_mov(d0_bignum_t *r, const d0_bignum_t *a)
{
	if(r == a)
		return r; // trivial
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	BN_copy(&r->z, &a->z);
	return r;
}

d0_bignum_t *d0_bignum_neg(d0_bignum_t *r, const d0_bignum_t *a)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	if(r != a)
		BN_copy(&r->z, &a->z);
	BN_set_negative(&r->z, !BN_is_negative(&r->z));
	return r;
}

d0_bignum_t *d0_bignum_shl(d0_bignum_t *r, const d0_bignum_t *a, ssize_t n)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	if(n > 0)
		BN_lshift(&r->z, &a->z, n);
	else if(n < 0)
		BN_rshift(&r->z, &a->z, n);
	else if(r != a)
		BN_copy(&r->z, &a->z);
	return r;
}

d0_bignum_t *d0_bignum_add(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *b)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	BN_add(&r->z, &a->z, &b->z);
	return r;
}

d0_bignum_t *d0_bignum_sub(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *b)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	BN_sub(&r->z, &a->z, &b->z);
	return r;
}

d0_bignum_t *d0_bignum_mul(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *b)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	BN_mul(&r->z, &a->z, &b->z);
	return r;
}

d0_bignum_t *d0_bignum_divmod(d0_bignum_t *q, d0_bignum_t *m, const d0_bignum_t *a, const d0_bignum_t *b)
{
	if(!q && !m)
		m = d0_bignum_new();
	if(q)
	{
		if(m)
			BN_div(&q->z, &m->z, &a->z, &b->z, &ctx);
		else
			BN_div(&q->z, NULL, &a->z, &b->z, &ctx);
		assert(!"I know this code is broken (rounds towards zero), need handle negative correctly");
	}
	else
		BN_nnmod(&q->z, NULL, &a->z, &b->z, &ctx);
	if(m)
		return m;
	else
		return q;
}

d0_bignum_t *d0_bignum_mod_add(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *b, const d0_bignum_t *m)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	BN_mod_add(&r->z, &a->z, &b->z, &m->z, &ctx);
	return r;
}

d0_bignum_t *d0_bignum_mod_mul(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *b, const d0_bignum_t *m)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	BN_mod_mul(&r->z, &a->z, &b->z, &m->z, &ctx);
	return r;
}

d0_bignum_t *d0_bignum_mod_pow(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *b, const d0_bignum_t *m)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	BN_mod_exp(&r->z, &a->z, &b->z, &m->z, &ctx);
	return r;
}

BOOL d0_bignum_mod_inv(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *m)
{
	// here, r MUST be set, as otherwise we cannot return error state!
	return !!BN_mod_inverse(&r->z, &a->z, &m->z, &ctx);
}

int d0_bignum_isprime(d0_bignum_t *r, int param)
{
	return BN_is_prime(&r->z, param, NULL, &ctx, NULL);
}

d0_bignum_t *d0_bignum_gcd(d0_bignum_t *r, d0_bignum_t *s, d0_bignum_t *t, const d0_bignum_t *a, const d0_bignum_t *b)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	if(s)
		assert(!"Extended gcd not implemented");
	else if(t)
		assert(!"Extended gcd not implemented");
	else
		BN_gcd(&r->z, &a->z, &b->z, &ctx);
	return r;
}

char *d0_bignum_tostring(const d0_bignum_t *x, unsigned int base)
{
	if(base == 10)
		return BN_bn2dec(&x->z);
	else if(base == 16)
		return BN_bn2hex(&x->z);
	else
		assert(!"Other bases not implemented");
}
