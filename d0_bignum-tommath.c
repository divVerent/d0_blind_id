/*
 * FILE:	d0_bignum-gmp.c
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

/* NOTE: this file links against libgmp (http://gmplib.org), which is under the
 * Lesser General Public License 2.1 or later. You may have to abide to its
 * terms too if you use this file.
 * To alternatively link to OpenSSL, provide the option --with-openssl to
 * ./configure.
 */

#ifdef WIN32
#include <windows.h>
#include <wincrypt.h>
#endif

#include "d0_bignum.h"

#include <tommath.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

struct d0_bignum_s
{
	mp_int z;
};

static d0_bignum_t temp;

#include <stdio.h>

#ifdef WIN32
HCRYPTPROV hCryptProv;
#else
static FILE *randf;
#endif

void rand_bytes(unsigned char *buf, size_t n)
{
#ifdef WIN32
	CryptGenRandom(hCryptProv, n, (PBYTE) buf);
#else
	if(!randf)
		return;
	fread(buf, 1, n, randf);
#endif
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_bignum_INITIALIZE(void)
{
	D0_BOOL ret = 1;
	unsigned char buf[256];
	d0_bignum_init(&temp);
#ifdef WIN32
	{
		if(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
		}
		else if(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET))
		{
		}
		else
		{
			fprintf(stderr, "WARNING: could not initialize random number generator (CryptAcquireContext failed)\n");
			ret = 0;
			hCryptProv = NULL;
		}
	}
#else
	randf = fopen("/dev/urandom", "rb");
	if(!randf)
		randf = fopen("/dev/random", "rb");
	if(randf)
	{
		setbuf(randf, NULL);
	}
	else
	{
		fprintf(stderr, "WARNING: could not initialize random number generator (no random device found)\n");
		ret = 0;
	}
#endif

	return ret;
}

void d0_bignum_SHUTDOWN(void)
{
	d0_bignum_clear(&temp);
#ifdef WIN32
	if(hCryptProv)
	{
		CryptReleaseContext(hCryptProv, 0);
		hCryptProv = NULL;
	}
#endif
}

D0_BOOL d0_iobuf_write_bignum(d0_iobuf_t *buf, const d0_bignum_t *bignum)
{
	static unsigned char numbuf[65536];
	size_t count = 0;
	numbuf[0] = (mp_iszero(&bignum->z) ? 0 : (bignum->z.sign == MP_ZPOS) ? 1 : 3);
	if((numbuf[0] & 3) != 0) // nonzero
	{
		count = mp_unsigned_bin_size(&bignum->z);
		if(count > sizeof(numbuf) - 1)
			return 0;
		mp_to_unsigned_bin(&bignum->z, numbuf+1);
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
		mp_read_unsigned_bin(&bignum->z, numbuf+1, count-1);
		if(numbuf[0] & 2) // negative
			bignum->z.sign = MP_NEG;
	}
	else // zero
	{
		mp_zero(&bignum->z);
	}
	return bignum;
}

ssize_t d0_bignum_export_unsigned(const d0_bignum_t *bignum, void *buf, size_t bufsize)
{
	unsigned long count;
	count = mp_unsigned_bin_size(&bignum->z);
	if(count > bufsize)
		return -1;
	if(bufsize > count)
	{
		// pad from left (big endian numbers!)
		memset(buf, 0, bufsize - count);
		buf += bufsize - count;
	}
	bufsize = count;
	mp_to_unsigned_bin_n(&bignum->z, buf, &bufsize);
	if(bufsize > count)
	{
		// REALLY BAD
		// mpz_sizeinbase lied to us
		// buffer overflow
		// there is no sane way whatsoever to handle this
		abort();
	}
	if(bufsize < count)
	{
		// BAD
		// mpz_sizeinbase lied to us
		// move the number
		if(count == 0)
		{
			memset(buf, 0, count);
		}
		else
		{
			memmove(buf + count - bufsize, buf, bufsize);
			memset(buf, 0, count - bufsize);
		}
	}
	return bufsize;
}

d0_bignum_t *d0_bignum_import_unsigned(d0_bignum_t *bignum, const void *buf, size_t bufsize)
{
	size_t count;
	if(!bignum) bignum = d0_bignum_new(); if(!bignum) return NULL;
	mp_read_unsigned_bin(&bignum->z, buf, bufsize);
	return bignum;
}

d0_bignum_t *d0_bignum_new(void)
{
	d0_bignum_t *b = d0_malloc(sizeof(d0_bignum_t));
	mp_init(&b->z);
	return b;
}

void d0_bignum_free(d0_bignum_t *a)
{
	mp_clear(&a->z);
	d0_free(a);
}

void d0_bignum_init(d0_bignum_t *b)
{
	mp_init(&b->z);
}

void d0_bignum_clear(d0_bignum_t *a)
{
	mp_clear(&a->z);
}

size_t d0_bignum_size(const d0_bignum_t *r)
{
	return mp_count_bits(&r->z);
}

int d0_bignum_cmp(const d0_bignum_t *a, const d0_bignum_t *b)
{
	return mp_cmp(&a->z, &b->z);
}

static d0_bignum_t *d0_bignum_rand_0_to_limit(d0_bignum_t *r, const d0_bignum_t *limit)
{
	size_t n = d0_bignum_size(limit);
	size_t b = (n + 7) / 8;
	unsigned char mask = "\xFF\x7F\x3F\x1F\x0F\x07\x03\x01"[8*b - n];
	unsigned char numbuf[65536];
	assert(b <= sizeof(numbuf));
	for(;;)
	{
		rand_bytes(&numbuf, b);
		numbuf[0] &= mask;
		r = d0_bignum_import_unsigned(r, numbuf, b);
		if(d0_bignum_cmp(r, limit) < 0)
			return r;
	}
}

d0_bignum_t *d0_bignum_rand_range(d0_bignum_t *r, const d0_bignum_t *min, const d0_bignum_t *max)
{
	mp_sub(&max->z, &min->z, &temp.z);
	r = d0_bignum_rand_0_to_limit(r, &temp);
	mp_add(&r->z, &min->z, &r->z);
	return r;
}

d0_bignum_t *d0_bignum_rand_bit_atmost(d0_bignum_t *r, size_t n)
{
	d0_bignum_one(&temp);
	d0_bignum_shl(&temp, &temp, n);
	r = d0_bignum_rand_0_to_limit(r, &temp);
	return r;
}

d0_bignum_t *d0_bignum_rand_bit_exact(d0_bignum_t *r, size_t n)
{
	d0_bignum_one(&temp);
	d0_bignum_shl(&temp, &temp, n-1);
	r = d0_bignum_rand_0_to_limit(r, &temp);
	d0_bignum_add(r, r, &temp);
	return r;
}

d0_bignum_t *d0_bignum_zero(d0_bignum_t *r)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	mp_zero(&r->z);
	return r;
}

d0_bignum_t *d0_bignum_one(d0_bignum_t *r)
{
	return d0_bignum_int(r, 1);
}

d0_bignum_t *d0_bignum_int(d0_bignum_t *r, int n)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	mp_set_int(&r->z, n);
	return r;
}

d0_bignum_t *d0_bignum_mov(d0_bignum_t *r, const d0_bignum_t *a)
{
	if(r == a)
		return r; // trivial
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	mp_copy(&a->z, &r->z);
	return r;
}

d0_bignum_t *d0_bignum_neg(d0_bignum_t *r, const d0_bignum_t *a)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	mp_neg(&a->z, &r->z);
	return r;
}

d0_bignum_t *d0_bignum_shl(d0_bignum_t *r, const d0_bignum_t *a, ssize_t n)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	if(n > 0)
		mp_mul_2d(&a->z,  n, &r->z);
	else if(n < 0)
		mp_div_2d(&a->z, -n, &r->z, NULL);
	else
		mp_copy(&a->z, &r->z);
	return r;
}

d0_bignum_t *d0_bignum_add(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *b)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	mp_add(&a->z, &b->z, &r->z);
	return r;
}

d0_bignum_t *d0_bignum_sub(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *b)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	mp_sub(&a->z, &b->z, &r->z);
	return r;
}

d0_bignum_t *d0_bignum_mul(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *b)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	mp_mul(&a->z, &b->z, &r->z);
	return r;
}

d0_bignum_t *d0_bignum_divmod(d0_bignum_t *q, d0_bignum_t *m, const d0_bignum_t *a, const d0_bignum_t *b)
{
	if(!q && !m)
		m = d0_bignum_new();
	if(q)
		mp_div(&a->z, &b->z, &q->z, m ? &m->z : NULL);
	else
		mp_mod(&a->z, &b->z, &m->z);
	if(m)
		return m;
	else
		return q;
}

d0_bignum_t *d0_bignum_mod_add(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *b, const d0_bignum_t *m)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	mp_addmod(&a->z, &b->z, &m->z, &r->z);
	return r;
}

d0_bignum_t *d0_bignum_mod_sub(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *b, const d0_bignum_t *m)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	mp_submod(&a->z, &b->z, &m->z, &r->z);
	return r;
}

d0_bignum_t *d0_bignum_mod_mul(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *b, const d0_bignum_t *m)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	mp_mulmod(&a->z, &b->z, &m->z, &r->z);
	return r;
}

d0_bignum_t *d0_bignum_mod_pow(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *b, const d0_bignum_t *m)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	mp_exptmod(&a->z, &b->z, &m->z, &r->z);
	return r;
}

D0_BOOL d0_bignum_mod_inv(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *m)
{
	// here, r MUST be set, as otherwise we cannot return error state!
	return mp_invmod(&a->z, &m->z, &r->z) == MP_OKAY;
}

int d0_bignum_isprime(d0_bignum_t *r, int param)
{
	int ret = 0;
	if(param < 1)
		param = 1;
	mp_prime_is_prime(&r->z, param, &ret);
	return ret;
}

d0_bignum_t *d0_bignum_gcd(d0_bignum_t *r, d0_bignum_t *s, d0_bignum_t *t, const d0_bignum_t *a, const d0_bignum_t *b)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	if(s || t)
		mp_exteuclid(&a->z, &b->z, s ? &s->z : NULL, t ? &t->z : NULL, &r->z);
	else
		mp_gcd(&a->z, &b->z, &r->z);
	return r;
}

char *d0_bignum_tostring(const d0_bignum_t *x, unsigned int base)
{
	static char str[65536];
	mp_toradix_n(&x->z, str, base, sizeof(str));
	return str;
}
