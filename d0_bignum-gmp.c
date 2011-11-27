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

#include <gmp.h>
#include <string.h>
#include <stdlib.h>

struct d0_bignum_s
{
	mpz_t z;
};

static gmp_randstate_t RANDSTATE;
static d0_bignum_t temp;
static unsigned char numbuf[65536];
static void *tempmutex = NULL; // hold this mutex when using RANDSTATE or temp or numbuf

#include <time.h>
#include <stdio.h>

static void *allocate_function (size_t alloc_size)
{
	return d0_malloc(alloc_size);
}
static void *reallocate_function (void *ptr, size_t old_size, size_t new_size)
{
	void *data;
	if(old_size == new_size)
		return ptr;
	data = d0_malloc(new_size);
	if(ptr && data)
		memcpy(data, ptr, (old_size < new_size) ? old_size : new_size);
	d0_free(ptr);
	return data;
}
void deallocate_function (void *ptr, size_t size)
{
	d0_free(ptr);
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_bignum_INITIALIZE(void)
{
	FILE *f;
	D0_BOOL ret = 1;
	unsigned char buf[256];

	tempmutex = d0_createmutex();
	d0_lockmutex(tempmutex);

	mp_set_memory_functions(allocate_function, reallocate_function, deallocate_function);

	d0_bignum_init(&temp);
	gmp_randinit_mt(RANDSTATE);
	gmp_randseed_ui(RANDSTATE, time(NULL));
	* (time_t *) (&buf[0]) = time(0); // if everything else fails, we use the current time + uninitialized data
#ifdef WIN32
	{
		HCRYPTPROV hCryptProv;
		if(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			if(!CryptGenRandom(hCryptProv, sizeof(buf), (PBYTE) &buf[0]))
			{
				fprintf(stderr, "WARNING: could not initialize random number generator (CryptGenRandom failed)\n");
				ret = 0;
			}
			CryptReleaseContext(hCryptProv, 0);
		}
		else if(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET))
		{
			if(!CryptGenRandom(hCryptProv, sizeof(buf), (PBYTE) &buf[0]))
			{
				fprintf(stderr, "WARNING: could not initialize random number generator (CryptGenRandom failed)\n");
				ret = 0;
			}
			CryptReleaseContext(hCryptProv, 0);
		}
		else
		{
			fprintf(stderr, "WARNING: could not initialize random number generator (CryptAcquireContext failed)\n");
			ret = 0;
		}
	}
#else
	f = fopen("/dev/urandom", "rb");
	if(!f)
		f = fopen("/dev/random", "rb");
	if(f)
	{
		setbuf(f, NULL);
		if(fread(buf, sizeof(buf), 1, f) != 1)
		{
			fprintf(stderr, "WARNING: could not initialize random number generator (read from random device failed)\n");
			ret = 0;
		}
		fclose(f);
	}
	else
	{
		fprintf(stderr, "WARNING: could not initialize random number generator (no random device found)\n");
		ret = 0;
	}
#endif

	mpz_import(temp.z, sizeof(buf), 1, 1, 0, 0, buf);
	gmp_randseed(RANDSTATE, temp.z);

	d0_unlockmutex(tempmutex);

	return ret;
}

void d0_bignum_SHUTDOWN(void)
{
	d0_lockmutex(tempmutex);

	d0_bignum_clear(&temp);
	gmp_randclear(RANDSTATE);

	d0_unlockmutex(tempmutex);
	d0_destroymutex(tempmutex);
	tempmutex = NULL;
}

D0_BOOL d0_iobuf_write_bignum(d0_iobuf_t *buf, const d0_bignum_t *bignum)
{
	D0_BOOL ret;
	size_t count = 0;

	d0_lockmutex(tempmutex);
	numbuf[0] = mpz_sgn(bignum->z) & 3;
	if((numbuf[0] & 3) != 0) // nonzero
	{
		count = (mpz_sizeinbase(bignum->z, 2) + 7) / 8;
		if(count > sizeof(numbuf) - 1)
		{
			d0_unlockmutex(tempmutex);
			return 0;
		}
		mpz_export(numbuf+1, &count, 1, 1, 0, 0, bignum->z);
	}
	ret = d0_iobuf_write_packet(buf, numbuf, count + 1);
	d0_unlockmutex(tempmutex);
	return ret;
}

d0_bignum_t *d0_iobuf_read_bignum(d0_iobuf_t *buf, d0_bignum_t *bignum)
{
	size_t count = sizeof(numbuf);

	d0_lockmutex(tempmutex);
	if(!d0_iobuf_read_packet(buf, numbuf, &count))
	{
		d0_unlockmutex(tempmutex);
		return NULL;
	}
	if(count < 1)
	{
		d0_unlockmutex(tempmutex);
		return NULL;
	}
	if(!bignum)
		bignum = d0_bignum_new();
	if(!bignum)
	{
		d0_unlockmutex(tempmutex);
		return NULL;
	}
	if(numbuf[0] & 3) // nonzero
	{
		mpz_import(bignum->z, count-1, 1, 1, 0, 0, numbuf+1);
		if(numbuf[0] & 2) // negative
			mpz_neg(bignum->z, bignum->z);
	}
	else // zero
	{
		mpz_set_ui(bignum->z, 0);
	}
	d0_unlockmutex(tempmutex);
	return bignum;
}

ssize_t d0_bignum_export_unsigned(const d0_bignum_t *bignum, void *buf, size_t bufsize)
{
	size_t count;
	count = (mpz_sizeinbase(bignum->z, 2) + 7) / 8;
	if(count > bufsize)
		return -1;
	if(bufsize > count)
	{
		// pad from left (big endian numbers!)
		memset(buf, 0, bufsize - count);
		buf += bufsize - count;
	}
	bufsize = count;
	mpz_export(buf, &bufsize, 1, 1, 0, 0, bignum->z);
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
	mpz_import(bignum->z, bufsize, 1, 1, 0, 0, buf);
	return bignum;
}

d0_bignum_t *d0_bignum_new(void)
{
	d0_bignum_t *b = d0_malloc(sizeof(d0_bignum_t));
	mpz_init(b->z);
	return b;
}

void d0_bignum_free(d0_bignum_t *a)
{
	mpz_clear(a->z);
	d0_free(a);
}

void d0_bignum_init(d0_bignum_t *b)
{
	mpz_init(b->z);
}

void d0_bignum_clear(d0_bignum_t *a)
{
	mpz_clear(a->z);
}

size_t d0_bignum_size(const d0_bignum_t *r)
{
	return mpz_sizeinbase(r->z, 2);
}

int d0_bignum_cmp(const d0_bignum_t *a, const d0_bignum_t *b)
{
	return mpz_cmp(a->z, b->z);
}

d0_bignum_t *d0_bignum_rand_range(d0_bignum_t *r, const d0_bignum_t *min, const d0_bignum_t *max)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	d0_lockmutex(tempmutex);
	mpz_sub(temp.z, max->z, min->z);
	mpz_urandomm(r->z, RANDSTATE, temp.z);
	d0_unlockmutex(tempmutex);
	mpz_add(r->z, r->z, min->z);
	return r;
}

d0_bignum_t *d0_bignum_rand_bit_atmost(d0_bignum_t *r, size_t n)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	d0_lockmutex(tempmutex);
	mpz_urandomb(r->z, RANDSTATE, n);
	d0_unlockmutex(tempmutex);
	return r;
}

d0_bignum_t *d0_bignum_rand_bit_exact(d0_bignum_t *r, size_t n)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	d0_lockmutex(tempmutex);
	mpz_urandomb(r->z, RANDSTATE, n-1);
	d0_unlockmutex(tempmutex);
	mpz_setbit(r->z, n-1);
	return r;
}

d0_bignum_t *d0_bignum_zero(d0_bignum_t *r)
{
	return d0_bignum_int(r, 0);
}

d0_bignum_t *d0_bignum_one(d0_bignum_t *r)
{
	return d0_bignum_int(r, 1);
}

d0_bignum_t *d0_bignum_int(d0_bignum_t *r, int n)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	mpz_set_si(r->z, n);
	return r;
}

d0_bignum_t *d0_bignum_mov(d0_bignum_t *r, const d0_bignum_t *a)
{
	if(r == a)
		return r; // trivial
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	mpz_set(r->z, a->z);
	return r;
}

d0_bignum_t *d0_bignum_neg(d0_bignum_t *r, const d0_bignum_t *a)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	mpz_neg(r->z, a->z);
	return r;
}

d0_bignum_t *d0_bignum_shl(d0_bignum_t *r, const d0_bignum_t *a, ssize_t n)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	if(n > 0)
		mpz_mul_2exp(r->z, a->z, n);
	else if(n < 0)
		mpz_fdiv_q_2exp(r->z, a->z, -n);
	else
		mpz_set(r->z, a->z);
	return r;
}

d0_bignum_t *d0_bignum_add(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *b)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	mpz_add(r->z, a->z, b->z);
	return r;
}

d0_bignum_t *d0_bignum_sub(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *b)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	mpz_sub(r->z, a->z, b->z);
	return r;
}

d0_bignum_t *d0_bignum_mul(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *b)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	mpz_mul(r->z, a->z, b->z);
	return r;
}

d0_bignum_t *d0_bignum_divmod(d0_bignum_t *q, d0_bignum_t *m, const d0_bignum_t *a, const d0_bignum_t *b)
{
	if(!q && !m)
		m = d0_bignum_new();
	if(q)
		if(m)
			mpz_fdiv_qr(q->z, m->z, a->z, b->z);
		else
			mpz_fdiv_q(q->z, a->z, b->z);
	else
		mpz_fdiv_r(m->z, a->z, b->z);
	if(m)
		return m;
	else
		return q;
}

d0_bignum_t *d0_bignum_mod_add(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *b, const d0_bignum_t *m)
{
	r = d0_bignum_add(r, a, b);
	mpz_fdiv_r(r->z, r->z, m->z);
	return r;
}

d0_bignum_t *d0_bignum_mod_sub(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *b, const d0_bignum_t *m)
{
	r = d0_bignum_sub(r, a, b);
	mpz_fdiv_r(r->z, r->z, m->z);
	return r;
}

d0_bignum_t *d0_bignum_mod_mul(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *b, const d0_bignum_t *m)
{
	r = d0_bignum_mul(r, a, b);
	mpz_fdiv_r(r->z, r->z, m->z);
	return r;
}

d0_bignum_t *d0_bignum_mod_pow(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *b, const d0_bignum_t *m)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	mpz_powm(r->z, a->z, b->z, m->z);
	return r;
}

D0_BOOL d0_bignum_mod_inv(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *m)
{
	// here, r MUST be set, as otherwise we cannot return error state!
	return mpz_invert(r->z, a->z, m->z);
}

int d0_bignum_isprime(const d0_bignum_t *r, int param)
{
	return mpz_probab_prime_p(r->z, param);
}

d0_bignum_t *d0_bignum_gcd(d0_bignum_t *r, d0_bignum_t *s, d0_bignum_t *t, const d0_bignum_t *a, const d0_bignum_t *b)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	if(s)
		mpz_gcdext(r->z, s->z, t ? t->z : NULL, a->z, b->z);
	else if(t)
		mpz_gcdext(r->z, t->z, NULL, b->z, a->z);
	else
		mpz_gcd(r->z, a->z, b->z);
	return r;
}

char *d0_bignum_tostring(const d0_bignum_t *x, unsigned int base)
{
	return mpz_get_str(NULL, base, x->z); // this allocates!
}
