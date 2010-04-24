#include "d0_bignum.h"

#include <gmp.h>

struct d0_bignum_s
{
	mpz_t z;
};

static gmp_randstate_t RANDSTATE;

#include <time.h>
void d0_bignum_INITIALIZE()
{
	gmp_randinit_default(RANDSTATE);
	gmp_randseed_ui(RANDSTATE, time(NULL)); // TODO seed
}

void d0_bignum_SHUTDOWN()
{
	// free RANDSTATE
}

BOOL d0_iobuf_write_bignum(d0_iobuf_t *buf, const d0_bignum_t *bignum)
{
	static unsigned char numbuf[65536];
	size_t count = 0;
	numbuf[0] = mpz_sgn(bignum->z) & 3;
	if((numbuf[0] & 3) != 0) // nonzero
	{
		count = (mpz_sizeinbase(bignum->z, 2) + 7) / 8;
		if(count > sizeof(numbuf) - 1)
			return 0;
		mpz_export(numbuf+1, &count, 1, 1, 0, 0, bignum->z);
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
		mpz_import(bignum->z, count-1, 1, 1, 0, 0, numbuf+1);
		if(numbuf[0] & 2) // negative
			mpz_neg(bignum->z, bignum->z);
	}
	else // zero
	{
		mpz_set_ui(bignum->z, 0);
	}
	return bignum;
}

d0_bignum_t *d0_bignum_new()
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
	static d0_bignum_t *temp = NULL; if(!temp) temp = d0_bignum_new();
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	mpz_sub(temp->z, max->z, min->z);
	mpz_urandomm(r->z, RANDSTATE, temp->z);
	mpz_add(r->z, r->z, min->z);
	return r;
}

d0_bignum_t *d0_bignum_rand_bit_atmost(d0_bignum_t *r, size_t n)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	mpz_urandomb(r->z, RANDSTATE, n);
	return r;
}

d0_bignum_t *d0_bignum_rand_bit_exact(d0_bignum_t *r, size_t n)
{
	if(!r) r = d0_bignum_new(); if(!r) return NULL;
	mpz_urandomb(r->z, RANDSTATE, n-1);
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

BOOL d0_bignum_mod_inv(d0_bignum_t *r, const d0_bignum_t *a, const d0_bignum_t *m)
{
	// here, r MUST be set, as otherwise we cannot return error state!
	return mpz_invert(r->z, a->z, m->z);
}

int d0_bignum_isprime(d0_bignum_t *r, int param)
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
	return mpz_get_str(NULL, base, x->z);
}
