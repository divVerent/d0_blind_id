/*
 * FILE:	d0_blind_id.c
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

#include "d0_blind_id.h"

#include <stdio.h>
#include <string.h>
#include "d0_bignum.h"
#include "sha2.h"

// old "positive" protocol, uses one extra mod_inv in verify stages
// #define D0_BLIND_ID_POSITIVE_PROTOCOL

// our SHA is SHA-256
#define SHA_DIGESTSIZE 32
const unsigned char *sha(unsigned char *h, const unsigned char *in, size_t len)
{
	d0_blind_id_util_sha256((char *) h, (const char *) in, len);
	return h;
}

// for zero knowledge, we need multiple instances of schnorr ID scheme... should normally be sequential
// parallel schnorr ID is not provably zero knowledge :(
//   (evil verifier can know all questions in advance, so sequential is disadvantage for him)
// we'll just live with a 1:1048576 chance of cheating, and support reauthenticating

#define SCHNORR_BITS 20
// probability of cheat: 2^(-bits+1)

#define SCHNORR_HASHSIZE SHA_DIGESTSIZE
// cannot be >= SHA_DIGESTSIZE
// *8 must be >= SCHNORR_BITS
// no need to save bits here

#define MSGSIZE 640 // ought to be enough for anyone

struct d0_blind_id_s
{
	// signing (Xonotic pub and priv key)
	d0_bignum_t *rsa_n, *rsa_e, *rsa_d;

	// public data (Schnorr ID)
	d0_bignum_t *schnorr_G;

	// private data (player ID private key)
	d0_bignum_t *schnorr_s;

	// public data (player ID public key, this is what the server gets to know)
	d0_bignum_t *schnorr_g_to_s;
	d0_bignum_t *schnorr_H_g_to_s_signature; // 0 when signature is invalid
	// as hash function H, we get the SHA1 and reinterpret as bignum - yes, it always is < 160 bits

	// temp data
	d0_bignum_t *rsa_blind_signature_camouflage; // random number blind signature

	d0_bignum_t *r; // random number for schnorr ID
	d0_bignum_t *t; // for DH key exchange
	d0_bignum_t *g_to_t; // for DH key exchange
	d0_bignum_t *other_g_to_t; // for DH key exchange
	d0_bignum_t *challenge; // challenge

	char msghash[SCHNORR_HASHSIZE]; // init hash
	char msg[MSGSIZE]; // message
	size_t msglen; // message length
};

//#define CHECKDEBUG
#ifdef CHECKDEBUG
#define CHECK(x) do { if(!(x)) { fprintf(stderr, "CHECK FAILED (%s:%d): %s\n", __FILE__, __LINE__, #x); goto fail; } } while(0)
#define CHECK_ASSIGN(var, value) do { d0_bignum_t *val; val = value; if(!val) { fprintf(stderr, "CHECK FAILED (%s:%d): %s\n", __FILE__, __LINE__, #value); goto fail; } var = val; } while(0)
#else
#define CHECK(x) do { if(!(x)) goto fail; } while(0)
#define CHECK_ASSIGN(var, value) do { d0_bignum_t *val; val = value; if(!val) goto fail; var = val; } while(0)
#endif

#define USING(x) if(!(ctx->x)) return 0
#define REPLACING(x)

// safe to use
static d0_bignum_t *zero, *one, *four;

static d0_bignum_t *temp0, *temp1, *temp2, *temp3, *temp4;
static void *tempmutex = NULL; // hold this mutex when using temp0 to temp4
#define USINGTEMPS() int locked = 0
#define LOCKTEMPS() do { if(!locked) d0_lockmutex(tempmutex); locked = 1; } while(0)
#define UNLOCKTEMPS() do { if(locked) d0_unlockmutex(tempmutex); locked = 0; } while(0);

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_INITIALIZE(void)
{
	USINGTEMPS();
	d0_initfuncs();
	tempmutex = d0_createmutex();
	LOCKTEMPS();
	CHECK(d0_bignum_INITIALIZE());
	CHECK_ASSIGN(zero, d0_bignum_int(zero, 0));
	CHECK_ASSIGN(one, d0_bignum_int(one, 1));
	CHECK_ASSIGN(four, d0_bignum_int(four, 4));
	CHECK_ASSIGN(temp0, d0_bignum_int(temp0, 0));
	CHECK_ASSIGN(temp1, d0_bignum_int(temp1, 0));
	CHECK_ASSIGN(temp2, d0_bignum_int(temp2, 0));
	CHECK_ASSIGN(temp3, d0_bignum_int(temp3, 0));
	CHECK_ASSIGN(temp4, d0_bignum_int(temp4, 0));
	UNLOCKTEMPS();
	return 1;
fail:
	UNLOCKTEMPS();
	return 0;
}

void d0_blind_id_SHUTDOWN(void)
{
	USINGTEMPS();
	LOCKTEMPS();
	d0_bignum_free(zero);
	d0_bignum_free(one);
	d0_bignum_free(four);
	d0_bignum_free(temp0);
	d0_bignum_free(temp1);
	d0_bignum_free(temp2);
	d0_bignum_free(temp3);
	d0_bignum_free(temp4);
	d0_bignum_SHUTDOWN();
	UNLOCKTEMPS();
	d0_destroymutex(tempmutex);
	tempmutex = NULL;
}

// (G-1)/2
static d0_bignum_t *d0_dl_get_order(d0_bignum_t *o, const d0_bignum_t *G)
{
	CHECK_ASSIGN(o, d0_bignum_sub(o, G, one));
	CHECK(d0_bignum_shl(o, o, -1)); // order o = (G-1)/2
	return o;
fail:
	return NULL;
}
// 2o+1
d0_bignum_t *d0_dl_get_from_order(d0_bignum_t *G, const d0_bignum_t *o)
{
	CHECK_ASSIGN(G, d0_bignum_shl(G, o, 1));
	CHECK(d0_bignum_add(G, G, one));
	return G;
fail:
	return NULL;
}

// temps must NOT be locked when calling this
static D0_BOOL d0_dl_generate_key(size_t size, d0_bignum_t *G)
{
	USINGTEMPS(); // using: temp0
	if(size < 16)
		size = 16;
	for(;;)
	{
		LOCKTEMPS();
		CHECK(d0_bignum_rand_bit_exact(temp0, size-1));
		if(d0_bignum_isprime(temp0, 0) == 0)
			continue;
		CHECK(d0_dl_get_from_order(G, temp0));
		if(d0_bignum_isprime(G, 10) == 0)
			continue;
		if(d0_bignum_isprime(temp0, 10) == 0) // finish the previous test
			continue;
		UNLOCKTEMPS();
		break;
	}
	return 1;
fail:
	UNLOCKTEMPS();
	return 0;
}

// temps must NOT be locked when calling this
static D0_BOOL d0_rsa_generate_key(size_t size, d0_blind_id_t *ctx)
{
	USINGTEMPS(); // uses temp1 to temp4
	int fail = 0;
	int gcdfail = 0;
	int pb = (size + 1)/2;
	int qb = size - pb;
	if(pb < 8)
		pb = 8;
	if(qb < 8)
		qb = 8;

	// we use ctx->rsa_d for the first result so that we can unlock temps later
        for (;;)
	{
		LOCKTEMPS();
		CHECK(d0_bignum_rand_bit_exact(ctx->rsa_d, pb));
		if(d0_bignum_isprime(ctx->rsa_d, 10) == 0)
		{
			UNLOCKTEMPS();
			continue;
		}
		CHECK(d0_bignum_sub(temp2, ctx->rsa_d, one));
		CHECK(d0_bignum_gcd(temp4, NULL, NULL, temp2, ctx->rsa_e));
		if(!d0_bignum_cmp(temp4, one))
			break;
		if(++gcdfail == 3)
			goto fail;
		++gcdfail;
	}
	UNLOCKTEMPS();

	gcdfail = 0;
        for (;;)
	{
		LOCKTEMPS();
		CHECK(d0_bignum_rand_bit_exact(temp1, qb));
		if(!d0_bignum_cmp(temp1, ctx->rsa_d))
		{
			UNLOCKTEMPS();
			if(++fail == 3)
				goto fail;
			continue;
		}
		fail = 0;
		if(d0_bignum_isprime(temp1, 10) == 0)
		{
			UNLOCKTEMPS();
			continue;
		}
		CHECK(d0_bignum_sub(temp3, temp1, one));
		CHECK(d0_bignum_gcd(temp4, NULL, NULL, temp3, ctx->rsa_e));
		if(!d0_bignum_cmp(temp4, one))
		{
			// we do NOT unlock, as we still need temp1 and temp3
			break;
		}
		UNLOCKTEMPS();
		if(++gcdfail == 3)
			goto fail;
		++gcdfail;
	}

	// ctx->rsa_n = ctx->rsa_d*temp1
	CHECK(d0_bignum_mul(ctx->rsa_n, ctx->rsa_d, temp1));

	// ctx->rsa_d = ctx->rsa_e^-1 mod (ctx->rsa_d-1)(temp1-1)
	CHECK(d0_bignum_sub(temp2, ctx->rsa_d, one)); // we can't reuse the value from above because temps were unlocked
	CHECK(d0_bignum_mul(temp0, temp2, temp3));
	CHECK(d0_bignum_mod_inv(ctx->rsa_d, ctx->rsa_e, temp0));
	UNLOCKTEMPS();
	return 1;
fail:
	UNLOCKTEMPS();
	return 0;
}

// temps must NOT be locked when calling this
static D0_BOOL d0_rsa_generate_key_fastreject(size_t size, d0_fastreject_function reject, d0_blind_id_t *ctx, void *pass)
{
	USINGTEMPS(); // uses temp1 to temp4
	int fail = 0;
	int gcdfail = 0;
	int pb = (size + 1)/2;
	int qb = size - pb;
	if(pb < 8)
		pb = 8;
	if(qb < 8)
		qb = 8;

	// we use ctx->rsa_d for the first result so that we can unlock temps later
        for (;;)
	{
		LOCKTEMPS();
		CHECK(d0_bignum_rand_bit_exact(ctx->rsa_d, pb));
		if(d0_bignum_isprime(ctx->rsa_d, 10) == 0)
		{
			UNLOCKTEMPS();
			continue;
		}
		CHECK(d0_bignum_sub(temp2, ctx->rsa_d, one));
		CHECK(d0_bignum_gcd(temp4, NULL, NULL, temp2, ctx->rsa_e));
		if(!d0_bignum_cmp(temp4, one))
			break;
		if(++gcdfail == 3)
			return 0;
		++gcdfail;
	}
	UNLOCKTEMPS();

	gcdfail = 0;
        for (;;)
	{
		LOCKTEMPS();
		CHECK(d0_bignum_rand_bit_exact(temp1, qb));
		if(!d0_bignum_cmp(temp1, ctx->rsa_d))
		{
			UNLOCKTEMPS();
			if(++fail == 3)
				return 0;
			continue;
		}
		fail = 0;

		// n = ctx->rsa_d*temp1
		CHECK(d0_bignum_mul(ctx->rsa_n, ctx->rsa_d, temp1));
		if(reject(ctx, pass))
		{
			UNLOCKTEMPS();
			continue;
		}

		if(d0_bignum_isprime(temp1, 10) == 0)
		{
			UNLOCKTEMPS();
			continue;
		}
		CHECK(d0_bignum_sub(temp3, temp1, one));
		CHECK(d0_bignum_gcd(temp4, NULL, NULL, temp3, ctx->rsa_e));
		if(!d0_bignum_cmp(temp4, one))
		{
			// we do NOT unlock, as we still need temp3
			break;
		}
		UNLOCKTEMPS();
		if(++gcdfail == 3)
			return 0;
		++gcdfail;
	}

	// ctx->rsa_d = ctx->rsa_e^-1 mod (ctx->rsa_d-1)(temp1-1)
	CHECK(d0_bignum_sub(temp2, ctx->rsa_d, one)); // we can't reuse the value from above because temps were unlocked
	CHECK(d0_bignum_mul(ctx->rsa_d, temp2, temp3));
	CHECK(d0_bignum_mod_inv(ctx->rsa_d, ctx->rsa_e, temp0));
	UNLOCKTEMPS();
	return 1;
fail:
	UNLOCKTEMPS();
	return 0;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_longhash_destructive(unsigned char *convbuf, size_t sz, unsigned char *outbuf, size_t outbuflen)
{
	size_t n, i;
	char shabuf[32];

	n = outbuflen;
	while(n > SHA_DIGESTSIZE)
	{
		memcpy(outbuf, sha(shabuf, convbuf, sz), SHA_DIGESTSIZE);
		outbuf += SHA_DIGESTSIZE;
		n -= SHA_DIGESTSIZE;
		for(i = 0; i < sz; ++i)
			if(++convbuf[i])
				break; // stop until no carry
	}
	memcpy(outbuf, sha(shabuf, convbuf, sz), n);
	return 1;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_longhash_bignum(const d0_bignum_t *in, unsigned char *outbuf, size_t outbuflen)
{
	unsigned char convbuf[1024];
	size_t sz;

	CHECK(d0_bignum_export_unsigned(in, convbuf, sizeof(convbuf)) >= 0);
	sz = (d0_bignum_size(in) + 7) / 8;
	CHECK(d0_longhash_destructive(convbuf, sz, outbuf, outbuflen));
	return 1;

fail:
	return 0;
}

void d0_blind_id_clear(d0_blind_id_t *ctx)
{
	if(ctx->rsa_n) d0_bignum_free(ctx->rsa_n);
	if(ctx->rsa_e) d0_bignum_free(ctx->rsa_e);
	if(ctx->rsa_d) d0_bignum_free(ctx->rsa_d);
	if(ctx->schnorr_G) d0_bignum_free(ctx->schnorr_G);
	if(ctx->schnorr_s) d0_bignum_free(ctx->schnorr_s);
	if(ctx->schnorr_g_to_s) d0_bignum_free(ctx->schnorr_g_to_s);
	if(ctx->schnorr_H_g_to_s_signature) d0_bignum_free(ctx->schnorr_H_g_to_s_signature);
	if(ctx->rsa_blind_signature_camouflage) d0_bignum_free(ctx->rsa_blind_signature_camouflage);
	if(ctx->r) d0_bignum_free(ctx->r);
	if(ctx->challenge) d0_bignum_free(ctx->challenge);
	if(ctx->t) d0_bignum_free(ctx->t);
	if(ctx->g_to_t) d0_bignum_free(ctx->g_to_t);
	if(ctx->other_g_to_t) d0_bignum_free(ctx->other_g_to_t);
	memset(ctx, 0, sizeof(*ctx));
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_copy(d0_blind_id_t *ctx, const d0_blind_id_t *src)
{
	d0_blind_id_clear(ctx);
	if(src->rsa_n) CHECK_ASSIGN(ctx->rsa_n, d0_bignum_mov(NULL, src->rsa_n));
	if(src->rsa_e) CHECK_ASSIGN(ctx->rsa_e, d0_bignum_mov(NULL, src->rsa_e));
	if(src->rsa_d) CHECK_ASSIGN(ctx->rsa_d, d0_bignum_mov(NULL, src->rsa_d));
	if(src->schnorr_G) CHECK_ASSIGN(ctx->schnorr_G, d0_bignum_mov(NULL, src->schnorr_G));
	if(src->schnorr_s) CHECK_ASSIGN(ctx->schnorr_s, d0_bignum_mov(NULL, src->schnorr_s));
	if(src->schnorr_g_to_s) CHECK_ASSIGN(ctx->schnorr_g_to_s, d0_bignum_mov(NULL, src->schnorr_g_to_s));
	if(src->schnorr_H_g_to_s_signature) CHECK_ASSIGN(ctx->schnorr_H_g_to_s_signature, d0_bignum_mov(NULL, src->schnorr_H_g_to_s_signature));
	if(src->rsa_blind_signature_camouflage) CHECK_ASSIGN(ctx->rsa_blind_signature_camouflage, d0_bignum_mov(NULL, src->rsa_blind_signature_camouflage));
	if(src->r) CHECK_ASSIGN(ctx->r, d0_bignum_mov(NULL, src->r));
	if(src->challenge) CHECK_ASSIGN(ctx->challenge, d0_bignum_mov(NULL, src->challenge));
	if(src->t) CHECK_ASSIGN(ctx->t, d0_bignum_mov(NULL, src->t));
	if(src->g_to_t) CHECK_ASSIGN(ctx->g_to_t, d0_bignum_mov(NULL, src->g_to_t));
	if(src->other_g_to_t) CHECK_ASSIGN(ctx->other_g_to_t, d0_bignum_mov(NULL, src->other_g_to_t));
	memcpy(ctx->msg, src->msg, sizeof(ctx->msg));
	ctx->msglen = src->msglen;
	memcpy(ctx->msghash, src->msghash, sizeof(ctx->msghash));
	return 1;
fail:
	d0_blind_id_clear(ctx);
	return 0;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_generate_private_key_fastreject(d0_blind_id_t *ctx, int k, d0_fastreject_function reject, void *pass)
{
	REPLACING(rsa_e); REPLACING(rsa_d); REPLACING(rsa_n);

	CHECK_ASSIGN(ctx->rsa_e, d0_bignum_int(ctx->rsa_e, 65537));
	CHECK_ASSIGN(ctx->rsa_d, d0_bignum_zero(ctx->rsa_d));
	CHECK_ASSIGN(ctx->rsa_n, d0_bignum_zero(ctx->rsa_n));
	if(reject)
		CHECK(d0_rsa_generate_key_fastreject(k+1, reject, ctx, pass)); // must fit G for sure
	else
		CHECK(d0_rsa_generate_key(k+1, ctx)); // must fit G for sure
	return 1;
fail:
	return 0;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_generate_private_key(d0_blind_id_t *ctx, int k)
{
	return d0_blind_id_generate_private_key_fastreject(ctx, k, NULL, NULL);
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_read_private_key(d0_blind_id_t *ctx, const char *inbuf, size_t inbuflen)
{
	d0_iobuf_t *in = NULL;

	REPLACING(rsa_n); REPLACING(rsa_e); REPLACING(rsa_d);

	in = d0_iobuf_open_read(inbuf, inbuflen);

	CHECK_ASSIGN(ctx->rsa_n, d0_iobuf_read_bignum(in, ctx->rsa_n));
	CHECK_ASSIGN(ctx->rsa_e, d0_iobuf_read_bignum(in, ctx->rsa_e));
	CHECK_ASSIGN(ctx->rsa_d, d0_iobuf_read_bignum(in, ctx->rsa_d));
	return d0_iobuf_close(in, NULL);

fail:
	d0_iobuf_close(in, NULL);
	return 0;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_read_public_key(d0_blind_id_t *ctx, const char *inbuf, size_t inbuflen)
{
	d0_iobuf_t *in = NULL;

	REPLACING(rsa_n); REPLACING(rsa_e);

	in = d0_iobuf_open_read(inbuf, inbuflen);
	CHECK_ASSIGN(ctx->rsa_n, d0_iobuf_read_bignum(in, ctx->rsa_n));
	CHECK_ASSIGN(ctx->rsa_e, d0_iobuf_read_bignum(in, ctx->rsa_e));
	return d0_iobuf_close(in, NULL);

fail:
	d0_iobuf_close(in, NULL);
	return 0;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_write_private_key(const d0_blind_id_t *ctx, char *outbuf, size_t *outbuflen)
{
	d0_iobuf_t *out = NULL;

	USING(rsa_n); USING(rsa_e); USING(rsa_d);

	out = d0_iobuf_open_write(outbuf, *outbuflen);
	CHECK(d0_iobuf_write_bignum(out, ctx->rsa_n));
	CHECK(d0_iobuf_write_bignum(out, ctx->rsa_e));
	CHECK(d0_iobuf_write_bignum(out, ctx->rsa_d));
	return d0_iobuf_close(out, outbuflen);

fail:
	d0_iobuf_close(out, outbuflen);
	return 0;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_write_public_key(const d0_blind_id_t *ctx, char *outbuf, size_t *outbuflen)
{
	d0_iobuf_t *out = NULL;

	USING(rsa_n); USING(rsa_e);

	out = d0_iobuf_open_write(outbuf, *outbuflen);
	CHECK(d0_iobuf_write_bignum(out, ctx->rsa_n));
	CHECK(d0_iobuf_write_bignum(out, ctx->rsa_e));
	return d0_iobuf_close(out, outbuflen);

fail:
	if(!d0_iobuf_close(out, outbuflen))
		return 0;
	return 0;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_fingerprint64_public_key(const d0_blind_id_t *ctx, char *outbuf, size_t *outbuflen)
{
	d0_iobuf_t *out = NULL;
	unsigned char convbuf[2048];
	d0_iobuf_t *conv = NULL;
	size_t sz, n;
	char shabuf[32];

	USING(rsa_n); USING(rsa_e);

	out = d0_iobuf_open_write(outbuf, *outbuflen);
	conv = d0_iobuf_open_write(convbuf, sizeof(convbuf));

	CHECK(d0_iobuf_write_bignum(conv, ctx->rsa_n));
	CHECK(d0_iobuf_write_bignum(conv, ctx->rsa_e));
	CHECK(d0_iobuf_close(conv, &sz));
	conv = NULL;

	n = (*outbuflen / 4) * 3;
	if(n > SHA_DIGESTSIZE)
		n = SHA_DIGESTSIZE;
	CHECK(d0_iobuf_write_raw(out, sha(shabuf, convbuf, sz), n) == n);
	CHECK(d0_iobuf_conv_base64_out(out));

	return d0_iobuf_close(out, outbuflen);

fail:
	if(conv)
		d0_iobuf_close(conv, &sz);
	d0_iobuf_close(out, outbuflen);
	return 0;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_generate_private_id_modulus(d0_blind_id_t *ctx)
{
	USING(rsa_n);
	REPLACING(schnorr_G);

	CHECK_ASSIGN(ctx->schnorr_G, d0_bignum_zero(ctx->schnorr_G));
	CHECK(d0_dl_generate_key(d0_bignum_size(ctx->rsa_n)-1, ctx->schnorr_G));
	return 1;
fail:
	return 0;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_read_private_id_modulus(d0_blind_id_t *ctx, const char *inbuf, size_t inbuflen)
{
	d0_iobuf_t *in = NULL;

	REPLACING(schnorr_G);

	in = d0_iobuf_open_read(inbuf, inbuflen);
	CHECK_ASSIGN(ctx->schnorr_G, d0_iobuf_read_bignum(in, ctx->schnorr_G));
	return d0_iobuf_close(in, NULL);

fail:
	d0_iobuf_close(in, NULL);
	return 0;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_write_private_id_modulus(const d0_blind_id_t *ctx, char *outbuf, size_t *outbuflen)
{
	d0_iobuf_t *out = NULL;

	USING(schnorr_G);

	out = d0_iobuf_open_write(outbuf, *outbuflen);
	CHECK(d0_iobuf_write_bignum(out, ctx->schnorr_G));
	return d0_iobuf_close(out, outbuflen);

fail:
	d0_iobuf_close(out, outbuflen);
	return 0;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_generate_private_id_start(d0_blind_id_t *ctx)
{
	USINGTEMPS(); // temps: temp0 = order
	USING(schnorr_G);
	REPLACING(schnorr_s); REPLACING(schnorr_g_to_s);

	LOCKTEMPS();
	CHECK(d0_dl_get_order(temp0, ctx->schnorr_G));
	CHECK_ASSIGN(ctx->schnorr_s, d0_bignum_rand_range(ctx->schnorr_s, zero, temp0));
	CHECK_ASSIGN(ctx->schnorr_g_to_s, d0_bignum_mod_pow(ctx->schnorr_g_to_s, four, ctx->schnorr_s, ctx->schnorr_G));
	CHECK_ASSIGN(ctx->schnorr_H_g_to_s_signature, d0_bignum_zero(ctx->schnorr_H_g_to_s_signature));
	UNLOCKTEMPS();
	return 1;

fail:
	UNLOCKTEMPS();
	return 0;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_generate_private_id_request(d0_blind_id_t *ctx, char *outbuf, size_t *outbuflen)
{
	d0_iobuf_t *out = NULL;
	unsigned char hashbuf[2048];
	size_t sz;

	USINGTEMPS(); // temps: temp0 rsa_blind_signature_camouflage^challenge, temp1 (4^s)*rsa_blind_signature_camouflage^challenge
	USING(rsa_n); USING(rsa_e); USING(schnorr_g_to_s);
	REPLACING(rsa_blind_signature_camouflage);

	out = d0_iobuf_open_write(outbuf, *outbuflen);

	CHECK_ASSIGN(ctx->rsa_blind_signature_camouflage, d0_bignum_rand_bit_atmost(ctx->rsa_blind_signature_camouflage, d0_bignum_size(ctx->rsa_n)));
	CHECK(d0_bignum_mod_pow(temp0, ctx->rsa_blind_signature_camouflage, ctx->rsa_e, ctx->rsa_n));

	// we will actually sign HA(4^s) to prevent a malleability attack!
	LOCKTEMPS();
	sz = (d0_bignum_size(ctx->rsa_n) + 7) / 8; // this is too long, so we have to take the value % rsa_n when "decrypting"
	if(sz > sizeof(hashbuf))
		sz = sizeof(hashbuf);
	CHECK(d0_longhash_bignum(ctx->schnorr_g_to_s, hashbuf, sz));
	CHECK(d0_bignum_import_unsigned(temp2, hashbuf, sz));

	// hash complete
	CHECK(d0_bignum_mod_mul(temp1, temp2, temp0, ctx->rsa_n));
	CHECK(d0_iobuf_write_bignum(out, temp1));
	UNLOCKTEMPS();
	return d0_iobuf_close(out, outbuflen);

fail:
	UNLOCKTEMPS();
	d0_iobuf_close(out, outbuflen);
	return 0;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_answer_private_id_request(const d0_blind_id_t *ctx, const char *inbuf, size_t inbuflen, char *outbuf, size_t *outbuflen)
{
	d0_iobuf_t *in = NULL;
	d0_iobuf_t *out = NULL;

	USINGTEMPS(); // temps: temp0 input, temp1 temp0^d
	USING(rsa_d); USING(rsa_n);

	in = d0_iobuf_open_read(inbuf, inbuflen);
	out = d0_iobuf_open_write(outbuf, *outbuflen);

	LOCKTEMPS();
	CHECK(d0_iobuf_read_bignum(in, temp0));
	CHECK(d0_bignum_mod_pow(temp1, temp0, ctx->rsa_d, ctx->rsa_n));
	CHECK(d0_iobuf_write_bignum(out, temp1));

	UNLOCKTEMPS();
	d0_iobuf_close(in, NULL);
	return d0_iobuf_close(out, outbuflen);

fail:
	UNLOCKTEMPS();
	d0_iobuf_close(in, NULL);
	d0_iobuf_close(out, outbuflen);
	return 0;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_finish_private_id_request(d0_blind_id_t *ctx, const char *inbuf, size_t inbuflen)
{
	d0_iobuf_t *in = NULL;

	USINGTEMPS(); // temps: temp0 input, temp1 rsa_blind_signature_camouflage^-1
	USING(rsa_blind_signature_camouflage); USING(rsa_n);
	REPLACING(schnorr_H_g_to_s_signature);

	in = d0_iobuf_open_read(inbuf, inbuflen);

	LOCKTEMPS();

	CHECK(d0_iobuf_read_bignum(in, temp0));
	CHECK(d0_bignum_mod_inv(temp1, ctx->rsa_blind_signature_camouflage, ctx->rsa_n));
	CHECK_ASSIGN(ctx->schnorr_H_g_to_s_signature, d0_bignum_mod_mul(ctx->schnorr_H_g_to_s_signature, temp0, temp1, ctx->rsa_n));

	UNLOCKTEMPS();
	return d0_iobuf_close(in, NULL);

fail:
	UNLOCKTEMPS();
	d0_iobuf_close(in, NULL);
	return 0;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_read_private_id_request_camouflage(d0_blind_id_t *ctx, const char *inbuf, size_t inbuflen)
{
	d0_iobuf_t *in = NULL;

	REPLACING(rsa_blind_signature_camouflage);

	in = d0_iobuf_open_read(inbuf, inbuflen);

	CHECK_ASSIGN(ctx->rsa_blind_signature_camouflage, d0_iobuf_read_bignum(in, ctx->rsa_blind_signature_camouflage));

	return d0_iobuf_close(in, NULL);

fail:
	d0_iobuf_close(in, NULL);
	return 0;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_write_private_id_request_camouflage(const d0_blind_id_t *ctx, char *outbuf, size_t *outbuflen)
{
	d0_iobuf_t *out = NULL;

	USING(rsa_blind_signature_camouflage);

	out = d0_iobuf_open_write(outbuf, *outbuflen);

	CHECK(d0_iobuf_write_bignum(out, ctx->rsa_blind_signature_camouflage));

	return d0_iobuf_close(out, outbuflen);

fail:
	d0_iobuf_close(out, outbuflen);
	return 0;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_read_private_id(d0_blind_id_t *ctx, const char *inbuf, size_t inbuflen)
{
	d0_iobuf_t *in = NULL;

	REPLACING(schnorr_s); REPLACING(schnorr_g_to_s); REPLACING(schnorr_H_g_to_s_signature);

	in = d0_iobuf_open_read(inbuf, inbuflen);

	CHECK_ASSIGN(ctx->schnorr_s, d0_iobuf_read_bignum(in, ctx->schnorr_s));
	CHECK_ASSIGN(ctx->schnorr_g_to_s, d0_iobuf_read_bignum(in, ctx->schnorr_g_to_s));
	CHECK_ASSIGN(ctx->schnorr_H_g_to_s_signature, d0_iobuf_read_bignum(in, ctx->schnorr_H_g_to_s_signature));

	return d0_iobuf_close(in, NULL);

fail:
	d0_iobuf_close(in, NULL);
	return 0;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_read_public_id(d0_blind_id_t *ctx, const char *inbuf, size_t inbuflen)
{
	d0_iobuf_t *in = NULL;

	REPLACING(schnorr_g_to_s); REPLACING(schnorr_H_g_to_s_signature);

	in = d0_iobuf_open_read(inbuf, inbuflen);

	CHECK_ASSIGN(ctx->schnorr_g_to_s, d0_iobuf_read_bignum(in, ctx->schnorr_g_to_s));
	CHECK_ASSIGN(ctx->schnorr_H_g_to_s_signature, d0_iobuf_read_bignum(in, ctx->schnorr_H_g_to_s_signature));

	return d0_iobuf_close(in, NULL);

fail:
	d0_iobuf_close(in, NULL);
	return 0;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_write_private_id(const d0_blind_id_t *ctx, char *outbuf, size_t *outbuflen)
{
	d0_iobuf_t *out = NULL;

	USING(schnorr_s); USING(schnorr_g_to_s); USING(schnorr_H_g_to_s_signature);

	out = d0_iobuf_open_write(outbuf, *outbuflen);

	CHECK(d0_iobuf_write_bignum(out, ctx->schnorr_s));
	CHECK(d0_iobuf_write_bignum(out, ctx->schnorr_g_to_s));
	CHECK(d0_iobuf_write_bignum(out, ctx->schnorr_H_g_to_s_signature));

	return d0_iobuf_close(out, outbuflen);

fail:
	d0_iobuf_close(out, outbuflen);
	return 0;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_write_public_id(const d0_blind_id_t *ctx, char *outbuf, size_t *outbuflen)
{
	d0_iobuf_t *out = NULL;

	USING(schnorr_g_to_s); USING(schnorr_H_g_to_s_signature);

	out = d0_iobuf_open_write(outbuf, *outbuflen);

	CHECK(d0_iobuf_write_bignum(out, ctx->schnorr_g_to_s));
	CHECK(d0_iobuf_write_bignum(out, ctx->schnorr_H_g_to_s_signature));

	return d0_iobuf_close(out, outbuflen);

fail:
	d0_iobuf_close(out, outbuflen);
	return 0;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_authenticate_with_private_id_start(d0_blind_id_t *ctx, D0_BOOL is_first, D0_BOOL send_modulus, const char *msg, size_t msglen, char *outbuf, size_t *outbuflen)
// start =
//   first run: send 4^s, 4^s signature
//   1. get random r, send HASH(4^r)
{
	d0_iobuf_t *out = NULL;
	unsigned char convbuf[1024];
	d0_iobuf_t *conv = NULL;
	size_t sz = 0;
	D0_BOOL failed = 0;
	char shabuf[32];

	USINGTEMPS(); // temps: temp0 order, temp0 4^r
	if(is_first)
	{
		USING(schnorr_g_to_s); USING(schnorr_H_g_to_s_signature);
	}
	USING(schnorr_G);
	REPLACING(r); REPLACING(t); REPLACING(g_to_t);

	out = d0_iobuf_open_write(outbuf, *outbuflen);

	if(is_first)
	{
		// send ID
		if(send_modulus)
			CHECK(d0_iobuf_write_bignum(out, ctx->schnorr_G));
		CHECK(d0_iobuf_write_bignum(out, ctx->schnorr_g_to_s));
		CHECK(d0_iobuf_write_bignum(out, ctx->schnorr_H_g_to_s_signature));
	}

	// start schnorr ID scheme
	// generate random number r; x = g^r; send hash of x, remember r, forget x
	LOCKTEMPS();
	CHECK(d0_dl_get_order(temp0, ctx->schnorr_G));
#ifdef RNG_XKCD
	CHECK_ASSIGN(ctx->r, d0_bignum_int(ctx->r, 4)); // decided by fair dice roll
#else
	CHECK_ASSIGN(ctx->r, d0_bignum_rand_range(ctx->r, zero, temp0));
#endif

	// initialize Signed Diffie Hellmann
	// we already have the group order in temp1
#ifdef RNG_XKCD
	CHECK_ASSIGN(ctx->t, d0_bignum_int(ctx->t, 4)); // decided by fair dice roll
#else
	CHECK_ASSIGN(ctx->t, d0_bignum_rand_range(ctx->t, zero, temp0));
#endif
	// can we SOMEHOW do this with just one mod_pow?

	CHECK(d0_bignum_mod_pow(temp0, four, ctx->r, ctx->schnorr_G));
	CHECK_ASSIGN(ctx->g_to_t, d0_bignum_mod_pow(ctx->g_to_t, four, ctx->t, ctx->schnorr_G));
	CHECK(!failed);

	// hash it, hash it, everybody hash it
	conv = d0_iobuf_open_write(convbuf, sizeof(convbuf));
	CHECK(d0_iobuf_write_bignum(conv, temp0));
	CHECK(d0_iobuf_write_bignum(conv, ctx->g_to_t));
	CHECK(d0_iobuf_write_packet(conv, msg, msglen));
	CHECK(d0_iobuf_write_bignum(conv, temp0));
	UNLOCKTEMPS();
	CHECK(d0_iobuf_write_bignum(conv, ctx->g_to_t));
	d0_iobuf_close(conv, &sz);
	conv = NULL;
	CHECK(d0_iobuf_write_raw(out, sha(shabuf, convbuf, sz), SCHNORR_HASHSIZE) == SCHNORR_HASHSIZE);
	CHECK(d0_iobuf_write_packet(out, msg, msglen));

	return d0_iobuf_close(out, outbuflen);

fail:
	UNLOCKTEMPS();
	d0_iobuf_close(out, outbuflen);
	return 0;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_authenticate_with_private_id_challenge(d0_blind_id_t *ctx, D0_BOOL is_first, D0_BOOL recv_modulus, const char *inbuf, size_t inbuflen, char *outbuf, size_t *outbuflen, D0_BOOL *status)
//   first run: get 4^s, 4^s signature
//   1. check sig
//   2. save HASH(4^r)
//   3. send challenge challenge of SCHNORR_BITS
{
	d0_iobuf_t *in = NULL;
	d0_iobuf_t *out = NULL;
	unsigned char hashbuf[2048];
	size_t sz;

	USINGTEMPS(); // temps: temp0 order, temp0 signature check
	if(is_first)
	{
		REPLACING(schnorr_g_to_s); REPLACING(schnorr_H_g_to_s_signature);
		if(recv_modulus)
			REPLACING(schnorr_G);
		else
			USING(schnorr_G);
	}
	else
	{
		USING(schnorr_g_to_s); USING(schnorr_H_g_to_s_signature);
		USING(schnorr_G);
	}
	USING(rsa_e); USING(rsa_n);
	REPLACING(challenge); REPLACING(msg); REPLACING(msglen); REPLACING(msghash); REPLACING(r); REPLACING(t);

	in = d0_iobuf_open_read(inbuf, inbuflen);
	out = d0_iobuf_open_write(outbuf, *outbuflen);

	if(is_first)
	{
		if(recv_modulus)
		{
			CHECK_ASSIGN(ctx->schnorr_G, d0_iobuf_read_bignum(in, ctx->schnorr_G));
			CHECK(d0_bignum_cmp(ctx->schnorr_G, zero) > 0);
			CHECK(d0_bignum_cmp(ctx->schnorr_G, ctx->rsa_n) < 0);
		}
		CHECK_ASSIGN(ctx->schnorr_g_to_s, d0_iobuf_read_bignum(in, ctx->schnorr_g_to_s));
		CHECK(d0_bignum_cmp(ctx->schnorr_g_to_s, zero) >= 0);
		CHECK(d0_bignum_cmp(ctx->schnorr_g_to_s, ctx->schnorr_G) < 0);
		CHECK_ASSIGN(ctx->schnorr_H_g_to_s_signature, d0_iobuf_read_bignum(in, ctx->schnorr_H_g_to_s_signature));
		CHECK(d0_bignum_cmp(ctx->schnorr_H_g_to_s_signature, zero) >= 0);
		CHECK(d0_bignum_cmp(ctx->schnorr_H_g_to_s_signature, ctx->rsa_n) < 0);

		if(d0_bignum_cmp(ctx->schnorr_H_g_to_s_signature, zero))
		{
			// check signature of key (t = k^d, so, t^challenge = k)
			LOCKTEMPS();
			CHECK(d0_bignum_mod_pow(temp0, ctx->schnorr_H_g_to_s_signature, ctx->rsa_e, ctx->rsa_n));

			// we will actually sign SHA(4^s) to prevent a malleability attack!
			sz = (d0_bignum_size(ctx->rsa_n) + 7) / 8; // this is too long, so we have to take the value % rsa_n when "decrypting"
			if(sz > sizeof(hashbuf))
				sz = sizeof(hashbuf);
			CHECK(d0_longhash_bignum(ctx->schnorr_g_to_s, hashbuf, sz));
			CHECK(d0_bignum_import_unsigned(temp2, hashbuf, sz));

			// + 7 / 8 is too large, so let's mod it
			CHECK(d0_bignum_divmod(NULL, temp1, temp2, ctx->rsa_n));

			// hash complete
			CHECK(d0_bignum_cmp(temp0, temp1) == 0);
		}
	}

	CHECK(d0_iobuf_read_raw(in, ctx->msghash, SCHNORR_HASHSIZE));
	ctx->msglen = MSGSIZE;
	CHECK(d0_iobuf_read_packet(in, ctx->msg, &ctx->msglen));

	// send challenge
#ifdef RNG_XKCD
	CHECK_ASSIGN(ctx->challenge, d0_bignum_int(ctx->challenge, 4)); // decided by fair dice roll
#else
	CHECK_ASSIGN(ctx->challenge, d0_bignum_rand_bit_atmost(ctx->challenge, SCHNORR_BITS));
#endif
	CHECK(d0_iobuf_write_bignum(out, ctx->challenge));

	// Diffie Hellmann send
	LOCKTEMPS();
	CHECK(d0_dl_get_order(temp0, ctx->schnorr_G));
#ifdef RNG_XKCD
	CHECK_ASSIGN(ctx->t, d0_bignum_int(ctx->t, 4)); // decided by fair dice roll
#else
	CHECK_ASSIGN(ctx->t, d0_bignum_rand_range(ctx->t, zero, temp0));
#endif
	CHECK(d0_bignum_mod_pow(temp0, four, ctx->t, ctx->schnorr_G));
	CHECK(d0_iobuf_write_bignum(out, temp0));
	UNLOCKTEMPS();

	if(status)
		*status = !!d0_bignum_cmp(ctx->schnorr_H_g_to_s_signature, zero);

	d0_iobuf_close(in, NULL);
	return d0_iobuf_close(out, outbuflen);

fail:
	UNLOCKTEMPS();
	d0_iobuf_close(in, NULL);
	d0_iobuf_close(out, outbuflen);
	return 0;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_authenticate_with_private_id_response(d0_blind_id_t *ctx, const char *inbuf, size_t inbuflen, char *outbuf, size_t *outbuflen)
//   1. read challenge challenge of SCHNORR_BITS
//   2. reply with r + s * challenge mod order
{
	d0_iobuf_t *in = NULL;
	d0_iobuf_t *out = NULL;

	USINGTEMPS(); // temps: 0 order, 1 prod, 2 y, 3 challenge
	REPLACING(other_g_to_t); REPLACING(t);
	USING(schnorr_G); USING(schnorr_s); USING(r); USING(g_to_t);

	in = d0_iobuf_open_read(inbuf, inbuflen);
	out = d0_iobuf_open_write(outbuf, *outbuflen);

	LOCKTEMPS();
	CHECK(d0_iobuf_read_bignum(in, temp3));
	CHECK(d0_bignum_cmp(temp3, zero) >= 0);
	CHECK(d0_bignum_size(temp3) <= SCHNORR_BITS);

	// send response for schnorr ID scheme
	// i.challenge. r + ctx->schnorr_s * temp3
	CHECK(d0_dl_get_order(temp0, ctx->schnorr_G));
	CHECK(d0_bignum_mod_mul(temp1, ctx->schnorr_s, temp3, temp0));
#ifdef D0_BLIND_ID_POSITIVE_PROTOCOL
	CHECK(d0_bignum_mod_add(temp2, ctx->r, temp1, temp0));
#else
	CHECK(d0_bignum_mod_sub(temp2, ctx->r, temp1, temp0));
#endif
	CHECK(d0_iobuf_write_bignum(out, temp2));
	UNLOCKTEMPS();

	// Diffie Hellmann recv
	CHECK_ASSIGN(ctx->other_g_to_t, d0_iobuf_read_bignum(in, ctx->other_g_to_t));
	CHECK(d0_bignum_cmp(ctx->other_g_to_t, zero) > 0);
	CHECK(d0_bignum_cmp(ctx->other_g_to_t, ctx->schnorr_G) < 0);
	// Diffie Hellmann send
	CHECK(d0_iobuf_write_bignum(out, ctx->g_to_t));

	d0_iobuf_close(in, NULL);
	return d0_iobuf_close(out, outbuflen);

fail:
	UNLOCKTEMPS();
	d0_iobuf_close(in, NULL);
	d0_iobuf_close(out, outbuflen);
	return 0;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_authenticate_with_private_id_verify(d0_blind_id_t *ctx, const char *inbuf, size_t inbuflen, char *msg, size_t *msglen, D0_BOOL *status)
//   1. read y = r + s * challenge mod order
//   2. verify: g^y (g^s)^-challenge = g^(r+s*challenge-s*challenge) = g^r
//      (check using H(g^r) which we know)
{
	d0_iobuf_t *in = NULL;
	unsigned char convbuf[1024];
	d0_iobuf_t *conv = NULL;
	size_t sz;
	char shabuf[32];

	USINGTEMPS(); // temps: 0 y 1 order
	USING(challenge); USING(schnorr_G);
	REPLACING(other_g_to_t);

	in = d0_iobuf_open_read(inbuf, inbuflen);

	LOCKTEMPS();

	CHECK(d0_dl_get_order(temp1, ctx->schnorr_G));
	CHECK(d0_iobuf_read_bignum(in, temp0));
	CHECK(d0_bignum_cmp(temp0, zero) >= 0);
	CHECK(d0_bignum_cmp(temp0, temp1) < 0);

	// verify schnorr ID scheme
#ifdef D0_BLIND_ID_POSITIVE_PROTOCOL
	// we need 4^r = 4^temp0 (g^s)^-challenge
	CHECK(d0_bignum_mod_inv(temp1, ctx->schnorr_g_to_s, ctx->schnorr_G));
	CHECK(d0_bignum_mod_pow(temp2, temp1, ctx->challenge, ctx->schnorr_G));
#else
	// we need 4^r = 4^temp0 (g^s)^challenge
	CHECK(d0_bignum_mod_pow(temp2, ctx->schnorr_g_to_s, ctx->challenge, ctx->schnorr_G));
#endif
	CHECK(d0_bignum_mod_pow(temp1, four, temp0, ctx->schnorr_G));
	CHECK_ASSIGN(temp3, d0_bignum_mod_mul(temp3, temp1, temp2, ctx->schnorr_G));

	// Diffie Hellmann recv
	CHECK_ASSIGN(ctx->other_g_to_t, d0_iobuf_read_bignum(in, ctx->other_g_to_t));
	CHECK(d0_bignum_cmp(ctx->other_g_to_t, zero) > 0);
	CHECK(d0_bignum_cmp(ctx->other_g_to_t, ctx->schnorr_G) < 0);

	// hash it, hash it, everybody hash it
	conv = d0_iobuf_open_write(convbuf, sizeof(convbuf));
	CHECK(d0_iobuf_write_bignum(conv, temp3));
	CHECK(d0_iobuf_write_bignum(conv, ctx->other_g_to_t));
	CHECK(d0_iobuf_write_packet(conv, ctx->msg, ctx->msglen));
	CHECK(d0_iobuf_write_bignum(conv, temp3));
	UNLOCKTEMPS();
	CHECK(d0_iobuf_write_bignum(conv, ctx->other_g_to_t));
	d0_iobuf_close(conv, &sz);
	conv = NULL;
	if(memcmp(sha(shabuf, convbuf, sz), ctx->msghash, SCHNORR_HASHSIZE))
	{
		// FAIL (not owned by player)
		goto fail;
	}

	if(status)
		*status = !!d0_bignum_cmp(ctx->schnorr_H_g_to_s_signature, zero);

	if(ctx->msglen <= *msglen)
		memcpy(msg, ctx->msg, ctx->msglen);
	else
		memcpy(msg, ctx->msg, *msglen);
	*msglen = ctx->msglen;

	d0_iobuf_close(in, NULL);
	return 1;

fail:
	UNLOCKTEMPS();
	d0_iobuf_close(in, NULL);
	return 0;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_authenticate_with_private_id_generate_missing_signature(d0_blind_id_t *ctx)
{
	size_t sz;
	unsigned char hashbuf[2048];

	USINGTEMPS(); // temps: 2 hash
	REPLACING(schnorr_H_g_to_s_signature);
	USING(schnorr_g_to_s); USING(rsa_d); USING(rsa_n);

	LOCKTEMPS();

	// we will actually sign SHA(4^s) to prevent a malleability attack!
	sz = (d0_bignum_size(ctx->rsa_n) + 7) / 8; // this is too long, so we have to take the value % rsa_n when "decrypting"
	if(sz > sizeof(hashbuf))
		sz = sizeof(hashbuf);
	CHECK(d0_longhash_bignum(ctx->schnorr_g_to_s, hashbuf, sz));
	LOCKTEMPS();
	CHECK(d0_bignum_import_unsigned(temp2, hashbuf, sz));

	// + 7 / 8 is too large, so let's mod it
	CHECK(d0_bignum_divmod(NULL, temp1, temp2, ctx->rsa_n));
	CHECK(d0_bignum_mod_pow(ctx->schnorr_H_g_to_s_signature, temp1, ctx->rsa_d, ctx->rsa_n));

	UNLOCKTEMPS();
	return 1;

fail:
	UNLOCKTEMPS();
	return 0;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_sign_with_private_id_sign_internal(d0_blind_id_t *ctx, D0_BOOL is_first, D0_BOOL send_modulus, D0_BOOL with_msg, const char *message, size_t msglen, char *outbuf, size_t *outbuflen)
{
	d0_iobuf_t *out = NULL;
	unsigned char *convbuf = NULL;
	unsigned char hashbuf[2048];
	d0_iobuf_t *conv = NULL;
	size_t sz = 0;

	USINGTEMPS(); // temps: 0 order 1 4^r 2 hash
	if(is_first)
	{
		USING(schnorr_g_to_s); USING(schnorr_H_g_to_s_signature);
	}
	USING(schnorr_G);
	USING(schnorr_s);
	REPLACING(r);

	out = d0_iobuf_open_write(outbuf, *outbuflen);

	if(is_first)
	{
		// send ID
		if(send_modulus)
			CHECK(d0_iobuf_write_bignum(out, ctx->schnorr_G));
		CHECK(d0_iobuf_write_bignum(out, ctx->schnorr_g_to_s));
		CHECK(d0_iobuf_write_bignum(out, ctx->schnorr_H_g_to_s_signature));
	}

	// start schnorr SIGNATURE scheme
	// generate random number r; x = g^r; send hash of H(m||r), remember r, forget x
	LOCKTEMPS();
	CHECK(d0_dl_get_order(temp0, ctx->schnorr_G));
	CHECK_ASSIGN(ctx->r, d0_bignum_rand_range(ctx->r, zero, temp0));
	CHECK(d0_bignum_mod_pow(temp1, four, ctx->r, ctx->schnorr_G));

	// hash it, hash it, everybody hash it
	conv = d0_iobuf_open_write_p((void **) &convbuf, 0);
	CHECK(d0_iobuf_write_packet(conv, message, msglen));
	CHECK(d0_iobuf_write_bignum(conv, temp1));
	d0_iobuf_close(conv, &sz);
	conv = NULL;
	CHECK(d0_longhash_destructive(convbuf, sz, hashbuf, (d0_bignum_size(temp0) + 7) / 8));
	d0_free(convbuf);
	convbuf = NULL;
	CHECK(d0_bignum_import_unsigned(temp2, hashbuf, (d0_bignum_size(temp0) + 7) / 8));
	CHECK(d0_iobuf_write_bignum(out, temp2));

	// multiply with secret, sub k, modulo order
	CHECK(d0_bignum_mod_mul(temp1, temp2, ctx->schnorr_s, temp0));
#ifdef D0_BLIND_ID_POSITIVE_PROTOCOL
	CHECK(d0_bignum_mod_add(temp2, ctx->r, temp1, temp0));
#else
	CHECK(d0_bignum_mod_sub(temp2, ctx->r, temp1, temp0));
#endif
	CHECK(d0_iobuf_write_bignum(out, temp2));
	UNLOCKTEMPS();

	// write the message itself
	if(with_msg)
		CHECK(d0_iobuf_write_packet(out, message, msglen));

	return d0_iobuf_close(out, outbuflen);

fail:
	UNLOCKTEMPS();
	d0_iobuf_close(out, outbuflen);
	return 0;
}
D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_sign_with_private_id_sign(d0_blind_id_t *ctx, D0_BOOL is_first, D0_BOOL send_modulus, const char *message, size_t msglen, char *outbuf, size_t *outbuflen)
{
	return d0_blind_id_sign_with_private_id_sign_internal(ctx, is_first, send_modulus, 1, message, msglen, outbuf, outbuflen);
}
D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_sign_with_private_id_sign_detached(d0_blind_id_t *ctx, D0_BOOL is_first, D0_BOOL send_modulus, const char *message, size_t msglen, char *outbuf, size_t *outbuflen)
{
	return d0_blind_id_sign_with_private_id_sign_internal(ctx, is_first, send_modulus, 0, message, msglen, outbuf, outbuflen);
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_sign_with_private_id_verify_internal(d0_blind_id_t *ctx, D0_BOOL is_first, D0_BOOL recv_modulus, D0_BOOL with_msg, const char *inbuf, size_t inbuflen, char *msg, size_t *msglen, D0_BOOL *status)
{
	d0_iobuf_t *in = NULL;
	d0_iobuf_t *conv = NULL;
	unsigned char *convbuf = NULL;
	unsigned char hashbuf[2048];
	size_t sz;

	USINGTEMPS(); // temps: 0 sig^e 2 g^s 3 g^-s 4 order
	if(is_first)
	{
		REPLACING(schnorr_g_to_s); REPLACING(schnorr_H_g_to_s_signature);
		if(recv_modulus)
			REPLACING(schnorr_G);
		else
			USING(schnorr_G);
	}
	else
	{
		USING(schnorr_g_to_s); USING(schnorr_H_g_to_s_signature);
		USING(schnorr_G);
	}
	USING(rsa_e); USING(rsa_n);

	in = d0_iobuf_open_read(inbuf, inbuflen);

	if(is_first)
	{
		if(recv_modulus)
		{
			CHECK_ASSIGN(ctx->schnorr_G, d0_iobuf_read_bignum(in, ctx->schnorr_G));
			CHECK(d0_bignum_cmp(ctx->schnorr_G, zero) > 0);
			CHECK(d0_bignum_cmp(ctx->schnorr_G, ctx->rsa_n) < 0);
		}
		CHECK_ASSIGN(ctx->schnorr_g_to_s, d0_iobuf_read_bignum(in, ctx->schnorr_g_to_s));
		CHECK(d0_bignum_cmp(ctx->schnorr_g_to_s, zero) >= 0);
		CHECK(d0_bignum_cmp(ctx->schnorr_g_to_s, ctx->schnorr_G) < 0);
		CHECK_ASSIGN(ctx->schnorr_H_g_to_s_signature, d0_iobuf_read_bignum(in, ctx->schnorr_H_g_to_s_signature));
		CHECK(d0_bignum_cmp(ctx->schnorr_H_g_to_s_signature, zero) >= 0);
		CHECK(d0_bignum_cmp(ctx->schnorr_H_g_to_s_signature, ctx->rsa_n) < 0);

		// check signature of key (t = k^d, so, t^challenge = k)
		LOCKTEMPS();
		CHECK(d0_bignum_mod_pow(temp0, ctx->schnorr_H_g_to_s_signature, ctx->rsa_e, ctx->rsa_n));

		// we will actually sign SHA(4^s) to prevent a malleability attack!
		sz = (d0_bignum_size(ctx->rsa_n) + 7) / 8; // this is too long, so we have to take the value % rsa_n when "decrypting"
		if(sz > sizeof(hashbuf))
			sz = sizeof(hashbuf);
		CHECK(d0_longhash_bignum(ctx->schnorr_g_to_s, hashbuf, sz));
		CHECK(d0_bignum_import_unsigned(temp2, hashbuf, sz));

		// + 7 / 8 is too large, so let's mod it
		CHECK(d0_bignum_divmod(NULL, temp1, temp2, ctx->rsa_n));

		// hash complete
		if(d0_bignum_cmp(temp0, temp1))
		{
			// accept the key anyway, but mark as failed signature! will later return 0 in status
			CHECK(d0_bignum_zero(ctx->schnorr_H_g_to_s_signature));
		}
	}

	CHECK(d0_dl_get_order(temp4, ctx->schnorr_G));
	CHECK(d0_iobuf_read_bignum(in, temp0)); // e == H(m || g^r)
	CHECK(d0_iobuf_read_bignum(in, temp1)); // x == (r - s*e) mod |G|
	if(with_msg)
		CHECK(d0_iobuf_read_packet(in, msg, msglen));

	// VERIFY: g^x * (g^s)^-e = g^(x - s*e) = g^r

	// verify schnorr ID scheme
	// we need g^r = g^x (g^s)^e
	CHECK(d0_bignum_mod_pow(temp2, four, temp1, ctx->schnorr_G));
#ifdef D0_BLIND_ID_POSITIVE_PROTOCOL
	CHECK(d0_bignum_mod_inv(temp3, ctx->schnorr_g_to_s, ctx->schnorr_G));
	CHECK(d0_bignum_mod_pow(temp1, temp3, temp0, ctx->schnorr_G));
#else
	CHECK(d0_bignum_mod_pow(temp1, ctx->schnorr_g_to_s, temp0, ctx->schnorr_G));
#endif
	CHECK_ASSIGN(temp3, d0_bignum_mod_mul(temp3, temp1, temp2, ctx->schnorr_G)); // temp3 now is g^r

	// hash it, hash it, everybody hash it
	conv = d0_iobuf_open_write_p((void **) &convbuf, 0);
	CHECK(d0_iobuf_write_packet(conv, msg, *msglen));
	CHECK(d0_iobuf_write_bignum(conv, temp3));
	d0_iobuf_close(conv, &sz);
	conv = NULL;
	CHECK(d0_longhash_destructive(convbuf, sz, hashbuf, (d0_bignum_size(temp4) + 7) / 8));
	d0_free(convbuf);
	convbuf = NULL;
	CHECK(d0_bignum_import_unsigned(temp1, hashbuf, (d0_bignum_size(temp4) + 7) / 8));

	// verify signature
	CHECK(!d0_bignum_cmp(temp0, temp1));
	UNLOCKTEMPS();

	if(status)
		*status = !!d0_bignum_cmp(ctx->schnorr_H_g_to_s_signature, zero);

	d0_iobuf_close(in, NULL);
	return 1;

fail:
	UNLOCKTEMPS();
	d0_iobuf_close(in, NULL);
	return 0;
}
D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_sign_with_private_id_verify(d0_blind_id_t *ctx, D0_BOOL is_first, D0_BOOL recv_modulus, const char *inbuf, size_t inbuflen, char *msg, size_t *msglen, D0_BOOL *status)
{
	return d0_blind_id_sign_with_private_id_verify_internal(ctx, is_first, recv_modulus, 1, inbuf, inbuflen, msg, msglen, status);
}
D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_sign_with_private_id_verify_detached(d0_blind_id_t *ctx, D0_BOOL is_first, D0_BOOL recv_modulus, const char *inbuf, size_t inbuflen, const char *msg, size_t msglen, D0_BOOL *status)
{
	return d0_blind_id_sign_with_private_id_verify_internal(ctx, is_first, recv_modulus, 0, inbuf, inbuflen, (char *) msg, &msglen, status);
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_fingerprint64_public_id(const d0_blind_id_t *ctx, char *outbuf, size_t *outbuflen)
{
	d0_iobuf_t *out = NULL;
	unsigned char convbuf[1024];
	d0_iobuf_t *conv = NULL;
	size_t sz, n;
	char shabuf[32];

	USING(rsa_n);
	USING(rsa_e);
	USING(schnorr_g_to_s);

	out = d0_iobuf_open_write(outbuf, *outbuflen);
	conv = d0_iobuf_open_write(convbuf, sizeof(convbuf));

	CHECK(d0_iobuf_write_bignum(conv, ctx->rsa_n));
	CHECK(d0_iobuf_write_bignum(conv, ctx->rsa_e));
	CHECK(d0_iobuf_write_bignum(conv, ctx->schnorr_g_to_s));
	CHECK(d0_iobuf_close(conv, &sz));
	conv = NULL;

	n = (*outbuflen / 4) * 3;
	if(n > SHA_DIGESTSIZE)
		n = SHA_DIGESTSIZE;
	CHECK(d0_iobuf_write_raw(out, sha(shabuf, convbuf, sz), n) == n);
	CHECK(d0_iobuf_conv_base64_out(out));

	return d0_iobuf_close(out, outbuflen);

fail:
	if(conv)
		d0_iobuf_close(conv, &sz);
	d0_iobuf_close(out, outbuflen);
	return 0;
}

D0_BOOL d0_blind_id_sessionkey_public_id(const d0_blind_id_t *ctx, char *outbuf, size_t *outbuflen)
{
	D0_BOOL ret;

	USINGTEMPS(); // temps: temp0 result
	USING(t); USING(other_g_to_t); USING(schnorr_G);

	LOCKTEMPS();
	CHECK(d0_bignum_mod_pow(temp0, ctx->other_g_to_t, ctx->t, ctx->schnorr_G));
	ret = d0_longhash_bignum(temp0, (unsigned char *) outbuf, *outbuflen);
	UNLOCKTEMPS();
	return ret;

fail:
	UNLOCKTEMPS();
	return 0;
}

D0_WARN_UNUSED_RESULT D0_BOOL d0_blind_id_verify_public_id(const d0_blind_id_t *ctx, D0_BOOL *status)
{
	unsigned char hashbuf[2048];
	size_t sz;

	USINGTEMPS(); // temps: temp0 temp1 temp2
	USING(schnorr_H_g_to_s_signature); USING(rsa_e); USING(rsa_n); USING(schnorr_g_to_s);

	if(d0_bignum_cmp(ctx->schnorr_H_g_to_s_signature, zero))
	{
		// check signature of key (t = k^d, so, t^challenge = k)
		LOCKTEMPS();

		CHECK(d0_bignum_mod_pow(temp0, ctx->schnorr_H_g_to_s_signature, ctx->rsa_e, ctx->rsa_n));

		// we will actually sign SHA(4^s) to prevent a malleability attack!
		sz = (d0_bignum_size(ctx->rsa_n) + 7) / 8; // this is too long, so we have to take the value % rsa_n when "decrypting"
		if(sz > sizeof(hashbuf))
			sz = sizeof(hashbuf);
		CHECK(d0_longhash_bignum(ctx->schnorr_g_to_s, hashbuf, sz));
		CHECK(d0_bignum_import_unsigned(temp2, hashbuf, sz));

		// + 7 / 8 is too large, so let's mod it
		CHECK(d0_bignum_divmod(NULL, temp1, temp2, ctx->rsa_n));

		// hash complete
		CHECK(d0_bignum_cmp(temp0, temp1) == 0);

		*status = 1;
	}
	else
		*status = 0;

	UNLOCKTEMPS();
	return 1;

fail:
	UNLOCKTEMPS();
	return 0;
}

d0_blind_id_t *d0_blind_id_new(void)
{
	d0_blind_id_t *b = d0_malloc(sizeof(d0_blind_id_t));
	memset(b, 0, sizeof(*b));
	return b;
}

void d0_blind_id_free(d0_blind_id_t *a)
{
	d0_blind_id_clear(a);
	d0_free(a);
}

void d0_blind_id_util_sha256(char *out, const char *in, size_t n)
{
	SHA256_CTX context;
	SHA256_Init(&context);
	SHA256_Update(&context, (const unsigned char *) in, n);
	return SHA256_Final((unsigned char *) out, &context);
}

void d0_blind_id_setmallocfuncs(d0_malloc_t *m, d0_free_t *f)
{
	d0_setmallocfuncs(m, f);
}
void d0_blind_id_setmutexfuncs(d0_createmutex_t *c, d0_destroymutex_t *d, d0_lockmutex_t *l, d0_unlockmutex_t *u)
{
	d0_setmutexfuncs(c, d, l, u);
}
