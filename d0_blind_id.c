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

#include "d0_blind_id.h"

#include <stdio.h>
#include <string.h>
#include "d0_bignum.h"
#include "sha1.h"

// for zero knowledge, we need multiple instances of schnorr ID scheme... should normally be sequential
// parallel schnorr ID is not provably zero knowledge :(
//   (evil verifier can know all questions in advance, so sequential is disadvantage for him)
// we'll just live with a 1:1048576 chance of cheating, and support reauthenticating

#define SCHNORR_BITS 20
// probability of cheat: 2^(-bits+1)

#define SCHNORR_HASHSIZE 3
// cannot be >= SHA_DIGEST_LENGTH
// *8 must be >= SCHNORR_BITS

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
	d0_bignum_t *schnorr_4_to_s;
	d0_bignum_t *schnorr_4_to_s_signature;

	// temp data
	d0_bignum_t *rn; // random number blind signature
	d0_bignum_t *r; // random number for schnorr ID
	char xnbh[SCHNORR_HASHSIZE]; // init hash
	d0_bignum_t *e; // challenge
	char msg[MSGSIZE]; // message
	size_t msglen; // message length
};

#define CHECK(x) do { if(!(x)) goto fail; } while(0)
#define CHECK_ASSIGN(var, value) do { d0_bignum_t *val; val = value; if(!val) goto fail; var = val; } while(0)

static d0_bignum_t *zero, *one, *four, *temp0, *temp1, *temp2, *temp3, *temp4;

void d0_blind_id_INITIALIZE()
{
	d0_bignum_INITIALIZE();
	CHECK_ASSIGN(zero, d0_bignum_int(zero, 0));
	CHECK_ASSIGN(one, d0_bignum_int(one, 1));
	CHECK_ASSIGN(four, d0_bignum_int(four, 4));
	CHECK_ASSIGN(temp0, d0_bignum_int(temp0, 0));
	CHECK_ASSIGN(temp1, d0_bignum_int(temp1, 0));
	CHECK_ASSIGN(temp2, d0_bignum_int(temp2, 0));
	CHECK_ASSIGN(temp3, d0_bignum_int(temp3, 0));
	CHECK_ASSIGN(temp4, d0_bignum_int(temp4, 0));
fail:
	;
}

void d0_blind_id_SHUTDOWN()
{
	d0_bignum_free(zero);
	d0_bignum_free(one);
	d0_bignum_free(four);
	d0_bignum_free(temp0);
	d0_bignum_free(temp1);
	d0_bignum_free(temp2);
	d0_bignum_free(temp3);
	d0_bignum_free(temp4);
	d0_bignum_SHUTDOWN();
}

// (G-1)/2
d0_bignum_t *d0_dl_get_order(d0_bignum_t *o, const d0_bignum_t *G)
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

BOOL d0_dl_generate_key(size_t size, d0_bignum_t *G)
{
	// using: temp0
	if(size < 16)
		size = 16;
	for(;;)
	{
		CHECK(d0_bignum_rand_bit_exact(temp0, size-1));
		if(d0_bignum_isprime(temp0, 0) == 0)
			continue;
		CHECK(d0_dl_get_from_order(G, temp0));
		if(d0_bignum_isprime(G, 10) == 0)
			continue;
		if(d0_bignum_isprime(temp0, 10) == 0) // finish the previous test
			continue;
		break;
	}
	return 1;
fail:
	return 0;
}

BOOL d0_rsa_generate_key(size_t size, const d0_bignum_t *e, d0_bignum_t *d, d0_bignum_t *n)
{
	// uses temp0 to temp4
	int fail = 0;
	int gcdfail = 0;
	if(size < 16)
		size = 16;
	int pb = (size + 1)/2;
	int qb = size - pb;
        for (;;)
	{
		CHECK(d0_bignum_rand_bit_exact(temp0, pb));
		if(d0_bignum_isprime(temp0, 10) == 0)
			continue;
		CHECK(d0_bignum_sub(temp2, temp0, one));
		CHECK(d0_bignum_gcd(temp4, NULL, NULL, temp2, e));
		if(!d0_bignum_cmp(temp4, one))
			break;
		if(++gcdfail == 3)
			return 0;
		++gcdfail;
	}
	gcdfail = 0;
        for (;;)
	{
		CHECK(d0_bignum_rand_bit_exact(temp1, qb));
		if(!d0_bignum_cmp(temp1, temp0))
		{
			if(++fail == 3)
				return 0;
		}
		fail = 0;
		if(d0_bignum_isprime(temp1, 10) == 0)
			continue;
		CHECK(d0_bignum_sub(temp3, temp1, one));
		CHECK(d0_bignum_gcd(temp4, NULL, NULL, temp3, e));
		if(!d0_bignum_cmp(temp4, one))
			break;
		if(++gcdfail == 3)
			return 0;
		++gcdfail;
	}

	// n = temp0*temp1
	CHECK(d0_bignum_mul(n, temp0, temp1));
		
	// d = e^-1 mod (temp0-1)(temp1-1)
	CHECK(d0_bignum_mul(temp0, temp2, temp3));
	CHECK(d0_bignum_mod_inv(d, e, temp0));
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
	if(ctx->schnorr_4_to_s) d0_bignum_free(ctx->schnorr_4_to_s);
	if(ctx->schnorr_4_to_s_signature) d0_bignum_free(ctx->schnorr_4_to_s_signature);
	if(ctx->rn) d0_bignum_free(ctx->rn);
	if(ctx->r) d0_bignum_free(ctx->r);
	if(ctx->e) d0_bignum_free(ctx->e);
	memset(ctx, 0, sizeof(*ctx));
}

void d0_blind_id_copy(d0_blind_id_t *ctx, const d0_blind_id_t *src)
{
	d0_blind_id_clear(ctx);
	if(src->rsa_n) ctx->rsa_n = d0_bignum_mov(NULL, src->rsa_n);
	if(src->rsa_e) ctx->rsa_e = d0_bignum_mov(NULL, src->rsa_e);
	if(src->rsa_d) ctx->rsa_d = d0_bignum_mov(NULL, src->rsa_d);
	if(src->schnorr_G) ctx->schnorr_G = d0_bignum_mov(NULL, src->schnorr_G);
	if(src->schnorr_s) ctx->schnorr_s = d0_bignum_mov(NULL, src->schnorr_s);
	if(src->schnorr_4_to_s) ctx->schnorr_4_to_s = d0_bignum_mov(NULL, ctx->schnorr_G);
	if(src->schnorr_4_to_s_signature) ctx->schnorr_4_to_s_signature = d0_bignum_mov(NULL, src->schnorr_4_to_s_signature);
	if(src->rn) ctx->rn = d0_bignum_mov(NULL, src->rn);
	if(src->r) ctx->r = d0_bignum_mov(NULL, src->r);
	if(src->e) ctx->e = d0_bignum_mov(NULL, src->e);
	// TODO xnbh, msg, msglen?
}

WARN_UNUSED_RESULT BOOL d0_blind_id_generate_private_keys(d0_blind_id_t *ctx, int k)
{
	d0_blind_id_clear(ctx);
	CHECK_ASSIGN(ctx->schnorr_G, d0_bignum_new());
	CHECK(d0_dl_generate_key(k, ctx->schnorr_G));
	CHECK_ASSIGN(ctx->rsa_e, d0_bignum_int(NULL, 65537));
	CHECK_ASSIGN(ctx->rsa_d, d0_bignum_new());
	CHECK_ASSIGN(ctx->rsa_n, d0_bignum_new());
	CHECK(d0_rsa_generate_key(k+1, ctx->rsa_e, ctx->rsa_d, ctx->rsa_n)); // must fit G for sure
	return 1;
fail:
	return 0;
}

WARN_UNUSED_RESULT BOOL d0_blind_id_read_private_keys(d0_blind_id_t *ctx, const char *inbuf, size_t inbuflen)
{
	d0_iobuf_t *in = d0_iobuf_open_read(inbuf, inbuflen);
	d0_blind_id_clear(ctx);
	CHECK_ASSIGN(ctx->schnorr_G, d0_iobuf_read_bignum(in, NULL));
	CHECK_ASSIGN(ctx->rsa_n, d0_iobuf_read_bignum(in, NULL));
	CHECK_ASSIGN(ctx->rsa_e, d0_iobuf_read_bignum(in, NULL));
	CHECK_ASSIGN(ctx->rsa_d, d0_iobuf_read_bignum(in, NULL));
	return d0_iobuf_close(in, NULL);

fail:
	d0_iobuf_close(in, NULL);
	return 0;
}

WARN_UNUSED_RESULT BOOL d0_blind_id_read_public_keys(d0_blind_id_t *ctx, const char *inbuf, size_t inbuflen)
{
	d0_iobuf_t *in = d0_iobuf_open_read(inbuf, inbuflen);
	d0_blind_id_clear(ctx);
	CHECK_ASSIGN(ctx->schnorr_G, d0_iobuf_read_bignum(in, NULL));
	CHECK_ASSIGN(ctx->rsa_n, d0_iobuf_read_bignum(in, NULL));
	CHECK_ASSIGN(ctx->rsa_e, d0_iobuf_read_bignum(in, NULL));
	return d0_iobuf_close(in, NULL);

fail:
	d0_iobuf_close(in, NULL);
	return 0;
}

#define USING(x) if(!(ctx->x)) return 0
#define WRITING(x,f) if(ctx->x) { f(ctx->x); ctx->x = NULL; }
#define REPLACING(x)

WARN_UNUSED_RESULT BOOL d0_blind_id_write_private_keys(d0_blind_id_t *ctx, char *outbuf, size_t *outbuflen)
{
	USING(rsa_n); USING(rsa_e); USING(rsa_d);

	d0_iobuf_t *out = d0_iobuf_open_write(outbuf, *outbuflen);
	CHECK(d0_iobuf_write_bignum(out, ctx->schnorr_G));
	CHECK(d0_iobuf_write_bignum(out, ctx->rsa_n));
	CHECK(d0_iobuf_write_bignum(out, ctx->rsa_e));
	CHECK(d0_iobuf_write_bignum(out, ctx->rsa_d));
	return d0_iobuf_close(out, outbuflen);

fail:
	d0_iobuf_close(out, outbuflen);
	return 0;
}

WARN_UNUSED_RESULT BOOL d0_blind_id_write_public_keys(d0_blind_id_t *ctx, char *outbuf, size_t *outbuflen)
{
	USING(rsa_n); USING(rsa_e); USING(rsa_d);

	d0_iobuf_t *out = d0_iobuf_open_write(outbuf, *outbuflen);
	CHECK(d0_iobuf_write_bignum(out, ctx->schnorr_G));
	CHECK(d0_iobuf_write_bignum(out, ctx->rsa_n));
	CHECK(d0_iobuf_write_bignum(out, ctx->rsa_e));
	return d0_iobuf_close(out, outbuflen);

fail:
	if(!d0_iobuf_close(out, outbuflen))
		return 0;
	return 0;
}

WARN_UNUSED_RESULT BOOL d0_blind_id_generate_private_id_start(d0_blind_id_t *ctx)
{
	// temps: temp0 order
	USING(schnorr_G);
	REPLACING(schnorr_s); REPLACING(schnorr_4_to_s);

	CHECK(d0_dl_get_order(temp0, ctx->schnorr_G));
	CHECK_ASSIGN(ctx->schnorr_s, d0_bignum_rand_range(ctx->schnorr_s, zero, temp0));
	CHECK_ASSIGN(ctx->schnorr_4_to_s, d0_bignum_mod_pow(ctx->schnorr_4_to_s, four, ctx->schnorr_s, ctx->schnorr_G));
	return 1;

fail:
	return 0;
}

WARN_UNUSED_RESULT BOOL d0_blind_id_generate_private_id_request(d0_blind_id_t *ctx, char *outbuf, size_t *outbuflen)
{
	// temps: temp0 temp1
	USING(rsa_n); USING(rsa_e); USING(schnorr_4_to_s);
	REPLACING(rn);

	d0_iobuf_t *out = d0_iobuf_open_write(outbuf, *outbuflen);

	CHECK_ASSIGN(ctx->rn, d0_bignum_rand_bit_atmost(ctx->rn, d0_bignum_size(ctx->rsa_n)));
	CHECK(d0_bignum_mod_pow(temp0, ctx->rn, ctx->rsa_e, ctx->rsa_n));
	CHECK(d0_bignum_mod_mul(temp1, ctx->schnorr_4_to_s, temp0, ctx->rsa_n));
	CHECK(d0_iobuf_write_bignum(out, temp1));
	return d0_iobuf_close(out, outbuflen);

fail:
	d0_iobuf_close(out, outbuflen);
	return 0;
}

WARN_UNUSED_RESULT BOOL d0_blind_id_answer_private_id_request(d0_blind_id_t *ctx, const char *inbuf, size_t inbuflen, char *outbuf, size_t *outbuflen)
{
	// temps: temp0 temp1
	USING(rsa_d); USING(rsa_n);

	d0_iobuf_t *in = d0_iobuf_open_read(inbuf, inbuflen);
	d0_iobuf_t *out = d0_iobuf_open_write(outbuf, *outbuflen);

	CHECK(d0_iobuf_read_bignum(in, temp0));
	CHECK(d0_bignum_mod_pow(temp1, temp0, ctx->rsa_d, ctx->rsa_n));
	CHECK(d0_iobuf_write_bignum(out, temp1));

	d0_iobuf_close(in, NULL);
	return d0_iobuf_close(out, outbuflen);

fail:
	d0_iobuf_close(in, NULL);
	d0_iobuf_close(out, outbuflen);
	return 0;
}

WARN_UNUSED_RESULT BOOL d0_blind_id_finish_private_id_request(d0_blind_id_t *ctx, const char *inbuf, size_t inbuflen)
{
	// temps: temp0 temp1
	USING(rn); USING(rsa_n);
	REPLACING(schnorr_4_to_s_signature);

	d0_iobuf_t *in = d0_iobuf_open_read(inbuf, inbuflen);

	CHECK(d0_iobuf_read_bignum(in, temp0));
	CHECK(d0_bignum_mod_inv(temp1, ctx->rn, ctx->rsa_n));
	CHECK_ASSIGN(ctx->schnorr_4_to_s_signature, d0_bignum_mod_mul(ctx->schnorr_4_to_s_signature, temp0, temp1, ctx->rsa_n));

	return d0_iobuf_close(in, NULL);

fail:
	d0_iobuf_close(in, NULL);
	return 0;
}

WARN_UNUSED_RESULT BOOL d0_blind_id_read_private_id(d0_blind_id_t *ctx, const char *inbuf, size_t inbuflen)
{
	REPLACING(schnorr_s); REPLACING(schnorr_4_to_s); REPLACING(schnorr_4_to_s_signature);

	d0_iobuf_t *in = d0_iobuf_open_read(inbuf, inbuflen);

	CHECK_ASSIGN(ctx->schnorr_s, d0_iobuf_read_bignum(in, ctx->schnorr_s));
	CHECK_ASSIGN(ctx->schnorr_4_to_s, d0_iobuf_read_bignum(in, ctx->schnorr_4_to_s));
	CHECK_ASSIGN(ctx->schnorr_4_to_s_signature, d0_iobuf_read_bignum(in, ctx->schnorr_4_to_s_signature));

	return d0_iobuf_close(in, NULL);

fail:
	d0_iobuf_close(in, NULL);
	return 0;
}

WARN_UNUSED_RESULT BOOL d0_blind_id_read_public_id(d0_blind_id_t *ctx, const char *inbuf, size_t inbuflen)
{
	REPLACING(schnorr_4_to_s); REPLACING(schnorr_4_to_s_signature);

	d0_iobuf_t *in = d0_iobuf_open_read(inbuf, inbuflen);

	CHECK_ASSIGN(ctx->schnorr_4_to_s, d0_iobuf_read_bignum(in, ctx->schnorr_4_to_s));
	CHECK_ASSIGN(ctx->schnorr_4_to_s_signature, d0_iobuf_read_bignum(in, ctx->schnorr_4_to_s_signature));

	return d0_iobuf_close(in, NULL);

fail:
	d0_iobuf_close(in, NULL);
	return 0;
}

WARN_UNUSED_RESULT BOOL d0_blind_id_write_private_id(d0_blind_id_t *ctx, char *outbuf, size_t *outbuflen)
{
	USING(schnorr_s); USING(schnorr_4_to_s); USING(schnorr_4_to_s_signature);

	d0_iobuf_t *out = d0_iobuf_open_write(outbuf, *outbuflen);

	CHECK(d0_iobuf_write_bignum(out, ctx->schnorr_s));
	CHECK(d0_iobuf_write_bignum(out, ctx->schnorr_4_to_s));
	CHECK(d0_iobuf_write_bignum(out, ctx->schnorr_4_to_s_signature));

	return d0_iobuf_close(out, outbuflen);

fail:
	d0_iobuf_close(out, outbuflen);
	return 0;
}

WARN_UNUSED_RESULT BOOL d0_blind_id_write_public_id(d0_blind_id_t *ctx, char *outbuf, size_t *outbuflen)
{
	USING(schnorr_4_to_s); USING(schnorr_4_to_s_signature);

	d0_iobuf_t *out = d0_iobuf_open_write(outbuf, *outbuflen);

	CHECK(d0_iobuf_write_bignum(out, ctx->schnorr_4_to_s));
	CHECK(d0_iobuf_write_bignum(out, ctx->schnorr_4_to_s_signature));

	return d0_iobuf_close(out, outbuflen);

fail:
	d0_iobuf_close(out, outbuflen);
	return 0;
}

WARN_UNUSED_RESULT BOOL d0_blind_id_authenticate_with_private_id_start(d0_blind_id_t *ctx, int is_first, char *msg, size_t msglen, char *outbuf, size_t *outbuflen)
// start =
//   first run: send 4^s, 4^s signature
//   1. get random r, send HASH(4^r)
{
	if(is_first)
	{
		USING(schnorr_4_to_s); USING(schnorr_4_to_s_signature);
	}
	USING(schnorr_G);
	REPLACING(r);

	d0_iobuf_t *out = d0_iobuf_open_write(outbuf, *outbuflen);

	if(is_first)
	{
		// send ID
		CHECK(d0_iobuf_write_bignum(out, ctx->schnorr_4_to_s));
		CHECK(d0_iobuf_write_bignum(out, ctx->schnorr_4_to_s_signature));
	}

	// start schnorr ID scheme
	// generate random number r; x = g^r; send hash of x, remember r, forget x
	CHECK(d0_dl_get_order(temp0, ctx->schnorr_G));
	CHECK_ASSIGN(ctx->r, d0_bignum_rand_range(ctx->r, zero, temp0));
	CHECK(d0_bignum_mod_pow(temp0, four, ctx->r, ctx->schnorr_G));

	// hash it, hash it, everybody hash it
	unsigned char convbuf[1024];
	d0_iobuf_t *conv = d0_iobuf_open_write(convbuf, sizeof(convbuf));
	size_t sz;
	CHECK(d0_iobuf_write_bignum(conv, temp0));
	CHECK(d0_iobuf_write_packet(conv, msg, msglen));
	CHECK(d0_iobuf_write_bignum(conv, temp0));
	d0_iobuf_close(conv, &sz);
	conv = NULL;
	CHECK(d0_iobuf_write_raw(out, sha(convbuf, sz), SCHNORR_HASHSIZE) == SCHNORR_HASHSIZE);
	CHECK(d0_iobuf_write_packet(out, msg, msglen));

	return d0_iobuf_close(out, outbuflen);

fail:
	d0_iobuf_close(out, outbuflen);
	return 0;
}

WARN_UNUSED_RESULT BOOL d0_blind_id_authenticate_with_private_id_challenge(d0_blind_id_t *ctx, int is_first, const char *inbuf, size_t inbuflen, char *outbuf, size_t *outbuflen)
//   first run: get 4^s, 4^s signature
//   1. check sig
//   2. save HASH(4^r)
//   3. send challenge e of SCHNORR_BITS
{
	if(is_first)
	{
		REPLACING(schnorr_4_to_s); REPLACING(k); REPLACING(schnorr_4_to_s_signature);
		USING(schnorr_G); USING(rsa_n);
	}
	else
	{
		USING(schnorr_4_to_s_signature); USING(schnorr_4_to_s);
	}
	USING(rsa_e); USING(rsa_n);
	REPLACING(e); REPLACING(msg); REPLACING(msglen);

	d0_iobuf_t *in = d0_iobuf_open_read(inbuf, inbuflen);
	d0_iobuf_t *out = d0_iobuf_open_write(outbuf, *outbuflen);

	if(is_first)
	{
		CHECK_ASSIGN(ctx->schnorr_4_to_s, d0_iobuf_read_bignum(in, NULL));
		CHECK(d0_bignum_cmp(ctx->schnorr_4_to_s, zero) >= 0);
		CHECK(d0_bignum_cmp(ctx->schnorr_4_to_s, ctx->schnorr_G) < 0);
		CHECK_ASSIGN(ctx->schnorr_4_to_s_signature, d0_iobuf_read_bignum(in, ctx->schnorr_4_to_s_signature));
		CHECK(d0_bignum_cmp(ctx->schnorr_4_to_s_signature, zero) >= 0);
		CHECK(d0_bignum_cmp(ctx->schnorr_4_to_s_signature, ctx->rsa_n) < 0);
	}

	// check signature of key (t = k^d, so, t^e = k)
	CHECK(d0_bignum_mod_pow(temp0, ctx->schnorr_4_to_s_signature, ctx->rsa_e, ctx->rsa_n));
	if(d0_bignum_cmp(temp0, ctx->schnorr_4_to_s))
	{
		// FAIL (not signed by Xonotic)
		goto fail;
		// TODO: accept the key anyway, but mark as failed signature!
	}

	CHECK(d0_iobuf_read_raw(in, ctx->xnbh, SCHNORR_HASHSIZE));
	ctx->msglen = MSGSIZE;
	CHECK(d0_iobuf_read_packet(in, ctx->msg, &ctx->msglen));

	// send challenge
	CHECK_ASSIGN(ctx->e, d0_bignum_rand_bit_atmost(ctx->e, SCHNORR_BITS));

	CHECK(d0_iobuf_write_bignum(out, ctx->e));

	d0_iobuf_close(in, NULL);
	return d0_iobuf_close(out, outbuflen);

fail:
	d0_iobuf_close(in, NULL);
	d0_iobuf_close(out, outbuflen);
	return 0;
}

WARN_UNUSED_RESULT BOOL d0_blind_id_authenticate_with_private_id_response(d0_blind_id_t *ctx, const char *inbuf, size_t inbuflen, char *outbuf, size_t *outbuflen)
//   1. read challenge e of SCHNORR_BITS
//   2. reply with r + s * e mod order
{
	// temps: 0 order, 1 prod, 2 y, 3 e
	USING(schnorr_G); USING(schnorr_s); USING(r);

	d0_iobuf_t *in = d0_iobuf_open_read(inbuf, inbuflen);
	d0_iobuf_t *out = d0_iobuf_open_write(outbuf, *outbuflen);

	CHECK(d0_iobuf_read_bignum(in, temp3));
	// TODO check if >= 2^SCHNORR_BITS or < 0, if yes, then fail (needed for zero knowledge)
	CHECK(d0_bignum_cmp(temp3, zero) >= 0);
	CHECK(d0_bignum_size(temp3) <= SCHNORR_BITS);

	// send response for schnorr ID scheme
	// i.e. r + ctx->schnorr_s * temp3
	CHECK(d0_dl_get_order(temp0, ctx->schnorr_G));
	CHECK(d0_bignum_mod_mul(temp1, ctx->schnorr_s, temp3, temp0));
	CHECK(d0_bignum_mod_add(temp2, temp1, ctx->r, temp0));
	CHECK(d0_iobuf_write_bignum(out, temp2));

	d0_iobuf_close(in, NULL);
	return d0_iobuf_close(out, outbuflen);

fail:
	d0_iobuf_close(in, NULL);
	d0_iobuf_close(out, outbuflen);
	return 0;
}

WARN_UNUSED_RESULT BOOL d0_blind_id_authenticate_with_private_id_verify(d0_blind_id_t *ctx, const char *inbuf, size_t inbuflen, char *msg, ssize_t *msglen)
//   1. read y = r + s * e mod order
//   2. verify: g^y (g^s)^-e = g^(r+s*e-s*e) = g^r
//      (check using H(g^r) which we know)
{
	// temps: 0 y 1 order
	USING(e); USING(schnorr_G);

	d0_iobuf_t *in = d0_iobuf_open_read(inbuf, inbuflen);

	*msglen = -1;
	CHECK(d0_dl_get_order(temp1, ctx->schnorr_G));
	CHECK(d0_iobuf_read_bignum(in, temp0));
	CHECK(d0_bignum_cmp(temp0, zero) >= 0);
	CHECK(d0_bignum_cmp(temp0, temp1) < 0);

	// verify schnorr ID scheme
	// we need 4^temp0 (g^s)^-e
	CHECK(d0_bignum_neg(temp1, ctx->e));
	CHECK(d0_bignum_mod_pow(temp2, ctx->schnorr_4_to_s, temp1, ctx->schnorr_G));
	CHECK(d0_bignum_mod_pow(temp1, four, temp0, ctx->schnorr_G));
	CHECK(d0_bignum_mod_mul(temp3, temp1, temp2, ctx->schnorr_G));
	// hash must be equal to xnbh

	// hash it, hash it, everybody hash it
	unsigned char convbuf[1024];
	d0_iobuf_t *conv = d0_iobuf_open_write(convbuf, sizeof(convbuf));
	size_t sz;
	CHECK(d0_iobuf_write_bignum(conv, temp3));
	CHECK(d0_iobuf_write_packet(conv, ctx->msg, ctx->msglen));
	CHECK(d0_iobuf_write_bignum(conv, temp3));
	d0_iobuf_close(conv, &sz);
	conv = NULL;
	if(memcmp(sha(convbuf, sz), ctx->xnbh, SCHNORR_HASHSIZE))
	{
		// FAIL (not owned by player)
		goto fail;
	}

	if(ctx->msglen <= (size_t) *msglen)
		memcpy(msg, ctx->msg, ctx->msglen);
	else
		memcpy(msg, ctx->msg, *msglen);
	*msglen = ctx->msglen;

	d0_iobuf_close(in, NULL);
	return 1;

fail:
	d0_iobuf_close(in, NULL);
	return 0;
}

WARN_UNUSED_RESULT BOOL d0_blind_id_fingerprint64_public_id(d0_blind_id_t *ctx, char *outbuf, size_t *outbuflen)
{
	USING(schnorr_4_to_s);

	static unsigned char convbuf[1024];
	d0_iobuf_t *out = d0_iobuf_open_write(outbuf, *outbuflen);
	d0_iobuf_t *conv = d0_iobuf_open_write(convbuf, sizeof(convbuf));

	size_t n, sz;

	CHECK(d0_iobuf_write_bignum(conv, ctx->schnorr_4_to_s));
	CHECK(d0_iobuf_close(conv, &sz));
	conv = NULL;

	n = (*outbuflen / 4) * 3;
	if(n > SHA_DIGESTSIZE)
		n = SHA_DIGESTSIZE;
	if(d0_iobuf_write_raw(out, sha(convbuf, sz), n) != n)
		goto fail;
	if(!d0_iobuf_conv_base64_out(out))
		goto fail;

	return d0_iobuf_close(out, outbuflen);

fail:
	if(conv)
		if(!d0_iobuf_close(conv, &sz)) { }
	if(!d0_iobuf_close(out, outbuflen))
		return 0;
	return 0;
}

d0_blind_id_t *d0_blind_id_new()
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
