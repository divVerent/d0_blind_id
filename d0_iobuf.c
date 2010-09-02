/*
 * FILE:	d0_iobuf.c
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
 * $Format:commit %H$, $Id$
 */

#include "d0_iobuf.h"

#include <string.h>

struct d0_iobuf_s
{
	const unsigned char *inbuf;
	unsigned char *outbuf;
	size_t inpos, outpos, inbuflen, outbuflen;
	BOOL ok;
};

d0_iobuf_t *d0_iobuf_open_read(const void *buf, size_t len)
{
	d0_iobuf_t *b = d0_malloc(sizeof(d0_iobuf_t));
	b->inbuf = (const unsigned char *) buf;
	b->outbuf = NULL;
	b->inpos = b->outpos = 0;
	b->inbuflen = len;
	b->outbuflen = 0;
	b->ok = 1;
	return b;
}

d0_iobuf_t *d0_iobuf_open_write(void *buf, size_t len)
{
	d0_iobuf_t *b = d0_malloc(sizeof(d0_iobuf_t));
	b->inbuf = (const unsigned char *) buf;
	b->outbuf = (unsigned char *) buf;
	b->inpos = b->outpos = 0;
	b->inbuflen = len;
	b->outbuflen = len;
	b->ok = 1;
	return b;
}

BOOL d0_iobuf_close(d0_iobuf_t *buf, size_t *len)
{
	BOOL r = buf->ok;
	if(len)
		*len = buf->outpos;
	d0_free(buf);
	return r;
}

size_t d0_iobuf_write_raw(d0_iobuf_t *buf, const void *s, size_t n)
{
	size_t nreal = n;
	if(nreal > buf->outbuflen - buf->outpos)
	{
		buf->ok = 0;
		nreal = buf->outbuflen - buf->outpos;
	}
	memcpy(buf->outbuf + buf->outpos, s, nreal);
	buf->outpos += nreal;
	return nreal;
}

size_t d0_iobuf_read_raw(d0_iobuf_t *buf, void *s, size_t n)
{
	size_t nreal = n;
	if(nreal > buf->inbuflen - buf->inpos)
	{
		buf->ok = 0;
		nreal = buf->inbuflen - buf->inpos;
	}
	memcpy(s, buf->inbuf + buf->inpos, nreal);
	buf->inpos += nreal;
	return nreal;
}

BOOL d0_iobuf_write_packet(d0_iobuf_t *buf, const void *s, size_t n)
{
	unsigned char c;
	size_t nn = n;
	while(nn)
	{
		c = nn & 0x7F;
		nn >>= 7;
		if(nn)
			c |= 0x80;
		if(d0_iobuf_write_raw(buf, &c, 1) != 1)
			return 0;
	}
	if(d0_iobuf_write_raw(buf, s, n) != n)
		return 0;
	return 1;
}

BOOL d0_iobuf_read_packet(d0_iobuf_t *buf, void *s, size_t *np)
{
	unsigned char c;
	size_t n = 0;
	size_t nn = 1;
	do
	{
		if(d0_iobuf_read_raw(buf, &c, 1) != 1)
			return 0;
		n |= nn * (c & 0x7F);
		nn <<= 7;
	}
	while(c & 0x80);
	if(n > *np)
		return 0;
	if(d0_iobuf_read_raw(buf, s, n) != n)
		return 0;
	*np = n;
	return 1;
}

BOOL d0_iobuf_conv_base64_in(d0_iobuf_t *buf)
{
	// compand the in-buffer
	return 0;
}

static const char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static void base64_3to4(const unsigned char *in, unsigned char *out, int bytes)
{
	unsigned char i0 = (bytes > 0) ? in[0] : 0;
	unsigned char i1 = (bytes > 1) ? in[1] : 0;
	unsigned char i2 = (bytes > 2) ? in[2] : 0;
	unsigned char o0 = base64[i0 >> 2];
	unsigned char o1 = base64[((i0 << 4) | (i1 >> 4)) & 077];
	unsigned char o2 = base64[((i1 << 2) | (i2 >> 6)) & 077];
	unsigned char o3 = base64[i2 & 077];
	out[0] = (bytes > 0) ? o0 : '?';
	out[1] = (bytes > 0) ? o1 : '?';
	out[2] = (bytes > 1) ? o2 : '=';
	out[3] = (bytes > 2) ? o3 : '=';
}

BOOL d0_iobuf_conv_base64_out(d0_iobuf_t *buf)
{
	size_t blocks, i;
	// expand the out-buffer
	blocks = ((buf->outpos + 2) / 3);
	if(blocks*4 > buf->outbuflen)
		return 0;
	for(i = blocks; i > 0; )
	{
		--i;
		base64_3to4(buf->outbuf + 3*i, buf->outbuf + 4*i, buf->outpos - 3*i);
	}
	buf->outpos = blocks * 4;
	return 1;
}
