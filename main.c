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
 * $Format:commit %H$
 * $Id$
 */

#include "d0_blind_id.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

void bench(double *b)
{
	static struct timeval thistime, lasttime;
	static double x = 0;
	static double *lastclock = &x;
	lasttime = thistime;
	gettimeofday(&thistime, NULL);
	*lastclock += (thistime.tv_sec - lasttime.tv_sec) + 0.000001 * (thistime.tv_usec - lasttime.tv_usec);
	lastclock = b;
}

#ifndef WIN32
#include <sys/signal.h>
#endif
volatile D0_BOOL quit = 0;
void mysignal(int signo)
{
	(void) signo;
	quit = 1;
}

#include <stdarg.h>
#include <stdlib.h>
static void errx(int status, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	fputs("\n", stderr);
	exit(status);
}

int main(int argc, char **argv)
{
	char buf[65536]; size_t bufsize;
	char buf2[65536]; size_t buf2size;
	d0_blind_id_t *ctx_self, *ctx_other;

	d0_blind_id_INITIALIZE();
	ctx_self = d0_blind_id_new();
	ctx_other = d0_blind_id_new();

	printf("keygen RSA...\n");
	if(!d0_blind_id_generate_private_key(ctx_self, 1024))
		errx(1, "keygen fail");
	buf2size = sizeof(buf2) - 1;
	if(!d0_blind_id_fingerprint64_public_key(ctx_self, buf2, &buf2size))
		errx(2, "fp64 fail");
	printf("key has fingerprint %s\n", buf2);
	bufsize = sizeof(buf); if(!d0_blind_id_write_public_key(ctx_self, buf, &bufsize))
		errx(2, "writepub fail");
	if(!d0_blind_id_read_public_key(ctx_other, buf, bufsize))
		errx(3, "readpub fail");

	printf("keygen modulus...\n");
	if(!d0_blind_id_generate_private_id_modulus(ctx_other))
		errx(1, "keygen fail");
	/*
	bufsize = sizeof(buf); if(!d0_blind_id_write_private_id_modulus(ctx_other, buf, &bufsize))
		errx(2, "writepub fail");
	if(!d0_blind_id_read_private_id_modulus(ctx_self, buf, bufsize))
		errx(3, "readpub fail");
	*/

#ifndef WIN32
	signal(SIGINT, mysignal);
#endif

	int n = 0;
	double bench_gen = 0, bench_fp = 0, bench_stop = 0;
	do
	{
		bench(&bench_gen);
		bufsize = sizeof(buf); if(!d0_blind_id_generate_private_id_start(ctx_other))
			errx(4, "genid fail");
		bench(&bench_fp);
		buf2size = sizeof(buf2) - 1; if(!d0_blind_id_fingerprint64_public_id(ctx_other, buf2, &buf2size))
			errx(4, "fp64 fail");
		bench(&bench_stop);
		if(n % 1024 == 0)
			printf("gen=%f fp=%f\n", n/bench_gen, n/bench_fp);
		++n;
	}
	while(!(quit || argc != 2 || (buf2size > strlen(argv[1]) && !memcmp(buf2, argv[1], strlen(argv[1])))));

	buf2[buf2size] = 0;
	printf("Generated key has ID: %s\n", buf2);

	bufsize = sizeof(buf); if(!d0_blind_id_generate_private_id_request(ctx_other, buf, &bufsize))
		errx(4, "genreq fail");
	buf2size = sizeof(buf2); if(!d0_blind_id_answer_private_id_request(ctx_self, buf, bufsize, buf2, &buf2size))
		errx(5, "ansreq fail");
	if(!d0_blind_id_finish_private_id_request(ctx_other, buf2, buf2size))
		errx(6, "finishreq fail");

	bufsize = sizeof(buf); if(!d0_blind_id_write_public_id(ctx_other, buf, &bufsize))
		errx(7, "writepub2 fail");
	if(!d0_blind_id_read_public_id(ctx_self, buf, bufsize))
		errx(8, "readpub2 fail");

	n = 0;
	double bench_auth = 0, bench_chall = 0, bench_resp = 0, bench_verify = 0, bench_dhkey1 = 0, bench_dhkey2 = 0, bench_sign = 0, bench_signverify = 0;
	D0_BOOL status;
	while(!quit)
	{
		bench(&bench_sign);
		bufsize = sizeof(buf); if(!d0_blind_id_sign_with_private_id_sign(ctx_other, 1, 1, "hello world", 11, buf, &bufsize))
			errx(9, "sign fail");
		bench(&bench_signverify);
		buf2size = sizeof(buf2); if(!d0_blind_id_sign_with_private_id_verify(ctx_self, 1, 1, buf, bufsize, buf2, &buf2size, &status))
			errx(9, "signverify fail");
		bench(&bench_stop);
		if(buf2size != 11 || memcmp(buf2, "hello world", 11))
			errx(13, "signhello fail");
		if(!status)
			errx(14, "signsignature fail");
		bench(&bench_auth);
		bufsize = sizeof(buf); if(!d0_blind_id_authenticate_with_private_id_start(ctx_other, 1, 1, "hello world", 11, buf, &bufsize))
			errx(9, "start fail");
		bench(&bench_chall);
		buf2size = sizeof(buf2); if(!d0_blind_id_authenticate_with_private_id_challenge(ctx_self, 1, 1, buf, bufsize, buf2, &buf2size, &status))
			errx(10, "challenge fail");
		if(!status)
			errx(14, "signature prefail");
		bench(&bench_resp);
		bufsize = sizeof(buf); if(!d0_blind_id_authenticate_with_private_id_response(ctx_other, buf2, buf2size, buf, &bufsize))
			errx(11, "response fail");
		bench(&bench_verify);
		buf2size = sizeof(buf2); if(!d0_blind_id_authenticate_with_private_id_verify(ctx_self, buf, bufsize, buf2, &buf2size, &status))
			errx(12, "verify fail");
		if(buf2size != 11 || memcmp(buf2, "hello world", 11))
			errx(13, "hello fail");
		if(!status)
			errx(14, "signature fail");
		bench(&bench_dhkey1);
		bufsize = 20; if(!d0_blind_id_sessionkey_public_id(ctx_self, buf, &bufsize))
			errx(15, "dhkey1 fail");
		bench(&bench_dhkey2);
		buf2size = 20; if(!d0_blind_id_sessionkey_public_id(ctx_other, buf2, &buf2size))
			errx(16, "dhkey2 fail");
		bench(&bench_stop);
		if(bufsize != buf2size || memcmp(buf, buf2, bufsize))
			errx(17, "dhkey match fail");
		++n;
		if(n % 1024 == 0)
			printf("sign=%f signverify=%f auth=%f chall=%f resp=%f verify=%f dh1=%f dh2=%f\n", n/bench_sign, n/bench_signverify, n/bench_auth, n/bench_chall, n/bench_resp, n/bench_verify, n/bench_dhkey1, n/bench_dhkey2);
	}

	return 0;
}
