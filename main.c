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
#include <time.h>

void bench(double *b)
{
	static struct timespec thistime, lasttime;
	static double x = 0;
	static double *lastclock = &x;
	lasttime = thistime;
	clock_gettime(CLOCK_MONOTONIC, &thistime);
	*lastclock += (thistime.tv_sec - lasttime.tv_sec) + 0.000000001 * (thistime.tv_nsec - lasttime.tv_nsec);
	lastclock = b;
}

#include <sys/signal.h>
volatile BOOL quit = 0;
void mysignal(int signo)
{
	(void) signo;
	quit = 1;
}

#include <err.h>
int main(int argc, char **argv)
{
	char buf[65536]; size_t bufsize;
	char buf2[65536]; size_t buf2size; ssize_t buf2ssize;
	d0_blind_id_t *ctx_self, *ctx_other;

	d0_blind_id_INITIALIZE();
	ctx_self = d0_blind_id_new();
	ctx_other = d0_blind_id_new();

	if(!d0_blind_id_generate_private_keys(ctx_self, 1024))
		errx(1, "keygen fail");
	bufsize = sizeof(buf); if(!d0_blind_id_write_public_keys(ctx_self, buf, &bufsize))
		errx(2, "writepub fail");
	if(!d0_blind_id_read_public_keys(ctx_other, buf, bufsize))
		errx(3, "readpub fail");

	signal(SIGINT, mysignal);

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
	double bench_auth = 0, bench_chall = 0, bench_resp = 0, bench_verify = 0;
	BOOL status;
	while(!quit)
	{
		bench(&bench_auth);
		bufsize = sizeof(buf); if(!d0_blind_id_authenticate_with_private_id_start(ctx_other, 1, "hello world", 11, buf, &bufsize))
			errx(9, "start fail");
		bench(&bench_chall);
		buf2size = sizeof(buf2); if(!d0_blind_id_authenticate_with_private_id_challenge(ctx_self, 1, buf, bufsize, buf2, &buf2size, NULL))
			errx(10, "challenge fail");
		bench(&bench_resp);
		bufsize = sizeof(buf); if(!d0_blind_id_authenticate_with_private_id_response(ctx_other, buf2, buf2size, buf, &bufsize))
			errx(11, "response fail");
		bench(&bench_verify);
		buf2ssize = sizeof(buf2); if(!d0_blind_id_authenticate_with_private_id_verify(ctx_self, buf, bufsize, buf2, &buf2ssize, &status))
			errx(12, "verify fail");
		if(buf2ssize != 11 || memcmp(buf2, "hello world", 11))
			errx(13, "hello fail");
		if(!status)
			errx(14, "signature fail");
		bench(&bench_stop);
		++n;
		if(n % 1024 == 0)
			printf("auth=%f chall=%f resp=%f verify=%f\n", n/bench_auth, n/bench_chall, n/bench_resp, n/bench_verify);
	}

	return 0;
}
