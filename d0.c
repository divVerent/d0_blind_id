/*
 * include the license notice into the dynamic library to "reproduce the
 * copyright notice" automatically, so the application developer does not have
 * to care about this term
 */
const char *d0_bsd_license_notice = "\n"
"/*\n"
" * FILE:	d0.c\n"
" * AUTHOR:	Rudolf Polzer - divVerent@xonotic.org\n"
" * \n"
" * Copyright (c) 2010, Rudolf Polzer\n"
" * All rights reserved.\n"
" *\n"
" * Redistribution and use in source and binary forms, with or without\n"
" * modification, are permitted provided that the following conditions\n"
" * are met:\n"
" * 1. Redistributions of source code must retain the above copyright\n"
" *    notice, this list of conditions and the following disclaimer.\n"
" * 2. Redistributions in binary form must reproduce the above copyright\n"
" *    notice, this list of conditions and the following disclaimer in the\n"
" *    documentation and/or other materials provided with the distribution.\n"
" * 3. Neither the name of the copyright holder nor the names of contributors\n"
" *    may be used to endorse or promote products derived from this software\n"
" *    without specific prior written permission.\n"
" * \n"
" * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTOR(S) ``AS IS'' AND\n"
" * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE\n"
" * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE\n"
" * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTOR(S) BE LIABLE\n"
" * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL\n"
" * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS\n"
" * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)\n"
" * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT\n"
" * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY\n"
" * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF\n"
" * SUCH DAMAGE.\n"
" *\n"
" * $Format:commit %H$, $Id$\n"
" */\n";

#include "d0.h"

#include <stdlib.h>

void *(*d0_malloc)(size_t len) = malloc;
void (*d0_free)(void *p) = free;
