/*
 * Copyright (C) 2006-2012, Julien Ridoux <julien@synclab.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "../config.h"

#if defined (__linux__)
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>

#include "radclock.h"
#include "radclock-private.h"
#include "logger.h"






#if defined(__APPLE__)
#if defined(__ppc__)
	#define rdtsca(val) do { \
		u_int32_t _upper, _lower; \
		__asm __volatile( \
				"mftb %0\n" \
				"mftbu %1" \
				: "=r" (_lower), "=r" (_upper)); \
		(val) = ((uint64_t)_lower) | (((uint64_t)_upper)<<32); \
	} while(0)


#elif defined (__i386__)
	#define rdtsca(val) __asm__ __volatile__("rdtsc" : "=A" (val))

#elif defined (__x86_64__)
	/* So we 64 bits machine and no header ... black magic area */
	#define rdtsca(val) do { \
		unsigned int __a,__d; \
		asm volatile("rdtsc" : "=a" (__a), "=d" (__d)); \
		(val) = ((unsigned long)__a) | (((unsigned long)__d)<<32); \
	} while(0)
#endif

inline 
vcounter_t radclock_readtsc(void)
{
	vcounter_t val;
    rdtsca(val);
	return val;
}

#endif





int radclock_get_vcounter(struct radclock *handle, vcounter_t *vcount)
{
	return handle->get_vcounter(handle, vcount);
}



