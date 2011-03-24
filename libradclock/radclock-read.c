/*
 * Copyright (C) 2006-2011 Julien Ridoux <julien@synclab.org>
 *
 * This file is part of the radclock program.
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
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



#if defined (__FreeBSD__)

# ifdef HAVE_RDTSC
#  ifdef HAVE_MACHINE_CPUFUNC_H
#   include <machine/cpufunc.h>
#  else
#   error "FreeBSD with rdtsc() defined but no machine/cpufunc.h header"
#  endif
# else
static inline uint64_t
rdtsc(void)
{
    u_int32_t low, high;
    __asm __volatile("rdtsc" : "=a" (low), "=d" (high));
    return (low | ((u_int64_t)high << 32));
}
# endif

inline
vcounter_t radclock_readtsc(void) {
	return rdtsc;
}

#endif



#if defined (__linux__)

#if HAVE_RDTSCLL_ASM
# include <asm/msr.h>
#elif HAVE_RDTSCLL_ASM_X86
# include <asm-x86/msr.h>
#elif HAVE_RDTSCLL_ASM_X86_64
# include <asm-x86_64/msr.h>
#else 
/* rdtscll not defined ... turn to black magic */
# ifdef __x86_64__
#  define rdtscll(val) do { \
		unsigned int __a,__d; \
		asm volatile("rdtsc" : "=a" (__a), "=d" (__d)); \
		(val) = ((unsigned long)__a) | (((unsigned long)__d)<<32); \
	} while(0)
# endif
# ifdef __i386__
	#define rdtscll(val) __asm__ __volatile__("rdtsc" : "=A" (val))
# endif
#endif

inline 
vcounter_t radclock_readtsc(void)
{
	vcounter_t val;
    rdtscll(val);
	return val;
}

#endif


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


inline int radclock_get_vcounter_rdtsc(struct radclock *handle, vcounter_t *vcount)
{
	*vcount = radclock_readtsc();
	return 0;
}


int radclock_get_vcounter_syscall(struct radclock *handle, vcounter_t *vcount)
{
	int ret;
	if (vcount == NULL)
		return -1;

	ret = syscall(handle->syscall_get_vcounter, vcount);
	
	if ( ret < 0 ) {
		logger(RADLOG_ERR, "error on syscall get_vcounter: %s", strerror(errno));
		return -1;
	}
	return 0;
}



