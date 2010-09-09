/*
 * Copyright (C) 2006-2010 Julien Ridoux <julien@synclab.org>
 *
 * This file is part of the radclock program.
 * 
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see <http://www.gnu.org/licenses/>.
 */


#include "../config.h"

#if defined (__linux__)
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>


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
#endif





#include <string.h>
#include <errno.h>

#include "radclock.h"
#include "radclock-private.h"
#include "logger.h"


int radclock_get_vcounter(struct radclock *handle, vcounter_t *vcount)
{
	return handle->get_vcounter(handle, vcount);
}


int radclock_get_vcounter_rdtsc(struct radclock *handle, vcounter_t *vcount)
{
	*vcount = rdtsc();
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




int radclock_get_vcounter_latency(struct radclock *handle, vcounter_t *vcount, vcounter_t *vcount_lat, tsc_t *tsc_lat)
{
	int ret;
	ret = syscall(handle->syscall_get_vcounter_latency, vcount, vcount_lat, tsc_lat);
	
	if ( ret < 0 ) {
		logger(RADLOG_ERR, "error on syscall get_vcounter_latency: %s", strerror(errno));
		return -1;
	}
	return 0;
}




// TODO: all stuff below should go ... one day XXX


/*
 * - WARNING -
 * This file is a mess for a lot of reasons:
 *    different architectures: PPC, i386, x86_64, ...
 *    different OS with different include files
 *    different distributions that provide or not the rdtsc calls
 *
 * There are also some uncertainties ... why does rdtscll on linux returns crazy results?
 * There is work to do to have a complete coverage of all possibilities ...
 */



#if defined (__linux__)

#if defined (HAVE_RDTSCLL)
/* if we have it, must be one of these headers */
#if HAVE_ASM_MSR_H
# include <asm/msr.h>
#elif HAVE_ASM_X86_MSR_H
# include <asm-x86/msr.h>
#elif HAVE_ASM_X86_64_MSR_H
# include <asm-x86_64/msr.h>
#endif
#ifndef rdtscll
#error "rdtscll() exist but we didn't include the correct header?"
#endif
#define linux_rdtscll(val) rdtscll(val)

#else /* HAVE_RDTSCLL not defined  */


#ifdef __x86_64__
	/* So we 64 bits machine and no header ... black magic area */
	#define linux_rdtscll(val) do { \
		unsigned int __a,__d; \
		asm volatile("rdtsc" : "=a" (__a), "=d" (__d)); \
		(val) = ((unsigned long)__a) | (((unsigned long)__d)<<32); \
	} while(0)
#endif

# ifdef __i386__
	#define linux_rdtscll(val) __asm__ __volatile__("rdtsc" : "=A" (val))
#endif

#endif
#endif

/* We first want to define the rdtsc function for OS or distro that do not provide one.
 * Also, some distributions replaced the asm-i385/msr.h by the asm-x86_64/msr.h version.
 * In such case the rdtscll macro is broken if not run on 64 bits architecture.
 */
#if defined(__APPLE__)
#if defined(__ppc__)
	#define rdtsc(val) do { \
		u_int32_t _upper, _lower; \
		__asm __volatile( \
				"mftb %0\n" \
				"mftbu %1" \
				: "=r" (_lower), "=r" (_upper)); \
		(val) = ((uint64_t)_lower) | (((uint64_t)_upper)<<32); \
	} while(0)


#elif defined (__i386__)
	#define rdtsc(val) __asm__ __volatile__("rdtsc" : "=A" (val))

#elif defined (__x86_64__)
	/* So we 64 bits machine and no header ... black magic area */
	#define rdtsc(val) do { \
		unsigned int __a,__d; \
		asm volatile("rdtsc" : "=a" (__a), "=d" (__d)); \
		(val) = ((unsigned long)__a) | (((unsigned long)__d)<<32); \
	} while(0)
#endif
#endif



tsc_t radclock_readtsc(void) {
	tsc_t val;
#ifdef linux
	linux_rdtscll(val);
#elif defined(__APPLE__)
	rdtsc(val);
#else
	/* FreeBSD ... nice guys ... :) */
	val = rdtsc();
#endif
	return val;
}


