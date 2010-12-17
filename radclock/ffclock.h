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


#ifndef _FFCLOCK_H
#define _FFCLOCK_H


#include "../config.h"
#ifdef WITH_RADKERNEL_FBSD
#include <sys/time.h>
#endif


#ifdef WITH_RADKERNEL_LINUX
#error "struct ffclock_data has to be defined (with ktime?)"
#endif



#include "radclock.h"

/*
 * XXX Deprecated
 * Old kernel data structure
 * TODO: remove when backward compatibility for kernel versions < 2 is dropped.
 */
struct radclock_fixedpoint
{
	/** phat as an int shifted phat_shift to the left */
	uint64_t phat_int;

	/** the time reference to add a delta vcounter to as an int (<< TIME_SHIFT) */
	uint64_t time_int;

	/** the vcounter value corresponding to the time reference */
	vcounter_t vcounter_ref;

	/** the shift amount for phat_int */
	uint8_t phat_shift;

	/** the shift amount for ca_int */
	uint8_t time_shift;

	/** maximum bit for vcounter difference without overflow */
	uint8_t countdiff_maxbits;
};

/*
 * XXX Deprecated
 * Set fixedpoint data in the kernel for computing timestamps there 
 */
inline int set_kernel_fixedpoint(struct radclock *handle, struct radclock_fixedpoint *fpdata);




#ifdef WITH_RADKERNEL_FBSD
struct ffclock_data
{
    /* Time conversion of ffcounter below */
    struct bintime time;

    /* Last synchronization daemon update or update_ffclock() */
    vcounter_t ffcounter;
    
	/* Timecounter period estimate (<< per_shift) */
    uint64_t period;
    
	/* Clock status word */
    uint32_t status;
    
	/* Average of clock error bound in [ns] */
    uint32_t error_bound_avg;
    
	/* Period estimate shift */
    uint8_t per_shift;
    
	/* Maximum bits holding ffcounter diff without overflow (2^ffdelta_max) */
    uint8_t ffdelta_max;
};
#endif



#if defined (__linux__)
struct ffclock_data
{
	/** phat as an int shifted phat_shift to the left */
	uint64_t phat_int;

	/** the time reference to add a delta vcounter to as an int (<< TIME_SHIFT) */
	uint64_t time_int;

	/** the vcounter value corresponding to the time reference */
	vcounter_t vcounter_ref;

	/** the shift amount for phat_int */
	uint8_t phat_shift;

	/** the shift amount for ca_int */
	uint8_t time_shift;

	/** maximum bit for vcounter difference without overflow */
	uint8_t countdiff_maxbits;

	/* Clock status word */
	uint32_t status;

	/* Average of clock error bound in [ns] */
	uint32_t error_bound_avg;
};
#endif





inline int set_kernel_ffclock(struct radclock *clock_handle);

int has_vm_vcounter(void);

#endif 	/* _FFCLOCK_H */
