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


#ifndef _KCLOCK_H
#define _KCLOCK_H

#include "../config.h"

/*
 * This is very strongly inspired by the bintime structure in FreeBSD. See
 * sys/time.h there for the details.
 */
#if defined (__FreeBSD__)
#include <sys/time.h>
#else
struct bintime {
	int64_t sec;
	uint64_t frac;
};
#endif

#if defined (__FreeBSD__) && defined (HAVE_SYS_TIMEFFC_H)
#include <sys/timeffc.h>
#else
struct ffclock_estimate
{
    /* Time conversion of ffcounter below */
    struct bintime time;

	/* Timecounter period estimate */
    uint64_t period;

	/* Timecounter short term period estimate (aka plocal) */
    uint64_t period_shortterm;

    /* Last synchronization daemon update or update_ffclock() */
    vcounter_t last_update;
    
	/* Clock status word */
    uint32_t status;
    
	/* Average of clock error bound in [ns] */
    uint32_t error_bound_avg;
};
#endif

int get_kernel_ffclock(struct radclock *clock, struct ffclock_estimate *cest);
int set_kernel_ffclock(struct radclock *clock, struct ffclock_estimate *cest);

void fill_ffclock_estimate(struct radclock_data *rad_data,
		struct radclock_error *rad_err, struct ffclock_estimate *cest);
void fill_clock_data(struct ffclock_estimate *cest, struct radclock_data *rad_data);

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
int set_kernel_fixedpoint(struct radclock *clock, struct radclock_fixedpoint *fp);


#endif 	/* _KCLOCK_H */
