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
	struct bintime	update_time;	/* Time of last estimates update. */
	vcounter_t	update_ffcount;		/* Counter value at last update. */
	vcounter_t	leapsec_next;		/* Counter value of next leap second. */
	uint64_t	period;				/* Estimate of counter period. */
	uint32_t	errb_abs;			/* Bound on absolute clock error [ns]. */
	uint32_t	errb_rate;			/* Bound on counter rate error [ps/s]. */
	uint32_t	status;				/* Clock status. */
	int16_t		leapsec_total;		/* All leap seconds seen so far. */
	int8_t		leapsec;			/* Next leap second (in {-1,0,1}). */

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
