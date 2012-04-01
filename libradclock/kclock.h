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
