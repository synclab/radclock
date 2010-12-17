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



#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <syslog.h>

#include "../config.h"
#include "radclock.h"
#include "radclock-private.h"
#include "ffclock.h"
#include "sync_algo.h"
#include "proto_ntp.h"
#include "fixedpoint.h"
#include "verbose.h"
#include "jdebug.h"



/**
 * Code for working out integer approximations
 */


/* Counts number of bits */
static inline uint8_t bitcountll(long long unsigned val)
{
	return (uint8_t) ceil(log(val)/log(2));
}


/* XXX Deprecated
 * We estimate how many bits are required to hold the number of seconds of the
 * current time so that we can shift by the remaining number of bits.
 * We a bit generous and add 1 bit to cover the case we are close
 * to the event when a new bit is flipped.
 * The time_shift is computed from a bitcountll(vcounter_t) base. 
 */
inline uint8_t calculate_time_shift(long double time)
{
	return ( (sizeof(vcounter_t) * 8) - (bitcountll((long long unsigned)time) + 1));
}


/* Number of bits needed to hold the COUNTERDIFF_MAX seconds equivalent ticks.
 * The value of one of the parameters has to be picked up, it makes sense to
 * allocate bits for the raw counter difference and deduce phat_shift from it.
 * It does not mean the counter diff will never overflow, if we don't update
 * often enough, then things get screwed.
 */
inline uint8_t calculate_countdiff_maxbits(double phat, float delay)
{
	return ( bitcountll( delay / phat ) );
}


/* Number of bits to shift phat with, deduced from the number of bits allocated
 * to the countdiff, and the actual value of phat
 */
inline uint8_t calculate_phat_shift(double phat, uint8_t countdiff_maxbit)
{
	uint8_t phat_int_bits;
	phat_int_bits = (sizeof(vcounter_t) * 8) - countdiff_maxbit - 1;
	return ( bitcountll( (1LL << phat_int_bits) * (1/phat) ) );
}


/*
 * XXX Deprecated
 * Old way of pushing clock updates to the kernel.
 * TODO: comment out but keep for history record 
 */
int calculate_fixedpoint_data(vcounter_t vcounter_ref,
		long double time_ref,
		double phat,
		struct radclock_fixedpoint *fpdata)
{
	uint8_t time_shift;
	uint8_t phat_shift;
	uint8_t countdiff_maxbits;
	long double time_int;
	long double phat_int; 

	/* Time shift */
	time_shift = calculate_time_shift(time_ref);
	time_int = time_ref * (long double) (1LL << time_shift);

	/* counterdiff maximum size */
	countdiff_maxbits = calculate_countdiff_maxbits(phat, COUNTERDIFF_MAX);

	/* Phat shift */
	phat_shift = calculate_phat_shift(phat, countdiff_maxbits);
	phat_int = (long double) phat * (long double) (1LL << phat_shift);

	/* Truncate phat and time_ref to unisigned integers */
	fpdata->phat_int = (long long unsigned int) phat_int;
	fpdata->time_int = (long long unsigned int) time_int;
	fpdata->phat_shift = phat_shift;
	fpdata->time_shift = time_shift;
	fpdata->countdiff_maxbits = countdiff_maxbits;
	fpdata->vcounter_ref = vcounter_ref;

/*
verbose(LOG_ERR, "time_shift= %u, phat_shift= %u, maxbit= %u",
		time_shift, phat_shift, countdiff_maxbits);

verbose(LOG_ERR, "initffclock: phat_int= %llu, time_int= %llu\n",
			(long long unsigned) fpdata->phat_int,
			(long long unsigned) fpdata->time_int);
*/

	return 0;
}



/*
 * XXX Deprecated
 * Old way of pushing clock updates to the kernel.
 * TODO: comment out but keep for history record 
 */
int update_kernel_fixed(struct radclock *handle)
{
	JDEBUG

	struct radclock_fixedpoint fpdata;
	vcounter_t vcount;
	long double time;
	int err;

	/* If we are starting (or restarting), the last estimate in the kernel
	 * may be better than ours after the very first stamp. Let's make sure we do
	 * not push something too stupid
	 */
	if ( OUTPUT(handle, n_stamps) < NTP_BURST )
		return 0;

	memset(&fpdata,0,sizeof(fpdata));

	err = radclock_get_vcounter(handle, &vcount);
	if ( err < 0 ) {
		verbose(LOG_ERR, "radclock_get_vcounter failed, fixedpoint not updated");
		return -1;
	}

	if (radclock_vcount_to_abstime_fp(handle, &vcount, &time))
		verbose(LOG_ERR, "Error calculating time");
	
	calculate_fixedpoint_data(
		vcount,
		time,
		RAD_DATA(handle)->phat,
		&fpdata);

	return set_kernel_fixedpoint(handle, &fpdata);
}


/*
 * Version free from the math library
 */
static inline uint8_t bitcount(long long unsigned val)
{
	uint8_t bits;

	bits = 0;
	while ( val > 0 ) {
		val = val >> 1;
		bits++;
	}
	
	return bits;
}


/*
 * Function is called every time a new stamp is processed.
 * It assumes that the kernel supports update of the fixedpoint version of the
 * clock estimates and that the last_changed stamp is updated on each call to
 * process_bidir stamp.
 * With this, no need to read the current time, rely on last_changed only.
 * XXX: is the comment above accurate and true? 
 */
int build_ffclock_data(struct radclock *clock_handle, struct ffclock_data *fdata)
{
	JDEBUG
	double phat;
	vcounter_t vcount;
	long long unsigned cycles;
	long long unsigned period;
	long double time;
	uint8_t per_shift;
	uint8_t ffdelta_max;
	long double phat_int;

	vcount = GLOBAL_DATA(clock_handle)->last_changed;
	phat = GLOBAL_DATA(clock_handle)->phat;


	/* Convert vcount to long double time and to bintime */
	if (radclock_vcount_to_abstime_fp(clock_handle, &vcount, &time))
		verbose(LOG_ERR, "Error calculating time");

	fdata->time.sec = (time_t) time;
	fdata->time.frac = (time - (time_t) time) * (1LLU << 63); 


	/* Given current phat, number of cycles for the maximum size interval
	 * between two clock updates in the kernel. 0.5 sec is also assumed in the
	 * kernel.
	 */
	cycles = (long long unsigned) (1 / phat * 0.5);	
	ffdelta_max = bitcount(cycles);

	for ( per_shift=63; per_shift>0; per_shift--)
	{	
		period = (long long unsigned) ((1LLU << per_shift) * phat);

		verbose(LOG_ERR, "ffclock_data:  period = %llu , %u bits",
			period, bitcount(period));

		if ( bitcount(period) + ffdelta_max <= 64 )
			break;
	}
	
	phat_int = (long double) phat * (long double) (1LLU << per_shift);

	ffdelta_max = 64 - bitcount((uint64_t) phat_int);

	/* Truncate phat_int to unsigned integers */
	fdata->period = (uint64_t) phat_int;
	fdata->per_shift = per_shift;
	fdata->ffcounter = vcount;
	fdata->ffdelta_max = ffdelta_max;
	fdata->status = GLOBAL_DATA(clock_handle)->status;
	fdata->error_bound_avg = (uint32_t) RAD_ERROR(clock_handle)->error_bound_avg * 1e9;


	verbose(LOG_ERR, "ffclock_data: time = %llu.%llu, "
			"period = %llu, "
			"per_shift = %u, ffdelta_max = %u",
			(long long unsigned) fdata->time.sec,
			(long long unsigned) fdata->time.frac,
			(long long unsigned) fdata->period,
			fdata->per_shift,
			fdata->ffdelta_max);

	return 0;
}



