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



#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <syslog.h>

#include "../config.h"
#include "radclock.h"
#include "radclock-private.h"
#include "radclock_daemon.h"
#include "sync_history.h"
#include "sync_algo.h"
#include "proto_ntp.h"
#include "fixedpoint.h"
#include "misc.h"
#include "verbose.h"
#include "jdebug.h"



/* Counts number of bits */
static inline uint8_t
bitcountll(long long unsigned val)
{
	return ((uint8_t) ceil(log(val)/log(2)));
}


/* XXX Deprecated
 * We estimate how many bits are required to hold the number of seconds of the
 * current time so that we can shift by the remaining number of bits.
 * We a bit generous and add 1 bit to cover the case we are close
 * to the event when a new bit is flipped.
 * The time_shift is computed from a bitcountll(vcounter_t) base.
 */
inline uint8_t
calculate_time_shift(long double time)
{
	return ((sizeof(vcounter_t) * 8) - (bitcountll((long long unsigned)time) + 1));
}


/* Number of bits needed to hold the COUNTERDIFF_MAX seconds equivalent ticks.
 * The value of one of the parameters has to be picked up, it makes sense to
 * allocate bits for the raw counter difference and deduce phat_shift from it.
 * It does not mean the counter diff will never overflow, if we don't update
 * often enough, then things get screwed.
 */
inline uint8_t
calculate_countdiff_maxbits(double phat, float delay)
{
	return (bitcountll( delay / phat ));
}


/* Number of bits to shift phat with, deduced from the number of bits allocated
 * to the countdiff, and the actual value of phat
 */
inline uint8_t
calculate_phat_shift(double phat, uint8_t countdiff_maxbit)
{
	uint8_t phat_int_bits;
	phat_int_bits = (sizeof(vcounter_t) * 8) - countdiff_maxbit - 1;
	return (bitcountll((1LL << phat_int_bits) * (1/phat)));
}


/*
 * XXX Deprecated
 * Old way of pushing clock updates to the kernel.
 * TODO: comment out but keep for history record
 */
int
calculate_fixedpoint_data(vcounter_t vcounter_ref, long double time_ref,
		double phat, struct radclock_fixedpoint *fpdata)
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

	return (0);
}



/*
 * XXX Deprecated
 * Old way of pushing clock updates to the kernel.
 * TODO: comment out but keep for history record
 */
int update_kernel_fixed(struct radclock_handle *handle)
{
	struct radclock_fixedpoint fpdata;
	vcounter_t vcount;
	long double time;
	int err;

	JDEBUG

	/* If we are starting (or restarting), the last estimate in the kernel
	 * may be better than ours after the very first stamp. Let's make sure we do
	 * not push something too stupid
	 */
	if (OUTPUT(handle, n_stamps) < NTP_BURST)
		return (0);

	memset(&fpdata,0,sizeof(fpdata));

	err = radclock_get_vcounter(handle->clock, &vcount);
	if (err < 0) {
		verbose(LOG_ERR, "radclock_get_vcounter failed, fixedpoint not updated");
		return (-1);
	}

	counter_to_time(&handle->rad_data, &vcount, &time);

	calculate_fixedpoint_data(vcount, time, RAD_DATA(handle)->phat, &fpdata);

	return (set_kernel_fixedpoint(handle->clock, &fpdata));
}

