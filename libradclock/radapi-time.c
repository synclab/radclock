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

#include <sys/types.h>
#include <sys/time.h>

#include "radclock.h"
#include "radclock-private.h"
#include "kclock.h"
#include "logger.h"


// TODO: check all return values and error codes

// TODO: in all this file, check which functions need to call get_global_data
// and conditions for that (last update too far in the past ?)
// Should check for clock not synchronised? This is specific to the sync algo
// and should be designed that way. Following is a reminder of outdated code
/*
if ( ts < data->last_changed || ts - data->last_changed * data->phat > 10000 )
{
	logger(RADLOG_WARNING, 
		"radclock seems unsynchronised, last updated %7.1lf [sec] ago",
		(ts - data->last_changed) * data->phat);
}
*/

/* Defines bound on SKM scale. A bit redundant with other defines but easy to
 * fix if needed.
 */
#define OUT_SKM	1024



/*
 * Inspect data to get an idea about the quality.
 * TODO: error codes should be fixed
 * TODO: other stuff to take into account in composing quality estimate? Needed
 * or clock status and clock error take care of it?
 * TODO: massive problem with thread synchronisation ...
 */
int
raddata_quality(vcounter_t now, vcounter_t last, vcounter_t valid, double phat)
{
	/* 
	 * Something really bad is happening:
	 * - counter is going backward (should never happen)
	 * - virtual machine read H/W counter then migrated, things are out of whack
	 * - ...?
	 */
// XXX FIXME XXX THIS IS WRONG
// can read counter, then data updated, then compare ... BOOM!
	if (now < last)
		return 3;

	/*
	 * Several scenarios again:
	 * - the data is really old, clock status should say the same
	 * - virtual machine migrated, but cannot be sure. Mark data as very bad.
	 */
	if (phat * (now - valid) > OUT_SKM)
		return 3;

	/* The data is old, but still in SKM_SCALE */
	if (now > valid)
		return 2;

	return 0;
}




/*
 * Build the time using the absolute clock plus the local relative rate
 * correction (has no effect if not running plocal).
 */
static inline int
ffcounter_to_abstime_shm(struct radclock *clock, vcounter_t vcount,
		long double *time)
{
	struct radclock_shm *shm;
	vcounter_t valid, last;
	double phat;
	int generation;

	shm = (struct radclock_shm *) clock->ipc_shm;
	do {
		/* Quality ingredients */
		generation = shm->gen;
		valid = SHM_DATA(shm)->valid_till;
		last  = SHM_DATA(shm)->last_changed;
		phat  = SHM_DATA(shm)->phat;

		*time = vcount * (long double)phat + SHM_DATA(shm)->ca;

		if ((clock->local_period_mode == RADCLOCK_LOCAL_PERIOD_ON)
			&& ((SHM_DATA(shm)->status & STARAD_WARMUP) != STARAD_WARMUP))
		{
			*time += (vcount - last) *
				(long double)(SHM_DATA(shm)->phat_local - phat);
		}
	} while (generation != shm->gen || !shm->gen);

	return raddata_quality(vcount, last, valid, phat);
}


static inline int
ffcounter_to_abstime_kernel(struct radclock *clock, vcounter_t vcount,
		long double *time)
{
	struct ffclock_estimate cest;
	struct radclock_data rad_data;

// TODO FIXME error code is out of whack
	if (get_kernel_ffclock(clock, &cest))
		return (1);
	fill_clock_data(&cest, &rad_data);

	*time = vcount * rad_data.phat + rad_data.ca;

	if ((clock->local_period_mode == RADCLOCK_LOCAL_PERIOD_ON) &&
			((rad_data.status & STARAD_WARMUP) != STARAD_WARMUP))
	{
		*time += (vcount - rad_data.last_changed) *
			(long double)(rad_data.phat_local - rad_data.phat);
	}

	return raddata_quality(vcount, rad_data.last_changed, rad_data.valid_till,
			rad_data.phat);
}


/*
 * Build a delay using the difference clock.
 * This function does not fail, SKM model should be checked before call
 */
static inline int
ffcounter_to_difftime_shm(struct radclock *clock, vcounter_t from_vcount,
		vcounter_t till_vcount, long double *time)
{
	struct radclock_shm *shm;
	vcounter_t now, valid, last;
	double phat;
	int generation;

	// TODO Stupid performance penalty, but needs more thought
	if (radclock_get_vcounter(clock, &now))
		return (1);

	shm = (struct radclock_shm *) clock->ipc_shm;
	do {
		generation = shm->gen;
		valid = SHM_DATA(shm)->valid_till;
		last  = SHM_DATA(shm)->last_changed;
		phat  = SHM_DATA(shm)->phat;
		*time = (till_vcount - from_vcount) *
				(long double)SHM_DATA(shm)->phat_local;
	} while (generation != shm->gen || !shm->gen);

	return raddata_quality(now, last, valid, phat);
}


static inline int
ffcounter_to_difftime_kernel(struct radclock *clock, vcounter_t from_vcount,
		vcounter_t till_vcount, long double *time)
{
	struct ffclock_estimate cest;
	struct radclock_data rad_data;
	vcounter_t now;

	// TODO Stupid performance penalty, but needs more thought
	if (radclock_get_vcounter(clock, &now))
		return (1);


// TODO FIXME error code is out of whack
	if (get_kernel_ffclock(clock, &cest))
		return (1);
	fill_clock_data(&cest, &rad_data);

	*time = (till_vcount - from_vcount) * (long double)rad_data.phat_local;

	return raddata_quality(now, rad_data.last_changed, rad_data.valid_till,
			rad_data.phat);
}


/*
 * Check if we are in the SKM model bounds or not
 * Need to know if we are in SKM world. If not, can't use the difference clock,
 * need to substract two absolute timestamps. Testing should always be done
 * using the 'current' vcount value since we use the current global data !!!
 * Use phat for this comparison but using plocal should be fine as well
 */
// XXX  quite a few issues here
// 		- the value of the SKM scale is hard coded ... but otherwise?
// 		- Validity of the global data
// 		- error code(s) to return
static inline int
in_skm(struct radclock *clock, const vcounter_t *past_count, const vcounter_t *vc)
{
	struct radclock_shm *shm;
	vcounter_t now;

	if (!vc)
		radclock_get_vcounter(clock, &now);
	now = *vc;

	shm = (struct radclock_shm *) clock->ipc_shm;
	if ((now - *past_count) * SHM_DATA(shm)->phat < 1024)
		return (1);
	else
		return (0);
}


int
radclock_gettime(struct radclock *clock, long double *abstime)
{
	vcounter_t vcount;
	int quality;

	/* Check for critical bad input */
	if (!clock || !abstime)
		return (1);

	/* Make sure we can get a raw timestamp */
	if (radclock_get_vcounter(clock, &vcount) < 0)
		return (1);
	
	/* Retrieve clock data */
	if (clock->ipc_shm)
		quality = ffcounter_to_abstime_shm(clock, vcount, abstime);
	else
		quality = ffcounter_to_abstime_kernel(clock, vcount, abstime);
	return (quality);
}


int
radclock_vcount_to_abstime(struct radclock *clock, const vcounter_t *vcount,
		long double *abstime)
{
	int quality;

	/* Check for critical bad input */
	if (!clock || !vcount || !abstime)
		return (1);

	if (clock->ipc_shm)
		quality = ffcounter_to_abstime_shm(clock, *vcount, abstime);
	else
		quality = ffcounter_to_abstime_kernel(clock, *vcount, abstime);
	return (quality);
}


int
radclock_elapsed(struct radclock *clock, const vcounter_t *from_vcount,
		long double *duration)
{
	vcounter_t vcount;
	int quality = 0;

	/* Check for critical bad input */
	if (!clock || !from_vcount || !duration)
		return (1);

	/* Make sure we can get a raw timestamp */
	if (radclock_get_vcounter(clock, &vcount) < 0)
		return (1);
	
	/* Retrieve clock data */
	if (clock->ipc_shm)
		quality = ffcounter_to_difftime_shm(clock, *from_vcount, vcount, duration);
	else
		quality = ffcounter_to_difftime_kernel(clock, *from_vcount, vcount, duration);

// TODO is this the  good behaviour, we should request the clock data associated
// to from_vcount? maybe not
	if (!in_skm(clock, from_vcount, &vcount))
		return (1);

	return (quality);
}


int
radclock_duration(struct radclock *clock, const vcounter_t *from_vcount,
		const vcounter_t *till_vcount, long double *duration)
{
	vcounter_t vcount;
	int quality = 0;

	/* Check for critical bad input */
	if (!clock || !from_vcount || !till_vcount || !duration)
		return (1);

	/* Make sure we can get a raw timestamp */
	if (radclock_get_vcounter(clock, &vcount) < 0)
		return (1);
	
	/* Retrieve clock data */
	if (clock->ipc_shm)
		quality = ffcounter_to_difftime_shm(clock, *from_vcount, *till_vcount,
				duration);
	else
		quality = ffcounter_to_difftime_kernel(clock, *from_vcount, *till_vcount,
				duration);

// TODO is this the  good behaviour, we should request the clock data associated
// to from_vcount? maybe not
	if (!in_skm(clock, from_vcount, &vcount))
		return (1);

	return (quality);
}

