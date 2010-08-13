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

#include <sys/types.h>
#include <sys/time.h>

#include "radclock.h"
#include "radclock-private.h"
#include "logger.h"


// TODO: check all return values and error codes

// TODO: in all this file, check which functions need to call get_global_data and conditions for that (last update too far in the past ?)
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




/* Build the time using the absolute clock plus the local relative rate
 * correction (has no effect if not running plocal).
 */ 
static inline long double radclock_vcount_to_ld(
		const struct radclock *handle, vcounter_t vcount)
{
	long double base_time = (long double) vcount * (long double) RAD_DATA(handle)->phat 
		+ RAD_DATA(handle)->ca;

	if ( (handle->local_period_mode == RADCLOCK_LOCAL_PERIOD_ON)
		&& ((RAD_DATA(handle)->status & STARAD_WARMUP) != STARAD_WARMUP) )
	{
		base_time+= 
			(long double)(vcount - RAD_DATA(handle)->last_changed) * 
			(long double)(RAD_DATA(handle)->phat_local - RAD_DATA(handle)->phat);
	}
	return base_time;
}

/* Build a delay using the difference clock.
 * This function does not fail, SKM model should be checked before call
 */
static inline long double radclock_delay_to_ld(
		const struct radclock_data *data, vcounter_t from_vcount, vcounter_t till_vcount)
{
		return (long double) ((till_vcount-from_vcount) * data->phat_local);
}


/* Check if we are in the SKM model bounds or not 
 * Need to know if we are in SKM world. If not, can't use the difference clock,
 * need to substract two absolute timestamps. Testing should always be done
 * using the 'current' vcount value since we use the current global data !!!
 * Use phat for this comparison but using plocal should be fine as well
 */
// XXX  quite a few issues here
// 		- the value of the SKM scale is hard coded ... but otherwise?
// 		- Validity of the global data
// 		- error code(s) to return
static inline int in_skm(struct radclock *handle, const vcounter_t *past_count, const vcounter_t *vc) 
{
	vcounter_t now;
	if ( !vc )
		radclock_get_vcounter(handle, &now);
	now = *vc;

	if ( (now - *past_count) * RAD_DATA(handle)->phat < 1024 )
		return 1;
	else
		return 0;
}


/* The generic timeval constructor */
static inline void radclock_ld_to_tv(long double time, struct timeval *tv)
{
	tv->tv_sec  = (uint32_t) time;   
	tv->tv_usec = (uint32_t) (1000000*(time - tv->tv_sec) + 0.5); 
}




int radclock_gettimeofday(struct radclock *handle , struct timeval *abstime_tv) 
{
	vcounter_t vcount;
	int data_quality = 0;

	/* Check for critical bad input */ 
	if ( !handle )
		return 1;

	/* Make sure we can get a raw timestamp */	
	if ( radclock_get_vcounter(handle, &vcount) < 0 )
		return 1;
	
	/* Retrieve clock data */
	if ( !RAD_DATA(handle) || !abstime_tv)
		return 1;

	data_quality = radclock_check_outdated(handle, &vcount, IPC_REQ_RAD_DATA);
	radclock_ld_to_tv(radclock_vcount_to_ld(handle, vcount), abstime_tv);
	return data_quality;
}


int radclock_gettimeofday_fp(struct radclock *handle, long double *abstime_fp) 
{
	vcounter_t vcount;
	int data_quality = 0;

	/* Check for critical bad input */ 
	if ( !handle )
		return 1;

	/* Make sure we can get a raw timestamp */	
	if ( radclock_get_vcounter(handle, &vcount) < 0 )
		return 1;
	
	/* Retrieve clock data */
	if ( !RAD_DATA(handle) || !abstime_fp)
		return 1;

	data_quality = radclock_check_outdated(handle, &vcount, IPC_REQ_RAD_DATA);
	*abstime_fp = radclock_vcount_to_ld(handle, vcount);
	return data_quality;
}


int radclock_vcount_to_abstime(struct radclock *handle, const vcounter_t *vcount, struct timeval *abstime_tv) 
{     
	int data_quality = 0;

	/* Check for critical bad input */ 
	if ( !handle || !RAD_DATA(handle) || !vcount || !abstime_tv)
		return 1;

	data_quality = radclock_check_outdated(handle, NULL, IPC_REQ_RAD_DATA);
	radclock_ld_to_tv(radclock_vcount_to_ld(handle, *vcount), abstime_tv);
	return data_quality;
}


int radclock_vcount_to_abstime_fp(struct radclock *handle, const vcounter_t *vcount, long double *abstime_fp)
{
	int data_quality = 0;

	/* Check for critical bad input */ 
	if ( !handle || !RAD_DATA(handle) || !vcount || !abstime_fp)
		return 1;

	data_quality = radclock_check_outdated(handle, NULL, IPC_REQ_RAD_DATA);
	*abstime_fp = radclock_vcount_to_ld(handle, *vcount);
	return data_quality;
}


int radclock_elapsed(struct radclock *handle, const vcounter_t *from_vcount, struct timeval *duration_tv)
{
	vcounter_t vcount;
	int data_quality = 0;

	/* Check for critical bad input */ 
	if ( !handle )
		return 1;

	/* Make sure we can get a raw timestamp */	
	if ( radclock_get_vcounter(handle, &vcount) < 0 )
		return 1;
	
	/* Retrieve clock data */
	if ( !RAD_DATA(handle) || !from_vcount || !duration_tv)
		return 1;

	data_quality = radclock_check_outdated(handle, &vcount, IPC_REQ_RAD_DATA);
// TODO is this the  good behaviour, we should request the clock data associated to from_vcount? maybe not
	if ( !in_skm(handle, from_vcount, &vcount) )
		return 1;

	radclock_ld_to_tv(radclock_delay_to_ld(RAD_DATA(handle), *from_vcount, vcount), duration_tv);
	return data_quality;
}


int radclock_elapsed_fp(struct radclock *handle, const vcounter_t *from_vcount, long double *duration_fp)
{
	vcounter_t vcount;
	int data_quality = 0;

	/* Check for critical bad input */ 
	if ( !handle )
		return 1;

	/* Make sure we can get a raw timestamp */	
	if ( radclock_get_vcounter(handle, &vcount) < 0 )
		return 1;
	
	/* Retrieve clock data */
	if ( !RAD_DATA(handle) || !from_vcount || !duration_fp)
		return 1;

	data_quality = radclock_check_outdated(handle, &vcount, IPC_REQ_RAD_DATA);
// TODO is this the  good behaviour, we should request the clock data associated to from_vcount? maybe not
	if ( !in_skm(handle, from_vcount, &vcount) )
		return 1;

	*duration_fp = radclock_delay_to_ld(RAD_DATA(handle), *from_vcount, vcount);
	return data_quality;
}


int radclock_duration(struct radclock *handle, const vcounter_t *from_vcount, const vcounter_t *till_vcount, struct timeval *duration_tv)
{
	vcounter_t vcount;
	int data_quality = 0;

	/* Check for critical bad input */ 
	if ( !handle )
		return 1;

	/* Make sure we can get a raw timestamp */	
	if ( radclock_get_vcounter(handle, &vcount) < 0 )
		return 1;
	
	/* Retrieve clock data */
	if ( !RAD_DATA(handle) || !from_vcount || !till_vcount || !duration_tv)
		return 1;

	data_quality = radclock_check_outdated(handle, &vcount, IPC_REQ_RAD_DATA);
// TODO is this the  good behaviour, we should request the clock data associated to from_vcount? maybe not
	if ( !in_skm(handle, from_vcount, &vcount) )
		return 1;

	radclock_ld_to_tv(radclock_delay_to_ld(RAD_DATA(handle), *from_vcount, *till_vcount), duration_tv);
	return data_quality;
}


int radclock_duration_fp(struct radclock *handle, const vcounter_t *from_vcount, const vcounter_t *till_vcount, long double *duration_fp)
{
	vcounter_t vcount;
	int data_quality = 0;

	/* Check for critical bad input */ 
	if ( !handle )
		return 1;

	/* Make sure we can get a raw timestamp */	
	if ( radclock_get_vcounter(handle, &vcount) < 0 )
		return 1;
	
	/* Retrieve clock data */
	if ( !RAD_DATA(handle) || !from_vcount || !till_vcount || !duration_fp)
		return 1;

	data_quality = radclock_check_outdated(handle, &vcount, IPC_REQ_RAD_DATA);
// TODO is this the  good behaviour, we should request the clock data associated to from_vcount? maybe not
	if ( !in_skm(handle, from_vcount, &vcount) )
		return 1;

	*duration_fp = radclock_delay_to_ld(RAD_DATA(handle), *from_vcount, *till_vcount);
	return data_quality;
}


