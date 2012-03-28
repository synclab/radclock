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

#include <sys/types.h>
#include <sys/time.h>
#include <math.h>

#include <radclock.h>
#include "radclock-private.h"
#include "logger.h"


/*
 * Specifies if local refinement of hardware counter period should be used when
 * computing time.
 */
int
radclock_set_local_period_mode(struct radclock *clock,
		radclock_local_period_t *local_period_mode)
{
	if (!clock || !local_period_mode)
		return (1);

	switch (*local_period_mode) {
		case RADCLOCK_LOCAL_PERIOD_ON:
		case RADCLOCK_LOCAL_PERIOD_OFF:
			break;
		default:
			logger(RADLOG_ERR, "Unknown local period mode");
			return (1);
	}

	clock->local_period_mode = *local_period_mode;
	return (0);
}


// TODO: should kill this? plocal is always used.
int
radclock_get_local_period_mode(struct radclock *clock,
		radclock_local_period_t *local_period_mode)
{
	if (!clock || !local_period_mode)
		return (1);

	*local_period_mode = clock->local_period_mode;
	return (0);
}




int
radclock_get_last_stamp(struct radclock *clock, vcounter_t *last_vcount)
{
	struct radclock_data rad_data;
	struct radclock_shm *shm;
	int generation;

	if (!clock || !last_vcount)
		return (1);

	if (clock->ipc_shm) {
		shm = (struct radclock_shm *) clock->ipc_shm;
		do {
			generation = shm->gen;
			*last_vcount = SHM_DATA(shm)->last_changed;
		} while (generation != shm->gen || !shm->gen);
	} else {

		if (get_kernel_ffclock(clock, &rad_data) < 0)
			return (1);
		*last_vcount = rad_data.last_changed;
	}

	return (0);
}


int
radclock_get_till_stamp(struct radclock *clock, vcounter_t *till_vcount)
{
	struct radclock_data rad_data;
	struct radclock_shm *shm;
	int generation;

	if (!clock || !till_vcount)
		return (1);

	if (clock->ipc_shm) {
		shm = (struct radclock_shm *) clock->ipc_shm;
		do {
			generation = shm->gen;
			*till_vcount = SHM_DATA(shm)->valid_till;
		} while (generation != shm->gen || !shm->gen);
	} else {
		if (get_kernel_ffclock(clock, &rad_data) < 0)
			return (1);
		*till_vcount = rad_data.valid_till;
	}

	return (0);
}


int
radclock_get_period(struct radclock *clock, double *period)
{
	struct radclock_data rad_data;
	struct radclock_shm *shm;
	int generation;

	if (!clock || !period)
		return (1);

	if (clock->ipc_shm) {
		shm = (struct radclock_shm *) clock->ipc_shm;
		do {
			generation = shm->gen;
			*period = SHM_DATA(shm)->phat;
		} while (generation != shm->gen || !shm->gen);
	} else {
		if (get_kernel_ffclock(clock, &rad_data) < 0)
			return (1);
		*period = rad_data.phat;
	}

	return (0);
}


int
radclock_get_offset(struct radclock *clock, long double *offset)
{
	struct radclock_data rad_data;
	struct radclock_shm *shm;
	int generation;

	if (!clock || !offset)
		return (1);

	if (clock->ipc_shm) {
		shm = (struct radclock_shm *) clock->ipc_shm;
		do {
			generation = shm->gen;
			*offset = SHM_DATA(shm)->ca;
		} while (generation != shm->gen || !shm->gen);
	} else {
		if (get_kernel_ffclock(clock, &rad_data) < 0)
			return (1);
		*offset = rad_data.ca;
	}

	return (0);
}


int
radclock_get_period_error(struct radclock *clock, double *err_period)
{
	struct radclock_data rad_data;
	struct radclock_shm *shm;
	int generation;

	if (!clock || !err_period)
		return (1);

	if (clock->ipc_shm) {
		shm = (struct radclock_shm *) clock->ipc_shm;
		do {
			generation = shm->gen;
			*err_period = SHM_DATA(shm)->phat_err;
		} while (generation != shm->gen || !shm->gen);
	} else {
		if (get_kernel_ffclock(clock, &rad_data) < 0)
			return (1);
		*err_period = rad_data.phat_err;
	}

	return (0);
}


int
radclock_get_offset_error(struct radclock *clock, double *err_offset)
{
	struct radclock_data rad_data;
	struct radclock_shm *shm;
	int generation;

	if (!clock || !err_offset)
		return (1);

	if (clock->ipc_shm) {
		shm = (struct radclock_shm *) clock->ipc_shm;
		do {
			generation = shm->gen;
			*err_offset = SHM_DATA(shm)->ca_err;
		} while (generation != shm->gen || !shm->gen);
	} else {
		if (get_kernel_ffclock(clock, &rad_data) < 0)
			return (1);
		*err_offset = rad_data.ca_err;
	}

	return (0);
}


int
radclock_get_status(struct radclock *clock, unsigned int *status)
{
	struct radclock_data rad_data;
	struct radclock_shm *shm;
	int generation;

	if (!clock || !status)
		return (1);

	if (clock->ipc_shm) {
		shm = (struct radclock_shm *) clock->ipc_shm;
		do {
			generation = shm->gen;
			*status = SHM_DATA(shm)->status;
		} while (generation != shm->gen || !shm->gen);
	} else {
		if (get_kernel_ffclock(clock, &rad_data) < 0)
			return (1);
		*status = rad_data.status;
	}

	return (0);
}


// TODO: for all 3 functions, implement kernel based fall back case if ipc_shm is NULL
// this may imply adapting get_kernel_ffclock to include return of error metrics
int
radclock_get_clockerror_bound(struct radclock *clock, double *error_bound)
{
	struct radclock_shm *shm;
	int generation;

	if (!clock || !error_bound)
		return (1);

	if (!clock->ipc_shm)
		return (1);

	shm = (struct radclock_shm *) clock->ipc_shm;
	do {
		generation = shm->gen;
		*error_bound = SHM_ERROR(shm)->error_bound;
	} while (generation != shm->gen || !shm->gen);

	return (0);
}


int
radclock_get_clockerror_bound_avg(struct radclock *clock, double *error_bound_avg)
{
	struct radclock_shm *shm;
	int generation;

	if (!clock || !error_bound_avg)
		return (1);

	if (!clock->ipc_shm)
		return (1);

	shm = (struct radclock_shm *) clock->ipc_shm;
	do {
		generation = shm->gen;
		*error_bound_avg = SHM_ERROR(shm)->error_bound_avg;
	} while (generation != shm->gen || !shm->gen);

	return (0);
}


int
radclock_get_clockerror_bound_std(struct radclock *clock, double *error_bound_std)
{
	struct radclock_shm *shm;
	int generation;

	if (!clock || !error_bound_std)
		return (1);

	if (!clock->ipc_shm)
		return (1);

	shm = (struct radclock_shm *) clock->ipc_shm;
	do {
		generation = shm->gen;
		*error_bound_std = SHM_ERROR(shm)->error_bound_std;
	} while (generation != shm->gen || !shm->gen);

	return (0);
}

int
radclock_get_min_RTT(struct radclock *clock, double *min_RTT)
{
	struct radclock_shm *shm;
	int generation;

	if (!clock || !min_RTT)
		return (1);

	if (!clock->ipc_shm)
		return (1);

	shm = (struct radclock_shm *) clock->ipc_shm;
	do {
		generation = shm->gen;
		*min_RTT = SHM_ERROR(shm)->min_RTT;
	} while (generation != shm->gen || !shm->gen);

	return (0);
}

