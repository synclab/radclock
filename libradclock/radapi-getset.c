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



// TODO check this is still needed with the IPC SHM, or if should be rebranded
// in virtual machine world?
int
radclock_set_autoupdate(struct radclock *handle, radclock_autoupdate_t *update_mode)
{
	switch (*update_mode) {  
		case RADCLOCK_UPDATE_ALWAYS:
		case RADCLOCK_UPDATE_NEVER:
		case RADCLOCK_UPDATE_AUTO:
			break;
		default:
			logger(RADLOG_ERR, "Unknown autoupdate mode");
			return (1);
	}

	if ( handle && RAD_DATA(handle)) {
		handle->autoupdate_mode = *update_mode; 
		return (0);
	}
	else
		return (1);
}


// TODO check this is still needed with the IPC SHM, or if should be rebranded
// in virtual machine world?
int
radclock_get_autoupdate(struct radclock *handle, radclock_autoupdate_t *update_mode)
{
	if ( handle && RAD_DATA(handle)) {
		*update_mode = handle->autoupdate_mode; 
		return (0);
	}
	else
		return (1);
}


int
radclock_set_local_period_mode(struct radclock *handle,
		radclock_local_period_t *local_period_mode)
{
	switch (*local_period_mode) {  
		case RADCLOCK_LOCAL_PERIOD_ON:
		case RADCLOCK_LOCAL_PERIOD_OFF:
			break;
		default:
			logger(RADLOG_ERR, "Unknown local period mode");
			return (1);
	}

	if ( handle && RAD_DATA(handle)) {
		handle->local_period_mode = *local_period_mode;
		return (0);
	}
	else
		return (1);
}


// TODO: should kill this? plocal is always used.
int
radclock_get_local_period_mode(struct radclock *handle,
		radclock_local_period_t *local_period_mode)
{
	if ( handle && RAD_DATA(handle)) {
		*local_period_mode = handle->local_period_mode; 
		return (0);
	}
	else
		return (1);
}




int
radclock_get_last_stamp(struct radclock *clock, vcounter_t *last_vcount)
{
	struct radclock_data_shm *data;
	int generation;

	if (!clock || !last_vcount)
		return (1);

	if (!clock->ipc_shm)
		return (1);

	data = (struct radclock_data_shm *) clock->ipc_shm;
	do {
		generation = data->gen;
		*last_vcount = data->new->last_changed;
	} while (generation != data->gen || !data->gen);

	return (0); 
}


int
radclock_get_till_stamp(struct radclock *clock, vcounter_t *till_vcount)
{
	struct radclock_data_shm *data;
	int generation;

	if (!clock || !till_vcount)
		return (1);

	if (!clock->ipc_shm)
		return (1);

	data = (struct radclock_data_shm *) clock->ipc_shm;
	do {
		generation = data->gen;
		*till_vcount = data->new->valid_till;
	} while (generation != data->gen || !data->gen);

	return (0); 
}


int
radclock_get_period(struct radclock *clock, double *period)
{
	struct radclock_data_shm *data;
	int generation;

	if (!clock || !period)
		return (1);

	if (!clock->ipc_shm)
		return (1);

	data = (struct radclock_data_shm *) clock->ipc_shm;
	do {
		generation = data->gen;
		*period = data->new->phat;
	} while (generation != data->gen || !data->gen);

	return (0); 
}


int
radclock_get_offset(struct radclock *clock, long double *offset)
{
	struct radclock_data_shm *data;
	int generation;

	if (!clock || !offset)
		return (1);

	if (!clock->ipc_shm)
		return (1);

	data = (struct radclock_data_shm *) clock->ipc_shm;
	do {
		generation = data->gen;
		*offset = data->new->ca;
	} while (generation != data->gen || !data->gen);

	return (0); 
}


int
radclock_get_period_error(struct radclock *clock, double *err_period)
{
	struct radclock_data_shm *data;
	int generation;

	if (!clock || !err_period)
		return (1);

	if (!clock->ipc_shm)
		return (1);

	data = (struct radclock_data_shm *) clock->ipc_shm;
	do {
		generation = data->gen;
		*err_period = data->new->phat_err;
	} while (generation != data->gen || !data->gen);

	return (0); 
}


int
radclock_get_offset_error(struct radclock *clock, double *err_offset)
{
	struct radclock_data_shm *data;
	int generation;

	if (!clock || !err_offset)
		return (1);

	if (!clock->ipc_shm)
		return (1);

	data = (struct radclock_data_shm *) clock->ipc_shm;
	do {
		generation = data->gen;
		*err_offset = data->new->ca_err;
	} while (generation != data->gen || !data->gen);

	return (0); 
}


int
radclock_get_status(struct radclock *clock, unsigned int *status)
{
	struct radclock_data_shm *data;
	int generation;

	if (!clock || !status)
		return (1);

	if (!clock->ipc_shm)
		return (1);

	data = (struct radclock_data_shm *) clock->ipc_shm;
	do {
		generation = data->gen;
		*status = data->new->status;
	} while (generation != data->gen || !data->gen);

	return (0); 
}


int
radclock_get_clockerror_bound(struct radclock *clock, double *error_bound)
{
	struct radclock_data_shm *data;
	int generation;

	if (!clock || !error_bound)
		return (1);

	if (!clock->ipc_shm)
		return (1);

	data = (struct radclock_data_shm *) clock->ipc_shm;
	do {
		generation = data->gen;
		//TODO XXX FIXME ERROR not in SHM
		*error_bound = RAD_ERROR(clock)->error_bound; 
	} while (generation != data->gen || !data->gen);

	return (0); 
}


int
radclock_get_clockerror_bound_avg(struct radclock *clock, double *error_bound_avg)
{
	struct radclock_data_shm *data;
	int generation;

	if (!clock || !error_bound_avg)
		return (1);

	if (!clock->ipc_shm)
		return (1);

	data = (struct radclock_data_shm *) clock->ipc_shm;
	do {
		generation = data->gen;
		//TODO XXX FIXME ERROR not in SHM
		*error_bound_avg = RAD_ERROR(clock)->error_bound_avg; 
	} while (generation != data->gen || !data->gen);

	return (0); 
}


int
radclock_get_clockerror_bound_std(struct radclock *clock, double *error_bound_std)
{
	struct radclock_data_shm *data;
	int generation;

	if (!clock || !error_bound_std)
		return (1);

	if (!clock->ipc_shm)
		return (1);

	data = (struct radclock_data_shm *) clock->ipc_shm;
	do {
		generation = data->gen;
		//TODO XXX FIXME ERROR not in SHM
		*error_bound_std = RAD_ERROR(clock)->error_bound_std;
	} while (generation != data->gen || !data->gen);

	return (0); 
}

int
radclock_get_min_RTT(struct radclock *clock, double *min_RTT)
{
	struct radclock_data_shm *data;
	int generation;

	if (!clock || !min_RTT)
		return (1);

	if (!clock->ipc_shm)
		return (1);

	data = (struct radclock_data_shm *) clock->ipc_shm;
	do {
		generation = data->gen;
		//TODO XXX FIXME ERROR not in SHM
		*min_RTT = RAD_ERROR(clock)->min_RTT;
	} while (generation != data->gen || !data->gen);

	return (0); 
}

