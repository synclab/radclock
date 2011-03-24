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




int radclock_set_autoupdate(struct radclock *handle, radclock_autoupdate_t *update_mode)
{
	switch (*update_mode) {  
		case RADCLOCK_UPDATE_ALWAYS:
		case RADCLOCK_UPDATE_NEVER:
		case RADCLOCK_UPDATE_AUTO:
			break;
		default:
			logger(RADLOG_ERR, "Unknown autoupdate mode");
			return 1;
	}

	if ( handle && RAD_DATA(handle)) {
		handle->autoupdate_mode = *update_mode; 
		return 0;
	}
	else
		return 1;
}


int radclock_get_autoupdate(struct radclock *handle, radclock_autoupdate_t *update_mode)
{
	if ( handle && RAD_DATA(handle)) {
		*update_mode = handle->autoupdate_mode; 
		return 0;
	}
	else
		return 1;
}


int radclock_set_local_period_mode(struct radclock *handle, radclock_local_period_t *local_period_mode)
{
	switch (*local_period_mode) {  
		case RADCLOCK_LOCAL_PERIOD_ON:
		case RADCLOCK_LOCAL_PERIOD_OFF:
			break;
		default:
			logger(RADLOG_ERR, "Unknown local period mode");
			return 1;
	}

	if ( handle && RAD_DATA(handle)) {
		handle->local_period_mode = *local_period_mode;
		return 0;
	}
	else
		return 1;
}


int radclock_get_local_period_mode(struct radclock *handle, radclock_local_period_t *local_period_mode)
{
	if ( handle && RAD_DATA(handle)) {
		*local_period_mode = handle->local_period_mode; 
		return 0;
	}
	else
		return 1;
}




int radclock_get_last_stamp(struct radclock *handle, vcounter_t *last_vcount)
{
	int data_quality = 0;
	if ( !handle || !RAD_DATA(handle) || !last_vcount)
		return 1;

	data_quality = radclock_check_outdated(handle, NULL, IPC_REQ_RAD_DATA);
	*last_vcount = RAD_DATA(handle)->last_changed;
	return data_quality;
}


int radclock_get_till_stamp(struct radclock *handle, vcounter_t *till_vcount)
{
	int data_quality = 0;
	if ( !handle || !RAD_DATA(handle) || !till_vcount)
		return 1;

	data_quality = radclock_check_outdated(handle, NULL, IPC_REQ_RAD_DATA);
	*till_vcount = RAD_DATA(handle)->valid_till; 
	return data_quality;
}


int radclock_get_period(struct radclock *handle, double *period)
{
	int data_quality = 0;
	if ( !handle || !RAD_DATA(handle) || !period)
		return 1;

	data_quality = radclock_check_outdated(handle, NULL, IPC_REQ_RAD_DATA);
	*period = RAD_DATA(handle)->phat;
	return data_quality;
}


int radclock_get_offset(struct radclock *handle, long double *offset)
{
	int data_quality = 0;
	if ( !handle || !RAD_DATA(handle) || !offset)
		return 1;

	data_quality = radclock_check_outdated(handle, NULL, IPC_REQ_RAD_DATA);
	*offset = RAD_DATA(handle)->ca;
	return data_quality;
}


int radclock_get_period_error(struct radclock *handle, double *err_period)
{
	int data_quality = 0;
	if ( !handle || !RAD_DATA(handle) || !err_period)
		return 1;

	data_quality = radclock_check_outdated(handle, NULL, IPC_REQ_RAD_DATA);
	*err_period = RAD_DATA(handle)->phat_err;
	return data_quality;
}


int radclock_get_offset_error(struct radclock *handle, double *err_offset)
{
	int data_quality = 0;
	if ( !handle || !RAD_DATA(handle) || !err_offset)
		return 1;

	data_quality = radclock_check_outdated(handle, NULL, IPC_REQ_RAD_DATA);
	*err_offset = RAD_DATA(handle)->ca_err;
	return data_quality;
}


int radclock_get_status(struct radclock *handle, unsigned int *status)
{
	int data_quality = 0;
	if ( !handle || !RAD_DATA(handle) || !status)
		return 1;

	data_quality = radclock_check_outdated(handle, NULL, IPC_REQ_RAD_DATA);
	*status = RAD_DATA(handle)->status;
	return data_quality;
}


int radclock_get_clockerror_bound(struct radclock *handle, double *error_bound)
{
	int data_quality = 0;
	if ( !handle || !RAD_DATA(handle) || !error_bound)
		return 1;

	data_quality = radclock_check_outdated(handle, NULL, IPC_REQ_RAD_ERROR);
	*error_bound = RAD_ERROR(handle)->error_bound; 
	return data_quality;
}


int radclock_get_clockerror_bound_avg(struct radclock *handle, double *error_bound_avg)
{
	int data_quality = 0;
	if ( !handle || !RAD_DATA(handle) || !error_bound_avg)
		return 1;

	data_quality = radclock_check_outdated(handle, NULL, IPC_REQ_RAD_ERROR);
	*error_bound_avg = RAD_ERROR(handle)->error_bound_avg; 
	return data_quality;
}


int radclock_get_clockerror_bound_std(struct radclock *handle, double *error_bound_std)
{
	int data_quality = 0;
	if ( !handle || !RAD_DATA(handle) || !error_bound_std)
		return 1;

	data_quality = radclock_check_outdated(handle, NULL, IPC_REQ_RAD_ERROR);
	*error_bound_std = RAD_ERROR(handle)->error_bound_std;
	return data_quality;
}

int radclock_get_min_RTT(struct radclock *handle, double *min_RTT)
{
	int data_quality = 0;
	if ( !handle || !RAD_DATA(handle) || !min_RTT)
		return 1;

	data_quality = radclock_check_outdated(handle, NULL, IPC_REQ_RAD_ERROR);
	*min_RTT = RAD_ERROR(handle)->min_RTT;
	return data_quality;
}



