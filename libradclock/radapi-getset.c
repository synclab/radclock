/*
 * Copyright (C) 2006-2009 Julien Ridoux <julien@synclab.org>
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

	if ( handle && GLOBAL_DATA(handle)) {
		handle->autoupdate_mode = *update_mode; 
		return 0;
	}
	else
		return 1;
}


int radclock_get_autoupdate(struct radclock *handle, radclock_autoupdate_t *update_mode)
{
	if ( handle && GLOBAL_DATA(handle)) {
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

	if ( handle && GLOBAL_DATA(handle)) {
		handle->local_period_mode = *local_period_mode;
		return 0;
	}
	else
		return 1;
}


int radclock_get_local_period_mode(struct radclock *handle, radclock_local_period_t *local_period_mode)
{
	if ( handle && GLOBAL_DATA(handle)) {
		*local_period_mode = handle->local_period_mode; 
		return 0;
	}
	else
		return 1;
}




int radclock_get_last_stamp(struct radclock *handle, vcounter_t *last_vcount)
{
	if (radclock_check_outdated(handle))  { return 1; }
	if ( handle && GLOBAL_DATA(handle)) {
		*last_vcount = GLOBAL_DATA(handle)->last_changed; 
		return 0;
	}
	else
		return 1;
}


int radclock_get_till_stamp(struct radclock *handle, vcounter_t *till_vcount)
{
	if (radclock_check_outdated(handle))  { return 1; }
	if ( handle && GLOBAL_DATA(handle)) {
		*till_vcount = GLOBAL_DATA(handle)->valid_till; 
		return 0;
	}
	else
		return 1;
}


int radclock_get_period(struct radclock *handle, double *period)
{
	if (radclock_check_outdated(handle))  { return 1; }
	if ( handle && GLOBAL_DATA(handle) ) {
		*period = GLOBAL_DATA(handle)->phat; 
		return 0;
	}
	else
		return 1;
}


int radclock_get_offset(struct radclock *handle, long double *offset)
{
	if (radclock_check_outdated(handle))  { return 1; }
	if ( handle && GLOBAL_DATA(handle) ) {
		*offset = GLOBAL_DATA(handle)->ca;
		return 0; 
	}
	else
		return 1;
}


int radclock_get_period_error(struct radclock *handle, double *err_period)
{
	if (radclock_check_outdated(handle))  { return 1; }
	if ( handle && GLOBAL_DATA(handle) ) {
		*err_period = GLOBAL_DATA(handle)->phat_err; 
		return 0;
	}
	else
		return 1;
}


int radclock_get_offset_error(struct radclock *handle, double *err_offset)
{
	if (radclock_check_outdated(handle))  { return 1; }
	if ( handle && GLOBAL_DATA(handle) ) {
		*err_offset = GLOBAL_DATA(handle)->ca_err;
		return 0; 
	}
	else
		return 1;
}


int radclock_get_status(struct radclock *handle, unsigned int *status)
{
	if (radclock_check_outdated(handle))  { return 1; }
	if ( handle && GLOBAL_DATA(handle) ) {
		*status = GLOBAL_DATA(handle)->status;
		return 0; 
	}
	else
		return 1;
}


int radclock_get_clockerror_bound(struct radclock *handle, double *error_bound)
{
	if (radclock_check_outdated(handle))  { return 1; }
	if ( handle && RAD_ERROR(handle) ) {
		*error_bound = RAD_ERROR(handle)->error_bound; 
		return 0;
	}
	else
		return 1;
}


int radclock_get_clockerror_bound_avg(struct radclock *handle, double *error_bound_avg)
{
	if (radclock_check_outdated(handle))  { return 1; }
	if ( handle && RAD_ERROR(handle) ) {
		*error_bound_avg = RAD_ERROR(handle)->error_bound_avg; 
		return 0;
	}
	else
		return 1;
}


int radclock_get_clockerror_bound_std(struct radclock *handle, double *error_bound_std)
{
	if (radclock_check_outdated(handle))  { return 1; }
	if ( handle && RAD_ERROR(handle) ) {
		*error_bound_std = RAD_ERROR(handle)->error_bound_std;
		return 0;
	}
	else
		return 1;
}

int radclock_get_min_RTT(struct radclock *handle, double *min_RTT)
{
	if (radclock_check_outdated(handle))  { return 1; }
	if ( handle && RAD_ERROR(handle) ) {
		*min_RTT = RAD_ERROR(handle)->min_RTT;
		return 0;
	}
	else
		return 1;
}



