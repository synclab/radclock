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

#include "radclock.h"
#include "radclock-private.h"
#include "radclock_daemon.h"
#include "misc.h"
#include "logger.h"
#include "jdebug.h"


int
counter_to_time(struct radclock_data *rad_data, vcounter_t *vcount, long double *time)
{
	JDEBUG

	vcounter_t last;

	do {
		/* Quality ingredients */
		last  = rad_data->last_changed;

		*time = *vcount * (long double)rad_data->phat + rad_data->ca;

		*time += (*vcount - last) * (long double)rad_data->phat_local -
			rad_data->phat;

	} while (last != rad_data->last_changed);

	return (0);
}

