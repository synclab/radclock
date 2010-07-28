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

#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <syslog.h>
#include <sys/stat.h>

#include "../config.h"
#include "radclock.h"
#include "radclock-private.h"
#include "verbose.h"
#include "sync_algo.h"
#include "config_mgr.h"
#include "jdebug.h"



int pull_data_none(struct radclock *clock_handle)
{
	JDEBUG
	return 0;
}


int push_data_none(struct radclock *clock_handle)
{
	JDEBUG
	return 0;
}



int init_virtual_machine_mode(struct radclock *clock_handle)
{
	JDEBUG
	switch ( clock_handle->conf->virtual_machine )
	{
		case VM_NONE:
			RAD_VM(clock_handle)->pull_data = &pull_data_none;
			RAD_VM(clock_handle)->push_data = &push_data_none;
			break;

		case VM_XEN_MASTER:
			break;

		case VM_XEN_SLAVE:
			break;

		case VM_VBOX_MASTER:
			break;

		case VM_VBOX_SLAVE:
			break;

		default:
			verbose(LOG_ERR, "Unknown virtual machine mode during init.");
			return -1;
	}
	return 0;
}



