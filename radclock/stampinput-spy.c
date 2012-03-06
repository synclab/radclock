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


/**
 * A stamp source for reading from live input, but spying on the system clock.
 * Also has the ability to create output
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "../config.h"
#include "sync_algo.h"
#include "config_mgr.h"
#include "verbose.h"
#include "create_stamp.h"
#include "stampinput.h"
#include "stampinput_int.h"
#include "rawdata.h"
#include "jdebug.h"






static int spystamp_init(struct radclock *handle, struct stampsource *source)
{
	verbose(LOG_NOTICE, "Reading live from spy source");
	source->priv_data = NULL; 
	return 0;
}



static int
spystamp_get_next(struct radclock *handle, struct stampsource *source,
	struct stamp_t *stamp)
{
	int err;

	JDEBUG

	err = deliver_rawdata_spy(handle, stamp);
	if (err < 0) {
		/* Signals empty buffer */
		return err;
	}
	stamp->type = STAMP_SPY;
	stamp->qual_warning = 0;
	source->ntp_stats.ref_count += 2;

	return 0;
}



static void spystamp_breakloop(struct radclock *handle, struct stampsource *source)
{
	/*  
	 * Used to exit the capture loop if a signal has been caught. 
	 */
	return;
}


static void spystamp_finish(struct radclock *handle, struct stampsource *source)
{
	/* Nothing to close */
}


static int spystamp_update_filter(struct radclock *handle, struct stampsource *source)
{
	/* So far nothing to do */
	return 0;
}


static int spystamp_update_dumpout(struct radclock *handle, struct stampsource *source)
{
	/* So far nothing to do */
	return 0;
}




struct stampsource_def spy_source =
{
	.init 				= spystamp_init,
	.get_next_stamp 	= spystamp_get_next,
	.source_breakloop 	= spystamp_breakloop,
	.destroy 			= spystamp_finish,
	.update_filter  	= spystamp_update_filter,
	.update_dumpout 	= spystamp_update_dumpout,
};

