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


/*
 * Generic stamp source helper
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <pcap.h>

#include "../config.h"
#include "sync_algo.h"
#include "config_mgr.h"
#include "verbose.h"
#include "create_stamp.h"
#include "stampinput.h"
#include "stampinput_int.h"
#include "jdebug.h"


extern struct stampsource_def ascii_source;
extern struct stampsource_def livepcap_source;
extern struct stampsource_def filepcap_source;


int is_live_source(struct radclock *clock_handle)
{
	int input_type = 0;
	
	if (strlen(clock_handle->conf->sync_in_ascii) > 0) 		input_type++;
	if (strlen(clock_handle->conf->sync_in_pcap) > 0) 		input_type++; 
	if (strlen(clock_handle->conf->network_device) > 0) 	input_type++; 

	if (input_type > 1) {
		verbose (LOG_ERR, "Error: Conflict detected, two distinct inputs, \
							check conf file and/or command line");
		exit(EXIT_FAILURE);
	}
	/* If no source selected, fall back to live capture */
	if (input_type == 0) {
		return 1;
	}
	if (strlen(clock_handle->conf->network_device) > 0)
		return 1;
	else
		return 0;
}



/**
 * Try to create a source from the given config
 * @return a source or NULL if there was an error creating it
 */
struct stampsource *create_source(struct radclock *handle)
{
	struct stampsource *src = (struct stampsource *) malloc(sizeof(struct stampsource));
	JDEBUG_MEMORY(JDBG_MALLOC, src);

	if (!src)
		goto err_out;

	if (strlen(handle->conf->sync_in_ascii) > 0) {
		INPUT_OPS(src) = &ascii_source;
		handle->conf->server_ipc = BOOL_OFF;  
		handle->conf->server_ntp = BOOL_OFF;  
	}
	else if(strlen(handle->conf->sync_in_pcap))
	{
		INPUT_OPS(src) = &filepcap_source;
		handle->conf->server_ipc = BOOL_OFF;  
		handle->conf->server_ntp = BOOL_OFF;  
	}
	else if(strlen(handle->conf->network_device))
	{
		INPUT_OPS(src) = &livepcap_source;
	}
	else
	{
	verbose(LOG_NOTICE, "No source specified, fall back on live input");
		INPUT_OPS(src) = &livepcap_source;
	}

	//Now that we've worked out which one, init it
	if (INPUT_OPS(src)->init(handle, src))
		goto child_err;
	
	memset(&src->ntp_stats,0 ,sizeof(struct timeref_stats));
	
	return src;
child_err:
	JDEBUG_MEMORY(JDBG_FREE, src);
	free(src);
err_out:
	return NULL;
}

/**
 * Retreive a stamp from the given handle into stamp
 * @return 0 on success a negitive value on error
 */
int get_next_stamp(struct radclock *handle, struct stampsource *source, struct bidir_stamp *stamp)
{
	return INPUT_OPS(source)->get_next_stamp(handle, source, stamp);
}

void source_breakloop(struct radclock *clock_handle, struct stampsource *source)
{
	return INPUT_OPS(source)->source_breakloop(clock_handle, source);
}


// TODO ;  to kill?
struct timeref_stats *stampsource_get_stats(struct radclock *clock_handle, struct stampsource *source)
{
	return &source->ntp_stats;
}

/**
 * Destroy the given source handle
 */
void destroy_source(struct radclock *clock_handle, struct stampsource *source)
{
	INPUT_OPS(source)->destroy(clock_handle, source);
	JDEBUG_MEMORY(JDBG_FREE, source);
	free(source);
}

/**
 * Change the BPF filter on the given source handle
 */
int update_filter_source(struct radclock *clock_handle, struct stampsource *source)
{
	return INPUT_OPS(source)->update_filter(clock_handle, source);
}

/**
 * Change the raw output 
 */
int update_dumpout_source(struct radclock *clock_handle, struct stampsource *source)
{
	return INPUT_OPS(source)->update_dumpout(clock_handle, source);
}

