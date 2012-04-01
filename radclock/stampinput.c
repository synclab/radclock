/*
 * Copyright (C) 2006-2012 Julien Ridoux <julien@synclab.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <pcap.h>

#include "../config.h"
#include "radclock.h"
#include "radclock-private.h"

#include "radclock_daemon.h"
#include "sync_history.h"
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
extern struct stampsource_def spy_source;


int
is_live_source(struct radclock_handle *handle)
{
	int input_type = 0;
	
	if (strlen(handle->conf->sync_in_ascii) > 0) 		input_type++;
	if (strlen(handle->conf->sync_in_pcap) > 0) 		input_type++; 
//	if (strlen(handle->conf->network_device) > 0) 	input_type++; 

	if (input_type > 1) {
		verbose (LOG_ERR, "Error: Conflict detected, two distinct inputs,"
							" check conf file and/or command line");
		exit(EXIT_FAILURE);
	}
	/* If no dead source selected, fall back to live capture */
	if (input_type == 0) {
		return 1;
	}
	else
		return 0;
/*
	if (strlen(handle->conf->network_device) > 0)
		return 1;
	else
		return 0;
*/
}



/**
 * Try to create a source from the given config
 * @return a source or NULL if there was an error creating it
 */
struct stampsource *
create_source(struct radclock_handle *handle)
{
	struct stampsource *src = (struct stampsource *) malloc(sizeof(struct stampsource));
	JDEBUG_MEMORY(JDBG_MALLOC, src);

	if (!src)
		goto err_out;

	switch (handle->run_mode) {

	case RADCLOCK_SYNC_DEAD:
		verbose(LOG_NOTICE, "Creating dead input source");
		/* is_live_source has checked there is only one dead input */
		if (strlen(handle->conf->sync_in_ascii) > 0) {
			INPUT_OPS(src) = &ascii_source;
			handle->conf->server_ipc = BOOL_OFF;  
			handle->conf->server_ntp = BOOL_OFF;  
		}

		if (strlen(handle->conf->sync_in_pcap) > 0) {
			INPUT_OPS(src) = &filepcap_source;
			handle->conf->server_ipc = BOOL_OFF;  
			handle->conf->server_ntp = BOOL_OFF;  
		}

		break;

	case RADCLOCK_SYNC_LIVE:
		verbose(LOG_NOTICE, "Creating live input source");
		switch (handle->conf->synchro_type)
		{
			case SYNCTYPE_SPY:
				INPUT_OPS(src) = &spy_source;
				break;

			case SYNCTYPE_NTP:
			case SYNCTYPE_PIGGY:
				INPUT_OPS(src) = &livepcap_source;
				break;

			case SYNCTYPE_PPS:
			case SYNCTYPE_1588:
			default:
				verbose(LOG_ERR, "Source for this sync' type does not exist.");
				return NULL;
		}
		break;

	case RADCLOCK_SYNC_NOTSET:
	default:
		verbose(LOG_ERR, "Run mode not set when creating input source");
		return NULL;
	}

	/* Now that we've worked out the type of input source, init it */
	if (INPUT_OPS(src)->init(handle, src) == -1)
		goto child_err;

	/* Initialise ntp_stats, common to all sources */
	memset(&src->ntp_stats, 0 ,sizeof(struct timeref_stats));
	
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
int
get_next_stamp(struct radclock_handle *handle, struct stampsource *source,
	struct stamp_t *stamp)
{
	return INPUT_OPS(source)->get_next_stamp(handle, source, stamp);
}

void
source_breakloop(struct radclock_handle *handle, struct stampsource *source)
{
	return INPUT_OPS(source)->source_breakloop(handle, source);
}


/**
 * Destroy the given source handle
 */
void
destroy_source(struct radclock_handle *handle, struct stampsource *source)
{
	INPUT_OPS(source)->destroy(handle, source);
	JDEBUG_MEMORY(JDBG_FREE, source);
	free(source);
}

/**
 * Change the BPF filter on the given source handle
 */
int
update_filter_source(struct radclock_handle *handle, struct stampsource *source)
{
	return INPUT_OPS(source)->update_filter(handle, source);
}

/**
 * Change the raw output 
 */
int
update_dumpout_source(struct radclock_handle *handle, struct stampsource *source)
{
	return INPUT_OPS(source)->update_dumpout(handle, source);
}

