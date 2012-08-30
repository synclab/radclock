/*
 * Copyright (C) 2006-2012, Julien Ridoux <julien@synclab.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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

#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <pcap.h>

#include "../config.h"
#include "radclock.h"
#include "radclock-private.h"

#include "radclock_daemon.h"
#include "verbose.h"
#include "sync_history.h"
#include "sync_algo.h"
#include "config_mgr.h"
#include "stampoutput.h"
#include "jdebug.h"


int
open_output_stamp(struct radclock_handle *handle)
{
	char *backup;

	/* Sometimes, there is nothing to do */
	if (strlen(handle->conf->sync_out_ascii) == 0)
		return (0);

	/* Test if previous file exists. Rename it if so */
	handle->stampout_fd = fopen(handle->conf->sync_out_ascii, "r");
	if (handle->stampout_fd) {
		fclose(handle->stampout_fd);
		backup = (char *) malloc(strlen(handle->conf->sync_out_ascii)+ 5);
		JDEBUG_MEMORY(JDBG_MALLOC, backup);

		sprintf(backup, "%s.old", handle->conf->sync_out_ascii);
		if (rename(handle->conf->sync_out_ascii, backup) < 0) {
			verbose(LOG_ERR, "Cannot rename existing output file: %s",
					handle->conf->sync_out_ascii);

			JDEBUG_MEMORY(JDBG_FREE, backup);
			free(backup);
			exit(EXIT_FAILURE);
		}
		verbose(LOG_NOTICE, "Backed up existing output file: %s",
				handle->conf->sync_out_ascii);
		JDEBUG_MEMORY(JDBG_FREE, backup);
		free(backup);
		handle->stampout_fd = NULL;
	}

	/* Open output file to store input data in preprocessed stamp format */
	handle->stampout_fd = fopen(handle->conf->sync_out_ascii,"w");
	if (handle->stampout_fd == NULL) {
		verbose(LOG_ERR, "Open failed on stamp output file- %s",
				handle->conf->sync_out_ascii);
		exit(EXIT_FAILURE);
	/* write out comment header describing data saved */
	} else {
		/* TODO: turn off buffering? */
		setvbuf(handle->stampout_fd, (char *)NULL, _IONBF, 0);
		fprintf(handle->stampout_fd, "%% BEGIN_HEADER\n");
		fprintf(handle->stampout_fd, "%% description: radclock local FFcounter "
				"and NTP server stamps\n");
		fprintf(handle->stampout_fd, "%% type: NTP_rad\n");
		fprintf(handle->stampout_fd, "%% version: 3\n");
		fprintf(handle->stampout_fd, "%% fields: Ta Tb Te Tf NTP_keystamp\n");
		fprintf(handle->stampout_fd, "%% END_HEADER\n");
	}
	return (0);
}


void close_output_stamp(struct radclock_handle *handle)
{
	if (handle->stampout_fd != NULL) {
		fflush(handle->stampout_fd);
		fclose(handle->stampout_fd);
	}
}




int
open_output_matlab(struct radclock_handle *handle)
{
	char *backup;

	/* Sometimes, there is nothing to do */
	if (strlen(handle->conf->clock_out_ascii) == 0)
		return (0);

	/* Test if previous file exists. Rename it if so */
	handle->matout_fd = fopen(handle->conf->clock_out_ascii, "r");
	if (handle->matout_fd) {
		fclose(handle->matout_fd);
		backup = (char*) malloc(strlen(handle->conf->clock_out_ascii) + 5);
		JDEBUG_MEMORY(JDBG_MALLOC, backup);

		sprintf(backup, "%s.old", handle->conf->clock_out_ascii);
		if (rename(handle->conf->clock_out_ascii, backup) < 0) {
			verbose(LOG_ERR, "Cannot rename existing output file: %s",
					handle->conf->clock_out_ascii);
			JDEBUG_MEMORY(JDBG_FREE, backup);
			free(backup);
			exit(EXIT_FAILURE);
		}
		verbose(LOG_NOTICE, "Backed up existing output file: %s",
				handle->conf->clock_out_ascii);
		JDEBUG_MEMORY(JDBG_FREE, backup);
		free(backup);
		handle->matout_fd = NULL;
	}


	/* Open output file to store synchronisation algorithm output (for Matlab,
	 * written in process_bidir_stamp).
	 */
	handle->matout_fd = fopen(handle->conf->clock_out_ascii,"w");
	if (handle->matout_fd == NULL) {
		verbose(LOG_ERR, "Open failed on Matlab output file- %s",
				handle->conf->clock_out_ascii);
		exit(EXIT_FAILURE);
	} else
		/* TODO turn off buffering ? */
		setvbuf(handle->matout_fd, (char *)NULL, _IONBF, 0);

	fprintf(handle->matout_fd, "%% BEGIN_HEADER\n");
	fprintf(handle->matout_fd, "%% description: radclock internals\n");
	fprintf(handle->matout_fd, "%% type: radclock\n");
	fprintf(handle->matout_fd, "%% version: 3\n");
	fprintf(handle->matout_fd, "%% fields: Tb Tf RTT phat plocal C thetahat "
			"RTThat RTThat_new RTThat_sh th_naive minET minET_last RADclockout "
			"RADclockin errTa errTf perr plocalerr wsum best_Tf "
			"clock_status\n");
	fprintf(handle->matout_fd, "%% END_HEADER\n");

	return (0);
}



void
close_output_matlab(struct radclock_handle *handle)
{
	if (handle->matout_fd != NULL) {
		fflush(handle->matout_fd);
		fclose(handle->matout_fd);
	}
}


void
print_out_files(struct radclock_handle *handle, struct stamp_t *stamp)
{
	int err;
	// XXX What is the reason for me to do it that way? Cannot remember.
	/* A single buffer to have a single disk access, it has to be big enough */
	char *buf;

	/* long double since must hold [sec] since timescale origin, and at least
	 * 1mus precision
	 */
	long double currtime_out, currtime_in;

	if ((stamp->type != STAMP_NTP) && (stamp->type != STAMP_SPY))
		verbose(LOG_ERR, "Do not know how to print these stamps!!");

	currtime_out = (long double)(BST(stamp)->Ta * OUTPUT(handle, phat)) +
		OUTPUT(handle, C);
	currtime_in  = (long double)(BST(stamp)->Tf * OUTPUT(handle, phat)) +
		OUTPUT(handle, C);

	/* Store generated stamp values */
	if (handle->stampout_fd != NULL) {
		err = fprintf(handle->stampout_fd,"%"VC_FMT" %.9Lf %.9Lf %"VC_FMT" %llu\n",
				BST(stamp)->Ta, BST(stamp)->Tb, BST(stamp)->Te, BST(stamp)->Tf,
				(long long unsigned)stamp->id);
		if (err < 0)
			verbose(LOG_ERR, "Failed to write data to timestamp file");
	}
	
	if (handle->matout_fd == NULL)
		return;

	buf = (char *) malloc(500 * sizeof(char));
	JDEBUG_MEMORY(JDBG_MALLOC, buf);

	sprintf(buf,
		"%.9Lf %"VC_FMT" %"VC_FMT" %.10lg %.10lg %.11Lf %.10lf "
		"%"VC_FMT" %"VC_FMT" %"VC_FMT" %.9le %.9le %.9le %.11Lf "
		"%.11Lf %.10lf %.10lf %.6le %.6le %.6le %"VC_FMT" %u\n",
		BST(stamp)->Tb,
		BST(stamp)->Tf,
		OUTPUT(handle, RTT),
		OUTPUT(handle, phat),
		OUTPUT(handle, plocal),
		OUTPUT(handle, C),
		OUTPUT(handle, thetahat),
		OUTPUT(handle, RTThat),
		OUTPUT(handle, RTThat_new),
		OUTPUT(handle, RTThat_shift),
		OUTPUT(handle, th_naive),
		OUTPUT(handle, minET),
		OUTPUT(handle, minET_last),
		currtime_out,
		currtime_in,
		OUTPUT(handle, errTa),
		OUTPUT(handle, errTf),
		OUTPUT(handle, perr),
		OUTPUT(handle, plocalerr),
		OUTPUT(handle, wsum),
		OUTPUT(handle, best_Tf),
		OUTPUT(handle, status)
		);

	err = fprintf(handle->matout_fd, "%s", buf);
	if (err < 0)
		verbose(LOG_ERR, "Failed to write data to matlab file");

	JDEBUG_MEMORY(JDBG_FREE, buf);
	free(buf);
}

