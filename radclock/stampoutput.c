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
		fprintf(handle->stampout_fd, "%% column 1 - Ta [vcount]\n");
		fprintf(handle->stampout_fd, "%% column 2 - Tb [sec]\n");
		fprintf(handle->stampout_fd, "%% column 3 - Te [sec]\n");
		fprintf(handle->stampout_fd, "%% column 4 - Tf [vcount]\n");
		fprintf(handle->stampout_fd, "%% column 5 - OUT src port\n");
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

	fprintf(handle->matout_fd, "%% NTP packet filtering run with:\n");
	fprintf(handle->matout_fd, "%%\n");
	fprintf(handle->matout_fd, "%% column 1 - Tb \n");
	fprintf(handle->matout_fd, "%% column 2 - Tf \n");
	fprintf(handle->matout_fd, "%% column 3 - RTT\n");
	fprintf(handle->matout_fd, "%% column 4 - phat\n");
	fprintf(handle->matout_fd, "%% column 5 - plocal\n");
	fprintf(handle->matout_fd, "%% column 6 - C\n");
	fprintf(handle->matout_fd, "%% column 7 - thetahat\n");
	fprintf(handle->matout_fd, "%% columns 8--10 - RTThat, RTThat_new,"
			"RTThat_sh\n");
	fprintf(handle->matout_fd, "%% columns 11--17 - th_naive, minET, minET_last,"
			" RADclockout, RADclockin, errTa, errTf\n");
	fprintf(handle->matout_fd, "%% columns 18--22 - perr, plocalerr, wsum, "
			"best_Tf, clock status\n");
	fprintf(handle->matout_fd, "%%\n");

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
		"%"VC_FMT" %"VC_FMT" %"VC_FMT" %.9lg %.9lg %.9lg %.11Lf "
		"%.11Lf %.10lf %.10lf %.6lg %.6lg %.6lg %"VC_FMT" %u\n",
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

