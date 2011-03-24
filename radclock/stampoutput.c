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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <pcap.h>

#include "../config.h"
#include "radclock.h"
#include "verbose.h"
#include "sync_algo.h"
#include "config_mgr.h"
#include "stampoutput.h"
#include "jdebug.h"




int open_output_stamp(struct radclock *clock_handle) 
{
	/* Sometimes, there is nothing to do */
	if (strlen(clock_handle->conf->sync_out_ascii) == 0)
   		return 0;

	/* Test if previous file exists. Rename it if so */
	if ((clock_handle->stampout_fd = fopen(clock_handle->conf->sync_out_ascii, "r"))) {
		fclose(clock_handle->stampout_fd);
		char* backup = (char*) malloc(strlen(clock_handle->conf->sync_out_ascii)+5);
		JDEBUG_MEMORY(JDBG_MALLOC, backup);

		sprintf(backup, "%s.old", clock_handle->conf->sync_out_ascii);
		if (rename(clock_handle->conf->sync_out_ascii, backup) < 0) {
			verbose(LOG_ERR, "Cannot rename existing output file: %s", clock_handle->conf->sync_out_ascii);

			JDEBUG_MEMORY(JDBG_FREE, backup);
			free(backup);
			exit(EXIT_FAILURE);
		}
		verbose(LOG_NOTICE, "Backed up existing output file: %s", clock_handle->conf->sync_out_ascii);
		JDEBUG_MEMORY(JDBG_FREE, backup);
		free(backup);
		clock_handle->stampout_fd = NULL;
	}

	/* Open output file to store input data in preprocessed stamp format */
	if ((clock_handle->stampout_fd = fopen(clock_handle->conf->sync_out_ascii,"w")) == NULL) {
		verbose(LOG_ERR, "Open failed on stamp output file- %s", clock_handle->conf->sync_out_ascii);
		exit(EXIT_FAILURE);
	} 
	else {    // write out comment header describing data saved 
		setvbuf(clock_handle->stampout_fd, (char *)NULL, _IONBF, 0);   // turn off buffering 
		fprintf(clock_handle->stampout_fd, "%% column 1 - Ta [vcount]\n");
		fprintf(clock_handle->stampout_fd, "%% column 2 - Tb [sec]\n");
		fprintf(clock_handle->stampout_fd, "%% column 3 - Te [sec]\n");
		fprintf(clock_handle->stampout_fd, "%% column 4 - Tf [vcount]\n");
		fprintf(clock_handle->stampout_fd, "%% column 5 - OUT src port\n");
	}
	return 0; 
}


void close_output_stamp(struct radclock *clock_handle) 
{
	if (clock_handle->stampout_fd != NULL) 
	{
		fflush(clock_handle->stampout_fd);  
		fclose(clock_handle->stampout_fd);
	}
}




int open_output_matlab(struct radclock *clock_handle) 
{
	/* Sometimes, there is nothing to do */
	if (strlen(clock_handle->conf->clock_out_ascii) == 0)
   		return 0;

	/* Test if previous file exists. Rename it if so */
	if ((clock_handle->matout_fd = fopen(clock_handle->conf->clock_out_ascii, "r"))) {
		fclose(clock_handle->matout_fd);
		char* backup = (char*) malloc(strlen(clock_handle->conf->clock_out_ascii)+5);
		JDEBUG_MEMORY(JDBG_MALLOC, backup);

		sprintf(backup, "%s.old", clock_handle->conf->clock_out_ascii);
		if (rename(clock_handle->conf->clock_out_ascii, backup) < 0) {
			verbose(LOG_ERR, "Cannot rename existing output file: %s", clock_handle->conf->clock_out_ascii);
			JDEBUG_MEMORY(JDBG_FREE, backup);
			free(backup);
			exit(EXIT_FAILURE);
		}
		verbose(LOG_NOTICE, "Backed up existing output file: %s", clock_handle->conf->clock_out_ascii);
		JDEBUG_MEMORY(JDBG_FREE, backup);
		free(backup);
		clock_handle->matout_fd = NULL;
	}


	/* Open output file to store synchronisation algorithm output 
	* (for Matlab, written in process_bidir_stamp) 
	*/     
	if ((clock_handle->matout_fd = fopen(clock_handle->conf->clock_out_ascii,"w")) == NULL) {
		verbose(LOG_ERR, "Open failed on Matlab output file- %s", clock_handle->conf->clock_out_ascii);
		exit(EXIT_FAILURE);
	} 
	else
		setvbuf(clock_handle->matout_fd, (char *)NULL, _IONBF, 0);   // turn off buffering

	fprintf(clock_handle->matout_fd, "%% NTP packet filtering run with:\n");
	fprintf(clock_handle->matout_fd, "%%\n");
	fprintf(clock_handle->matout_fd, "%% column 1 - Tb \n");
	fprintf(clock_handle->matout_fd, "%% column 2 - Tf \n");
	fprintf(clock_handle->matout_fd, "%% column 3 - RTT\n%% ----------------------------------------\n");
	fprintf(clock_handle->matout_fd, "%% column 4 - phat\n");
	fprintf(clock_handle->matout_fd, "%% column 5 - plocal\n");
	fprintf(clock_handle->matout_fd, "%% column 6 - C\n");
	fprintf(clock_handle->matout_fd, "%% column 7 - thetahat\n%% ----------------------------------------\n");
	fprintf(clock_handle->matout_fd, "%% columns 8--10 - RTThat, RTThat_new, RTThat_sh\n");
	fprintf(clock_handle->matout_fd, "%% columns 11--17 - th_naive, minET, minET_last, RADclockout, RADclockin, errTa, errTf\n");
	fprintf(clock_handle->matout_fd, "%% columns 18--22 - perr, plocalerr, wsum, best_Tf, clock status\n");
	fprintf(clock_handle->matout_fd, "%%\n");

	return 0;
}



void close_output_matlab(struct radclock *clock_handle) 
{
	if (clock_handle->matout_fd != NULL) {
		fflush(clock_handle->matout_fd); 
		fclose(clock_handle->matout_fd); 
	}
}



#define OUTPUT(clock, x) ((struct bidir_output*)clock->algo_output)->x
void print_out_files(struct radclock *clock_handle, struct stamp_t *stamp) 
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

	currtime_out = (long double)(BST(stamp)->Ta * OUTPUT(clock_handle, phat)) + OUTPUT(clock_handle, C);
	currtime_in  = (long double)(BST(stamp)->Tf * OUTPUT(clock_handle, phat)) + OUTPUT(clock_handle, C);

	/* Store generated stamp values */
	if (clock_handle->stampout_fd != NULL) { 
		err = fprintf(clock_handle->stampout_fd,"%"VC_FMT" %.9Lf %.9Lf %"VC_FMT" %d\n",
				BST(stamp)->Ta,
				BST(stamp)->Tb,
				BST(stamp)->Te,
				BST(stamp)->Tf,
				stamp->sPort);
		if ( err < 0 )
			verbose(LOG_ERR, "Failed to write data to timestamp file");
	}
	
	if (clock_handle->matout_fd == NULL)
	{
		return;
	}

	buf = (char *) malloc(500 * sizeof(char));
	JDEBUG_MEMORY(JDBG_MALLOC, buf);

	sprintf(buf, 
		"%.9Lf %"VC_FMT" %"VC_FMT" %.10lg %.10lg %.11Lf %.10lf "
		"%"VC_FMT" %"VC_FMT" %"VC_FMT" %.9lg %.9lg %.9lg %.11Lf "
		"%.11Lf %.10lf %.10lf %.6lg %.6lg %.6lg %"VC_FMT" %u\n",
		BST(stamp)->Tb,
		BST(stamp)->Tf,
		OUTPUT(clock_handle, RTT),
		OUTPUT(clock_handle, phat),
		OUTPUT(clock_handle, plocal),
		OUTPUT(clock_handle, C),
		OUTPUT(clock_handle, thetahat),
		OUTPUT(clock_handle, RTThat),
		OUTPUT(clock_handle, RTThat_new),
		OUTPUT(clock_handle, RTThat_shift),
		OUTPUT(clock_handle, th_naive),
		OUTPUT(clock_handle, minET),
		OUTPUT(clock_handle, minET_last),
		currtime_out,
		currtime_in,
		OUTPUT(clock_handle, errTa),
		OUTPUT(clock_handle, errTf),
		OUTPUT(clock_handle, perr),
		OUTPUT(clock_handle, plocalerr),
		OUTPUT(clock_handle, wsum),
		OUTPUT(clock_handle, best_Tf),
		OUTPUT(clock_handle, status)
		);
 
    err = fprintf(clock_handle->matout_fd, "%s", buf);
	if ( err < 0 )
		verbose(LOG_ERR, "Failed to write data to matlab file");

	JDEBUG_MEMORY(JDBG_FREE, buf);
	free(buf);
}

