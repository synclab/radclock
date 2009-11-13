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
 * functions for verbosity...
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>

#include "../config.h"
#include "radclock.h"
#include "radclock-private.h"
#include "verbose.h"



// TODO : Implement a callback here 
static struct verbose_data_t {
	struct radclock *clock;
	int is_daemon;
	int verbose_level;
	FILE* logfile;
} verbose_data = { NULL, 0, 0, NULL };


void set_verbose(struct radclock *clock, int is_daemon, int verbose_level) 
{
	JDEBUG
	verbose_data.clock = clock;
	verbose_data.verbose_level = verbose_level;
	verbose_data.is_daemon = is_daemon;
}


void unset_verbose()
{
	JDEBUG
	verbose_data.clock = NULL;
	verbose_data.verbose_level = 0;
	verbose_data.is_daemon = 0;
	fclose(verbose_data.logfile);
	verbose_data.logfile = NULL;
}


int get_verbose_level()
{
	return verbose_data.verbose_level;
}


/* Non daemon exits for now */
static void verb_panic(char * message)
{
	JDEBUG
	if ( verbose_data.is_daemon )
		syslog(LOG_ALERT, "Verb_panic: %s", message);
	else {
		fprintf(stderr, "verbose Panic: %s", message);
		exit(-1);
	}
}

static void verbose_init()
{
	// We got the string, let's output in the log files
	if ( verbose_data.is_daemon )
		verbose_data.logfile = fopen(DAEMON_LOG_FILE, "a");
	else
		verbose_data.logfile = fopen(BIN_LOG_FILE, "w");

	if (verbose_data.logfile == NULL) {
		verb_panic("Unable to open the log file\n");
	}
}

char *months[12] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};


void verbose(int facility, char* format, ...) 
{
	JDEBUG
	// Rebuild the entire string from the variable arguments 
	char *str;
	va_list arg;
	char ctime_buf[27]	= "";
	long double currtime;
	time_t currsec;
	struct tm *t;
	
	int n, size = 100;
	char  * customize;
	if (verbose_data.logfile == NULL)
	{
		verbose_init();
	}

	switch(facility) {
		case LOG_ERR:
			customize = "ERROR:     ";
			break;
		case LOG_WARNING:
			customize = "Warning:   ";
			break;
		case LOG_NOTICE:
			customize = "Info:      ";
			break;
		case VERB_QUALITY:
			customize = "Quality:   ";
			break;
		case VERB_CAUSALITY:
			customize = "Causality: ";
			break;
		case VERB_SANITY:
			customize = "Sanity:    ";
			break;
		case VERB_CONTROL:
			customize = "Control:   ";
			break;
		case VERB_SYNC:
			customize = "Sync:      ";
			break;
		case VERB_DEBUG:
			customize = "Debug:     ";
			break;
		case VERB_DEFAULT:
		default:
			customize = "";
			break;
	}

	str = malloc(size);
	while (1) {
		if (str == NULL) {
			verb_panic("panic - can't alloc for verbose");
			return;
		}
		/* Try to print in the allocated space. */
		va_start(arg, format);
		n = vsnprintf (str, size, format, arg);
		va_end(arg);
		/* If that worked, return the string. */
		if (n > -1 && n < size)
			break;
		/* Else try again with more space. */
		if (n > -1)    /* glibc 2.1 */
			size = n+1; /* precisely what is needed */
		else           /* glibc 2.0 */
			size *= 2;  /* twice the old size */
		str = realloc (str, size);
	}


	/* Retrieve date from RADclock, so cover the case of data replay, with
	 * somewhat consistent timestamps. There is a possibility of discrepancy
	 * between syslog timestamps and log file timestamps. The minute resolution
	 * will hide that in most cases.
	 */
	if ( verbose_data.clock == NULL )
	{
		sprintf(ctime_buf, "-RADclock Init-");
	}
	else	
	{
		radclock_gettimeofday_fp(verbose_data.clock, &currtime);
		/* The cast should 'floor' currtime */
		currsec = (time_t) currtime;      
		t = localtime(&currsec);
		sprintf(ctime_buf, "%s %02d %02d:%02d:%02d", 
				months[t->tm_mon], t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
	}

	
	/* Output messages to the log file, depending on the verbose level */ 
	switch (facility) {	
		case VERB_DEBUG:
			if (verbose_data.verbose_level > 1) 
				fprintf(verbose_data.logfile, "%s: %s%s\n", ctime_buf, customize, str);
			break;

		case VERB_QUALITY:
		case VERB_CAUSALITY:
		case VERB_SANITY:
		case VERB_CONTROL:
		case VERB_SYNC:
		case VERB_DEFAULT:
			if (verbose_data.verbose_level > 0) 
				fprintf(verbose_data.logfile, "%s: %s%s\n", ctime_buf, customize, str);
			break;

		default:
			/* In all other cases output in log file */
			fprintf(verbose_data.logfile, "%s: %s%s\n", ctime_buf, customize, str);
			if ( verbose_data.is_daemon )
				syslog(facility, "%s%s", customize, str);
			else
				fprintf(stderr, "%s: %s%s\n", ctime_buf, customize, str);
			break;
	}

	/* To get to this point logfile and str are non-NULL!)*/
	free(str);
	fflush(verbose_data.logfile);
}
