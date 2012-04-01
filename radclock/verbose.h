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

#ifndef _VERBOSE_H
#define _VERBOSE_H


#define DAEMON_LOG_FILE	"/var/log/radclock.log"
#define BIN_LOG_FILE	"radclock.log"


/** Here are the values we can use for the syslog. Guess that is standard values
 * LOG_EMERG		0
 * LOG_ALERT 		1
 * LOG_ERR 			3
 * LOG_WARNING 		4
 * LOG_NOTICE		5 
*/

/* These are algo related */
#define VERB_DEFAULT	10
#define VERB_QUALITY	11
#define VERB_CAUSALITY	12
#define VERB_SANITY		13
#define VERB_CONTROL	14
#define VERB_SYNC		15
#define VERB_DEBUG		20	


struct verbose_data_t {
	struct radclock_handle *handle;
	int is_daemon;
	int is_initialized;
	int verbose_level;
	char logfile[250];
	FILE* fd;
	pthread_mutex_t vmutex;
};


extern struct verbose_data_t verbose_data;

extern void verbose(int facility, const char* format, ...); 

extern void set_verbose(struct radclock_handle *handle, int verbose_level, int initialized);
extern void unset_verbose();
extern int get_verbose_level();
/* Short cut */
#define VERB_LEVEL get_verbose_level()


#endif  /* _VERBOSE_H */
