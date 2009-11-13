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


#ifndef _VERBOSE_H
#define _VERBOSE_H

#include "radclock.h"

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


extern int verbose_level;

void verbose(int facility, char* format, ...); 

void set_verbose(struct radclock *clock, int is_daemon, int verbose_level);
void unset_verbose();
int get_verbose_level();
/* Short cut */
#define VERB_LEVEL get_verbose_level()



#endif
