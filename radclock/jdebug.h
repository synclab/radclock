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


#ifndef _JDEBUG_H
#define _JDEBUG_H

/* See config.h for symbol definition */

#ifndef PACKAGE_STRING 
#error "From jdebug.h: ../config.h should be included before this file"
#endif



#ifdef WITH_JDEBUG

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#define JDEBUG fprintf(stdout, "%-24s - %-4d | %-25s ENTER\n", __FILE__, __LINE__, __FUNCTION__);

#define JDEBUG_RUSAGE getrusage(RUSAGE_SELF, &jdbg_rusage); \
		fprintf(stdout, "%-24s - %-4d | %-25s maxrss:  %6ld KB | stime: %ld.%ld, utime: %ld.%ld\n",\
		__FILE__, __LINE__, __FUNCTION__,\
		jdbg_rusage.ru_maxrss,\
		(long int)jdbg_rusage.ru_stime.tv_sec, (long int)jdbg_rusage.ru_stime.tv_usec,\
		(long int)jdbg_rusage.ru_utime.tv_sec, (long int)jdbg_rusage.ru_utime.tv_usec);

extern struct rusage jdbg_rusage;


#if defined (__FreeBSD__)
#include <malloc_np.h>
#define JDBG_MALLOC 	1
#define JDBG_FREE 		2

#define JDEBUG_MEMORY(_op, _x) \
	if (_op == JDBG_MALLOC)\
		fprintf(stdout, "%-24s - %-4d | %-25s malloc'd %6ld KB | memory allocated = %8ld Bytes\n",\
			__FILE__, __LINE__, __FUNCTION__,\
			malloc_usable_size(_x), jdbg_memuse+=malloc_usable_size(_x));\
	else \
		fprintf(stdout, "%-24s - %-4d | %-25s free'd   %6ld KB | memory allocated = %8ld Bytes\n",\
			__FILE__, __LINE__, __FUNCTION__,\
			malloc_usable_size(_x), jdbg_memuse-=malloc_usable_size(_x));

extern long int jdbg_memuse;

#else
#define JDEBUG_MEMORY(_op, _x) 
#endif


/* Allow debug-free compilation */
#else
#define JDEBUG
#define JDEBUG_MEMORY(_op, _x) 
#define JDEBUG_RUSAGE
#endif


#endif
