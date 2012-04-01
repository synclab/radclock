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
#include <pthread.h>
#include "radclock-private.h"
#include "pthread_mgr.h"

extern struct radclock *clock_handle;

static inline char *
pthread_id()
{
	pthread_t pth_id;
	pth_id = pthread_self();

	if (clock_handle->threads[PTH_DATA_PROC] == pth_id)
	   return "Thread DATA";	
	if (clock_handle->threads[PTH_TRIGGER] == pth_id)
	   return "Thread TRIG";	
	if (clock_handle->threads[PTH_FIXEDPOINT] == pth_id)
	   return "Thread FXPT";	
	if (clock_handle->threads[PTH_NTP_SERV] == pth_id)
	   return "Thread NTP ";	
	return "Thread MAIN";
}


#define JDEBUG fprintf(stdout, "%s | %-24s - %-4d - %-25s | ENTER\n", pthread_id(), __FILE__, __LINE__, __FUNCTION__);

#define JDEBUG_STR(_format, ...)  fprintf(stdout, "%s | %-24s - %-4d - %-25s | "_format"\n", pthread_id(), __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__);

#define JDEBUG_RUSAGE getrusage(RUSAGE_SELF, &jdbg_rusage); \
		fprintf(stdout, "%s | %-24s - %-4d - %-25s | USAGE  maxrss:  %6ld KB | stime: %ld.%ld, utime: %ld.%ld\n",\
		pthread_id(), __FILE__, __LINE__, __FUNCTION__,\
		(long int)jdbg_rusage.ru_maxrss,\
		(long int)jdbg_rusage.ru_stime.tv_sec, (long int)jdbg_rusage.ru_stime.tv_usec,\
		(long int)jdbg_rusage.ru_utime.tv_sec, (long int)jdbg_rusage.ru_utime.tv_usec);

extern struct rusage jdbg_rusage;


#define JDBG_MALLOC 	1
#define JDBG_FREE 		2
extern long int jdbg_memuse;

#if defined (__FreeBSD__)
#include <malloc_np.h>

#define JDEBUG_MEMORY(_op, _x) \
	if (_op == JDBG_MALLOC)\
		fprintf(stdout, "%s | %-24s - %-4d - %-25s | MALLOC %6ld KB | memory allocated = %8ld Bytes\n",\
			pthread_id(), __FILE__, __LINE__, __FUNCTION__,\
			(long int)malloc_usable_size(_x), jdbg_memuse+=malloc_usable_size(_x));\
	else \
		fprintf(stdout, "%s | %-24s - %-4d - %-25s | FREE   %6ld KB | memory allocated = %8ld Bytes\n",\
			pthread_id(), __FILE__, __LINE__, __FUNCTION__,\
			(long int)malloc_usable_size(_x), jdbg_memuse-=malloc_usable_size(_x));

#else
#define JDEBUG_MEMORY(_op, _x) \
	if (_op == JDBG_MALLOC)\
		fprintf(stdout, "%s | %-24s - %-4d - %-25s | MALLOC %6u KB | memory allocated = %8ld Bytes\n",\
			pthread_id(), __FILE__, __LINE__, __FUNCTION__,\
			sizeof(_x), jdbg_memuse+=sizeof(_x));\
	else \
		fprintf(stdout, "%s | %-24s - %-4d - %-25s | FREE   %6u KB | memory allocated = %8ld Bytes\n",\
			pthread_id(), __FILE__, __LINE__, __FUNCTION__,\
			sizeof(_x), jdbg_memuse-=sizeof(_x));
#endif


/* Allow debug-free compilation */
#else
#define JDEBUG
#define JDEBUG_STR(_format, ...)
#define JDEBUG_MEMORY(_op, _x) 
#define JDEBUG_RUSAGE
#endif


#endif
