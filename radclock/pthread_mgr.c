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


#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>

#include "../config.h"
#include <sync_algo.h>
#include <radclock.h>
#include "radclock-private.h"
#include "fixedpoint.h"
#include <verbose.h>
#include <stampoutput.h>

#include "pthread_mgr.h"



void init_thread_signal_mgt() 
{
	/* We just started a new thread and we don't want it to catch any
	 * Unix signal. This would be a bad behavior and would make the 
	 * recvfrom() call return with an error on SIGHUP or SIGTERM for
	 * example. We want the main program to catch signals and do what
	 * it want to deal with threads.
	 * Also it interacts with pcap_breakloop() and prevents it to terminate
	 * (maybe because it is reinitialising the read system call?)
	 * So first thing to do is to block all signals inherited from main.
	 */
	sigset_t block_mask;
	sigfillset(&block_mask);
	pthread_sigmask(SIG_BLOCK, &block_mask, NULL);
}





void* thread_trigger(void *c_handle)
{
	JDEBUG

	int err;

	/* Deal with UNIX signal catching */
	init_thread_signal_mgt();
	
	/* Clock handle to be able to read global data */
	struct radclock *clock_handle;
	clock_handle = (struct radclock*) c_handle;

	/* Initialise the trigger thread.
	 * If this fails, we commit a collective suicide
	 */
	err = trigger_init(clock_handle);
	if (err) {
		clock_handle->pthread_flag_stop = PTH_STOP_ALL; 
	}
	
	while ( (clock_handle->pthread_flag_stop & PTH_TRIGGER_STOP) != PTH_TRIGGER_STOP )
	{
		/* Check if processing thread did grab the lock, we don't want to
		 * lock repeatidly for ever. If we marked data ready to be processed, then
		 * the processing thread has to do his job. We signal again in case the 
		 * processing thread hadn't be listening before (at startup for example), then
		 * we sleep a little and probably get rescheduled.
		 */
		if (clock_handle->wakeup_data_ready == 1) {
			pthread_cond_signal(&clock_handle->wakeup_cond);
			usleep(10);
			continue;
		}

		/* Lock the pthread_mutex we share with the processing thread */
		pthread_mutex_lock(&clock_handle->wakeup_mutex);

		/* Do our job */
		trigger_work(clock_handle);

		/* Raise wakeup_dat_ready flag.
		 * Signal the processing thread, and unlock mutex to give the processing
		 * thread a chance at it. To be sure it grabs the lock we sleep for a
		 * little while ... 
		 */
		clock_handle->wakeup_data_ready = 1;
		pthread_cond_signal(&clock_handle->wakeup_cond);
		pthread_mutex_unlock(&clock_handle->wakeup_mutex);
	}

	/* Thread exit 
	 * In case we pass into the continue statement but then ordered to die, make
	 * sure we release the lock (and maybe silently fail)
	 */
	verbose(LOG_NOTICE, "Thread trigger is terminating.");	
	pthread_exit(NULL);
}





/**
 * Here we only deal with thread synchronisation
 * see process_data() for the real job
 */
void* thread_data_processing(void *c_handle)
{
	JDEBUG

	int err;

	/* Deal with UNIX signal catching */
	init_thread_signal_mgt();
	
	/* Clock handle to be able to read global data */
	struct radclock *clock_handle;
	clock_handle = (struct radclock*) c_handle;

	while ( (clock_handle->pthread_flag_stop & PTH_DATA_PROC_STOP) != PTH_DATA_PROC_STOP )
	{
		/* Block until we acquire the lock first, then release it and wait */
		pthread_mutex_lock(&clock_handle->wakeup_mutex);
	
		/* We may have been waiting for acquiring the lock, but the trigger
		 * thread has been gone dying, so it will never signal again. So we need
		 * to die
		 */
		if ( (clock_handle->pthread_flag_stop & PTH_DATA_PROC_STOP) == PTH_DATA_PROC_STOP )
		{
			pthread_mutex_unlock(&clock_handle->wakeup_mutex);
			break;
		}

		pthread_cond_wait(&clock_handle->wakeup_cond, &clock_handle->wakeup_mutex);

		/* Lower data ready first to make trigger thread block */
		clock_handle->wakeup_data_ready = 0;

		/* Process rawdata until there is something to process */
		do {
			err = process_rawdata(clock_handle);
		} while (!err); 

		pthread_mutex_unlock(&clock_handle->wakeup_mutex);
	}

	/* Thread exit */
	verbose(LOG_NOTICE, "Thread data processing is terminating.");
	pthread_exit(NULL);
}


void* thread_fixedpoint(void *c_handle)
{
	JDEBUG

	/* Deal with UNIX signal catching */
	init_thread_signal_mgt();
	
	/* Clock handle to be able to read global data */
	struct radclock *clock_handle;
	clock_handle = (struct radclock*) c_handle;

	long int mus;

	while ( (clock_handle->pthread_flag_stop & PTH_FIXEDPOINT_STOP) != PTH_FIXEDPOINT_STOP )
	{
		/* How long can we sleep? It depends on the number of bits allocated for a
		 * vcount diff to be sure we don't roll over.
		 * sleep = 2^bitcountll(COUNTERDIFF_MAX) * phat
		 * We want to be sure this is going to work fine, so can divide this period
		 * by 2 or 3 ... Let's say 5.
		 */
		mus = (long int) (COUNTERDIFF_MAX / 5 * 1e6);
		usleep(mus);

		update_kernel_fixed(clock_handle);
		verbose(VERB_DEBUG, "FP thread updated fixedpoint data to kernel.");
	}

	/* Thread exit */
	verbose(LOG_NOTICE, "Thread fixedpoint is terminating.");
	pthread_exit(NULL);
}







int start_thread_IPC_SERV(struct radclock *clock_handle) 
{
	int err;
	verbose(LOG_NOTICE, "Starting IPC thread");
	err = pthread_create(&(clock_handle->threads[PTH_IPC_SERV]), &(clock_handle->thread_attr), thread_ipc_server, (void *)(clock_handle));
	if (err) 
		verbose(LOG_ERR, "pthread_create() returned error number %d", err);
	 return err;
}


int start_thread_NTP_SERV(struct radclock *clock_handle) 
{
	int err;
	verbose(LOG_NOTICE, "Starting NTP server thread");
	err = pthread_create(&(clock_handle->threads[PTH_NTP_SERV]), &(clock_handle->thread_attr), thread_ntp_server, (void *)(clock_handle));
	if (err) 
		verbose(LOG_ERR, "pthread_create() returned error number %d", err);
	 return err;
}


int start_thread_DATA_PROC(struct radclock *clock_handle) 
{
	int err;
	verbose(LOG_NOTICE, "Starting data processing thread");
	err = pthread_create(&(clock_handle->threads[PTH_DATA_PROC]), &(clock_handle->thread_attr), thread_data_processing, (void *)(clock_handle));
	if (err) 
		verbose(LOG_ERR, "pthread_create() returned error number %d", err);
	 return err;
}


int start_thread_TRIGGER(struct radclock *clock_handle) 
{
	int err;
	verbose(LOG_NOTICE, "Starting trigger thread");
	err = pthread_create(&(clock_handle->threads[PTH_TRIGGER]), &(clock_handle->thread_attr), thread_trigger, (void *)(clock_handle));
	if (err) 
		verbose(LOG_ERR, "pthread_create() returned error number %d", err);
	 return err;
}


int start_thread_FIXEDPOINT(struct radclock *clock_handle) 
{
	int err;
	verbose(LOG_NOTICE, "Starting fixedpoint thread");
	err = pthread_create(&(clock_handle->threads[PTH_FIXEDPOINT]), &(clock_handle->thread_attr), thread_fixedpoint, (void *)(clock_handle));
	if (err) 
		verbose(LOG_ERR, "pthread_create() returned error number %d", err);
	 return err;
}

