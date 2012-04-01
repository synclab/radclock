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

#include <arpa/inet.h>

#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>

#include "../config.h"
#include "radclock.h"
#include "radclock-private.h"
#include "kclock.h"		// this one can go once fixedpoint thread is removed

#include "radclock_daemon.h"
#include "sync_history.h"
#include "sync_algo.h"
#include "config_mgr.h"
#include "fixedpoint.h"		// this one can go once fixedpoint thread is removed
#include "stampinput.h"
#include "stampoutput.h"
#include "pthread_mgr.h"
#include "verbose.h"
#include "jdebug.h"



void
init_thread_signal_mgt()
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
	sigemptyset(&block_mask);
	pthread_sigmask(SIG_SETMASK, &block_mask, NULL);
}


void *
thread_trigger(void *c_handle)
{
	struct radclock_handle *handle;
	int err;

	JDEBUG

	/* Deal with UNIX signal catching */
	init_thread_signal_mgt();
	
	/* Clock handle to be able to read global data */
	handle = (struct radclock_handle *) c_handle;

	/* Initialise the trigger thread.
	 * If this fails, we commit a collective suicide
	 */
	err = trigger_init(handle);
	if (err)
		handle->pthread_flag_stop = PTH_STOP_ALL;
	
	while ((handle->pthread_flag_stop & PTH_TRIGGER_STOP) != PTH_TRIGGER_STOP) {

		/*
		 * Check if processing thread did grab the lock, we don't want to lock
		 * repeatidly for ever. If we marked data ready to be processed, then
		 * the processing thread has to do his job. We signal again in case the
		 * processing thread hadn't be listening before (at startup for
		 * example), then we sleep a little and probably get rescheduled.
		 */
		if (handle->wakeup_data_ready == 1 && !VM_SLAVE(handle)) {
			pthread_cond_signal(&handle->wakeup_cond);
			usleep(50);
			continue;
		}

		/* Lock the pthread_mutex we share with the processing thread */
		pthread_mutex_lock(&handle->wakeup_mutex);

		/* Do our job */
		trigger_work(handle);

		/* Raise wakeup_dat_ready flag.
		 * Signal the processing thread, and unlock mutex to give the processing
		 * thread a chance at it. To be sure it grabs the lock we sleep for a
		 * little while ...
		 */
		handle->wakeup_data_ready = 1;
		pthread_cond_signal(&handle->wakeup_cond);
		pthread_mutex_unlock(&handle->wakeup_mutex);
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
void *
thread_data_processing(void *c_handle)
{
	struct bidir_peer peer;
	struct radclock_handle *handle;
	int err;

	JDEBUG

	/* Deal with UNIX signal catching */
	init_thread_signal_mgt();
	
	/* Clock handle to be able to read global data */
	handle = (struct radclock_handle *) c_handle;

	/* Init peer stamp counter, everything rely on this starting at 0 */
	init_peer_stamp_queue(&peer);
	peer.stamp_i = 0;
	
	// TODO XXX Need to manage peers better !!
	/* Register active peer */
	handle->active_peer = (void*) &peer;

	while ((handle->pthread_flag_stop & PTH_DATA_PROC_STOP) != PTH_DATA_PROC_STOP)
	{
		/* Block until we acquire the lock first, then release it and wait */
		pthread_mutex_lock(&handle->wakeup_mutex);

		/* Loosely signal this thread did lock the mutex */
		handle->wakeup_data_ready = 0;
	
		/* We may have been waiting for acquiring the lock, but the trigger
		 * thread has been gone dying, so it will never signal again. So we need
		 * to die
		 */
		if ((handle->pthread_flag_stop & PTH_DATA_PROC_STOP) ==
				PTH_DATA_PROC_STOP) {
			pthread_mutex_unlock(&handle->wakeup_mutex);
			break;
		}

		pthread_cond_wait(&handle->wakeup_cond, &handle->wakeup_mutex);

		/* Process rawdata until there is something to process */
		do {
			err = process_rawdata(handle, &peer);
			
			/* Something really bad, get out of here */
			if (err == -1) {
				handle->pthread_flag_stop = PTH_STOP_ALL;
				source_breakloop(handle, (struct stampsource *)handle->stamp_source);
				break;
			}
		} while (err == 0);

		pthread_mutex_unlock(&handle->wakeup_mutex);
	}

	destroy_peer_stamp_queue(&peer);

	/* Thread exit */
	verbose(LOG_NOTICE, "Thread data processing is terminating.");
	pthread_exit(NULL);
}


void *
thread_fixedpoint(void *c_handle)
{
	struct radclock_handle *handle;
	long int mus;

	JDEBUG

	/* Deal with UNIX signal catching */
	init_thread_signal_mgt();
	
	/* Clock handle to be able to read global data */
	handle = (struct radclock_handle *)c_handle;

	while ((handle->pthread_flag_stop & PTH_FIXEDPOINT_STOP) != PTH_FIXEDPOINT_STOP) {
		/* How long can we sleep? It depends on the number of bits allocated for a
		 * vcount diff to be sure we don't roll over.
		 * sleep = 2^bitcountll(COUNTERDIFF_MAX) * phat
		 * We want to be sure this is going to work fine, so can divide this period
		 * by 2 or 3 ... Let's say 5.
		 */
		mus = (long int) (COUNTERDIFF_MAX / 5 * 1e6);
		usleep(mus);

		update_kernel_fixed(handle);
		verbose(VERB_DEBUG, "FP thread updated fixedpoint data to kernel.");
	}

	/* Thread exit */
	verbose(LOG_NOTICE, "Thread fixedpoint is terminating.");
	pthread_exit(NULL);
}


int
start_thread_NTP_SERV(struct radclock_handle *handle)
{
	int err;
	pthread_attr_t thread_attr;
	pthread_attr_init(&thread_attr);
	pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_JOINABLE);

	verbose(LOG_NOTICE, "Starting NTP server thread");
	err = pthread_create(&(handle->threads[PTH_NTP_SERV]), &thread_attr,
			thread_ntp_server, (void *)(handle));
	if (err)
		verbose(LOG_ERR, "pthread_create() returned error number %d", err);
	 return (err);
}


int
start_thread_DATA_PROC(struct radclock_handle *handle)
{
	int err;
	pthread_attr_t thread_attr;
	pthread_attr_init(&thread_attr);
	pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_JOINABLE);

	verbose(LOG_NOTICE, "Starting data processing thread");
	err = pthread_create(&(handle->threads[PTH_DATA_PROC]), &thread_attr,
			thread_data_processing, (void *)(handle));
	if (err)
		verbose(LOG_ERR, "pthread_create() returned error number %d", err);
	 return (err);
}


int start_thread_TRIGGER(struct radclock_handle *handle)
{
	int err;
	pthread_attr_t thread_attr;
	pthread_attr_init(&thread_attr);
	pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_JOINABLE);
	struct sched_param sched;

	/*
	 * Increase the priority of that particular thread to improve the accuracy
	 * of the packet sender
	 */
	err = pthread_attr_getschedparam (&thread_attr, &sched);
	sched.sched_priority = sched_get_priority_max(SCHED_FIFO);
	err = pthread_attr_setschedparam (&thread_attr, &sched);
	
	pthread_attr_setschedpolicy(&thread_attr, SCHED_FIFO);

	verbose(LOG_NOTICE, "Starting trigger thread");
	err = pthread_create(&(handle->threads[PTH_TRIGGER]), &thread_attr,
			thread_trigger, (void *)(handle));
	if (err)
		verbose(LOG_ERR, "pthread_create() returned error number %d", err);
	
	return (err);
}


int start_thread_FIXEDPOINT(struct radclock_handle *handle)
{
	int err;
	pthread_attr_t thread_attr;
	pthread_attr_init(&thread_attr);
	pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_JOINABLE);

	verbose(LOG_NOTICE, "Starting fixedpoint thread");
	err = pthread_create(&(handle->threads[PTH_FIXEDPOINT]), &thread_attr,
			thread_fixedpoint, (void *)(handle));
	if (err)
		verbose(LOG_ERR, "pthread_create() returned error number %d", err);
	 return (err);
}

