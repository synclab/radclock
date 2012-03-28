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


#include "../config.h"

#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
//#include <signal.h>
#include <pthread.h>	// TODO create and init to move in radclock code
#include <unistd.h>
#include <string.h>

#include <radclock.h>
#include "radclock-private.h"
#include "logger.h"



// TODO split structure to have a minimal library version, and a radclock daemon
// one. Will really clean up the library code.
struct radclock *
radclock_create(void)
{
	struct radclock *clock = (struct radclock*) malloc(sizeof(struct radclock));
	if (!clock) 
		return NULL;

	/* Default values for the RADclock global data */
	RAD_DATA(clock)->phat 			= 1e-9;
	RAD_DATA(clock)->phat_err 		= 0;
	RAD_DATA(clock)->phat_local 	= 1e-9;
	RAD_DATA(clock)->phat_local_err = 0;
	RAD_DATA(clock)->ca 			= 0;
	RAD_DATA(clock)->ca_err 		= 0;
	RAD_DATA(clock)->status 		= STARAD_UNSYNC | STARAD_WARMUP;
	RAD_DATA(clock)->last_changed 	= 0;
	RAD_DATA(clock)->valid_till 	= 0;

	/* Clock error bound */
	RAD_ERROR(clock)->error_bound 		= 0;
	RAD_ERROR(clock)->error_bound_avg 	= 0;
	RAD_ERROR(clock)->error_bound_std 	= 0;
	RAD_ERROR(clock)->min_RTT 			= 0;
	
	/* Virtual machine stuff */
	RAD_VM(clock)->push_data = NULL; 
	RAD_VM(clock)->pull_data = NULL;

	/* Default values before calling init */
	clock->kernel_version		= -1;
	clock->is_daemon 			= 0;
	clock->local_period_mode 	= RADCLOCK_LOCAL_PERIOD_ON;
	clock->run_mode 			= RADCLOCK_SYNC_NOTSET;
	clock->ipc_shm_id			= 0;
	clock->ipc_shm				= NULL;

	/* Network Protocol related stuff */
	clock->client_data 	= NULL;
	clock->server_data 	= NULL;

	/* Syscall */
	clock->syscall_set_ffclock = 0;
	clock->syscall_get_vcounter = 0;

	/* PCAP */
	clock->pcap_handle 	= NULL;

	clock->stampout_fd 	= NULL;
	clock->matout_fd 	= NULL;

	/* Thread related stuff 
	 * Initialize and set thread detached attribute explicitely
	 */
	clock->pthread_flag_stop = 0;
	clock->wakeup_data_ready = 0;
	pthread_mutex_init(&(clock->globaldata_mutex), NULL);
	pthread_mutex_init(&(clock->wakeup_mutex), NULL);
	pthread_cond_init(&(clock->wakeup_cond), NULL);
	pthread_mutex_init(&(clock->rdb_mutex), NULL);

	/* Raw data buffer */
	clock->rdb_start 	= NULL;
	clock->rdb_end 		= NULL;

	clock->conf 	= NULL;

	clock->syncalgo_mode 	= RADCLOCK_BIDIR;
	clock->algo_output 	= NULL;

	clock->stamp_source = NULL;

	/* vcounter */
	clock->get_vcounter = NULL;

	return clock;
}


/*
 * Initialise shared memory segment.
 * IPC mechanism to access radclock updated clock parameters and error
 * estimates.
 */
int
init_shm_reader(struct radclock *clock)
{
	key_t shm_key;

	logger(RADLOG_ERR, "Enter init_shm_reader");

	shm_key = ftok(IPC_SHARED_MEMORY, 'a');
	if (shm_key == -1) {
		logger(RADLOG_ERR, "ftok: %s", strerror(errno));
		return (1);
	}

	clock->ipc_shm_id = shmget(shm_key, sizeof(struct radclock_shm), 0);
	if (clock->ipc_shm_id < 0) {
		logger(RADLOG_ERR, "shmget: %s", strerror(errno));
		return (1);
	}

	clock->ipc_shm = shmat(clock->ipc_shm_id, NULL, SHM_RDONLY);
	if (clock->ipc_shm == (void *) -1) {
		logger(RADLOG_ERR, "shmat: %s", strerror(errno));
		clock->ipc_shm = NULL;
		return (1);
	}

	return (0);
}



/*
 * Initialise what is common to radclock and other apps that have a clock
 */
int
radclock_init(struct radclock *clock) 
{
	/* Few branching to depending we are: 
	 * - (1) a client process, 
	 * - (2) the radclock algo serving data, 
	 * - (3) the radclock NOT serving data
	 */
	int err;

	if (clock == NULL) {
		logger(RADLOG_ERR, "The clock handle is NULL and can't be initialised");
		return -1;
	}

	/* Make sure we have detected the version of the kernel we are running on */
	clock->kernel_version = found_ffwd_kernel_version();

	err = radclock_init_vcounter_syscall(clock);
	if ( err < 0 )
		return -1;

	err = radclock_init_vcounter(clock);
	if ( err < 0 )
		return (-1);

	/* SHM on library side */
	err = init_shm_reader(clock);
	if (err)
		return (-1);

	return (0);
}


void
radclock_destroy(struct radclock *clock) 
{

	/* Detach IPC shared memory */
	shmdt(clock->ipc_shm);

	/* Free the clock and set to NULL, useful for partner software */
	free(clock);
	clock = NULL;
}



int
radclock_register_pcap(struct radclock *clock, pcap_t *pcap_handle)
{
	if (clock == NULL || pcap_handle == NULL)
		return (1);

	clock->pcap_handle = pcap_handle;
	return (0);
}

