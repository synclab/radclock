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




struct radclock * radclock_create(void)
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
/*
	clock->ipc_socket 			= -1;
	clock->ipc_socket_path 		= (char*) malloc(strlen(IPC_SOCKET_CLIENT)+strlen("socket")+20);
	strcpy(clock->ipc_socket_path, "");
*/

	clock->autoupdate_mode 		= RADCLOCK_UPDATE_AUTO;
	clock->local_period_mode 	= RADCLOCK_LOCAL_PERIOD_ON;
	clock->run_mode 			= RADCLOCK_SYNC_NOTSET;
/*
	clock->ipc_mode 			= RADCLOCK_IPC_CLIENT;
	clock->ipc_requests			= 0;
*/
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
		return (1);
	}

	return 0;
}



// TODO Nuke this one when IPC is relying on SHM only. 
/*
 * Should open a socket for the client when using IPC communication
 * The socket is configure to block until its timeout expires. This should limit
 * blocking on the call for updating the clock handle on the client side.
 * There is no perfect value for the timeout however. If one wants to capture packets
 * at high speed, it may be worth implementing an independant thread on the client as
 * well. So far, easy solution as been chosen.
 */
//
//int radclock_IPC_client_connect(struct radclock* clock_handle) 
//{
//	int s_client, len, desc;
//	struct sockaddr_un sun_server;
//	struct sockaddr_un sun_client;
//	char* client_socket_path;
//	struct timeval so_timeout;
//
//
//	/* Function called for the creation of the socket or after we lost connection
//	 * to the radclock daemon.
//	 * Let's do some cleaning before trying to reconnect
//	 */
//	if (clock_handle->ipc_socket >= 0)
//	{
//		close(clock_handle->ipc_socket);	
//		clock_handle->ipc_socket = -1;
//		if(unlink(clock_handle->ipc_socket_path) < 0)
//			logger(RADLOG_ERR, "Cleaning IPC socket Unlink: %s", strerror(errno));
//	}
//
//	/* Need to create a socket path. Array should be big enough for all cases */
//	client_socket_path = (char*) malloc(strlen(IPC_SOCKET_CLIENT)+strlen("socket")+20);
//#if defined(HAVE_MKSTEMPS)
//	sprintf(client_socket_path, "%s.XXXXXXXXXX.socket", IPC_SOCKET_CLIENT);
//	desc = mkstemps(client_socket_path, strlen(".socket"));	
//#elif  defined(HAVE_MKSTEMP)
//	sprintf(client_socket_path, "%s-socket.XXXXXX", IPC_SOCKET_CLIENT);
//	desc = mkstemp(client_socket_path);	
//#else
//# error need either mkstemps or mkstemp
//#endif
//	close(desc);
//	if(unlink(client_socket_path) < 0)
//		logger(RADLOG_ERR, "Unlink: %s", strerror(errno));
//	strcpy(sun_client.sun_path, client_socket_path);
//	strcpy(clock_handle->ipc_socket_path, client_socket_path);	
//	free(client_socket_path);
//
//
//	/* The well-known server socket */
//	sun_server.sun_family = AF_UNIX;
//	strcpy(sun_server.sun_path, IPC_SOCKET_SERVER);
//
//	/* Our socket family */
//	sun_client.sun_family = AF_UNIX;
//
//
//	if ((s_client = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
//		logger(RADLOG_ERR, "Socket() call failed: %s", strerror(errno));
//		return 1;
//	}
//
//	/* Set a timeout on the recv side to avoid blocking for lost packets */
//	so_timeout.tv_sec = 0;
//	so_timeout.tv_usec = 10000;	/* 10 ms, should be more than enough */
//	setsockopt(s_client, SOL_SOCKET, SO_RCVTIMEO, (void*)(&so_timeout), sizeof(struct timeval)); 
//
//	/* Need to bind the datagram socket, otherwise the server does not 
//	 * get a reply address 
//	 */ 
//	if (bind(s_client, (struct sockaddr *)&sun_client, sizeof(sun_client)) < 0) {
//		logger(RADLOG_ERR, "Socket bind failed: %s", strerror(errno));
//		close(s_client);
//	}
//
//	len = SUN_LEN(&sun_server);
//	if (connect(s_client, (struct sockaddr *)&sun_server, len) == -1) {
//		logger(RADLOG_ERR, "Socket connect failed: %s", strerror(errno));
//		return 1;
//	}
//
//	/* Reord socket descriptor for future communication, do it in here after 
//	 * everything else has been successful
//	 * */
//	clock_handle->ipc_socket = s_client;
//
//	return 0;
//}


/*
 * Initialise what is common to radclock and other apps that have a clock handle
 */
int radclock_init(struct radclock *clock_handle) 
{
	/* Few branching to depending we are: 
	 * - (1) a client process, 
	 * - (2) the radclock algo serving data, 
	 * - (3) the radclock NOT serving data
	 */
	int err;

	if (clock_handle == NULL) {
		logger(RADLOG_ERR, "The clock handle is NULL and can't be initialised");
		return -1;
	}

	/* Make sure we have detected the version of the kernel we are running on */
	clock_handle->kernel_version = found_ffwd_kernel_version();
	
	/*
	 * Attempt to retrieve some slightly better clock estimates from the kernel.
	 * If successful, this overwrites the naive default set by radclock_create.
	 * This is common to the radclock sync algo and any 3rd party application.
	 * This feature has been introduced in kernel version 2.
	 */
	err = 0;
	if (clock_handle->kernel_version >= 2)
		err = get_kernel_ffclock(clock_handle);
	if (err < 0) {
		logger(RADLOG_ERR, "Did not get initial ffclock data from kernel");
		return -1;
	}

	err = radclock_init_vcounter_syscall(clock_handle);
	if ( err < 0 )
		return -1;

	err = radclock_init_vcounter(clock_handle);
	if ( err < 0 )
		return -1;

	/*
	 * Libradclock only
	 */
	if (clock_handle->run_mode == RADCLOCK_SYNC_NOTSET) {
			err = init_shm_reader(clock_handle);
			if (err)
				return (-1);
	}	

//	if (clock_handle->ipc_mode == RADCLOCK_IPC_CLIENT) {
//		case RADCLOCK_IPC_CLIENT:
//			err = init_shm_reader(clock_handle);
//			if (err)
//				return (-1);
/*			clock_handle->ipc_requests = 0;
			err = radclock_IPC_client_connect(clock_handle);
			if ( err )
				return -1;
			break;
*/
			/* We are a radclock daemon and we are asked to serve data. Need to
			 * init some kernel related data structure.
			 */
/*
		case RADCLOCK_IPC_NONE:
		case RADCLOCK_IPC_SERVER:
			return 0;
		default:
			logger(RADLOG_ERR, "Got something really wrong, unknown IPC run mode");
			return -1;
	}
*/

	return 0;
}


void radclock_destroy(struct radclock *handle) 
{

// TODO all this IPC thing should go.

	/* Close the IPC socket */
/*
	if (handle->ipc_socket > 0)
		close(handle->ipc_socket);
*/
	/* Remove client socket file */
/*
	if ( strlen(handle->ipc_socket_path) > 0 )
	{
		if ( unlink(handle->ipc_socket_path) < 0 )
			logger(RADLOG_ERR, "Cleaning IPC socket Unlink: %s", strerror(errno));
	}
*/
	/* Detach IPC shared memory */
	shmdt(handle->ipc_shm);

	/* Free the clock and set to NULL, useful for partner software */
	free(handle);
	handle = NULL;
}




// TODO Nuke this one when IPC is relying on SHM only. 
/* Read global clock data 
 * This should be called by processes else than the radclock_algo
 */
//int radclock_read_IPCclock(struct radclock *handle, int req_type)
//{
//	int max_retries 	= 5; /* set to the number of times to retry on EAGAIN */
//	int valid_message 	= 0;
//	int n;
//
//	/* Exchanged messages */
//	struct ipc_request request;
//	struct ipc_reply   reply;
//
//	/* Forge the request */
//	request.magic_number = IPC_MAGIC_NUMBER;
//	request.request_type = req_type;
//
//	/* Send request
//	 * The SOCK_DGRAM socket has been connected before, so no need to use sendto()
//	 * or   recvfrom() this way we don't have to deal with passing the path of 
//	 * the server socket
//	 */
//	if (send(handle->ipc_socket, &request, sizeof(struct ipc_request), 0) < 0) {
//		logger(RADLOG_ERR, "Socket send() error. Retrying socket opening");
//		close(handle->ipc_socket);
//		handle->ipc_socket = 0;
//		radclock_IPC_client_connect(handle);
//		/* We don't want to block in here, so return and try reading time next time */
//		return 1;
//	}
//
//	/* Receive reply  */
//	/* This got more complicated
// 	 * Sometimes we will miss a reply since we will only ever check maxtimes +1 (currently 2)
// 	 * So we have to be able to clear the queue at the next call, so now we loop clearing messages
// 	 */
//	do
//	{
//		/* We have not yet received a valid message, recv with a timeout */
//		if(!valid_message){ 
//
//			n = recv(handle->ipc_socket, (void*)(&reply), sizeof(struct ipc_reply), 0);
//		
//		/* We have received a valid message, clear the buffer quickly (no timeout) */
//		} else {
//			
//			n = recv(handle->ipc_socket, (void*)(&reply), sizeof(struct ipc_reply), MSG_DONTWAIT);
//		
//		}
//
//		/* if we haven't received a message, yeild to let the server send one! */
//		if (!valid_message && n < 0) {
//		
//			sched_yield();
//		
//		/* If we fall into this case, we have received a valid  message, and the read buffer is empty, work done, time to leave. */
//		} else if (valid_message && n < 0){
//			
//			break;	
//
//		/* A very basic check that we might have the correct data */
//		} else if( n == sizeof(struct ipc_reply) && reply.reply_type == req_type){
//
//			valid_message = 1;
//
//			/* Update requested data */
//			switch (reply.reply_type)
//			{
//				case IPC_REQ_RAD_DATA:
//					*(RAD_DATA(handle)) = reply.rad_data;
//					break;
//				case IPC_REQ_RAD_ERROR:
//					*(RAD_ERROR(handle)) = reply.rad_error;
//					break;
//				default:
//					logger(RADLOG_ERR, "Received weird message from radclock_algo process");
//					break;
//			}
//		}
//
//	} while(n > 0 || (max_retries-- > 0));
//	/* Check reply */
//
//	return valid_message ? 0 : 1;
//}


// TODO Nuke this one when IPC is relying on SHM only. 
// But may be kept a little bit for historic reason
//int radclock_check_outdated(struct radclock* handle, vcounter_t *vc, int req_type)
//{
//	int err;
//	vcounter_t now;
//	vcounter_t valid_till;
//	vcounter_t last_changed;
//	radclock_autoupdate_t update_mode;
//
//	/* If we are the RADclock daemon, all this is useless and should actually
//	 * not been done at all
//	 */
//	if ( 	(handle->ipc_mode == RADCLOCK_IPC_SERVER) 
//		||  (handle->ipc_mode == RADCLOCK_IPC_NONE) )
//	{
//		return 0;
//	}
//
//	if ( radclock_get_autoupdate(handle, &update_mode) )
//		return 1;
//
//	valid_till = RAD_DATA(handle)->valid_till;
//	last_changed = RAD_DATA(handle)->last_changed;
//	
//	// Check if we need to read the clock parameters from the kernel	
//	switch (update_mode)
//	{
//		case RADCLOCK_UPDATE_AUTO:
//			if ( !vc )
//			{
//				/* Some API functions just need to get the clock params and do
//				 * not provide a vcounter
//				 */	
//				if ( radclock_get_vcounter(handle, &now) )
//					return 1;
//			}
//			else
//				now = *vc;
//
//			/* If now is within a valid poll period window the clock data is
//		 	 * fine and no need to ask radclock again. If we have exceeded 
//			 * the max number of consecutive requests in the window, then we
//			 * force an update, to make sure the data does not get too stale.
//			 * This is also our catch all case in the worst case scenarion of
//			 *  virtual machine migration.
//			 */ 
//			if ( (last_changed < now) && (now < valid_till) )
//			{
//				if ( handle->ipc_requests < 10 )
//				{
//					handle->ipc_requests++;
//					break;
//				}
//			}
//			// else: Too old data, fall back in RADCLOCK_UPDATE_ALWAYS
//
//		case RADCLOCK_UPDATE_ALWAYS:
//			/* Update the local copy of the clock. This may fail, but the clock
//			 * data may not be that bad. Return an idea of how bad the data is.
//			 * All requests require IPC_REQ_RAD_DATA to succeed. 
//			 */
//			err = radclock_read_IPCclock(handle, IPC_REQ_RAD_DATA);
//			if ( err < 0 )
//			{
//				/* We migrated to a crazy machine and failed the update. */
//				if ( now < last_changed )
//					return 3;
//				/* The data is really old, or we migrated to a crazy machine */
//				if ( ((now - valid_till) * RAD_DATA(handle)->phat) > 1024 )
//					return 3;
//				/* The data is old, but still in SKM_SCALE */
//				if ( now > valid_till )
//					return 2;
//			}
//			/* We manage to get a reply on the IPC channel, but this new one
//			 * failed. This is likely to be a transient error. But last_changed
//			 * and valid_till are recent, so cannot really say anything about
//			 * the quality of the data. Default to worst data quality scenario,
//			 * in case nobody has been requesting this type of request for a
//			 * while.
//			 */
//			if (req_type != IPC_REQ_RAD_DATA)
//			{
//				err = radclock_read_IPCclock(handle, req_type);
//				if ( err < 0 )
//					return 3;
//			}
//			handle->ipc_requests = 0;
//			break;
//
//		case RADCLOCK_UPDATE_NEVER:
//			return 0;
//
//		default:
//			// Unknown mode, should never happen with checks in set_autoupdate.
//			return 1;
//	}
//
//	return 0;
//}	

/*
 * Inspect data to get an idea about the quality.
 * TODO: error codes should be fixed
 * TODO: other stuff to take into account in composing quality estimate? Needed
 * or clock status and clock error take care of it?
 * TODO: massive problem with thread synchronisation ...
 */
int
raddata_quality(vcounter_t now, vcounter_t last, vcounter_t valid, double phat)
{
	/* 
	 * Something really bad is happening:
	 * - counter is going backward (should never happen)
	 * - virtual machine read H/W counter then migrated, things are out of whack
	 * - ...?
	 */
// XXX FIXME XXX THIS IS WRONG
// can read counter, then data updated, then compare ... BOOM!
	if (now < last)
		return 3;

	/*
	 * Several scenarios again:
	 * - the data is really old, clock status should say the same
	 * - virtual machine migrated, but cannot be sure. Mark data as very bad.
	 * TODO hard coded value !Y
	 */
	if (phat * (now - valid) > 1024)
		return 3;

	/* The data is old, but still in SKM_SCALE */
	if (now > valid)
		return 2;

	return 0;
}


