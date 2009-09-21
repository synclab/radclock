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


#include "../config.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
//#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>

#include <radclock.h>
#include "radclock-private.h"
#include "logger.h"




struct radclock * radclock_create(void)
{
	JDEBUG

	struct radclock *clock = (struct radclock*) malloc(sizeof(struct radclock));
	if (!clock) 
		return NULL;

	/* Default values for the RADclock global data */
	GLOBAL_DATA(clock)->phat 			= 1e-9;
	GLOBAL_DATA(clock)->phat_err 		= 0;
	GLOBAL_DATA(clock)->phat_local 		= 1e-9;
	GLOBAL_DATA(clock)->phat_local_err 	= 0;
	GLOBAL_DATA(clock)->ca 				= 0;
	GLOBAL_DATA(clock)->ca_err 			= 0;
	GLOBAL_DATA(clock)->status 			= STARAD_UNSYNC | STARAD_WARMUP;
	GLOBAL_DATA(clock)->last_changed 	= 0;
	GLOBAL_DATA(clock)->valid_till 		= 0;

	/* Default values before calling init */
	clock->is_daemon 			= 0;
	clock->ipc_socket 			= -1;
	clock->ipc_socket_path 		= (char*) malloc(strlen(IPC_SOCKET_CLIENT)+strlen("socket")+20);
	strcpy(clock->ipc_socket_path, "");

	clock->autoupdate_mode 		= RADCLOCK_UPDATE_AUTO;
	clock->local_period_mode 	= RADCLOCK_LOCAL_PERIOD_ON;
	clock->run_mode 			= RADCLOCK_RUN_NOTSET;
	clock->ipc_mode 			= RADCLOCK_IPC_CLIENT;

	/* Network Protocol related stuff */
	clock->client_data 	= NULL;
	clock->server_data 	= NULL;

	/* Syscall */
	clock->syscall_get_vcounter = 0;
	clock->syscall_get_vcounter_latency = 0;

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

	/* Raw data buffer */
	clock->rdb_start 	= NULL;
	clock->rdb_end 		= NULL;

	clock->conf 	= NULL;

	clock->syncalgo_mode 	= RADCLOCK_BIDIR;
	clock->algo_output 	= NULL;

	clock->stamp_source = NULL;

	return clock;
}




/*
 * Should open a socket for the client when using IPC communication
 * The socket is configure to block until its timeout expires. This should limit
 * blocking on the call for updating the clock handle on the client side.
 * There is no perfect value for the timeout however. If one wants to capture packets
 * at high speed, it may be worth implementing an independant thread on the client as
 * well. So far, easy solution as been chosen.
 */
int radclock_IPC_client_connect(struct radclock* clock_handle) 
{
	int s_client, len, desc;
	struct sockaddr_un sun_server;
	struct sockaddr_un sun_client;
	char* client_socket_path;
	struct timeval so_timeout;


	/* Function called for the creation of the socket or after we lost connection
	 * to the radclock daemon.
	 * Let's do some cleaning before trying to reconnect
	 */
	if (clock_handle->ipc_socket >= 0)
	{
		close(clock_handle->ipc_socket);	
		clock_handle->ipc_socket = -1;
		if(unlink(clock_handle->ipc_socket_path) < 0)
			logger(RADLOG_ERR, "Cleaning IPC socket Unlink: %s", strerror(errno));
	}

	/* Need to create a socket path. Array should be big enough for all cases */
	client_socket_path = (char*) malloc(strlen(IPC_SOCKET_CLIENT)+strlen("socket")+20);
#if defined(HAVE_MKSTEMPS)
	sprintf(client_socket_path, "%s.XXXXXXXXXX.socket", IPC_SOCKET_CLIENT);
	desc = mkstemps(client_socket_path, strlen(".socket"));	
#elif  defined(HAVE_MKSTEMP)
	sprintf(client_socket_path, "%s-socket.XXXXXX", IPC_SOCKET_CLIENT);
	desc = mkstemp(client_socket_path);	
#else
# error need either mkstemps or mkstemp
#endif
	close(desc);
	if(unlink(client_socket_path) < 0)
		logger(RADLOG_ERR, "Unlink: %s", strerror(errno));
	strcpy(sun_client.sun_path, client_socket_path);
	strcpy(clock_handle->ipc_socket_path, client_socket_path);	
	free(client_socket_path);


	/* The well-known server socket */
	sun_server.sun_family = AF_UNIX;
	strcpy(sun_server.sun_path, IPC_SOCKET_SERVER);

	/* Our socket family */
	sun_client.sun_family = AF_UNIX;


	if ((s_client = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
		logger(RADLOG_ERR, "Socket() call failed: %s", strerror(errno));
		return 1;
	}

	/* Set a timeout on the recv side to avoid blocking for lost packets */
	so_timeout.tv_sec = 0;
	so_timeout.tv_usec = 25000;	/* 25 ms, should be more than enough */
	setsockopt(s_client, SOL_SOCKET, SO_RCVTIMEO, (void*)(&so_timeout), sizeof(struct timeval)); 

	/* Need to bind the datagram socket, otherwise the server does not 
	 * get a reply address 
	 */ 
	if (bind(s_client, (struct sockaddr *)&sun_client, sizeof(sun_client)) < 0) {
		logger(RADLOG_ERR, "Socket bind failed: %s", strerror(errno));
		close(s_client);
	}

	len = SUN_LEN(&sun_server);
	if (connect(s_client, (struct sockaddr *)&sun_server, len) == -1) {
		logger(RADLOG_ERR, "Socket connect failed: %s", strerror(errno));
		return 1;
	}

	/* Reord socket descriptor for future communication, do it in here after 
	 * everything else has been successful
	 * */
	clock_handle->ipc_socket = s_client;

	return 0;
}



int set_clock_run_mode(struct radclock *handle) 
{
	radclock_runmode_t have_kernel_support;

	switch (handle->run_mode) 
	{
		case RADCLOCK_RUN_NOTSET:
			handle->run_mode = RADCLOCK_RUN_NOTSET;
			break;

		case RADCLOCK_RUN_DEAD:
			handle->run_mode = RADCLOCK_RUN_DEAD;
			break;

		case RADCLOCK_RUN_KERNEL:
			have_kernel_support = radclock_detect_support();
			if (have_kernel_support == RADCLOCK_RUN_KERNEL)
				handle->run_mode = RADCLOCK_RUN_KERNEL;
			else
				handle->run_mode = RADCLOCK_RUN_NOTSET;
			break;

		default:
			/* Unknown mode ... pb */
			logger(RADLOG_ERR, "The mode passed to init the radclock does not exist");
			return -1;
	}
	return 0;
}



// TODO: All of this is a bit ugly, could be written in a cleaner way, there is
// a bit of overlap in the meaning of run_mode and ipc_mode 
// TODO: most of this code should be taken out of the library
int radclock_init(struct radclock *clock_handle) 
{
	JDEBUG

		/* Few branching to depending we are: 
		 * - (1) a client process, 
		 * - (2) the radclock algo serving data, 
		 * - (3) the radclock NOT serving data
		 */
		int err = 0;
	if (clock_handle == NULL) {
		logger(RADLOG_ERR, "The clock handle is NULL and can't be initialised");
		return -1;
	}

	err = radclock_init_vcounter_syscall(clock_handle);
	if ( err < 0 )
		return -1;

	err = set_clock_run_mode(clock_handle);
	if (err < 0)
		return -1;

	switch ( clock_handle->ipc_mode) 
	{
		/* If we are a client we only need to connect to the server socket */
		case RADCLOCK_IPC_CLIENT:
			err = radclock_IPC_client_connect(clock_handle);
			if ( err )
				return -1;
			break;

			/* We are a radclock daemon and we are asked to serve data. Need to
			 * init some kernel related data structure.
			 */
		case RADCLOCK_IPC_NONE:
		case RADCLOCK_IPC_SERVER:

			switch (clock_handle->run_mode) {

				case RADCLOCK_RUN_NOTSET:
					logger(RADLOG_ERR, "No kernel support for the radclock, exiting");
					err = -1;
					break;

				case RADCLOCK_RUN_DEAD:
					/* We don't want to open a socket in this case to access shared
					 * global data. The RADCLOCK_UPDATE_NEVER mode prevent the code
					 * trying to access such shared resource.
					 */ 
					logger(RADLOG_NOTICE, "Initialise replay mode for the RADclock");
					radclock_autoupdate_t automode = RADCLOCK_UPDATE_NEVER;
					radclock_set_autoupdate(clock_handle, &automode);
					break;

				case RADCLOCK_RUN_KERNEL:
					logger(RADLOG_NOTICE, "Initialise kernel level support for the RADclock");
					err = radclock_init_kernelclock(clock_handle);
					break;

				default:
					return -1;
			}

			if (err < 0)
				return -1;

			break;

			/* Should never go here */
		default:
			logger(RADLOG_ERR, "Got something really wrong, unknown IPC run mode");
			return -1;
	}
	return 0;
}


void radclock_destroy(struct radclock *handle) 
{
	/* Close the IPC socket */
	if (handle->ipc_socket > 0)
		close(handle->ipc_socket);

	/* Clear thread stuff */
	pthread_mutex_destroy(&(handle->globaldata_mutex));
	pthread_mutex_destroy(&(handle->wakeup_mutex));
	pthread_cond_destroy(&(handle->wakeup_cond));

	/* Free the clock and set to NULL, useful for partner software */
	free(handle);
	handle = NULL;
}




/* Read global clock data 
 * This should be called by processes else than the radclock_algo
 */
int radclock_read_IPCclock(struct radclock *handle)
{
	int max_retries =1; /* set to the number of times to retry on EAGAIN */
	int valid_message=0;
	int n;

	/* Exchanged messages */
	struct ipc_request request;
	struct ipc_reply   reply;

	/* Forge the request */
	request.magic_number = IPC_MAGIC_NUMBER;
	request.request_type = IPC_REQ_GLOBALDATA;

	/* Send request
	 * The SOCK_DGRAM socket has been connected before, so no need to use sendto()
	 * or   recvfrom() this way we don't have to deal with passing the path of 
	 * the server socket
	 */
	if (send(handle->ipc_socket, &request, sizeof(struct ipc_request), 0) < 0) {
		logger(RADLOG_ERR, "Socket send() error. Retrying socket opening");
		close(handle->ipc_socket);
		handle->ipc_socket = 0;
		radclock_IPC_client_connect(handle);
		/* We don't want to block in here, so return and try reading time next time */
		return 1;
	}

	/* Receive reply  */
	/* This got more complicated
 	 * Sometimes we will miss a reply since we will only ever check maxtimes +1 (currently 2)
 	 * So we have to be able to clear the queue at the next call, so now we loop clearing messages
 	 */
	do
	{
		n = recv(handle->ipc_socket, (void*)(&reply), sizeof(struct ipc_reply), MSG_DONTWAIT);
		//if we haven't received a message, yeild to let the server send one!
		max_retries--;
		if (!valid_message && n < 0) {
			sched_yield();
		}
		else if ( n <0)
			continue;
		else if ( reply.reply_type != IPC_REQ_GLOBALDATA ) {
			logger(RADLOG_ERR, "Received weird message from radclock_algo process");
		}
		else
		{
			valid_message = 1;
			/* Update Global data */
			*(GLOBAL_DATA(handle)) = reply.rad_data;
		}
	} while(n >0 || (errno == EAGAIN && max_retries >0));

	/* Check reply */

	return valid_message ? 0 : 1;
}



int radclock_check_outdated(struct radclock* handle)
{
	int err;
	vcounter_t vcount;
	vcounter_t valid_till;
	radclock_autoupdate_t update_mode;

	/* If we are the RADclock daemon, all this is useless and should actually
	 * not been done at all
	 */
	if ( 	(handle->ipc_mode == RADCLOCK_IPC_SERVER) 
		||  (handle->ipc_mode == RADCLOCK_IPC_NONE) )
	{
		return 0;
	}


	err = radclock_get_autoupdate(handle, &update_mode);
	if ( err )  { return 1; }

	valid_till = GLOBAL_DATA(handle)->valid_till;
	
	// Check if we need to read the clock parameters from the kernel	
	switch (update_mode) {

		case RADCLOCK_UPDATE_AUTO:
			if ( err )  { return 1; }
			err = radclock_get_vcounter(handle, &vcount);
			if ( vcount < valid_till )
				break;
			// else: Too old data, fall back in RADCLOCK_UPDATE_ALWAYS

		case RADCLOCK_UPDATE_ALWAYS:
			// Update the local copy of the clock
			err = radclock_read_IPCclock(handle);
			if ( err < 0 )  { return 1; }
			break;

		case RADCLOCK_UPDATE_NEVER:
			goto exit;
			break;

		default:
			// Unknown mode, should never happen with checks in set_autoupdate.
			return 1;
	}

exit:
	return 0;
}	


