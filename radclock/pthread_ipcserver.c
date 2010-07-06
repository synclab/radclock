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



#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <errno.h>

#include "../config.h"
#include "radclock.h"
#include "radclock-private.h"
#include "verbose.h"
#include "sync_algo.h"
#include "pthread_mgr.h"
#include "jdebug.h"


/* 
 * Function run by the global data pthread server for IPC 
 */
void* thread_ipc_server(void *c_handle) 
{

	/* Deal with UNIX signal catching */
	init_thread_signal_mgt();

	/* Clock handle to be able to read global data */
	struct radclock *clock_handle;
	clock_handle = (struct radclock*) c_handle;

	/* Exchanged messages */
	struct ipc_request request;
	struct ipc_reply   reply;

	/* UNIX Socket structures */
	unsigned int s_server; 
	struct sockaddr_un sun_server, sun_client;
	socklen_t len;

	/* Socket path to deal with namespace */
	char *socket_path = IPC_SOCKET_SERVER;

	/* Bytes read */
	int n;

	/* Read timeout, otherwise we will block forever and never quit this thread */
	struct timeval so_timeout;

	// XXX TODO FIXME why this umask needed?
	/* Umask for socket file creation */
	umask(000);

	/* Create the socket */
	/* To make things easy, we use SOCK_DGRAM socket.
	 * Probably the best since the protocol of communication is a simple exchange
	 * of messages. No need to fork for connection oriented sockets or use a select()
	 * system call.
	 * If this has to change in the future, the socket API calls have to be modified
	 */
	sun_server.sun_family = AF_UNIX;
	strcpy(sun_server.sun_path, socket_path);
	len = SUN_LEN(&sun_server); // Use this macro to avoid a bug
	s_server = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (s_server == -1) {
		verbose(LOG_ERR, "Socket creation failed. Killing IPC thread");
		pthread_exit(NULL);
	}

	/* Set the receive timeout */
	so_timeout.tv_sec = 0;
	so_timeout.tv_usec = 100000;	/* 1 sec */
	setsockopt(s_server, SOL_SOCKET, SO_RCVTIMEO, (void*)(&so_timeout), sizeof(struct timeval)); 

	/* Let unlink fail silently since we may have quit cleanly before */
	unlink(sun_server.sun_path);

	/* Bind socket */
    if (bind(s_server, (struct sockaddr *)&sun_server, len) == -1 ) {
		verbose(LOG_ERR, "Socket bind() error. Killing IPC thread: %s", strerror(errno));
		pthread_exit(NULL);
	}

	/* Clock socket is fine, register it's descriptor into the clock handle */
	clock_handle->ipc_socket = s_server;

	/* Accept connections from clients.
	 * Process request, and send back  data
	 */
	verbose(LOG_NOTICE, "IPC thread initialised.");
	len = sizeof(sun_client);


	while ( (clock_handle->pthread_flag_stop & PTH_IPC_SERV_STOP) != PTH_IPC_SERV_STOP )
	{
	
		/* Receive the request 
		 * Need a recvfrom() call, since we need to get client return address
		 */
		n = recvfrom(s_server, (void*)(&request), sizeof(struct ipc_request), 0, (struct sockaddr*)&sun_client, &len);
		if (n < 0) {
			/* We timed out, let's start over again */
			continue;	
		}
	
		/* Check received request */	
		if (request.magic_number != IPC_MAGIC_NUMBER) {
			verbose(LOG_WARNING, "IPC thread received something weird from %s", sun_client.sun_path);
			continue;
		}

		/* Create the right answer. 
		 * So far a unique one, but may need more in the future
		 * We lock data to avoid half-valid data (competiion with the sync_algo), remember 
		 * that pthread_mutex_lock() is a blocking function! Should be fine since the data protected
		 * should be updated fairly quickly
		 */
		pthread_mutex_lock(&clock_handle->globaldata_mutex);
		switch (request.request_type) {
			case IPC_REQ_RAD_DATA:
				reply.reply_type 	= IPC_REQ_RAD_DATA;
				reply.rad_data 		= *(RAD_DATA(clock_handle)); 
				break;
			case IPC_REQ_RAD_ERROR:
				reply.reply_type 	= IPC_REQ_RAD_ERROR;
				reply.rad_error 	= *(RAD_ERROR(clock_handle)); 
				break;
			default:
				verbose(LOG_WARNING, "IPC thread received unknown request from %s", sun_client.sun_path);
				pthread_mutex_unlock(&clock_handle->globaldata_mutex);
				continue;
		}
		pthread_mutex_unlock(&clock_handle->globaldata_mutex);

		/* Send data back using the client's address */
		if (sendto(s_server, &reply, sizeof(struct ipc_reply), 0, (struct sockaddr *)&sun_client, len) < 0) {
			verbose(LOG_ERR, "Socket send() error: %s", strerror(errno));
		}
	
		/* Someone told us to die ... sniff */
		if ( clock_handle->ipc_mode == RADCLOCK_IPC_NONE)
			pthread_exit(NULL);
	}

	/* Thread exit */
	verbose(LOG_NOTICE, "Thread IPC server is terminating.");
	pthread_exit(NULL);
}



