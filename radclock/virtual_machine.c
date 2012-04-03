/*
 * Copyright (C) 2006-2012, Julien Ridoux <julien@synclab.org>
 * Copyright (C) 2009-2012, Timothy Broomhead <t.broomhead@ugrad.unimelb.edu.au>
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

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "../config.h"
#include "radclock.h"
#include "radclock-private.h"

#include "radclock_daemon.h"
#include "verbose.h"
#include "sync_history.h"
#include "sync_algo.h"
#include "pthread_mgr.h"
#include "config_mgr.h"
#include "jdebug.h"


// Not sure where to put this at the moment or a cleaner way
#define NOXENSUPPORT 0x01


#ifdef WITH_XENSTORE
#include <xs.h>
#define XENSTORE_PATH "/local/radclock"
#endif


#define VM_UDP_PORT		5001

int
init_xen(struct radclock_handle *handle)
{
	JDEBUG
#ifdef WITH_XENSTORE
	struct xs_handle *xs;
	struct xs_permissions perms[1];
	char *domstring;
	int domid;
	unsigned count;
	
	if ((xs = xs_domain_open()) == NULL) {
		return (NOXENSUPPORT);
	}
	domstring = xs_read(xs, XBT_NULL, "domid", &count);
	domid = atoi(domstring);
	free(domstring);

	perms[0].id = domid;
	perms[0].perms = XS_PERM_READ | XS_PERM_WRITE;
	
	if (handle->conf->server_xen == BOOL_ON) {
		verbose(LOG_INFO, "Making initial write to the xenstore");
		xs_write(xs, XBT_NULL, XENSTORE_PATH,
				RAD_DATA(handle),
				sizeof(*RAD_DATA(handle)));

		if (!xs_set_permissions(xs, XBT_NULL, XENSTORE_PATH, perms, 1)) {
			verbose(LOG_ERR,"Could not set permissions for Xenstore");
		}
	}
	if (handle->conf->synchro_type == SYNCTYPE_XEN) {
		// Set up a watch on the xenstore data, so we can block on this later
		xs_watch(xs, XENSTORE_PATH, "radData");
	}

	RAD_VM(handle)->store_handle = (void *) xs;
	return (0);

#else

	// Really this shouldn't happen, but maybe for robustness we should explicitly
	// change mode to none
	return (NOXENSUPPORT);

#endif
}


int
push_data_xen(struct radclock_handle *handle)
{
	JDEBUG
#ifdef WITH_XENSTORE
	struct xs_handle *xs;
	xs = (struct xs_handle *) RAD_VM(handle)->store_handle;
	verbose(LOG_INFO,"Writing data to the xenstore");
	xs_write(xs, XBT_NULL, XENSTORE_PATH,
			RAD_DATA(handle),
			sizeof(*RAD_DATA(handle)));
	return (0);
#else
	return (0);
#endif
}


int
receive_xen(struct radclock_handle *handle)
{
	JDEBUG
#ifdef WITH_XENSTORE
	
	struct xs_handle *xs;
	struct radclock_data *radclock_data_buf;
	unsigned len_read;
	char **vec;
	unsigned int num_strings;

	xs = (struct xs_handle *) RAD_VM(handle)->store_handle;
	vec = xs_read_watch(xs, &num_strings);

	radclock_data_buf = xs_read(xs, XBT_NULL, XENSTORE_PATH, &len_read);

	if (len_read != sizeof(struct radclock_data)) {
		verbose(LOG_ERR,"Data read from Xenstore not same length as RADclock data");
	} else {
		if (RAD_DATA(handle)->last_changed != radclock_data_buf->last_changed) {
			verbose(LOG_NOTICE, "Xenstore updated RADclock data");
		}
		memcpy(RAD_DATA(handle), radclock_data_buf, sizeof(*RAD_DATA(handle)));
	}

	free(radclock_data_buf);

	return (0);
#else
	return (0);
#endif
}


int
init_vm_udp(struct radclock_handle *handle)
{
	int err;

	JDEBUG

	if ((RAD_VM(handle)->sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		verbose(LOG_ERR, "Could not open socket for multicast");
		return (-1);
	}

	RAD_VM(handle)->server_addr.sin_family = AF_INET;
	RAD_VM(handle)->server_addr.sin_port = htons(VM_UDP_PORT);
	bzero(&(RAD_VM(handle)->server_addr.sin_zero),8);

	if (handle->conf->synchro_type == SYNCTYPE_VM_UDP) {

		RAD_VM(handle)->server_addr.sin_addr.s_addr = INADDR_ANY;
		err = bind(RAD_VM(handle)->sock, (struct sockaddr *)
				&(RAD_VM(handle)->server_addr), sizeof(struct sockaddr));
		if (err == -1){
			verbose(LOG_ERR, "Could not bind socket for VM UDP");
			return (-1);
		}
	}

	return (0);
}

int
receive_vm_udp(struct radclock_handle *handle)
{
	unsigned addr_len;
	int bytes_read;
	struct sockaddr_in server_addr;

	/*
	 * Read timeout, otherwise we would block forever and never quit this thread
	 */
	struct timeval so_timeout;

	/* Exchanged messages */
	struct vm_reply   reply;

	JDEBUG

	/* Set the receive timeout */

	//TODO This timeout should be some proportion of the poll period?
	so_timeout.tv_sec = 4;
	so_timeout.tv_usec = 0;

	setsockopt(RAD_VM(handle)->sock, SOL_SOCKET, SO_RCVTIMEO,
			(void*)(&so_timeout), sizeof(struct timeval));

	addr_len = sizeof(struct sockaddr);
	bytes_read = recvfrom(RAD_VM(handle)->sock, (void*)(&reply),
			sizeof(struct vm_reply), 0, (struct sockaddr *)&server_addr,
			&addr_len);
	
	if (bytes_read == 0) {

		// TODO: Here we timed out, maybe we should therefore request the time
		// data?

	} else if (bytes_read != sizeof(struct vm_reply)) {
		verbose(LOG_ERR,"Data read from sock not same length as RADclock reply");
	} else {
		/* Check received request */
		if (reply.magic_number != VM_MAGIC_NUMBER) {
			verbose(LOG_WARNING, "VM UDP received something weird.");
			return (0);
		}

		pthread_mutex_lock(&handle->globaldata_mutex);
		switch (reply.reply_type) {

		case VM_REQ_RAD_DATA:
			if (RAD_DATA(handle)->last_changed != reply.rad_data.last_changed) {
				verbose(LOG_NOTICE, "Multicast updated RADclock data");
				memcpy(RAD_DATA(handle), &(reply.rad_data),
						sizeof(*RAD_DATA(handle)));
			}
			break;
		
		case VM_REQ_RAD_ERROR:
			// TODO: I guess we can implement this if wanted in the future
			break;

		default:
			verbose(LOG_WARNING, "VM server thread received unknown request");
			pthread_mutex_unlock(&handle->globaldata_mutex);
			break;
		}
		pthread_mutex_unlock(&handle->globaldata_mutex);
	}

	return (0);
}


int
push_data_vm_udp(struct radclock_handle *handle)
{
	struct hostent *host;
	JDEBUG

	// TODO Need to read in the list of machines in the file and then send a
	// packet to each of them

	host = (struct hostent *) gethostbyname((char*)"10.0.31.3");
	RAD_VM(handle)->server_addr.sin_addr = *((struct in_addr *)host->h_addr);

	sendto(RAD_VM(handle)->sock, RAD_DATA(handle), sizeof(*RAD_DATA(handle)), 0,
			(struct sockaddr *)&(RAD_VM(handle)->server_addr),
			sizeof(struct sockaddr));

	return (0);
}


int
init_vmware(struct radclock_handle *handle)
{
	JDEBUG

	return (0);
}

int
push_data_vmware(struct radclock_handle *handle)
{
	JDEBUG

	return (0);
}

int
receive_vmware(struct radclock_handle *handle)
{
	JDEBUG

	return (0);
}

// This function is called once during startup
int
init_vm(struct radclock_handle *handle)
{
	int err;

	 err = 0;
	verbose(LOG_INFO, "Setting up virtual machine communication");

	if (handle->conf->synchro_type == SYNCTYPE_XEN ||
			handle->conf->server_xen == BOOL_ON) {
		err = init_xen(handle);
	}

	if (handle->conf->synchro_type == SYNCTYPE_VM_UDP ||
			handle->conf->server_vm_udp == BOOL_ON) {
		err = init_vm_udp(handle);
	}

	return (0);
}


// This function gets call on each clock update
int
push_data_vm(struct radclock_handle *handle)
{
	int err;

	err = 0;

	if (handle->conf->server_xen == BOOL_ON)
		err = push_data_xen(handle);

	if (handle->conf->server_vm_udp == BOOL_ON)
		err = push_data_vm_udp(handle);

	if (handle->conf->server_vmware == BOOL_ON)
		err = push_data_vmware(handle);

	return (0);
}


// This function gets called and should loop & block while waiting for new
// data
int
receive_loop_vm(struct radclock_handle *handle)
{

	while (1) {

		switch (handle->conf->synchro_type) {

		case SYNCTYPE_VM_UDP:
			receive_vm_udp(handle);
			break;

		case SYNCTYPE_XEN:
			receive_xen(handle);
			break;

		case SYNCTYPE_VMWARE:
			receive_vmware(handle);
			break;

		default:
			verbose(LOG_ERR, "Tried to get virtual client data, but not a "
					"known virtual client type.");
			break;
		}
	}

	return (0);
}


void *
thread_vm_udp_server(void *c_handle)
{
	struct radclock_handle *handle;

		/* Exchanged messages */
	struct vm_request request;
	struct vm_reply   reply;
	unsigned len;

	/* Socket */
	int sock;
	struct sockaddr_in my_addr;
	struct sockaddr_in client_addr;

	/* Bytes read */
	int n;
	int err;

	/* Read timeout, otherwise we will block forever and never quit this thread */
	struct timeval so_timeout;

	/* Deal with UNIX signal catching */
	init_thread_signal_mgt();

	/* Clock handle to be able to read global data */
	handle = (struct radclock_handle*) c_handle;

	/* Umask for socket file creation */
	umask(000);

	/* Create the socket */
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(VM_UDP_PORT);
	bzero(my_addr.sin_zero,8);
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		verbose(LOG_ERR, "Socket creation failed. Killing vm server thread");
		pthread_exit(NULL);
	}

	/* Set the receive timeout */
	so_timeout.tv_sec = 1;
	so_timeout.tv_usec = 0;	/* 1 sec */
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (void*)(&so_timeout),
			sizeof(struct timeval));
	my_addr.sin_addr.s_addr = INADDR_ANY;

	/* Bind socket */
    err = bind(sock, (struct sockaddr *)&my_addr, sizeof (struct sockaddr));
    if (err == -1) {
		verbose(LOG_ERR, "Socket bind() error. Killing vm server thread: %s",
				strerror(errno));
		pthread_exit(NULL);
	}

	/* Accept connections from clients.
	 * Process request, and send back  data
	 */
	verbose(LOG_NOTICE, "VM server thread initialised.");
	len = sizeof(struct sockaddr);


	while ((handle->pthread_flag_stop & PTH_VM_UDP_SERV_STOP) !=
			PTH_VM_UDP_SERV_STOP) {

		/* Receive the request
		 * Need a recvfrom() call, since we need to get client return address
		 */
		n = recvfrom(sock, (void*)(&request), sizeof(struct vm_request), 0,
				(struct sockaddr*)&client_addr, &len);
		if (n < 0) {
			/* We timed out, let's start over again */
			continue;
		}
	
		/* Check received request */
		if (request.magic_number != VM_MAGIC_NUMBER) {
			verbose(LOG_WARNING, "VM server thread received something weird.");
			continue;
		}

		verbose(LOG_INFO, "VM server thread received something.");
		/*
		 * Create the right answer.  So far a unique one, but may need more in
		 * the future We lock data to avoid half-valid data (competiion with the
		 * sync_algo), remember that pthread_mutex_lock() is a blocking
		 * function! Should be fine since the data protected should be updated
		 * fairly quickly
		 */
		pthread_mutex_lock(&handle->globaldata_mutex);
		switch (request.request_type) {
		case VM_REQ_RAD_DATA:
			reply.reply_type	= VM_REQ_RAD_DATA;
			reply.rad_data		= *(RAD_DATA(handle));
			break;
		case VM_REQ_RAD_ERROR:
			reply.reply_type	= VM_REQ_RAD_ERROR;
			reply.rad_error		= *(RAD_ERROR(handle));
			break;
		default:
			verbose(LOG_WARNING, "VM server thread received unknown request");
			pthread_mutex_unlock(&handle->globaldata_mutex);
			continue;
		}
		pthread_mutex_unlock(&handle->globaldata_mutex);

		/* Send data back using the client's address */
		sendto(sock, &reply, sizeof(struct vm_reply), 0,
				(struct sockaddr *)&client_addr, len);
		if (err < 0) {
			verbose(LOG_ERR, "VM server Socket send() error: %s", strerror(errno));
		}
	}

	/* Thread exit */
	verbose(LOG_NOTICE, "Thread IPC server is terminating.");
	pthread_exit(NULL);
}

