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

#include "../config.h"
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef WITH_RADKERNEL_FBSD
#include <sys/sysctl.h>
#endif

#include <netdb.h>

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "radclock.h"
#include "radclock-private.h"
#include "kclock.h"

#include "radclock_daemon.h"
#include "fixedpoint.h"
#include "verbose.h"
#include "sync_history.h"
#include "sync_algo.h"
#include "pthread_mgr.h"
#include "config_mgr.h"
#include "misc.h"
#include "jdebug.h"

// FIXME: only needed for system clock adjustments, this is a quick hack that
// should disappear as soon as possible

#ifdef WITH_RADKERNEL_NONE
int init_vm(struct radclock_handle *handle) { return (-ENOENT); }
int push_data_vm(struct radclock_handle *handle) { return (-ENOENT); }
int receive_loop_vm(struct radclock_handle *handle) { return (-ENOENT); }
void * thread_vm_udp_server(void *c_handle) { return (-ENOENT); }
#else

#include <sys/timex.h>

#ifdef WITH_RADKERNEL_FBSD
#define NTP_ADJTIME(x)	ntp_adjtime(x)
#else
#include <sys/timex.h>
#define NTP_ADJTIME(x)	adjtimex(x)
#endif

/* Make TIME_CONSTANT smaller for faster convergence but keep diff between nano
 * and not nano = 4
 */
#ifdef STA_NANO
#define KERN_RES	1e9
#define TIME_CONSTANT	6
#define TX_MODES	( MOD_OFFSET | MOD_STATUS | MOD_NANO )
#else
#define KERN_RES	1e6
#define TIME_CONSTANT	2
#define TX_MODES	( MOD_OFFSET | MOD_STATUS )
#endif


// Not sure where to put this at the moment or a cleaner way
#define NOXENSUPPORT 0x01


#ifdef WITH_XENSTORE
#include <xs.h>
#define XENSTORE_PATH "/local/radclock"
#endif


#define VM_UDP_PORT		5001

static int
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


static int
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


static int
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


static int
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

static int
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


static int
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


static int
init_vmware(struct radclock_handle *handle)
{
	JDEBUG

	return (0);
}

static int
push_data_vmware(struct radclock_handle *handle)
{
	JDEBUG

	return (0);
}

static int
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
	struct ffclock_estimate cest;
	int sysclock_firstadj;

	sysclock_firstadj = 0;

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

		/*
		 * Update IPC shared memory segment for all processes to get accurate
		 * clock parameters
		 */
		if ((handle->run_mode == RADCLOCK_SYNC_LIVE) &&
				(handle->conf->server_ipc == BOOL_ON)) {
			if (!HAS_STATUS(handle, STARAD_UNSYNC))
				update_ipc_shared_memory(handle);
		}

		// FIXME: get rid of most of this once Linux kernel support is rewritten
		/*
		 * To improve data accuracy, we kick a fixed point data update just
		 * after we have preocessed a new stamp. Locking is handled by the
		 * kernel so we should not have concurrency issue with the two threads
		 * updating the data.  If we are starting (or restarting), the last
		 * estimate in the kernel may be better than ours after the very first
		 * stamp. Let's make sure we do not push something too stupid, too
		 * quickly
		 */
		if (handle->run_mode == RADCLOCK_SYNC_LIVE &&
				handle->conf->adjust_sysclock == BOOL_ON &&
				!HAS_STATUS(handle, STARAD_UNSYNC)) {

			if (handle->clock->kernel_version < 2) {
				update_kernel_fixed(handle);
				verbose(VERB_DEBUG, "Sync pthread updated fixed point data "
						"to kernel.");
				verbose(LOG_INFO, "Sync pthread updated fixed point data "
						"to kernel.");
			} else {

// XXX Out of whack, need cleaning when make next version linux support
// FIXME
#ifdef WITH_RADKERNEL_FBSD
				/* If hardware counter has changed, restart over again */
				size_t size_ctl;
				char hw_counter[32];
				int err;
				size_ctl = sizeof(hw_counter);
				err = sysctlbyname("kern.timecounter.hardware", &hw_counter[0],
						&size_ctl, NULL, 0);
				if (err == -1) {
					verbose(LOG_ERR, "Cannot find kern.timecounter.hardware "
							"in sysctl");
					return (-1);
				}
				
				if (strcmp(handle->clock->hw_counter, hw_counter) != 0) {
					verbose(LOG_WARNING, "Hardware counter has changed (%s -> %s)."
						" Reinitialising radclock.", handle->clock->hw_counter,
						hw_counter);
					OUTPUT(handle, n_stamps) = 0;
					((struct bidir_peer *)handle->active_peer)->stamp_i = 0;
					//handle->server_data->burst = NTP_BURST;
					handle->server_data->burst = 8;
					strcpy(handle->clock->hw_counter, hw_counter);
	// XXX TODO: Reinitialise the stats structure as well?
					return (0);
				}
#endif
				fill_ffclock_estimate(&handle->rad_data, &handle->rad_error, &cest);
				set_kernel_ffclock(handle->clock, &cest);
				verbose(VERB_DEBUG, "Feed-forward kernel clock has been set.");
			}
		}

		// FIXME: get rid of most of this once Linux kernel support is rewritten
		/* 
		 * Adjust the system clock, we only pass in here if we are not
		 * piggybacking on ntp daemon.
		 */
		if ((handle->run_mode == RADCLOCK_SYNC_LIVE) &&
				(handle->conf->adjust_sysclock == BOOL_ON)) {
			// TODO: catch errors
			//update_system_clock(handle);
			
			// FIXME : ugly ugly stuff
			// Extract bits of update_system_clock that did not need a notion of
			// received packets	
			// Would be better to get rid of all this
			vcounter_t vcount;
			struct timeval sys_tv, rad_tv, delta_tv;
			struct timex tx;
			double offset;

			read_clocks(handle, &sys_tv, &rad_tv, &vcount);

			if (sysclock_firstadj == 0) {
				settimeofday(&rad_tv, NULL);
				sysclock_firstadj++;
			}
				
			subtract_tv(&delta_tv, rad_tv, sys_tv);
			offset = delta_tv.tv_sec + (double)delta_tv.tv_usec / 1e6;

			tx.modes = TX_MODES | MOD_MAXERROR | MOD_ESTERROR | MOD_TIMECONST;
			tx.offset = (int32_t) (offset * KERN_RES);
			tx.status = STA_PLL;
			tx.maxerror = (long) ((SERVER_DATA(handle)->rootdelay/2 +
					SERVER_DATA(handle)->rootdispersion) * 1e6);
			/* TODO: not the right estimate !! */
			tx.esterror = (long) (RAD_DATA(handle)->phat * 1e6);
			
			/* Play slightly with the rate of convergence of the PLL in the kernel. Try
			 * to converge faster when it is further away
			 * Also set a the status of the sysclock when it gets very good.
			 */
			if (offset < 0)
				offset = -offset;
			if (offset > 100e-6) {
				tx.constant = TIME_CONSTANT - 2;
				DEL_STATUS(handle, STARAD_SYSCLOCK);
			} else {
				ADD_STATUS(handle, STARAD_SYSCLOCK);
				if (offset > 40e-6)
					tx.constant = TIME_CONSTANT - 1;
				else
					tx.constant = TIME_CONSTANT;
			}
			NTP_ADJTIME(&tx);
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

#endif	/* WITH_RADKERNEL_NONE */
