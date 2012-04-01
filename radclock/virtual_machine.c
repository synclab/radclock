/*
 * Copyright (C) 2006-2012, Julien Ridoux <julien@synclab.org>
 * Copyright (C) 2009-2012, Timothy Broomhead <t.broomhead@ugrad.unimelb.edu.au>
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
#include "config_mgr.h"
#include "jdebug.h"


// Not sure where to put this at the moment or a cleaner way
#define NOXENSUPPORT 0x01


#ifdef WITH_XENSTORE
#include <xs.h>
#define XENSTORE_PATH "/local/radclock"
#endif



int
init_xenstore(struct radclock_handle *handle)
{
	JDEBUG
#ifdef WITH_XENSTORE
	struct xs_handle *xs;
	struct xs_permissions perms[1];
	char *domstring;
	int domid;
	unsigned count;


	if( ( xs = xs_domain_open() ) == NULL){
		return (NOXENSUPPORT);
	}
	if(handle->conf->virtual_machine == VM_XEN_MASTER){
		domstring = xs_read(xs, XBT_NULL, "domid", &count);
		domid = atoi(domstring);
		free(domstring);

		perms[0].id = domid;
		perms[0].perms = XS_PERM_READ | XS_PERM_WRITE;
		
		xs_write(xs, XBT_NULL, XENSTORE_PATH,
				RAD_DATA(handle),
				sizeof(*RAD_DATA(handle)));

		if(!xs_set_permissions(xs, XBT_NULL, XENSTORE_PATH, perms, 1)){
			verbose(LOG_ERR,"Could not set permissions for Xenstore");
		}
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

	xs_write(xs, XBT_NULL, XENSTORE_PATH,
			RAD_DATA(handle),
			sizeof(*RAD_DATA(handle)));
	return (0);
#else
	return (0);
#endif
}


int
pull_data_xen(struct radclock_handle *handle)
{
	JDEBUG
#ifdef WITH_XENSTORE
	int err;
	unsigned sleep_time;
	vcounter_t vcount, delta;
	struct xs_handle *xs;
	struct radclock_data *radclock_data_buf;
	unsigned len_read;
	xs = (struct xs_handle *) RAD_VM(handle)->store_handle;
	radclock_data_buf = xs_read(xs, XBT_NULL, XENSTORE_PATH,&len_read);
	if(len_read != sizeof(struct radclock_data)){
		verbose(LOG_ERR,"Data read from Xenstore not same length as RADclock data");
	} else {
		if(RAD_DATA(handle)->last_changed != radclock_data_buf->last_changed){
			verbose(LOG_NOTICE, "Xenstore updated RADclock data");
	}
		memcpy(RAD_DATA(handle), radclock_data_buf, sizeof(*RAD_DATA(handle)));
	}
	
	free(radclock_data_buf);

	err = radclock_get_vcounter(handle, &vcount);
	
	if(vcount < RAD_DATA(handle)->valid_till){
		if(vcount > RAD_DATA(handle)->last_changed){
		    delta = RAD_DATA(handle)->valid_till - vcount;
			// Calculate amount of time to sleep untill next valid_till
			sleep_time = delta * RAD_DATA(handle)->phat * 1000000;
			usleep(sleep_time);
		} else {
			verbose(LOG_ERR, "Virtual store data not suitable for this counter");
		}
	} else {
// We've gone over the valid till point, just keep checking at every 500000us until we are successful
		usleep(500000);
	}

	return (err);
#else
	return (0);
#endif
}


int
pull_data_none(struct radclock_handle *handle)
{
	JDEBUG
	return (0);
}


int push_data_none(struct radclock_handle *handle)
{
	JDEBUG
	return (0);
}


int
init_multicast(struct radclock_handle *handle)
{
	JDEBUG
	
	struct hostent *host;

	if( (RAD_VM(handle)->sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1){
		verbose(LOG_ERR, "Could not open socket for multicast");
		return (-1);
	}
	
	RAD_VM(handle)->server_addr.sin_family = AF_INET;
	RAD_VM(handle)->server_addr.sin_port = htons(5001);
	bzero(&(RAD_VM(handle)->server_addr.sin_zero),8);
	
	switch ( handle->conf->virtual_machine ) {

		case VM_MULTICAST_MASTER:
			host = (struct hostent *) gethostbyname((char *)"10.0.3.134");		
			RAD_VM(handle)->server_addr.sin_addr = *((struct in_addr *)host->h_addr);
			break;
	
		case VM_MULTICAST_SLAVE:
			RAD_VM(handle)->server_addr.sin_addr.s_addr = INADDR_ANY;
			if (bind(RAD_VM(handle)->sock,(struct sockaddr *)&(RAD_VM(handle)->server_addr), sizeof (struct sockaddr)) == -1){
				verbose(LOG_ERR, "Could not bind socket for multicast");
				return (-1);
			}

			break;
	
		default:
			verbose(LOG_ERR, "Cannot initialise multicast if not in multicast mode");
			return (-1);

	}
	return (0);
}


int
pull_data_multicast(struct radclock_handle *handle)
{
	unsigned addr_len;
	int bytes_read;
	char recv_data[1024];
	struct sockaddr_in client_addr;
	struct radclock_data radclock_data_buf;

	JDEBUG

	addr_len = sizeof(struct sockaddr);
	bytes_read = recvfrom(RAD_VM(handle)->sock, recv_data, 1024, 0,
			(struct sockaddr *)&client_addr, &addr_len);

	if (bytes_read != sizeof(struct radclock_data)) {
		verbose(LOG_ERR,"Data read from sock not same length as RADclock data");
	} else {

		memcpy(&radclock_data_buf, &recv_data, bytes_read);

		if (RAD_DATA(handle)->last_changed != radclock_data_buf.last_changed) {
			verbose(LOG_NOTICE, "Multicast updated RADclock data");
		}
		memcpy(RAD_DATA(handle), &radclock_data_buf, sizeof(*RAD_DATA(handle)));
	}

	return (0);
}


int
push_data_multicast(struct radclock_handle *handle)
{
	JDEBUG

// TODO error control?
	sendto(RAD_VM(handle)->sock, RAD_DATA(handle), sizeof(*RAD_DATA(handle)),
			0, (struct sockaddr *)&(RAD_VM(handle)->server_addr),
			sizeof(struct sockaddr));

	return (0);
}


int
init_virtual_machine_mode(struct radclock_handle *handle)
{
	JDEBUG

	/* If does not run as a VM_*, quick init and return */
	if (handle->conf->virtual_machine == VM_NONE) {
		RAD_VM(handle)->pull_data = &pull_data_none;
		RAD_VM(handle)->push_data = &push_data_none;
		return (0);
	}

	/* Check if the kernel is capable of doing all this */
	if (handle->clock->kernel_version < 1) {
		verbose(LOG_ERR, "Virtual machine mode requires Feed-Forward kernel "
				"support version 1 or above");
		return (1);
	}

	/* Do some checks on kernel / counters available.
	 * We need reliable counter, wide, and common to virtual master and slave
	 */
	if (!has_vm_vcounter(handle->clock))
		return (1);

	switch (handle->conf->virtual_machine) {

	case VM_XEN_MASTER:

		if (init_xenstore(handle) == NOXENSUPPORT) {
			verbose(LOG_ERR,
					"Could not open Xenstore as Master, changing virtual machine mode to none");
			handle->conf->virtual_machine = VM_NONE;
			RAD_VM(handle)->push_data = &push_data_none;
		} else {
			RAD_VM(handle)->push_data = &push_data_xen;
		}
		RAD_VM(handle)->pull_data = &pull_data_none;

		break;

	case VM_XEN_SLAVE:

		if (init_xenstore(handle) == NOXENSUPPORT) {
			verbose(LOG_ERR,
					"Could not open Xenstore as Slave, changing virtual machine mode to none");
			handle->conf->virtual_machine = VM_NONE;
			RAD_VM(handle)->pull_data = &pull_data_none;
		} else {
			RAD_VM(handle)->pull_data = &pull_data_xen;
		}
		RAD_VM(handle)->push_data = &push_data_none;
		
		break;

	case VM_MULTICAST_MASTER:
		if (init_multicast(handle) != 0) {
			verbose(LOG_ERR, "Could not initialise multicast-master, disabling multicast");
			handle->conf->virtual_machine = VM_NONE;
			RAD_VM(handle)->push_data =&push_data_none;
		} else {
			RAD_VM(handle)->push_data = &push_data_multicast;
		}
		RAD_VM(handle)->pull_data = &pull_data_none;
		break;

	case VM_MULTICAST_SLAVE:
		if (init_multicast(handle) != 0) {
			verbose(LOG_ERR, "Could not initialise multicast-slave, disabling multicast");
			handle->conf->virtual_machine = VM_NONE;
			RAD_VM(handle)->pull_data = &pull_data_none;
		} else {
			RAD_VM(handle)->pull_data = &pull_data_multicast;
		}
		RAD_VM(handle)->push_data = &push_data_none;
		break;

	case VM_VBOX_MASTER:
		break;

	case VM_VBOX_SLAVE:
		break;

	case VM_NONE:
	default:
		verbose(LOG_ERR, "Unknown virtual machine mode during init.");
		return (1);
	}
	return (0);
}
