/*
 * Copyright (C) 2006-2010 Julien Ridoux <julien@synclab.org>
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

// Not sure where to put this at the moment or a cleaner way
#define NOXENSUPPORT 0x01

#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <syslog.h>
#include <sys/stat.h>

#include "../config.h"
#include "radclock.h"
#include "radclock-private.h"
#include "verbose.h"
#include "sync_algo.h"
#include "config_mgr.h"
#include "jdebug.h"

#ifdef WITH_XENSTORE
#include <xs.h>
#define XENSTORE_PATH "/local/radclock"
#endif

int
init_xenstore(struct radclock *clock_handle){
	JDEBUG
#ifdef WITH_XENSTORE
	struct xs_handle *xs;
	struct xs_permissions perms[1];
	char *domstring;
	int domid;
	unsigned count;


	if( ( xs = xs_domain_open() ) == NULL){
		return NOXENSUPPORT;
	}
	if(clock_handle->conf->virtual_machine == VM_XEN_MASTER){
		domstring = xs_read(xs, XBT_NULL, "domid", &count);
		domid = atoi(domstring);
		free(domstring);

		perms[0].id = domid;
		perms[0].perms = XS_PERM_READ | XS_PERM_WRITE;
		
		xs_write(xs, XBT_NULL, XENSTORE_PATH,
				&(clock_handle->rad_data), 
				sizeof(clock_handle->rad_data));

		if(!xs_set_permissions(xs, XBT_NULL, XENSTORE_PATH, perms, 1)){
			verbose(LOG_ERR,"Could not set permissions for Xenstore");
		}
	}
	xs_daemon_close(xs);
	return 0;
#else
	// Really this shouldn't happen, but maybe for robustness we should explicitly
	// change mode to none
	return NOXENSUPPORT;
#endif
}
int
push_data_xen(struct radclock *clock_handle){
	JDEBUG
#ifdef WITH_XENSTORE
	struct xs_handle *xs;
	xs_transaction_t th;

	xs = xs_domain_open();
	th = xs_transaction_start(xs);

	xs_write(xs, th, XENSTORE_PATH,
			&(clock_handle->rad_data), 
			sizeof(clock_handle->rad_data));

	xs_transaction_end(xs, th, false);
	xs_daemon_close(xs);
	return 0;
#else
	return 0;
#endif
}


int pull_data_xen(struct radclock *clock_handle)
{
	JDEBUG
	return 0;
}

int pull_data_none(struct radclock *clock_handle)
{
	JDEBUG
	return 0;
}


int push_data_none(struct radclock *clock_handle)
{
	JDEBUG
	return 0;
}



int init_virtual_machine_mode(struct radclock *clock_handle)
{
	JDEBUG
	switch ( clock_handle->conf->virtual_machine )
	{
		case VM_NONE:
			RAD_VM(clock_handle)->pull_data = &pull_data_none;
			RAD_VM(clock_handle)->push_data = &push_data_none;
			break;

		case VM_XEN_MASTER:

			if(init_xenstore(clock_handle) == NOXENSUPPORT){
				verbose(LOG_ERR, 
						"Could not open Xenstore, changing virtual machine mode to none");
				clock_handle->conf->virtual_machine = VM_NONE;
				RAD_VM(clock_handle)->push_data = &push_data_none;
			} else {
				RAD_VM(clock_handle)->push_data = &push_data_xen;
			}
			RAD_VM(clock_handle)->pull_data = &pull_data_none;

			break;

		case VM_XEN_SLAVE:

			if(init_xenstore(clock_handle) == NOXENSUPPORT){
				verbose(LOG_ERR, 
						"Could not open Xenstore, changing virtual machine mode to none");
				clock_handle->conf->virtual_machine = VM_NONE;
				RAD_VM(clock_handle)->pull_data = &pull_data_none;
			} else {
				RAD_VM(clock_handle)->pull_data = &pull_data_xen;
			}
			RAD_VM(clock_handle)->push_data = &push_data_none;
			
			break;

		case VM_VBOX_MASTER:
			break;

		case VM_VBOX_SLAVE:
			break;

		default:
			verbose(LOG_ERR, "Unknown virtual machine mode during init.");
			return -1;
	}
	return 0;
}
