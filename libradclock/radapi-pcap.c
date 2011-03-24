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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>

#include <pcap.h>

#include <radclock.h>
#include "radclock-private.h"
#include "logger.h"



// TODO should be able to clean that up
#define K_RADCLOCK_TSMODE_SYSCLOCK		0x0001  /* return SW timeval and raw vcounter */
#define K_RADCLOCK_TSMODE_RADCLOCK		0x0002  /* return timeval based on RADclock and raw vcounter */
#define K_RADCLOCK_TSMODE_FAIRCOMPARE  	0x0003  /* return SW timeval, and vcounter read just before SW in global data */



int radclock_set_tsmode(struct radclock *handle, pcap_t *p_handle, radclock_tsmode_t mode)
{
	int kmode;
	if (handle == NULL) {
		logger(RADLOG_ERR, "Clock handle is null, can't set mode");
		return -1;
	}

	switch (mode)
	{
		case RADCLOCK_TSMODE_SYSCLOCK:
			kmode = K_RADCLOCK_TSMODE_SYSCLOCK;
			break;
		case RADCLOCK_TSMODE_RADCLOCK:
			kmode = K_RADCLOCK_TSMODE_RADCLOCK;
			break;
		case RADCLOCK_TSMODE_FAIRCOMPARE:
			kmode = K_RADCLOCK_TSMODE_FAIRCOMPARE;
			break;
		default:
			return -EINVAL;
	}
	if (!pcap_fileno(p_handle))
	{
		/* working from non-live capture return silently */
		return 0;
	}

	/* Call to system specific method to set the mode */
	if (descriptor_set_tsmode(handle, p_handle, kmode) == -1)
		return -1;

	return 0;
}



int radclock_get_tsmode(struct radclock *handle, pcap_t *p_handle, radclock_tsmode_t *mode)
{
	int kmode = 0;	// Need to be initialised for FreeBSD, don't exactly know why.
	
	if (handle == NULL) {
		logger(RADLOG_ERR, "Clock handle is null, can't set mode");
		return -1;
	}
	
	/* Call to system specific method to get the mode */
	if (descriptor_get_tsmode(handle, p_handle, &kmode) == -1)
		return -1;

	//TODO align enum with kernel modes
	*mode = kmode;

	return 0;
}


struct routine_priv_data
{
	struct radclock *handle;
	pcap_t *p_handle;
	struct pcap_pkthdr *header;
	unsigned char *packet;
	vcounter_t *vcount;
	struct timeval *ts;
	int ret;
};


void kernelclock_routine(u_char *user, const struct pcap_pkthdr *phdr, const u_char *pdata)
{
	struct routine_priv_data *data = (struct routine_priv_data *) user;
	memcpy(data->header, phdr, sizeof(struct pcap_pkthdr));
	data->packet = (unsigned char*)pdata;
	memcpy(data->ts, &phdr->ts, sizeof(struct timeval));
	data->ret = extract_vcount_stamp(data->p_handle, phdr, pdata, data->vcount);
}


// TODO check if this the right pcap_* to provide (packet per packet ??)
/* Ugly stuff ?
 * Because of the integration of the user version of the clock, we need to know
 * which routine to call here. Also this function is exported to the user API
 * so that anybody can call the pcap oriented capture while receovering the
 * vcount padded in the pcap header.
 * No other choice than having a clock handle as a parameter input ...
 */
int radclock_get_packet( struct radclock *handle, 
						pcap_t *p_handle, 
						struct pcap_pkthdr *header, 
						unsigned char **packet, 
						vcounter_t *vcount, 
						struct timeval *ts)
{
	struct routine_priv_data data = 
	{
		.handle 	= handle,
		.p_handle 	= p_handle,
		.header 	= header,
		.vcount 	= vcount,
		.ts 		= ts,
		.ret 		= 0,
		.packet 	= NULL,
	};
	/* Need to call the low level pcap_loop function to be able to pass our 
	 * own callback and get the vcount value */
	int err;

	err = pcap_loop(p_handle, 1 /*packet*/, kernelclock_routine, (u_char *) &data);
	*packet = data.packet;

	/* Error can be -1 (read error) or -2 (explicit loop break */
	if ( err < 0 )
		return err;
	if ( data.ret < 0)
		return -1;
	return 0;
}

