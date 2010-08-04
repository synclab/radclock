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


#ifndef _RAWDATA_H
#define _RAWDATA_H



/**
 * Raw data element.
 * A container for raw data being timestamped by the kernel and passed
 * to us. Example are a NTP packet captured via LibPcap or a PPS
 * timestamped.
 * Structure is designed to be versatile enough to handle raw data of
 * different nature in a doubled chain list.
 * IMPORTANT: the design is lock free. I could have created a mutex to
 * ensure the producer/consumer don't mess up, but the point of this 
 * buffer chain is to ensure low level capture function (e.g. the 
 * callback passed to pcap_loop()) returns as fast as possible. So we 
 * don't want to block and wait for the mutex to be unlocked.
 */

typedef enum { 
	RD_UNKNOWN,
	RD_SPY_STAMP,
	RD_PPS,
	RD_NTP_PACKET,		/* Handed by libpcap */
} rawdata_type_t;


struct raw_data {
	struct raw_data *prev;			/* Previous buddy */
	struct raw_data *next;			/* Next buddy */
	rawdata_type_t type;			/* If we know the type, let's put it there */
	int read;						/* Have I been read? i.e. am I ready to be freed? */
	vcounter_t vcount;				/* vcount stamp for this buddy */
	struct pcap_pkthdr pcap_hdr;	/* The PCAP header */
	void* buf;						/* Actual data, contains packet */
};



int capture_raw_data( struct radclock *clock_handle );

int deliver_raw_data( struct radclock *clock_handle, struct radpcap_packet_t *pkt, vcounter_t *vcount);

#endif
