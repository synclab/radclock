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
	RD_NTP_PACKET,		/* Handed by libpcap */
	RD_PPS,
} rawdata_type_t;


/*
 * Raw data structure specific to the SYP capture mode.
 * So far looks like a bidir stamp, but may change in the future.
 */
struct rd_spy_stamp {
	vcounter_t Ta;
	struct timeval Tb;
	struct timeval Te;
	vcounter_t Tf;
};


/*
 * Raw data structure specific to NTP and PIGGY capture modes.
 * Very libpacp oriented.
 */
struct rd_ntp_pkt {
	vcounter_t vcount;				/* vcount stamp for this buddy */
	struct pcap_pkthdr pcap_hdr;	/* The PCAP header */
	void* buf;						/* Actual data, contains packet */
};


/*
 * Raw data bundle. Holds actual raw_data and deals with link list
 * and light locking
 */
struct raw_data_bundle {
	struct raw_data_bundle *prev;	/* Previous buddy */
	struct raw_data_bundle *next;	/* Next buddy */
	int read;						/* Have I been read? i.e. ready to be freed? */
	rawdata_type_t type;			/* If we know the type, let's put it there */
	union rd_t {
		struct rd_ntp_pkt rd_ntp;
		struct rd_spy_stamp rd_spy;
	} rd;
};


#define RD_NTP(x) (&((x)->rd.rd_ntp))
#define RD_SPY(x) (&((x)->rd.rd_spy))



int capture_raw_data(struct radclock *clock_handle );

int deliver_rawdata_ntp(struct radclock *clock_handle, struct radpcap_packet_t *pkt, vcounter_t *vcount);

int deliver_rawdata_spy(struct radclock *clock_handle, struct stamp_t *stamp);

#endif
