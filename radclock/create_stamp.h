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





/*
 * Network level functions called by main to get packet data
 * 
 */
#ifndef _CREATE_STAMP_H
#define _CREATE_STAMP_H

#include <stdint.h>

/* Has to be smaller than RADPCAP_PACKET_BUFSIZE - sizeof(struct pcap_pkthdr) */
#define BPF_PACKET_SIZE 108
// TODO: check if this is still true!!!
// otherwise can be defined as BPF_PACKET_SIZE + sizeof(struct pcap_pkthdr) 
/* Set to the max for the users who capture any type of traffic */
#define RADPCAP_PACKET_BUFSIZE 65536



/************************************************************/
/**************** Reference Timestamp level *****************/ 


// store simple stats in incoming reference time information. Extensible.
struct timeref_stats {
  u_int32_t   ref_count;     // # ref TS inputs: NTP cases: # of pkts seen;  GPS: # of pulses 
  u_int32_t   badqual_count; // # judged of poor quality; NTP cases: not stratum 1; GPS: ?
}; 

/**************** NTP case *****************/ 
/*   Standard client-server NTP packet exchange.
                 
                              Tb     Te            real times:  ta < tb < te < tf
                              |      |          available TS's: Ta < Tf  [vcount units]
               Server  ------tb------te--------                 Tb < Te  [sec]
                            /          \
                           /            \  
               Client  ---ta-------------tf-----  
                         |                 |
                         Ta                Tf
*/

/* number of seconds between the unix/utc epochs and the ntp epoch */
/* UTC      epoch: 0[sec], 1/1/1972  but doesn't measure real time!!
   NTP base epoch: 0[sec], 1/1/1900  is updated to match UTC, damn! 
   Unix     epoch: 0[sec], 1/1/1970  Measures real time ?? apparently not! */ 



/* This is the generic header we use to replace existing one when saving the raw
 * files.
 */
typedef struct linux_sll_header_t {
	uint16_t pkttype;      	/* packet type */
	uint16_t hatype;       	/* link-layer address type */
	uint16_t halen;        	/* link-layer address length */
	char addr[8];	  		/* link-layer address */
	uint16_t protocol;      /* protocol */
} linux_sll_header_t;



typedef struct radpcap_packet_t {
	void *header;	/* Modified BPF header with vcount */
	void *payload;  /* Packet payload (ethernet) */
	void *buffer;	
	size_t size;	/* Captured size */
	u_int32_t type;	/* rt protocol type */
} radpcap_packet_t;




/******************************** Pkt level routines **********************************/
/**** pcap based (Linux and BSD, driver TSs) ****/
int get_bidir_stamp(struct radclock *handle,
		void * userdata,
		int (*get_packet)(struct radclock *handle, void *user, radpcap_packet_t **packet),
		struct stamp_t *stamp, 
		struct timeref_stats *stats, 
		char *src_ipaddr
);



int get_vcount(radpcap_packet_t *packet, vcounter_t *vcount);
inline unsigned int get_capture_length(radpcap_packet_t *packet);

#endif
