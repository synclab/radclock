/*
 * Copyright (C) 2006-2012, Julien Ridoux <julien@synclab.org>
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

#ifndef _CREATE_STAMP_H
#define _CREATE_STAMP_H


/*
 * Network level functions called by main to get packet data
 * 
 */
#include <stdint.h>

/* 
 * The size of the packets captured by libpcap for the purpose of timekeeping,
 * ie NTP packets. There are some assumptions in here. A quick breakdown:
 * 16 : Ethernet header (14) + 802.1Q extension (2)
 * 40 : max of IPv4 header (20) and IPv6 fixed header (40).
 * 72 : Cannot tell how many IPv6 extensions header there could be let's guess 3
 *      of 24 bytes each
 * 20 : UDP header
 * 88 : NTP Client/Server packet (not control!) (48)
 *      2 extensions (2 * 10)
 *      key identifier (4)
 *      Message Digest (MD5) (16)
 * ----
 * 236 bytes.
 */
#define BPF_PACKET_SIZE 236


/* 
 * The size of the buffer containing the data of interest to us.
 * For timekeeping it has to be as big as BPF_PACKET_SIZE and hold the result of
 * storing the vcounter timestamp in a SLL header. Good news SLL is 16 bytes,
 * just like Ethernet + 802.1Q extension.
 * Also need to hold the extra struct pcap_pkthdr (12 bytes currently using
 * timeval).
 * 
 * However, we provide timestamping function for users who are interested in
 * any kind of traffic. So max that value out.
 */
#define RADPCAP_PACKET_BUFSIZE 65535


/* 
 * store simple stats in incoming reference time information. Extensible.
 */
struct timeref_stats {
  u_int32_t   ref_count;     // # ref TS inputs: NTP cases: # of pkts seen;  GPS: # of pulses 
  u_int32_t   badqual_count; // # judged of poor quality; NTP cases: not stratum 1; GPS: ?
}; 



/*
 * This is the generic header we use to replace existing one when saving the raw
 * files.
 */
typedef struct linux_sll_header_t {
	uint16_t pkttype;      	/* packet type */
	uint16_t hatype;       	/* link-layer address type */
	uint16_t halen;        	/* link-layer address length */
	char addr[8];	  		/* link-layer address */
	uint16_t protocol;      /* protocol */
} linux_sll_header_t;


// TODO: not sure we really need the 'size' member anymore. We could get that
// value from the pcap header. XXX to check!!
typedef struct radpcap_packet_t {
	void *header;	/* Modified BPF header with vcount */
	void *payload;  /* Packet payload (ethernet) */
	void *buffer;	
	size_t size;	/* Captured size */
	u_int32_t type;	/* rt protocol type */
	struct sockaddr_storage ss_if;	/* Capture interface IP address */
} radpcap_packet_t;


/*
 * So far still pcap based
 */
int get_network_stamp(struct radclock_handle *handle, void * userdata,
		int (*get_packet)(struct radclock_handle *, void *, radpcap_packet_t **),
		struct stamp_t *stamp, struct timeref_stats *stats);

int get_vcount(radpcap_packet_t *packet, vcounter_t *vcount);

#endif
