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

#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../config.h"
#include "radclock.h"
#include "radclock-private.h"
#include "verbose.h"
#include "proto_ntp.h"
#include "sync_algo.h"        /* Because need  struct bidir_stamp defn */
#include "ntohll.h"
#include "create_stamp.h"
#include "jdebug.h"


// TODO: we should not have to redefine this
# ifndef useconds_t
typedef uint32_t useconds_t;
# endif

struct stq_elt {
	struct stamp_t stamp;
	struct stq_elt *prev;
	struct stq_elt *next;
};

struct stamp_queue {
	struct stq_elt *start;
	struct stq_elt *end;
	int size;
};

/* To prevent allocating heaps of memory if stamps are not paired in queue */
#define MAX_STQ_SIZE	20


/*
 * Converts fixed point NTP timestamp to floating point UNIX time
 */
long double
ntp_stamp_to_fp_unix_time(l_fp ntp_ts)
{
	long double  sec;
	sec  = (long double)(ntohl(ntp_ts.l_int) - JAN_1970);
	sec += (long double)(ntohl(ntp_ts.l_fra)) / 4294967296.0;
	return (sec);
}


radpcap_packet_t *
create_radpcap_packet()
{
	radpcap_packet_t *pkt;

	JDEBUG

	pkt = (radpcap_packet_t*) malloc(sizeof(radpcap_packet_t));
	JDEBUG_MEMORY(JDBG_MALLOC, pkt);

	pkt->buffer 	= (void *) malloc(RADPCAP_PACKET_BUFSIZE);
	JDEBUG_MEMORY(JDBG_MALLOC, pkt->buffer);

	pkt->header = NULL;
	pkt->payload = NULL;
	pkt->type = 0;
	pkt->size = 0;

	return (pkt);
}


void
destroy_radpcap_packet(radpcap_packet_t *packet)
{
	JDEBUG

	packet->header = NULL;
	packet->payload = NULL;

	if (packet->buffer) {
		JDEBUG_MEMORY(JDBG_FREE, packet->buffer);
		free(packet->buffer);
	}
	packet->buffer = NULL;

	JDEBUG_MEMORY(JDBG_FREE, packet);
	free(packet);
	packet = NULL;
}


/*
 * Get the IP payload from the radpcap_packet_t packet.  Here also (in addition
 * to get_vcount) we handle backward compatibility since we changed the way the
 * vcount and the link layer header are managed.
 *
 * We handle 3 formats:
 * 1- [pcap][ether][IP] : oldest format (vcount in pcap header timeval)
 * 2- [pcap][sll][ether][IP] : libtrace-3.0-beta3 format, vcount is in sll header
 * 3- [pcap][sll][IP] : remove link layer header, no libtrace, vcount in sll header
 * In live capture, the ssl header MUST be inserted before calling this function
 */
struct ip *
get_ip(radpcap_packet_t *packet, unsigned int *remaining)
{
	struct ip *ipptr 		= NULL;
	linux_sll_header_t *hdr = NULL;
	size_t offset			= 0;

	switch ( packet->type ) {
		case DLT_EN10MB:
			/* This is format 1, skip 14 bytes ethernet header */
			offset = sizeof(struct ether_header);
			break;
		case DLT_LINUX_SLL:
			/* Here we take advantage of a bug in bytes order in
			 * libtrace-3.0-beta3 to identify the formats. 
			 * If hdr->hatype = ARPHRD_ETHER (0x0001), we have format 3. 
			 * If hdr->hatype is 256 (0x0100) it's a libtrace format
			 */
			hdr = (linux_sll_header_t*) packet->payload;
			
			// TODO: endianness !!!!!
			if ( ntohs(hdr->hatype) == 0x0001 ) {
				/* skip 16 sll headers */
				offset = sizeof(linux_sll_header_t);
			}
			else {
				/* skip (14+16) bytes ethernet and sll headers */
				offset = sizeof(struct ether_header) + sizeof(linux_sll_header_t);
			}
			break;
		default:
			verbose(LOG_ERR, "MAC layer type not supported yet.");
			return NULL;
			break;
	}
	/* Descend into frame to get IP data */
	ipptr = (struct ip *)(packet->payload + offset);
	*remaining = *remaining - offset;

	/* Check we got a valid IP packet */
	if (ipptr->ip_v != 4) {
		verbose(LOG_ERR, "Not an IPv4 packet, endianness issue? ip_v = %u\n", ipptr->ip_v);
		return NULL;
	}
	return ipptr;
}

struct udphdr *
get_udp_from_ip(struct ip *ipptr, unsigned int *remaining)
{
	struct udphdr *udp = NULL;
	/* Check for UDP protocol only */
	if (ipptr->ip_p == 17) {
		// TODO : endianness !!!!! 
		/* If the packet is fragmented, reject it (see flags and fragment offset
		 * in IP header) */	
		if ( (ipptr->ip_off & 0xff1f) != 0)
			return NULL;

		/* If broken packet */
		if (remaining) {
			if (*remaining < (ipptr->ip_hl*4U)) {
				return NULL;
			}
		}

		*remaining -= (ipptr->ip_hl * 4);
		udp = (void *)((char *)ipptr + (ipptr->ip_hl * 4));
	}
	return udp;
}

void *
get_udp_payload(struct udphdr *udp, unsigned int *remaining)
{
    if (remaining) {
        if (*remaining < sizeof(struct udphdr))
            return NULL;
        *remaining -= sizeof(struct udphdr);
    }
    return (void*)((char *)udp + sizeof(struct udphdr));
}


/*
 * Retrieve the vcount value stored in the pcap header timestamp field.
 * This function is here for backward compatibility and may disappear one day,
 * especially because the naming convention is confusing. The ethernet frame is
 * used only for distinguishing the first raw file format.
 */
int
get_vcount_from_etherframe(radpcap_packet_t *packet, vcounter_t *vcount)
{
	JDEBUG

	if (packet->size < sizeof(struct pcap_pkthdr)) {
		verbose(LOG_ERR, "No PCAP header found.");
		return (-1);
	}

	// TODO : Endianness !!!!
	/* This is the oldest raw file format where the vcount was stored into the
	 * timestamp field of the pcap header.
	 * tv_sec holds the left hand of the counter, then put right hand of the
	 * counter into empty RHS of vcount
	 */
	*vcount  = (u_int64_t) (((struct pcap_pkthdr*)packet->header)->ts.tv_sec) << 32;
	*vcount += (u_int32_t) ((struct pcap_pkthdr*)packet->header)->ts.tv_usec;

	return (0);
}

/*
 * Retrieve the vcount value from the address field of the LINUX SLL
 * encapsulation header
 */
int
get_vcount_from_sll(radpcap_packet_t *packet, vcounter_t *vcount)
{
	vcounter_t aligned_vcount;

	JDEBUG

	if (packet->size < sizeof(struct pcap_pkthdr) + sizeof(linux_sll_header_t)) {
		verbose(LOG_ERR, "No PCAP or SLL header found.");
		return (-1);
	}
	
	linux_sll_header_t *hdr = packet->payload;
	if (!hdr) {
		verbose(LOG_ERR, "No SLL header found.");
		return (-1);
	}
	// TODO What does this comment mean?
	/* memcopy to ensure word alignedness and avoid potential sigbus's */
	memcpy(&aligned_vcount, hdr->addr, sizeof(vcounter_t));
	*vcount = ntohll(aligned_vcount);

	return 0;
}



/*
 * Generic function to retrieve the vcount. Depending on the link layer type it
 * calls more specific one. This ensures backward compatibility with older format
 */
int
get_vcount(radpcap_packet_t *packet, vcounter_t *vcount) {

	int ret;

	JDEBUG

	ret = -1;
	switch ( packet->type ) {
	case DLT_EN10MB:
		ret = get_vcount_from_etherframe(packet, vcount);
		break;
	case DLT_LINUX_SLL:
		ret = get_vcount_from_sll(packet, vcount);
		break;
	default:
		verbose(LOG_ERR, "Unsupported MAC layer.");
		break;
	}
	return ret;
}


void
init_peer_stamp_queue(struct bidir_peer *peer)
{
	peer->q = (struct stamp_queue *) calloc(1, sizeof(struct stamp_queue));
	peer->q->start = NULL;
	peer->q->end = NULL;
	peer->q->size = 0;
}

void
destroy_peer_stamp_queue(struct bidir_peer *peer)
{
	struct stq_elt *elt;

	elt = peer->q->end;
	while (elt != peer->q->start) {
		elt = elt->prev;
		free(elt);
	}
	free(peer->q->start);
	free(peer->q);
	peer->q = NULL;
}
	

/*
 * Insert a client or server NTP packet into the stamp queue. This routine
 * effectively pairs matching requests and replies. The stamp queue has been
 * introduced to allow matching of out of order NTP packets.
 * If no matching stamp is found, the new packet is inserted with partial
 * information. If a matching partial stamp exists, missing information is added
 * to the stamp.
 */
int
insert_stamp_queue(struct stamp_queue *q, struct stamp_t *new, int mode)
{
	struct stq_elt *stq;
	struct stq_elt *tmp;
	struct stamp_t *stamp;
	int found;

	JDEBUG

	if ((mode != MODE_CLIENT) && (mode != MODE_SERVER)) {
		verbose(LOG_ERR, "Unsupported NTP packet mode: %d", mode);
		return (-1);
	}

	found = 0;
	stq = q->start;
	tmp = q->start;
	while (stq != NULL) {
		stamp = &stq->stamp;
		if (stamp->id > new->id)
			tmp = stq;
		if ((stamp->type == STAMP_NTP) && (stamp->id == new->id)) {
			if (mode == MODE_CLIENT) {
				if (BST(stamp)->Ta != 0) {
					verbose(LOG_ERR, "Found duplicate NTP client request.");
					return (-1);
				}
			} else {
				if (BST(stamp)->Tf != 0) {
					verbose(LOG_ERR, "Found duplicate NTP server request.");
					return (-1);
				}
			}
			/* Found half-baked stamp to finish filling */
			found = 1;
			break;
		}
		stq = stq->next;
	}

	/*
	 * Haven't found an existing server stamp, which is quite normal. Create a
	 * new half-baked stamp and insert it in the peer queue structure.
	 * If the queue is getting bloated, delete the oldest stamp.
	 */
	if (!found) {
		if (q->size == MAX_STQ_SIZE) {
			verbose(LOG_WARNING, "Peer stamp queue has hit max size. Check the server?");
			q->end = q->end->prev;
			free(q->end->next);
			q->end->next = NULL;
			q->size--;
		}	

		stq = (struct stq_elt *) calloc(1, sizeof(struct stq_elt));
		stq->prev = NULL;
		stq->next = NULL;
		if (tmp != NULL) {
			stq->next = tmp;
			tmp->prev = stq;
			stq->prev = tmp->prev;
		}
		if (q->start == tmp)
			q->start = stq;
		if (q->size == 0)
			q->end = stq;
		q->size++;
	}

	/* Selectively copy content of new stamp over */
	stamp = &stq->stamp;
	stamp->type = STAMP_NTP;
	if (mode == MODE_CLIENT) {
		stamp->id = new->id;
		BST(stamp)->Ta = BST(new)->Ta;
	} else {
		stamp->id = new->id;
		strncpy(stamp->server_ipaddr, new->server_ipaddr, 16);
		stamp->ttl = new->ttl;
		stamp->refid = new->refid;
		stamp->stratum = new->stratum;
		stamp->leapsec = new->leapsec;
		stamp->rootdelay = new->rootdelay;
		stamp->rootdispersion = new->rootdispersion;
		BST(stamp)->Tb = BST(new)->Tb;
		BST(stamp)->Te = BST(new)->Te;
		BST(stamp)->Tf = BST(new)->Tf;
	}

	stq = q->start;
	while (stq != NULL) {
		stamp = &stq->stamp;
		verbose(VERB_DEBUG, "  stamp queue: %llu %.6Lf %.6Lf %llu %llu",
				(long long unsigned) BST(stamp)->Ta, BST(stamp)->Tb, BST(stamp)->Te,
				(long long unsigned) BST(stamp)->Tf, (long long unsigned) stamp->id);
		stq = stq->next;
	}

	if (found)
		return (0);
	else
		return (1);
}


/*
 * Check the client's request.
 * The radclock may serve NTP clients over the network. The BPF filter may not
 * be tight enough either. Make sure that requests from clients are discarded.
 */
int
bad_packet_client(struct ip *ip, struct ntp_pkt *ntp, char *src_ipaddr,
		struct timeref_stats *stats)
{
	if (strcmp(inet_ntoa(ip->ip_dst), src_ipaddr) == 0) {
		verbose(LOG_WARNING, "Destination address in client packet. "
				"Check the capture filter.");
		return (1);
	}
	return (0);
}

/*
 * Check the server's reply.
 * Make sure that this is not one of our reply to our NTP clients.
 * Make sure the leap second indicator is ok.
 * Make sure the server's stratum is not insane.
 */
int
bad_packet_server(struct ip *ip, struct ntp_pkt *ntp, char *src_ipaddr,
		struct timeref_stats *stats)
{
	/* Make sure to discard replies to our own NTP clients */
	if (strcmp(inet_ntoa(ip->ip_src), src_ipaddr) == 0) {
		verbose(LOG_WARNING, "Source address in server packet. "
				"Check the capture filter.");
		return (1);
	}

	/* If the server is unsynchronised we skip this packet */
	if (PKT_LEAP(ntp->li_vn_mode) == LEAP_NOTINSYNC) {
		verbose(LOG_WARNING, "NTP server says LEAP_NOTINSYNC, packet ignored.");
		stats->badqual_count++;
		return (1);
	}

	/* Check if the server clock is synchroninsed or not */
	if (ntp->stratum == STRATUM_UNSPEC) {
		verbose(LOG_WARNING, "Stratum unspecified, server packet ignored.");
		return (1);
	}

	return (0);
}

/*
 * Create a stamp structure, fill it with client side information and pass it
 * for insertion in the peer's stamp queue.
 */
int
push_stamp_client(struct stamp_queue *q, struct ntp_pkt *ntp, vcounter_t *vcount)
{
	struct stamp_t stamp;

	JDEBUG

	stamp.id = ((uint64_t) ntohl(ntp->xmt.l_int)) << 32;
	stamp.id |= (uint64_t) ntohl(ntp->xmt.l_fra);
	stamp.type = STAMP_NTP;
	BST(&stamp)->Ta = *vcount;

	verbose(VERB_DEBUG, "Stamp queue: inserting client stamp->id: %llu",
			(long long unsigned)stamp.id);

	return (insert_stamp_queue(q, &stamp, MODE_CLIENT));
}


/*
 * Create a stamp structure, fill it with server side information and pass it
 * for insertion in the peer's stamp queue.
 */
int
push_stamp_server(struct stamp_queue *q, struct ip *ip, struct ntp_pkt *ntp,
	vcounter_t *vcount)
{
	struct stamp_t stamp;

	JDEBUG

	stamp.type = STAMP_NTP;
	stamp.id = ((uint64_t) ntohl(ntp->org.l_int)) << 32;
	stamp.id |= (uint64_t) ntohl(ntp->org.l_fra);
	strncpy(stamp.server_ipaddr, inet_ntoa(ip->ip_src), 16);
	stamp.ttl = ip->ip_ttl;
	stamp.refid = ntohl(ntp->refid);
	stamp.stratum = ntp->stratum;
	stamp.leapsec = PKT_LEAP(ntp->li_vn_mode);
	stamp.rootdelay = ntohl(ntp->rootdelay) / 65536.;
	stamp.rootdispersion = ntohl(ntp->rootdispersion) / 65536.;
	BST(&stamp)->Tb = ntp_stamp_to_fp_unix_time(ntp->rec);
	BST(&stamp)->Te = ntp_stamp_to_fp_unix_time(ntp->xmt);
	BST(&stamp)->Tf = *vcount;

	verbose(VERB_DEBUG, "Stamp queue: inserting server stamp->id: %llu",
			(long long unsigned)stamp.id);

	return (insert_stamp_queue(q, &stamp, MODE_SERVER));
}


/*
 * Check that packet captured is a sane input, independent from its direction
 * (client request or server reply). Pass it to subroutines for additional
 * checks and insertion/matching in the peer's stamp queue.
 */
int
update_stamp_queue(struct stamp_queue *q, radpcap_packet_t *packet,
		struct timeref_stats *stats, char *src_ipaddr)
{
	struct ip *ip;
	struct udphdr *udp;
	struct ntp_pkt *ntp;
	unsigned int remaining;
	vcounter_t vcount;
	int err;

	JDEBUG

	/* Retrieve vcount from link layer header, if this fails, things are bad */
	if (get_vcount(packet, &vcount)) {
		verbose(LOG_ERR, "Error getting raw vcounter from link layer.\n");
		return (-1);
	}

	/* Descend into IP[UDP[NTP]] pkt to get NTP data */
	// XXX is caplen correct after we chopped the mac header and replaced it
	// with a SLL header?
	remaining = ((struct pcap_pkthdr *)packet->header)->caplen;
	ip = get_ip(packet, &remaining);
	if (!ip) {
		verbose(LOG_WARNING, "Not an IP packet.");
		return (1);
	}
	
	udp = get_udp_from_ip(ip, &remaining);
	if (!udp) {
		verbose(LOG_WARNING, "Not an UDP packet.");
		return (1);
	}

	ntp = get_udp_payload(udp, &remaining);
	if (!ntp) {
		verbose(LOG_WARNING, "Not an NTP packet.");
		return (1);
	}

	/*
	 * Make sure the NTP packet is not truncated. A normal NTP packet is at
	 * least 48 bytes long, but a control or private request is as small as 12
	 * bytes.
	 */
	if (remaining < 12) {
		verbose(LOG_WARNING, "NTP packet truncated, payload is %d bytes "
			"instead of at least 12 bytes", remaining);
		return (1);
	}

	err = 0;
	switch (PKT_MODE(ntp->li_vn_mode)) {
	case MODE_BROADCAST:
		verbose(VERB_DEBUG,"Received NTP broadcast packet from %s (Silent discard)",
			inet_ntoa(ip->ip_src));
		break;

	case MODE_CLIENT:
		err = bad_packet_client(ip, ntp, src_ipaddr, stats);
		if (err)
			break;
		err = push_stamp_client(q, ntp, &vcount);
		break;

	case MODE_SERVER:
		err = bad_packet_server(ip, ntp,src_ipaddr, stats);
		if (err)
			break;
		err = push_stamp_server(q, ip, ntp, &vcount);
		break;

	default:
		// `silent' cause is lost server pkt
		verbose(VERB_DEBUG,"Missed pkt due to invalid mode: mode = %d",
			PKT_MODE(ntp->li_vn_mode));
		err = 1;
		break;
	}

	return (err);
}


/*
 * Pull a full bidirectional stamp from the stamp queue. Since the stamp queue
 * allow out of order arrival of NTP packets, there is no intrinsic guarantee
 * that all stamps in the stamp queue will be valid. Start from the oldest stamp
 * and progress our way to the most recent one. First full stamp found is
 * returned. Any half-baked stamped earlier than first full stamp is destroyed.
 */
int
get_stamp_from_queue(struct stamp_queue *q, struct stamp_t *stamp)
{
	struct stq_elt *endq;
	struct stq_elt *stq;
	struct stamp_t *st;
	int qsize;

	JDEBUG

	/* Empty queue, won't find anything here */
	if (q->size == 0) {
		verbose (VERB_DEBUG, "stamp queue is empty, no stamp returned");
		return (1);
	}

	stq = q->end;
	while (stq != NULL) {
		st = &stq->stamp;
		if ((BST(st)->Ta != 0) && (BST(st)->Tf != 0)) {
			memcpy(stamp, st, sizeof(struct stamp_t));
			break;
		}
		stq = stq->prev;
	}

	if (stq == NULL) {
		verbose(VERB_DEBUG, "Did not find any full stamp in stamp queue");
		return (1);
	}

	qsize = q->size;
	endq = q->end;
	while ((endq != q->start) && (endq != stq)) {
		endq = endq->prev;
		free(endq->next);
		q->size--;
	}

	q->size--;
	if (q->size == 0) {
		q->start = NULL;
		q->end = NULL;
	} else {
		q->end = stq->prev;
		q->end->next = NULL;
	}

	verbose(VERB_DEBUG, "Stamp queue had %d stamps, freed %d, %d left",
		qsize, qsize - q->size, q->size);

	return (0);
}


/*
 * Retrieve network packet from live or dead pcap device. This routine tries to
 * handle out of order arrival of packets (note this is true for both dead and
 * live input) by adding an extra stamp queue to serialise stamps. There are a
 * few tricks to handle delayed packets when running live. Delayed packets
 * translate into an empty raw data buffer and the routine makes several
 * attempts to get delayed packets (by waiting along a geometric sleep time
 * progression). Delays can be caused by a large RTT in piggy-backing mode
 * (asynchronous wake), or busy system where pcap path is longer than NTP client
 * UDP socket path.
 */
int
get_network_stamp(struct radclock *clock, void *userdata,
	int (*get_packet)(struct radclock *, void *, radpcap_packet_t **),
	struct stamp_t *stamp, struct timeref_stats *stats, char *src_ipaddr)
{
	struct bidir_peer *peer;
	radpcap_packet_t *packet;
	int attempt;
	int err;
	useconds_t attempt_wait;
	char *c;
	char refid [16];

	JDEBUG

	// TODO manage peeers better
	peer = clock->active_peer;

	attempt_wait = 500;					/* Loosely calibrated for LAN RTT */
	err = 0;
	packet = create_radpcap_packet();

	for (attempt=12; attempt>=0; attempt--) {
		/*
		 * Read packet from raw data queue or pcap tracefile. There are a few
		 * tricks with error code because of the source abstraction:
		 * -2: run from tracefile and reached end of input
		 * -1: run from tracefile and read error
		 * -1: read live and raw data buffer is empty
		 */
		err = get_packet(clock, userdata, &packet);

		if (err == -2)
			return (-1);
		if (err < 0) {
			if (attempt == 0) {
				verbose(VERB_DEBUG, "Empty raw data buffer after all attempts "
						"(%.3f [ms])", attempt_wait / 1000.0);
				err = 1;
				break;
			} else {
				usleep(attempt_wait);
				attempt_wait += attempt_wait;
				continue;
			}
		}

		/* Counts pkts, regardless of content (initialised to 0 in main) */
		stats->ref_count++;

		/* Convert packet to stamp and push it to the stamp queue */
		err = update_stamp_queue(peer->q, packet, stats, src_ipaddr);

		/* Low level / input problem worth stopping */
		if (err == -1)
			break;

		/*
		 * If err == 0, there is at least one valid full fledged stamp in the
		 * queue. If running dead trace, this could fill the stamp queue with
		 * the entire trace file. Instead, break pcap_loog and process stamp.
		 */
		if (err == 0)
			break;
		/*
		 * If err == 1, inserted packet in queue, but did not pair it. Half
		 * baked stamp not worth processing, we try to read from the device
		 * again after a little while. The wait grows bigger on each attempt.
		 * Number of attempts bounded since we cannot stay here for ever.
		 */
		if (err == 1) {
			usleep(attempt_wait);
			attempt_wait += attempt_wait;
		}
	}
	/* Make sure we don't leak memory */
	destroy_radpcap_packet(packet);

	/* Error, something wrong worth killing everything */
	if (err == -1)
		return (-1);

	/* Nothing to do, no need to attempt to get a stamp from the stamp queue */
	if (err == 1)
		return (1);

	/* At least one stamp in the queue, go and get it. Should not fail but... */
	err = get_stamp_from_queue(peer->q, stamp);
	if (err)
		return (1);

	verbose(VERB_DEBUG, "Popped stamp queue: %llu %.6Lf %.6Lf %llu %llu",
			(long long unsigned) BST(stamp)->Ta, BST(stamp)->Tb, BST(stamp)->Te,
			(long long unsigned) BST(stamp)->Tf, (long long unsigned) stamp->id);

	/* Monitor change in server: logging and quality warning flag */
	if ((peer->ttl != stamp->ttl) || (peer->leapsec != stamp->leapsec) ||
			(peer->refid != stamp->refid) || (peer->stratum != stamp->stratum)) {
		if (stamp->qual_warning == 0)
			stamp->qual_warning = 1;

		c = (char *) &(stamp->refid);
		if (stamp->stratum == STRATUM_REFPRIM)
			snprintf(refid, 16, "%c%c%c%c", *(c+3), *(c+2), *(c+1), *(c+0));
		else
			snprintf(refid, 16, "%i.%i.%i.%i", *(c+3), *(c+2), *(c+1), *(c+0));
		verbose(LOG_WARNING, "New NTP server info on packet %u:",
				stats->ref_count);
		verbose(LOG_WARNING, "SERVER: %s, STRATUM: %d, TTL: %d, ID: %s, "
				"LEAP: %u", stamp->server_ipaddr, stamp->stratum, stamp->ttl,
				refid, stamp->leapsec);
	}

	/* Store the server refid will pass on to our potential NTP clients */
	// TODO do we have to keep this in both structures ?
	// TODO: the SERVER_DATA one should not be the refid but the peer's IP
	SERVER_DATA(clock)->refid = stamp->refid;
	peer->refid = stamp->refid;
	peer->ttl = stamp->ttl;
	peer->stratum = stamp->stratum;
	peer->leapsec = stamp->leapsec;

	/* Record NTP protocol specific values but only if not crazy */
	if ((stamp->stratum > STRATUM_REFCLOCK) && (stamp->stratum < STRATUM_UNSPEC) &&
			(stamp->leapsec != LEAP_NOTINSYNC)) {
		SERVER_DATA(clock)->stratum = stamp->stratum;
		SERVER_DATA(clock)->rootdelay = stamp->rootdelay;
		SERVER_DATA(clock)->rootdispersion = stamp->rootdispersion;
		verbose(VERB_DEBUG, "Received pkt stratum= %u, rootdelay= %.9f, "
				"roodispersion= %.9f", stamp->stratum, stamp->rootdelay,
				stamp->rootdispersion);
	}

	return (0);
}

