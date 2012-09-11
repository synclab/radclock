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

#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in_systm.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../config.h"
#include "radclock.h"
#include "radclock-private.h"
#include "radclock_daemon.h"
#include "verbose.h"
#include "proto_ntp.h"
#include "sync_history.h"        /* Because need  struct bidir_stamp defn */
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


int
check_ipv4(struct ip *iph, int remaining)
{
	if (iph->ip_v != 4) {
		verbose(LOG_WARNING, "Failed to parse IPv4 packet");
		return (1);
	}

	if ((iph->ip_off & 0xff1f) != 0) {
		verbose(LOG_WARNING, "Fragmented IP packet");
		return (1);
	}

	if (iph->ip_p != 17) {
		verbose(LOG_WARNING, "Not a UDP packet");
		return (1);
	}

	if (remaining < (iph->ip_hl * 4U)) {
		verbose(LOG_WARNING, "Broken IP packet");
		return (1);
	}

	return (0);
}


// TODO should there be more to do?
int
check_ipv6(struct ip6_hdr *ip6h, int remaining)
{
	if (ip6h->ip6_nxt != 17) {
		verbose(LOG_ERR, "IPv6 packet with extensions no supported");
		return (1);
	}

	if (remaining < 40) {
		verbose(LOG_WARNING, "Broken IP packet");
		return (1);
	}

	return (0);
}


/*
 * Get the IP payload from the radpcap_packet_t packet.  Here also (in addition
 * to get_vcount) we handle backward compatibility since we changed the way the
 * vcount and the link layer header are managed.
 *
 * We handle 3 formats (historical order):
 * 1 - [pcap][ether][IP] : oldest format (vcount in pcap header timeval)
 * 2 - [pcap][sll][ether][IP] : libtrace-3.0-beta3 format, vcount is in sll header
 * 3 - [pcap][sll][IP] : remove link layer header, no libtrace, vcount in sll header
 * In live capture, the ssl header MUST be inserted before calling this function
 * Ideally, we would like to get rid of formats 1 and 2 to simplify the code.
 */
// TODO and for non NTP packets? (ie 1588)
// FIXME: the ip pointer is dirty and will break with IPv6 packets
int
get_valid_ntp_payload(radpcap_packet_t *packet, struct ntp_pkt **ntp,
		struct sockaddr_storage *ss_src, struct sockaddr_storage *ss_dst,
		int *ttl)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct ip *iph;
	struct ip6_hdr *ip6h;
	struct udphdr *udph;
	linux_sll_header_t *sllh;
	uint16_t proto;
	int remaining;
	int err;

	JDEBUG

	remaining = ((struct pcap_pkthdr *)packet->header)->caplen;

	switch (packet->type) {

	/*
	 * This is format #1, skip 14 bytes ethernet header. Only NTP packets ever
	 * captured in this format are IPv4
	 */
	case DLT_EN10MB:
		iph = (struct ip *)(packet->payload + sizeof(struct ether_header));
		remaining -= sizeof(struct ether_header);
		ip6h = NULL;
		break;

	/*
	 * This is format #2 and #3. Here we take advantage of a bug in bytes order in
	 * libtrace-3.0-beta3 to identify the formats.
	 * - if sllh->hatype = ARPHRD_ETHER (0x0001), we have format 3.
	 * - if sllh->hatype is 256 (0x0100) it's a libtrace format.
	*/
	case DLT_LINUX_SLL:
		sllh = (linux_sll_header_t*) packet->payload;

		/* Format #2 */
		if (ntohs(sllh->hatype) != 0x0001) {
			iph = (struct ip *)(packet->payload + sizeof(struct ether_header) +
					sizeof(linux_sll_header_t));
			remaining -= sizeof(struct ether_header);
			ip6h = NULL;
			break;
		}

		/* This is format 3 */
		proto = ntohs(sllh->protocol);
		switch (proto) {

		/* IPv4 */
		case (ETHERTYPE_IP):
			ip6h = NULL;
			iph = (struct ip *)(packet->payload + sizeof(linux_sll_header_t));
			remaining -= sizeof(linux_sll_header_t);

			err = check_ipv4(iph, remaining);
			if (err)
				return (1);

			ss_src->ss_family = AF_INET;
			ss_dst->ss_family = AF_INET;
			sin = (struct sockaddr_in *)ss_src;
			sin->sin_addr = iph->ip_src;
			sin = (struct sockaddr_in *)ss_dst;
			sin->sin_addr = iph->ip_dst;
			*ttl = iph->ip_ttl;

			udph = (struct udphdr *)((char *)iph + (iph->ip_hl * 4));
			remaining -= sizeof(struct ip);
			break;

		/* IPv6 */
		case (ETHERTYPE_IPV6):
			iph = NULL;
			ip6h = (struct ip6_hdr *)(packet->payload + sizeof(linux_sll_header_t));
			remaining -= sizeof(linux_sll_header_t);

			err = check_ipv6(ip6h, remaining);
			if (err)
				return (1);

			ss_src->ss_family = AF_INET6;
			ss_dst->ss_family = AF_INET6;
			sin6 = (struct sockaddr_in6 *)ss_src;
			sin6->sin6_addr = ip6h->ip6_src;
			sin6 = (struct sockaddr_in6 *)ss_dst;
			sin6->sin6_addr = ip6h->ip6_dst;
			*ttl = ip6h->ip6_hops;

			udph = (struct udphdr *)((char *)ip6h + sizeof(struct ip6_hdr));
			remaining -= sizeof(struct ip6_hdr);
			break;

		/* IEEE 1588 over Ethernet */
		case (0x88F7):
			verbose(LOG_ERR, "1588 over Ethernet not implemented");
			return (1);

		default:
			verbose(LOG_ERR, "Unsupported protocol in SLL header %u", proto);
			return(1);
		}
		break;

	default:
		verbose(LOG_ERR, "MAC layer type not supported yet.");
		return (1);
		break;
	}

	if (remaining < sizeof(struct udphdr)) {
		verbose(LOG_WARNING, "Broken UDP datagram");
		return (1);
	}

	*ntp = (struct ntp_pkt *)((char *)udph + sizeof(struct udphdr));
	remaining -= sizeof(struct udphdr);

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

	return (0);
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
	struct stq_elt *elt, *prev;

	prev = NULL;
	elt = peer->q->end;

	while (peer->q->size > 1) {
		prev = elt->prev;
		free(elt);
		elt = prev;
		peer->q->size--;
	}

	free(prev);
	free(peer->q);
	peer->q = NULL;
}



/*
 * Swap two stamp queue elements in the same queue if rank ordering has been
 * broken. Called recursively until order restored.  This assumes that only one
 * element is at a wrong position.
 */
void
fix_queue_order(struct stamp_queue *q, struct stq_elt *stq)
{
	struct stq_elt *tmp;

	if (stq->next != NULL) {
		tmp = stq->next;
		/* Swap elements if stq->next is younger than stq. */
		if (stq->stamp.rank < tmp->stamp.rank) {
			if (stq->prev != NULL)
				stq->prev->next = tmp;
			if (tmp->next != NULL)
				tmp->next->prev = stq;
			tmp->prev = stq->prev;
			stq->next = tmp->next;
			tmp->next = stq;
			stq->prev = tmp;
			if (q->start == stq)
				q->start = tmp;
			if (q->end == tmp)
				q->end = stq;
			return (fix_queue_order(q, stq));
		}
	}

	if (stq->prev != NULL) {
		tmp = stq->prev;
		/* Swap elements if stq->prev is older than stq. */
		if (stq->stamp.rank > tmp->stamp.rank) {
			if (stq->next != NULL)
				stq->next->prev = tmp;
			if (tmp->prev != NULL)
				tmp->prev->next = stq;
			tmp->next = stq->next;
			stq->prev = tmp->prev;
			stq->next = tmp;
			tmp->prev = stq;
			if (q->start == tmp)
				q->start = stq;
			if (q->end == stq)
				q->end = tmp;
			return (fix_queue_order(q, stq));
		}
	}
}


/*
 * Insert a client or server NTP packet into the stamp queue. This routine
 * effectively pairs matching requests and replies. The stamp queue has been
 * introduced to allow matching of out of order NTP packets.
 * If no matching stamp is found, the new packet is inserted with partial
 * information. If a matching partial stamp exists, missing information is added
 * to the stamp.
 *
 * Quick algo ideas:
 * - use the full walk to find half-baked stamp.
 * - if was half-baked stamp, update rank and re-order queue if needed
 *   (note that rank defined as receiving stamp, outgoing packets in two-way
 *   requests will see their rank change).
 */
int
insert_stamp_queue(struct stamp_queue *q, struct stamp_t *new, int mode)
{
	struct stq_elt *stq, *insert, *halfstamp;
	struct stamp_t *stamp;

	JDEBUG

	if ((mode != MODE_CLIENT) && (mode != MODE_SERVER)) {
		verbose(LOG_ERR, "Unsupported NTP packet mode: %d", mode);
		return (-1);
	}

	/*
	 * Parse the queue to either find a half-baked stamp. If no matching stamp
	 * is found, mark a position to insert the new stamp to the left of. From
	 * start to end, the queue is ordered from young (higher ID) to old (lower
	 * ID). IDs increment as time passes.  Locate a place in the queue to place
	 * the new stamp.
	 */
	halfstamp = NULL;
	insert = NULL;
	stq = q->start;
	while (stq != NULL) {
		stamp = &stq->stamp;
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
		}

		/* Found half-baked stamp to finish filling */
		if (stamp->id == new->id) {
			halfstamp = stq;
			break;
		}
		/* Mark the first encounter with a stamp older than new. */
		if (insert == NULL && (new->rank > stamp->rank)) {
			insert = stq;
		}
		stq = stq->next;
	}

	/*
	 * Haven't found an existing server stamp, which is quite normal. Create a
	 * new stamp and insert it in the peer queue structure.
	 */
	if (halfstamp == NULL) {
		if (q->size == MAX_STQ_SIZE) {
			verbose(LOG_WARNING, "Peer stamp queue has hit max size. "
					"Check the server?");
			if (insert == q->end)
				insert = NULL;
			q->end = q->end->prev;
			free(q->end->next);
			q->end->next = NULL;
			q->size--;
		}

		/*
		 * Create new stamp queue element and insert in the queue.  Packets may
		 * have been received out of order (low probability) and bidir-stamp
		 * replies change the rank of half-baked stamp.  Both cases handled by
		 * reordering the queue once data is updated, but we can save time if we
		 * put the packet at about the right place.
		 */
		stq = (struct stq_elt *) calloc(1, sizeof(struct stq_elt));
		stq->prev = NULL;
		stq->next = NULL;
		/* Common case, new stamp is inserted to the left of insert. */
		if (insert != NULL) {
			if (q->start == insert)
				q->start = stq;
			stq->next = insert;
			stq->prev = insert->prev;
			if (insert->prev) {
				insert->prev->next = stq;
				insert->prev = stq;
			}
		}
		/*
		 * No insert mark, because it was either not found, or the queue hit max
		 * size or the queue is empty. In all cases, new has to be inserted at
		 * the end.
		 */
		else {
			if (q->size == 0) {
				q->start = stq;
				q->end = stq;
			}
			else {
				stq->prev = q->end;
				q->end->next = stq;
				q->end = stq;
			}
		}
		q->size++;
	}
	else
		stq = halfstamp;

	/* Selectively copy content of new stamp over */
	stamp = &stq->stamp;
	stamp->type = STAMP_NTP;
	stamp->rank = new->rank;
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

	/* Rank of half baked-stamp may have changed, fix queue order */
	fix_queue_order(q, stq);

	/* Verbose queue print out */
	stq = q->start;
	while (stq != NULL) {
		stamp = &stq->stamp;
		verbose(VERB_DEBUG, "  stamp queue: %llu %.6Lf %.6Lf %llu %llu",
				(long long unsigned) BST(stamp)->Ta, BST(stamp)->Tb, BST(stamp)->Te,
				(long long unsigned) BST(stamp)->Tf, (long long unsigned) stamp->id);
		stq = stq->next;
	}

	if (halfstamp)
		return (0);
	else
		return (1);
}


int
compare_sockaddr_storage(struct sockaddr_storage *first,
		struct sockaddr_storage *second)
{
	if (first->ss_family != second->ss_family)
		return (1);

	if (first->ss_family == AF_INET) {
		if (memcmp(&(((struct sockaddr_in *) first)->sin_addr),
				&(((struct sockaddr_in *) second)->sin_addr),
				sizeof(struct in_addr)) == 0)
			return (0);
	}
	// address family is AF_INET6
	else {
		if (memcmp(&(((struct sockaddr_in6 *) first)->sin6_addr),
				&(((struct sockaddr_in6 *) second)->sin6_addr),
				sizeof(struct in6_addr)) == 0)
			return (0);
	}

	return (1);
}

int
is_loopback_sockaddr_storage(struct sockaddr_storage *ss)
{
	struct in_addr *addr;
	struct in6_addr *addr6;

	if (ss->ss_family == AF_INET) {
		addr = &((struct sockaddr_in *)ss)->sin_addr;
		if (addr->s_addr == htonl(INADDR_LOOPBACK))
			return (1);
	} else {
		addr6 = &((struct sockaddr_in6 *)ss)->sin6_addr;
		if (IN6_IS_ADDR_LOOPBACK(addr6))
			return (1);
	}

	return (0);
// Not sure where to put this at the moment or a cleaner way
#define NOXENSUPPORT 0x01

}

/*
 * Check the client's request.
 * The radclock may serve NTP clients over the network. The BPF filter may not
 * be tight enough either. Make sure that requests from clients are discarded.
 */
int
bad_packet_client(struct ntp_pkt *ntp, struct sockaddr_storage *ss_if,
		struct sockaddr_storage *ss_dst, struct timeref_stats *stats)
{
	int err;

	err = compare_sockaddr_storage(ss_if, ss_dst);
	if (err == 0) {
		if (!is_loopback_sockaddr_storage(ss_dst)) { 
			verbose(LOG_WARNING, "Destination address in client packet. "
					"Check the capture filter.");
			return (1);
		}
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
bad_packet_server(struct ntp_pkt *ntp, struct sockaddr_storage *ss_if,
		struct sockaddr_storage *ss_src, struct timeref_stats *stats)
{
	int err;

	err = compare_sockaddr_storage(ss_if, ss_src);
	if (err == 0) {
		if (!is_loopback_sockaddr_storage(ss_src)) { 
			verbose(LOG_WARNING, "Source address in server packet. "
					"Check the capture filter.");
			return (1);
		}
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
	stamp.rank = (uint64_t)*vcount;
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
push_stamp_server(struct stamp_queue *q, struct ntp_pkt *ntp,
		vcounter_t *vcount, struct sockaddr_storage *ss_src, int *ttl)
{
	struct stamp_t stamp;

	JDEBUG

	stamp.type = STAMP_NTP;
	stamp.id = ((uint64_t) ntohl(ntp->org.l_int)) << 32;
	stamp.id |= (uint64_t) ntohl(ntp->org.l_fra);
	stamp.rank = (uint64_t)*vcount;

	// TODO not protocol independent. Getaddrinfo instead?
	if (ss_src->ss_family == AF_INET)
		inet_ntop(ss_src->ss_family,
			&((struct sockaddr_in *)ss_src)->sin_addr, stamp.server_ipaddr,
			INET6_ADDRSTRLEN);
	else
		inet_ntop(ss_src->ss_family,
			&((struct sockaddr_in6 *)ss_src)->sin6_addr, stamp.server_ipaddr,
			INET6_ADDRSTRLEN);

	stamp.ttl = *ttl;
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
		struct timeref_stats *stats)
{
	struct ntp_pkt *ntp;
	struct sockaddr_storage ss_src, ss_dst, *ss;
	vcounter_t vcount;
	int ttl;
	int err;
	char ipaddr[INET6_ADDRSTRLEN];

	JDEBUG

	/* Retrieve vcount from link layer header, if this fails, things are bad */
	if (get_vcount(packet, &vcount)) {
		verbose(LOG_ERR, "Error getting raw vcounter from link layer.\n");
		return (-1);
	}

	err = get_valid_ntp_payload(packet, &ntp, &ss_src, &ss_dst, &ttl);
	if (err) {
		verbose(LOG_WARNING, "Not an NTP packet.");
		return (1);
	}

	ss = &packet->ss_if;
	err = 0;
	switch (PKT_MODE(ntp->li_vn_mode)) {
	case MODE_BROADCAST:
		ss = &ss_src;
		if (ss->ss_family == AF_INET)
			inet_ntop(ss->ss_family,
				&((struct sockaddr_in *)&ss)->sin_addr, ipaddr, INET6_ADDRSTRLEN);
		else
			inet_ntop(ss->ss_family,
				&((struct sockaddr_in6 *)ss)->sin6_addr, ipaddr, INET6_ADDRSTRLEN);
		verbose(VERB_DEBUG,"Received NTP broadcast packet from %s (Silent discard)",
				ipaddr);
		break;

	case MODE_CLIENT:
		err = bad_packet_client(ntp, ss, &ss_dst, stats);
		if (err)
			break;
		err = push_stamp_client(q, ntp, &vcount);
		break;

	case MODE_SERVER:
		err = bad_packet_server(ntp, ss, &ss_src, stats);
		if (err)
			break;
		err = push_stamp_server(q, ntp, &vcount, &ss_src, &ttl);
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
	struct stq_elt *stq, *stq2;
	struct stamp_t *st;
	int qsize;

	JDEBUG

	/* Empty queue, won't find anything here */
	if (q->size == 0) {
		verbose (VERB_DEBUG, "stamp queue is empty, no stamp returned");
		return (1);
	}

	/* Start from the oldest stamps, at the end, with lowest id. */
	stq2 = NULL;
	stq = q->end;
	while (stq != NULL) {
		st = &stq->stamp;
		if ((BST(st)->Ta != 0) && (BST(st)->Tf != 0)) {
			memcpy(stamp, st, sizeof(struct stamp_t));
			stq2 = stq;
			break;
		}
		stq = stq->prev;
	}

	/* stq2 cannot be null if we do not return here. */
	if (stq2 == NULL) {
		verbose(VERB_DEBUG, "Did not find any full stamp in stamp queue");
		return (1);
	}

	/* Record queue size for later stats. */
	qsize = q->size;

	/* Clean the queue, fix the start and end queue pointer first. */
	q->end = stq2->prev;
	if (q->end != NULL)
		q->end->next = NULL;
	if (q->start == stq2)
		q->start = NULL;

	/* Remove the stamp we copied and all old unmatched stamps */
	stq = stq2;
	while (stq != NULL) {
		stq = stq->next;
		free(stq2);
		q->size--;
		stq2 = stq;
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
get_network_stamp(struct radclock_handle *handle, void *userdata,
	int (*get_packet)(struct radclock_handle *, void *, radpcap_packet_t **),
	struct stamp_t *stamp, struct timeref_stats *stats)
{
	struct bidir_peer *peer;
	radpcap_packet_t *packet;
	int attempt;
	int err;
	useconds_t attempt_wait;
	char *c;
	char refid [16];

	JDEBUG

	err = 0;
	attempt_wait = 500;					/* Loosely calibrated for LAN RTT */
	// TODO manage peeers better
	peer = handle->active_peer;
	packet = create_radpcap_packet();

	/*
	 * Used to have both live and dead PCAP inputs dealt the same way. But extra
	 * processing to give a chance to out-of-order packets make it too hard to
	 * keep the same path. Cases are decoupled below, the dead input does not
	 * need to sleep when reading PCAP file.
	 */
	switch(handle->run_mode) {

	/* Read packet from pcap tracefile. */
	case RADCLOCK_SYNC_DEAD:
		/*
		 * Error codes (although not used here):
		 * -2: reached end of input
		 * -1: read error
		 *  0: live capture error (should never happen)
		 */
		err = get_packet(handle, userdata, &packet);
		if (err)
			return (-1);

		/* Counts pkts, regardless of content (initialised to 0 in main) */
		stats->ref_count++;

		/*
		 * Convert packet to stamp and push it to the stamp queue, errors are:
		 * -1: Low level / input problem worth stopping, break with error code.
		 *  0: there is at least one valid full fledged stamp in the queue,
		 *     break with no error code -- do not want to fill the stamp queue
		 *     with the entire trace file.
		 *  1: inserted packet in queue, but did not pair it. Break with code to
		 *     be called again.
		 */
		err = update_stamp_queue(peer->q, packet, stats);
		switch (err) {
		case -1:
			verbose(LOG_ERR, "Stamp queue error");
			break;
		case  0:
			verbose(VERB_DEBUG, "Inserted packet and found match");
			break;
		case  1:
			verbose(VERB_DEBUG, "Inserted packet but no match");
			break;
		}
		break;

	/* Read packet from raw data queue or pcap tracefile. */
	case RADCLOCK_SYNC_LIVE:
		for (attempt=10; attempt>=0; attempt--) {
			/*
			 * Error codes:
			 * -1: run from tracefile and read error
			 * -1: read live and raw data buffer is empty
			 */
			err = get_packet(handle, userdata, &packet);
			if (err) {
				if (attempt == 0) {
					verbose(VERB_DEBUG, "Empty raw data buffer after all attempts "
							"(%.3f [ms])", attempt_wait / 1000.0);
					break;
				} else {
					usleep(attempt_wait);
					//attempt_wait += attempt_wait;
					continue;
				}
			}

			/* Counts pkts, regardless of content (initialised to 0 in main) */
			stats->ref_count++;

			/* Convert packet to stamp and push it to the stamp queue */
			err = update_stamp_queue(peer->q, packet, stats);

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
			 * to get the pair. Have been woken up by trigger thread, so only
			 * wait a little between 2 attempts.
			 */
			if (err == 1 && attempt % 2) {
				usleep(attempt_wait);
			}
		}
		break;
	
	case RADCLOCK_SYNC_NOTSET:
	default:
		verbose(LOG_ERR, "Run mode not set!");
		err = -1;
		break;
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
	// TODO: the NTP_SERVER one should not be the refid but the peer's IP
	NTP_SERVER(handle)->refid = stamp->refid;
	peer->refid = stamp->refid;
	peer->ttl = stamp->ttl;
	peer->stratum = stamp->stratum;
	peer->leapsec = stamp->leapsec;

	/* Record NTP protocol specific values but only if not crazy */
	if ((stamp->stratum > STRATUM_REFCLOCK) && (stamp->stratum < STRATUM_UNSPEC) &&
			(stamp->leapsec != LEAP_NOTINSYNC)) {
		NTP_SERVER(handle)->stratum = stamp->stratum;
		NTP_SERVER(handle)->rootdelay = stamp->rootdelay;
		NTP_SERVER(handle)->rootdispersion = stamp->rootdispersion;
		verbose(VERB_DEBUG, "Received pkt stratum= %u, rootdelay= %.9f, "
				"roodispersion= %.9f", stamp->stratum, stamp->rootdelay,
				stamp->rootdispersion);
	}

	return (0);
}

