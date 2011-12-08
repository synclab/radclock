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





/*
 * Network level functions called by main to get packet data
 * 
 * This file contains the functions required to extract or process data from 
 * a given source (live capture or trace file; ascii do not need).
 * The first set of functions implemented here are given a radpcap_packet 
 * (or higher network protocol layers) and are used to extract data (e.g ntp
 * payload, vcount stored in ethernet header, etc.)
 * The second key part is the actual processing of these data by the 
 * get_bidir_stamp() fucntion.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <assert.h>
#include <pcap.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <string.h>
#include <math.h>
#include <syslog.h>

#include "../config.h"
#include <radclock.h>
#include "radclock-private.h"
#include "verbose.h"
#include "proto_ntp.h"
#include "sync_algo.h"        /* Because need  struct bidir_stamp defn */
#include "pthread_mgr.h"
#include "create_stamp.h"
#include "ntohll.h"
#include "jdebug.h"



# ifndef useconds_t
typedef uint32_t useconds_t;
# endif



/* Converts fixedpt NTP timestamp structure to an easily manipulable TS in [sec] */
long double  ntpTS_to_UNIXsec(l_fp ntpTS) 
{
	long double  sec;
	sec  = (long double)(ntohl(ntpTS.l_int) - JAN_1970);
	sec += (long double)(ntohl(ntpTS.l_fra))/4294967296.0; // 
	return(sec);
}



radpcap_packet_t* create_radpcap_packet() {
	radpcap_packet_t *pkt = NULL;

	pkt = (radpcap_packet_t*) malloc(sizeof(radpcap_packet_t));
	JDEBUG_MEMORY(JDBG_MALLOC, pkt);

	pkt->buffer 	= (void *) malloc(RADPCAP_PACKET_BUFSIZE);
	JDEBUG_MEMORY(JDBG_MALLOC, pkt->buffer);

	pkt->header 	= NULL;
	pkt->payload 	= NULL;
	pkt->type 		= 0;
	pkt->size 		= 0;
	return pkt;
}

void destroy_radpcap_packet(radpcap_packet_t *packet) 
{
	JDEBUG

	packet->header  = NULL;
	packet->payload = NULL;
	if (packet->buffer)
	{
		JDEBUG_MEMORY(JDBG_FREE, packet->buffer);
		free(packet->buffer);
	}
	packet->buffer  = NULL;

	JDEBUG_MEMORY(JDBG_FREE, packet);
	free(packet);
	packet = NULL;
}


/* Get the length of packet capured */
inline unsigned int get_capture_length(radpcap_packet_t *packet) {
	assert(packet->size<65536);
	return ((struct pcap_pkthdr*)packet->header)->caplen;
}


/* Get the IP payload from the radpcap_packet_t packet.
 * Here also (in addition to get_vcount) we handle backward compatibility since we
 * changed the way the vcount and the link layer header are managed. 
 * We handle 3 formats:
 * 1- [pcap][ether][IP] : oldest format (vcount in pcap header timeval)
 * 2- [pcap][sll][ether][IP] : libtrace-3.0-beta3 format, vcount is in sll header
 * 3- [pcap][sll][IP] : remove link layer header, no libtrace, vcount in sll header
 * In live capture, the ssl header MUST be inserted before calling this function
 */
struct ip* get_ip (radpcap_packet_t *packet, unsigned int *remaining) {

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



struct udphdr* get_udp_from_ip(struct ip *ipptr, unsigned int *remaining) 
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


void *get_udp_payload(struct udphdr *udp, unsigned int *remaining)
{
    if (remaining) {
        if (*remaining < sizeof(struct udphdr))
            return NULL;
        *remaining -= sizeof(struct udphdr);
    }
    return (void*)((char*)udp+sizeof(struct udphdr));
}


/* Retrieve the vcount value stored in the pcap header timestamp field.
 * This function is here for backward compatibility and may disappear one day,
 * especially because the naming convention is confusing. The ethernet frame is
 * used only for distinguishing the first raw file format.
 */
int get_vcount_from_etherframe(radpcap_packet_t *packet, vcounter_t *vcount)
{
	if (packet->size < sizeof(struct pcap_pkthdr)) {
		verbose(LOG_ERR, "No PCAP header found.");
		return -1;
	}
		   
	// TODO : Endianness !!!!
	/* This is the oldest raw file format where the vcount was stored into the
	 * timestamp field of the pcap header.
	 * tv_sec holds the left hand of the counter, then put right hand of the 
	 * counter into empty RHS of vcount
	 */
	*vcount  = (u_int64_t) (((struct pcap_pkthdr*)packet->header)->ts.tv_sec) << 32;
	*vcount += (u_int32_t) ((struct pcap_pkthdr*)packet->header)->ts.tv_usec;

	return 0;
}



/* Retrieve the vcount value from the address field of the LINUX SLL
 * encapsulation header
 */
int get_vcount_from_sll(radpcap_packet_t *packet, vcounter_t *vcount)
{
	vcounter_t aligned_vcount;

	if (packet->size < sizeof(struct pcap_pkthdr) + sizeof(linux_sll_header_t)) {
		verbose(LOG_ERR, "No PCAP or SLL header found.");
		return -1;
	}
	
	linux_sll_header_t *hdr = packet->payload;
	if (!hdr)
	{
		verbose(LOG_ERR, "No SLL header found.");
		return -1;
	}
	/* memcopy to ensure word alignedness and avoid potential sigbus's */
	memcpy(&aligned_vcount, hdr->addr, sizeof(vcounter_t));
	*vcount = ntohll(aligned_vcount);
	
	return 0;
}



/* Generic function to retrieve the vcount. Depending on the link layer type it
 * calls more specific one. This ensures backward compatibility with older format
 */
int get_vcount(radpcap_packet_t *packet, vcounter_t *vcount) {

	int ret = -1;
	
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







/*
 * Look for client-server NTP packet pairs and extract timestamps and some 
 * server and route state information, convert and store in stamp structure
 * for sync algorithms.  This bidirectional version expects client-server 
 * interaction, it looks for NTP's MODE_CLIENT or MODE_SERVER codes (ntp.h) and
 * encodes the departure timestamp at the client as a very likely unique key 
 * for matching the returning server pkt.  Bpf filter already only passing NTP
 * pkts matching host IP address.  If inappropriate in other ways then they are 
 * discarded. If dangerous but not fatal conditions are detected, abstracted as
 * simple warning to algos (see below for details).  
 * - Could be extended to handle bpf based uni-directional case (eg using 
 *   MODE_BROADCAST), but dedicated unidir version probably preferable.  
 * - As it is called once per pair, an argument pointer is passed to keep track
 *   of stats like number of pkts/pairs rejected.
 * - Detects leapseconds and allows main to keep track of leapsec total. Leap 
 *   seconds removed from server stamps to avoid giving a spurious jump to 
 *   process_bidir_stamp, reinstated in main after.
 *
 * Return values:
 *  0: found matching packets, returns timestamp
 * -1: nothing to process anymore or no match found
 */
int get_bidir_stamp(struct radclock *handle,
			void * userdata,
			int (*get_packet)(struct radclock *handle, void *user, radpcap_packet_t **packet),
			struct stamp_t *stamp,
			uint64_t *stamp_id,
			struct timeref_stats *stats,
			char *src_ipaddr
			)
{
	JDEBUG

	vcounter_t vcount = 0;					// PKT capture level:  raw vcount timestamp from pkt capture header
	struct ntp_pkt *ntp; 				// NTP packet ... fun name for a packet structure ... pfff
	u_int64_t key_request = 0; 				// NTP level: for matching client and server pkts
	u_int64_t key_reply = 1; 				// NTP level: for matching client and server pkts
	static u_int32_t prev_serverid = 0; 	// NTP level: for checking change in server
	static long  prev_ttl = -1; 	// IP level:  for detecting route changes
	int searching = 1;
	int found_client = 0;
	int port = 0;
	int err = 0;

	/* Initial waiting time calibrated for LAN RTT, and max of 525.5 ms after 20
	 * attempts. If we wait for that long, the server may never reply
	 */
	int attempt = 20;
	unsigned int attempt_wait = 500;

	char refid[16];
	char *refid_str = refid;
	char *refid_char = NULL;

	struct ip *ip;
	struct udphdr *udp;
	unsigned int remaining;

	radpcap_packet_t *packet = create_radpcap_packet();
	memset(stamp, 0, sizeof (struct stamp_t));


/* search until a matching, valid client-server pair is found */
while (searching) {

	/* Re-initialise packet inspectors */
	ip = NULL;
	udp = NULL;
	remaining = 0;
	*stamp_id = 0;

	/* We may loop in here for a long time, break if received a TERM signal */
	if ((handle->pthread_flag_stop & PTH_DATA_PROC_STOP) == PTH_DATA_PROC_STOP )
	{
		err = -2;
		break;
	}

	/* Read the next captured packet.
	 * Note:  0 on success (found a packet)
	 *     : -1 the rdb list is empty
	 */
	err = get_packet(handle, userdata, &packet);
	if (err < 0)
	{
		/* We are replaying a trace, reached the end of data file. */
		if (handle->run_mode == RADCLOCK_SYNC_DEAD) 
		{
			err = -1;
			break;
		}
		/* Running live, no more pkts in the buffer and no client packet found.
		 * Signal uppper loop to break out and come back later.
		 * If a client has been found but no server packet or the server packet
		 * has been discarded (since still searching), the stamp structure is 
		 * bogus. Give up on that client, but signal the caller it can keep looking
		 */
		if (found_client == 0)
		{
			err = -1;
			break;
		}

		/* Here we found a client packet, but no server packet and the buffer is
		 * empty. 2 cases:
		 * - we are piggy backing and been awaken at a bad time
		 * - the trigger thread timed out and woke us up, but the server hasn't
		 *   replied yet (ie, timeout < RTT).
		 * In both cases we don't want to return and loose the client packet.
		 * Keep the wakeup_mutex, sleep a bit and give the server some time.
		 * Eventually, we give up on it.
		 */
		if ( attempt == 0 )
		{
			verbose(LOG_NOTICE, "No valid server reply after 500ms, giving up");
			err = -1;
			break;
		}
		verbose(VERB_DEBUG, "Buffer empty but keep looking (sleep %u)", attempt_wait);
		usleep((useconds_t)attempt_wait);
		/* The RTT can be quite large let's say a top of 500ms so add bigger and
		 * bigger chunks 20 times for napping
		 */
		attempt_wait += 2500;
		attempt--;
		continue;
	}

	/* Counts pkts, regardless of content (initialised to 0 in main) */
	stats->ref_count++;


	/* Retrieve vcount from link layer header, if this fails, things are bad */
	if (get_vcount(packet, &vcount)) {
		verbose(LOG_ERR, "Error getting raw vcounter from link layer.\n");
		err = -1;
		break;
	}
	
	/* Descend into IP[UDP[NTP]] pkt to get NTP data */
	remaining = get_capture_length(packet);
	ip = get_ip(packet, &remaining);
	if (!ip) {
		verbose(LOG_WARNING, "Not an IP packet.");
		continue;
	}
	
	udp = get_udp_from_ip(ip, &remaining);
	if (!udp) {
		verbose(LOG_WARNING, "Not an UDP packet.");
		continue;
	}

	ntp = get_udp_payload(udp, &remaining);
	if (!ntp) {
		verbose(LOG_WARNING, "Not an NTP packet.");
		continue;
	}

	/* 
	 * Here, we only want to check there is enough data to keep processing. A
	 * normal NTP packet is at least 48 bytes long, but a control or private
	 * request is as small as 12 bytes.
	 */ 
	if ( remaining < 12 ) {
		verbose(LOG_WARNING, "NTP packet truncated, payload is %d bytes "
				"instead of at least 12 bytes", remaining);
		continue;
	}

	/* Perform matching between client pkt and server reply pair, and testing. 
	Pairs ignored if:   
	server not stratum-0 or 1  
	mode is not MODE_CLIENT or MODE_SERVER  (from client or server)
	leap mode is ALARM, a signal that the 0erver is unsynchonised
	unmatched client pkts  (lost replies or unexpected pkts from any server)  
	very late (out of order) replies  (next client pkt will overwrite)
	Pair accepted but warning passed to sync algos via stamp structure if:
	server id changes    (if someone changes target server)
	TTL change in reply IP pkt (could mean route and therefore minRTT change)
	*/

	// stratum doesn't matter there, not the server
	// need key different for each pkt, careful if pkt not generated by SW-NTP
	
	switch (PKT_MODE(ntp->li_vn_mode)) {

	case MODE_BROADCAST:
		verbose(VERB_DEBUG,"Received NTP broadcast packet from %s (Silent discard)",
						inet_ntoa(ip->ip_src));
		break;


	case MODE_CLIENT:

		verbose(VERB_DEBUG, "Found a CLIENT NTP packet");

		/* Possible we receive ntp requests. But should not handle this kind of
		 * packets. This case should not be triggered since the bpf filter
		 * string makes a tight filter. But in case of a loose configuration ...
		 */
		if ( strcmp(inet_ntoa(ip->ip_dst), src_ipaddr) == 0) {
			verbose(LOG_WARNING, "Dst address in a client packet, check the capture filter.");
			break;
		}

		/* Create the key based on Ta to match reply from server
		 * Be sure we convert to host representation before creating the key.
		 * Also work with 64 bits entities to avoid stupid result
		 */
		key_request = ((uint64_t)ntohl(ntp->xmt.l_int)) << 32;
		key_request |= (uint64_t) ntohl(ntp->xmt.l_fra);
		found_client = 1;
		
		/* Store vcount from the lower layer */
		BST(stamp)->Ta = vcount;

		break;



	case MODE_SERVER:

		err = 0;

		verbose(VERB_DEBUG, "Found a SERVER NTP packet");

		/* We start with all possible conditions to reject packet */

		/* Possible we answer ntp requests. But should not handle this kind of 
		 * packets. This case should not be triggered since the bpf filter string
		 * makes a tight filter. But in case of a loose configuration ...
		 */
		if ( strcmp(inet_ntoa(ip->ip_src), src_ipaddr) == 0) {
			verbose(LOG_WARNING, "Src address in a server packet");
			break;
		}
							
		/* If the server is unsynchronised we skip this packet */
		if ( PKT_LEAP(ntp->li_vn_mode) == LEAP_NOTINSYNC )
		{
			verbose(LOG_WARNING, "NTP server says LEAP_NOTINSYNC, packet ignored.");
			stats->badqual_count++;
			break;
		}

		/* Check the packet corresponding to the server reply matches the client
		 * request we sent. Again, works on host representation 64 bits
		 * containers.
		 */
		key_reply = ((uint64_t) ntohl(ntp->org.l_int)) << 32;
		key_reply |= (uint64_t) ntohl(ntp->org.l_fra);
		if (key_request != key_reply) {
			verbose(VERB_DEFAULT, "key_request (%llu) and key_reply (%llu) do "
					"not match on %d th NTP packet, server packet ignored", 
					key_request, key_reply, stats->ref_count);
			break;
		}

		/* The key matches so we have a valid pair */
		*stamp_id = key_reply;

		/* Check if the server clock is synchroninsed or not */
		if ( ntp->stratum == STRATUM_UNSPEC )
		{
			verbose(LOG_WARNING, "Stratum unspecified, server packet ignored.");
			break;
		}

		/* We passed all sanity checks, so now monitor route changes etc */

		/* The refid field has a different interpretation depending on the stratum.
		 * We should also take into account IPv4 vs. IPv6 ... one day maybe
		 */
		refid_char = (char*) &(ntp->refid);
		if (ntp->stratum == STRATUM_REFPRIM) {
			snprintf(refid_str, 16, "%c%c%c%c", 
			*refid_char, *(refid_char+1), *(refid_char+2), *(refid_char+3)); 
		}
		else {
			snprintf(refid_str, 16, "%i.%i.%i.%i", 
			*refid_char, *(refid_char+1), *(refid_char+2), *(refid_char+3)); 
		}
		refid_char = NULL;

		if ( 	( ((struct bidir_output*)handle->algo_output)->n_stamps == 0 )
			|| 	( ip->ip_ttl != prev_ttl )
			|| 	( ntp->refid != prev_serverid )) 
		{
			verbose(LOG_WARNING, "New NTP server info on packet %u:", stats->ref_count);
			verbose(LOG_WARNING, "SERVER - IP: %s, STRATUM: %d, TTL: %lu, ID: %s, MODE: %u, LEAPINFO: %u",
				inet_ntoa(ip->ip_src), ntp->stratum, ip->ip_ttl, refid_str, 
				PKT_MODE(ntp->li_vn_mode), PKT_LEAP(ntp->li_vn_mode));
			verbose(LOG_WARNING, "HOST   - IP: %s, DST_PORT: %d", inet_ntoa(ip->ip_dst), port);

			/* warn of possible change in route or server, or unsync server */
			if (stamp->qual_warning == 0)
				stamp->qual_warning = 1;
		}

		/* Store the server refid will pass on to our potential NTP clients */
		memcpy(&(SERVER_DATA(handle)->refid), &(ip->ip_src), sizeof(in_addr_t));


		/* Store timestamps */
		BST(stamp)->Tb = ntpTS_to_UNIXsec(ntp->rec);
		BST(stamp)->Te = ntpTS_to_UNIXsec(ntp->xmt);   // xmt is now xmt'ed from server
		BST(stamp)->Tf = vcount;

		/* Record type */
		stamp->type = STAMP_NTP;


		/* Make leap second adjustments 
		 * Detect when first past a new leap second change, record total
		 */
		switch ( PKT_LEAP(ntp->li_vn_mode) )
		{
			case LEAP_ADDSECOND:
				((struct bidir_output*)handle->algo_output)->leapsectotal+=1;
				verbose(LOG_WARNING, "Leap second change!! leapsecond total is now %d",
					((struct bidir_output*)handle->algo_output)->leapsectotal);
				break;
			case LEAP_DELSECOND:
				((struct bidir_output*)handle->algo_output)->leapsectotal-=1;
				verbose(LOG_WARNING, "Leap second change!! leapsecond total is now %d",
					((struct bidir_output*)handle->algo_output)->leapsectotal);
				break;
			case LEAP_NOTINSYNC:
			case LEAP_NOWARNING:
			default:
				break;
		}
		/* Remove total detected leapseconds from UNIX timestamps taken 
		 * from server if clock jumps back, this brings it forward again */
		BST(stamp)->Tb += ((struct bidir_output*)handle->algo_output)->leapsectotal;
		BST(stamp)->Te += ((struct bidir_output*)handle->algo_output)->leapsectotal;

		/* If we passed all of this, update tracking of previous values and 
		 * then we're all good and can stop searching 
		 */
		prev_ttl 		= ip->ip_ttl;
		prev_serverid 	= ntp->refid;
		found_client	= 0;
		searching 		= 0;

		/* Record NTP protocol specific values but only if not crazy */
		if (   (ntp->stratum > STRATUM_REFCLOCK)
			&& (ntp->stratum < STRATUM_UNSPEC)	
			&& (PKT_LEAP(ntp->li_vn_mode) != LEAP_NOTINSYNC) )
		{
			SERVER_DATA(handle)->stratum 		= ntp->stratum;
			SERVER_DATA(handle)->rootdelay 		= ntohl(ntp->rootdelay) / 65536.;
			SERVER_DATA(handle)->rootdispersion = ntohl(ntp->rootdispersion) / 65536.;
			verbose(VERB_DEBUG, "Received pkt stratum= %u, rootdelay= %.9f, roodispersion= %.9f",
				   	SERVER_DATA(handle)->stratum, SERVER_DATA(handle)->rootdelay, SERVER_DATA(handle)->rootdispersion);
		}

		break;

	default:
		// `silent' cause is lost server pkt
		verbose(VERB_DEBUG,"Missed pkt due to invalid mode: mode = %d", PKT_MODE(ntp->li_vn_mode));
		break;
	} // switch

}  // While (searching)

	destroy_radpcap_packet(packet);

	return err;
}

