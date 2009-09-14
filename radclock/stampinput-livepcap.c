/*
 * Copyright (C) 2006-2009 Julien Ridoux <julien@synclab.org>
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


/**
 * A stamp source for reading from live input
 * Also has the ability to create output
 */
#include "../config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <assert.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>


#ifdef HAVE_IFADDRS_H
# include <ifaddrs.h>
#else
# error Need ifaddrs.h or to go back to using the ioctl
#endif

#include <sync_algo.h>
#include <config_mgr.h>
#include <verbose.h>
#include <pcap.h>

#include <create_stamp.h>

#include "stampinput.h"
#include "stampinput_int.h"
#include "ntohll.h"
#include "rawdata.h"


/* Defines required by the Linux SLL header */
#define LINUX_SLL_HOST		0
#define LINUX_SLL_BROADCAST	1
#define LINUX_SLL_MULTICAST	3
#define LINUX_SLL_OTHERHOST	3
#define LINUX_SLL_OUTGOING	4


#define LIVEPCAP_DATA(x) ((struct livepcap_data *)(x->priv_data))

struct livepcap_data
{
	pcap_t *live_input;
	pcap_dumper_t *trace_output;
	char src_ipaddr[16];
};




/* This is a function that replaces the link layer header by a Linux SLL one.
 * While this seems to be an overkill, it is essential. Since we store the
 * vcount read in kernel into the link layer header of the packet saved in raw
 * files, the Linux SLL header allows a generic post processing. Then we can
 * handle any type of link layer the interface is listening to (802.11, PPP,
 * PPPoE ...) 
 */
int insert_sll_header(radpcap_packet_t *packet)
{
	JDEBUG

	char *tmpbuffer;
	linux_sll_header_t *hdr;
	uint16_t proto_type = 0;
	size_t lheader_size = 0;
	
	switch( packet->type ) {
		case DLT_LINUX_SLL:
			/* Nothing to do here */
			return 0;

		case DLT_EN10MB:
			/* Set the size of the ethernet header and the protocol carried by
			 * the ethernet frame */
			// TODO: here we suppose the ethernet frame carries IP(v4) packets
			// TODO: but we can have several encapsulations (PPPoE, EAP,...)
			// TODO: the offset to the IP packet should be computed accordingly
			proto_type   = ((struct ether_header*)packet->payload)->ether_type;
			if (ntohs(proto_type) != ETHERTYPE_IP) {
				verbose(LOG_ERR,"It seems we are trying to capture encapsulated packets");
				return 1;
			}
			lheader_size = sizeof(struct ether_header);	
			break;

		default:
			/* failed */
			verbose(LOG_ERR, "Link Layer type not supported yet");
			return 1;
	}

	/* Allocate what will be the new packet buffer, remember, 
	 *  packet->size contains the pcap header and we remove the link layer 
	 *  header */
	tmpbuffer= malloc(sizeof(linux_sll_header_t) +packet->size -lheader_size);

	/* Copy the pcap header into the tmp buffer */
	memcpy(tmpbuffer,packet->header, sizeof(struct pcap_pkthdr));
	
	/* Create the Linux SLL header into the temporary buffer */
	hdr=(void*)((char*)tmpbuffer + sizeof(struct pcap_pkthdr));
	hdr->pkttype	= htons(LINUX_SLL_OTHERHOST);
	hdr->hatype		= htons(ARPHRD_ETHER);
	hdr->protocol	= proto_type; 

	/* Copy the payload remaining after ethernet header */
	memcpy(tmpbuffer +sizeof(struct pcap_pkthdr) +sizeof(linux_sll_header_t),
				packet->payload + lheader_size, /* Remove link header */
				get_capture_length(packet) -lheader_size);
	
	/* We made a copy so get rid of the former buffer */
	free(packet->buffer);
	
	/* Reposition radpcap_packet fields to new values */
	packet->buffer	= tmpbuffer;
	packet->header	= tmpbuffer;
	packet->payload = tmpbuffer + sizeof(struct pcap_pkthdr);
	packet->type	= DLT_LINUX_SLL;
	packet->size	= packet->size 
					  + sizeof(linux_sll_header_t)
					  - lheader_size;
	
	/* Update pcap header */
	((struct pcap_pkthdr*) packet->header)->caplen =
			((struct pcap_pkthdr*) packet->header)->caplen 
			+ sizeof(linux_sll_header_t)
			- lheader_size;
	((struct pcap_pkthdr*) packet->header)->len =
			((struct pcap_pkthdr*) packet->header)->len
			+ sizeof(linux_sll_header_t)
			- lheader_size;
	return 0;
}





/* Store the vcount value in place of the MAC adresses in the Linux SLL header 
 */
void set_vcount_in_sll(radpcap_packet_t *packet, vcounter_t vcount)
{
	JDEBUG

	vcounter_t network_vcount;
	
	/* Format the vcount to write */
	network_vcount = htonll(vcount);
	assert(sizeof(vcounter_t) == sizeof(char)*8);

	/* Hijack the address field to store the vcount */ 
	linux_sll_header_t *hdr = (linux_sll_header_t*) packet->payload;
	memcpy(hdr->addr, &network_vcount, sizeof(network_vcount));
	hdr->halen = htons(8);
}








/* This is the callback passed to get_bidir_stamp().
 * It takes a radpcap_packet_t and fills this structure with the actual packet
 * read from the live interface.
 * The first trick here is to use radpcap_get_packet() that actually retrieves 
 * the BPF header, the packet captured and the vcount value padded in between. 
 * The second trick, is to write all data retrieved to the output raw file (if
 * any) before passing the data to the sync algo. The link layer header is
 * replaced by a Linux SLL header and the vcount is stored in its address field.
 */
static int get_packet(struct radclock *handle, void *userdata, radpcap_packet_t **packet_p)
{
	JDEBUG

//	struct pcap_pkthdr *header;    /* The header that pcap gives us */
	vcounter_t vcount		= 0;
	vcounter_t vcount_debug = 0;
	int ret;

	struct livepcap_data *data = (struct livepcap_data *) userdata;
	pcap_dumper_t *traceoutput = data->trace_output;
	
	radpcap_packet_t *packet = *packet_p;

	/* Retrieve the next packet from the raw data buffer */
	ret = deliver_raw_data(handle, packet, &vcount);
	if (ret < 0 )
	{
		/* Raw data buffer is empty */
		return ret; 
	}

	/* Replace the link layer header by the Linux SLL header for generic
	 * encapsulation of the IP payload */
	if ( insert_sll_header(packet) ) {
		verbose(LOG_ERR, "Could not insert Linux SLL header");
	}

	/* Store the vcount in the address field of the SLL header */
	set_vcount_in_sll(packet, vcount);
	assert(get_vcount(packet, &vcount_debug) == 0);
	assert(vcount == vcount_debug);

	/* Write out raw data if -w option active in main program */
	if (traceoutput) {
		
		pcap_dump(  (u_char*) traceoutput, 
					(struct pcap_pkthdr*) packet->header, 
					(u_char*) packet->payload );

		if ( pcap_dump_flush(traceoutput) < 0 )
			verbose(LOG_ERR, "Error dumping packet");
	}
	*packet_p = packet;

	/* Return packet quality */
	return ret;
}




/* Get a free interface if none specified
 * Try to find a corresponding interface if a source host is given 
 */
int get_interface(char* if_name, char* ip_addr) 
{
	struct ifaddrs *devs;
	struct ifaddrs *dev;
	struct sockaddr_in *addr;

	int found = 0;
	addr = NULL;
	
	if (getifaddrs(&devs)) {
		perror("Failed to get interfaces");
		return 0;
	}

	/* 3 cases here. 
	 * - Either the user did specify an interface, and then we trust him blindly
	 * - If an address has been specified or found before, try to match it to confirm
	 *   everything is fine
	 * - Last do our best ...
	 */
	
	/* An interface was specified */ 
	if ( (!found) && (strlen(if_name) > 0) ) {
		dev = devs;
		while(dev) {
			// Look at internet interfaces only
			if (dev->ifa_addr->sa_family == AF_INET) {
				addr = (struct sockaddr_in *)dev->ifa_addr;
				if (strcmp(dev->ifa_name,if_name) == 0) {
					found = 1;
					strcpy(ip_addr, inet_ntoa(addr->sin_addr));
					break;
				}
			}
			dev= dev->ifa_next;
		}
		if (found)
			verbose(LOG_NOTICE, "Found IP address %s based on interface %s", ip_addr, if_name);
		else
			verbose(LOG_NOTICE, "Did not find any IP address based on interface %s", if_name);
	}

	/* An address was found, specified or not, we check it */
	if ( (!found)  && (strlen(ip_addr) > 0) ) {
		dev = devs;
		while(dev) {
			// Look at internet interfaces only
			if (dev->ifa_addr->sa_family == AF_INET) {
				addr = (struct sockaddr_in *)dev->ifa_addr;
				if (strcmp(inet_ntoa(addr->sin_addr),ip_addr) == 0) {
					strcpy(ip_addr, inet_ntoa(addr->sin_addr));
					strcpy(if_name, dev->ifa_name);
					found = 1;
					break;
				}
			}
			dev= dev->ifa_next;
		}
		if (!if_name)
			verbose(LOG_WARNING, "Found an IP address earlier but no interface matches ... weird");
		else
			verbose(LOG_NOTICE, "Matched IP address %s to interface %s", ip_addr, if_name);
	}

	/* Look for the first configured interface */
	if ( !found ) {
		dev = devs;
		while(dev) {
			// Look at internet interfaces only
			if (dev->ifa_addr->sa_family == AF_INET) {
				addr = (struct sockaddr_in *)dev->ifa_addr;
				if ( (addr->sin_addr.s_addr != (in_addr_t) 0x00000000) /* 0.0.0.0 */
				  && (addr->sin_addr.s_addr != (in_addr_t) 0x0100007f) /* 127.0.0.1 */ 
				  && (addr->sin_addr.s_addr != (in_addr_t) 0x0101007f) /* 127.0.1.1 */ 
				  && (addr->sin_addr.s_addr != (in_addr_t) 0xffffffff) /* 255.255.255.255 */ 
				  ) {
					strcpy(ip_addr, inet_ntoa(addr->sin_addr));
					strcpy(if_name, dev->ifa_name);
					found = 1;
					break;
				}
			}
			dev= dev->ifa_next;
		}
	}

	freeifaddrs(devs);
	if (!found) {
		verbose(LOG_ERR, "Did not find any suitable interface");
		return 0;
	}
	return 1;
}





/** Get the IP address of the localhost */
int get_address_by_name(char* addr, char* hostname) 
{
	struct hostent *he;
	struct sockaddr_in* s = (struct sockaddr_in*) malloc(sizeof(struct sockaddr_in));
	int lhost = 150;
	char *host = (char*) malloc(lhost* sizeof(char));
	char *domain = (char*) malloc(lhost* sizeof(char));
	int i=0;
	int found = 0;
	char **p_addr = NULL;

	// If not given retrieve the local host name
	if (strlen(hostname) == 0) {
		if (gethostname(host, lhost) < 0) {
			verbose(LOG_ERR, "Can't get localhost name");
			return 1;
		}
		if (getdomainname(domain, lhost) < 0) {
			verbose(LOG_ERR, "Can't get domain name");
			return 1;
		}
		if (strcmp(domain, "(none)") == 0)
			sprintf(hostname, "%s", host);
		else
			sprintf(hostname, "%s.%s", host, domain);
		verbose(LOG_NOTICE, "Found hostname %s", hostname);
	}

	// Retrieve the host IP address (even if hostname is effectively an IP addr)
	he = gethostbyname(hostname);
	if ( he == NULL ) {
		verbose(LOG_INFO, "Could not retrieve IP address based on hostname %s", hostname);
		return 1;
	}

	// Select an address that makes sense
	p_addr = he->h_addr_list;
	while(p_addr[i] != NULL) {
		memcpy(&(s->sin_addr.s_addr), p_addr[i], he->h_length);
		if ( (strcmp(inet_ntoa(s->sin_addr), "127.0.0.1") != 0)
		  && (strcmp(inet_ntoa(s->sin_addr), "127.0.1.1") != 0) 
		  && (strcmp(inet_ntoa(s->sin_addr), "0.0.0.0") != 0)) 
		{
			verbose(LOG_NOTICE, "Found address %s", inet_ntoa(s->sin_addr));
			found = 1;
			break;
		}
		i++;
	}
	if (!found) {
		verbose(LOG_NOTICE, "Did not find any valid address based on host name %s", hostname);
		free(host);
		free(s);
		return 1;
	}
	strcpy(addr, inet_ntoa(s->sin_addr));

	free(host);
	free(s);
	return 0;
}




/** Create a BPF filter expression 
 * Filter appends additional rules passed in pattern qualifier 
 * (port number, remote host name, etc) 
 */     
int build_BPFfilter( char *fltstr, int maxsize, char *hostname, char *ntp_host) 
{
	int strsize;
	char ntp_filter[150];
	
	if (strlen(hostname) == 0) {
		verbose(LOG_ERR, "No host info, no BPF filter");
		return -1;
	}
	if (strlen(ntp_host) == 0) {
		verbose(LOG_WARNING, "No NTP server specified, the BPF filter is not tight enough !!!");
		sprintf(ntp_filter, ") or (");
	}
	else
		sprintf(ntp_filter, "and dst host %s) or (src host %s and", ntp_host, ntp_host);
	
	strsize = snprintf(fltstr, maxsize, 
			"(src host %s and dst port 123 %s dst host %s and src port 123)",
			hostname, ntp_filter, hostname);

	return strsize;
}




/* Open a live device with a BPF filter */
static pcap_t* open_live(struct radclock *handle, char *src_ipaddr) 
{
	pcap_t* p_handle = NULL;
	struct bpf_program filter;       
	char fltstr[MAXLINE];               // bpf filter string
	int strsize = 0;
	int promiscuous = 0;
	int bpf_timeout = 5;		// waiting time on BPF before exporting packets (in [ms])
	char errbuf[PCAP_ERRBUF_SIZE];
	char addr_name[16] = "";
	char addr_if[16] = "";
	int err = 0;
	struct in_addr addr;

	/* Retrieve required IP addresses
	 * - useful to identify right interface to open
	 * - set a valid BPF filter to get rid of packets we don't want
	 */
	err = get_address_by_name(addr_name, handle->conf->hostname);
//	if (err)  { return NULL; }
	
	/* If we have a host, means we supposely know who we are */
	if ( strlen(handle->conf->hostname) > 0 )
		strcpy(addr_if, addr_name);

	/* In case we have an interface from the config file */
	if ( !get_interface(handle->conf->network_device, addr_if) ) {
		verbose(LOG_ERR, "Failed to find free device, pcap says: %s",
				pcap_geterr(p_handle));
		return NULL;
	}

	/* Ok, so now we may have two different IP addresses due to the 
	 * name and interface resolution. We need to match packets on 
	 * the open interface, so in any cases, favour the address from 
	 * the interface to build the BPF filter 
	 */
	verbose(LOG_NOTICE, "Using host name %s and address %s", handle->conf->hostname, addr_if);
	verbose(LOG_NOTICE, "Opening device %s", handle->conf->network_device);


	/* Build the BPF filter string
	 */
	strcpy(fltstr, "");
	strsize = build_BPFfilter(fltstr, MAXLINE, addr_if, handle->conf->time_server);  
	if ( (strsize < 0) || (strsize > MAXLINE-2) ) {     
		verbose(LOG_ERR, "BPF filter string error (too long?)");
		return NULL;
	}
	verbose(LOG_NOTICE, "Packet filter: %s", fltstr);


	/* We got the parameters, open the live device
	 * Set the timeout to 2ms before waking up the userland process, no IMMEDIATE mode!
	 */
	if ((p_handle = pcap_open_live(handle->conf->network_device, BPF_PACKET_SIZE, promiscuous, bpf_timeout, errbuf)) == NULL) {
		verbose(LOG_ERR, "Open failed on live interface, pcap says:  %s",
					errbuf);
		return NULL;
	} 
	else
		verbose(LOG_NOTICE, "Reading from live interface %s, linktype: %s",
				handle->conf->network_device, 
				pcap_datalink_val_to_name(pcap_datalink(p_handle)));


	// Compile and set up the BPF filter
	// no need to test broadcast addresses
	if (pcap_compile(p_handle, &filter, fltstr, 0, 0) == -1) {   
		verbose(LOG_ERR, "pcap filter compiling failure, pcap says: %s",pcap_geterr(p_handle));
		goto pcap_err;
	}
	if (pcap_setfilter(p_handle,&filter) == -1 )  {
		verbose(LOG_ERR, "pcap filter setting failure, pcap says: %s",pcap_geterr(p_handle));
		goto pcap_err;
	}

	return p_handle;
pcap_err:
	pcap_close(p_handle);
	return NULL;
}



static int livepcapstamp_init(struct radclock *handle, struct stampsource *source)
{
	/* Create the handle to be sure to dump the packet in the right format while
	 * being able to support any link layer type thanks to the LINUX_SLL
	 * encapsulation of the link layer .
	 */
	radclock_tsmode_t capture_mode;
	pcap_t *p_handle_traceout;
	p_handle_traceout = pcap_open_dead(DLT_LINUX_SLL, BPF_PACKET_SIZE);
	if (!p_handle_traceout) {
		verbose(LOG_ERR, "Error creating pcap handle");
		free(LIVEPCAP_DATA(source));
		return -1;
	}
	
	source->priv_data = malloc(sizeof(struct livepcap_data));
	if (!LIVEPCAP_DATA(source)) {
		verbose(LOG_ERR, "Error allocating memory");
		return -1;
	}
	strcpy(LIVEPCAP_DATA(source)->src_ipaddr,"");
	
		
	LIVEPCAP_DATA(source)->live_input = 
				open_live(handle, LIVEPCAP_DATA(source)->src_ipaddr);
	if (!LIVEPCAP_DATA(source)->live_input) {
		verbose(LOG_ERR, "Error creating pcap handle");
		free(LIVEPCAP_DATA(source));
		return -1;
	}
	// TODO that could be written in a more simpler way once we clean the sources 
	handle->pcap_handle = LIVEPCAP_DATA(source)->live_input; 

	/* Set the timestamping mode of the pcap handle for the radclock
	 * It should be RADCLOCK_TSMODE_SYSCLOCK !
	 */
//	if (radclock_set_tsmode(handle, LIVEPCAP_DATA(source)->live_input, RADCLOCK_TSMODE_RADCLOCK)){
//	if (radclock_set_tsmode(handle, LIVEPCAP_DATA(source)->live_input, RADCLOCK_TSMODE_FAIRCOMPARE)){
	if (radclock_set_tsmode(handle, LIVEPCAP_DATA(source)->live_input, RADCLOCK_TSMODE_SYSCLOCK)){
		verbose(LOG_WARNING, "Could not set RADclock timestamping mode");
	}

	//Init stats
	source->ntp_stats.ref_count = 0;
	source->ntp_stats.badqual_count = 0;
	
	if (strlen(handle->conf->sync_out_pcap) > 0) 
	{
		/* Test if previous file exists. Rename it if so */
		FILE* out_fd = NULL;
		if ((out_fd = fopen(handle->conf->sync_out_pcap, "r"))) {
			fclose(out_fd);
			char* backup = (char*) malloc(strlen(handle->conf->sync_out_pcap)+5);
			sprintf(backup, "%s.old", handle->conf->sync_out_pcap);
			if (rename(handle->conf->sync_out_pcap, backup) < 0) {
				verbose(LOG_ERR, "Cannot rename existing output file: %s", handle->conf->sync_out_pcap);
				free(backup);
				exit(EXIT_FAILURE);
			}
			verbose(LOG_NOTICE, "Backed up existing output file: %s", handle->conf->sync_out_pcap);
			free(backup);
			out_fd = NULL;
		}

		/* pcap_dump_open stores the link layer type in the dump file header */
		LIVEPCAP_DATA(source)->trace_output = pcap_dump_open(p_handle_traceout, 
															handle->conf->sync_out_pcap);
		if (!LIVEPCAP_DATA(source)->trace_output)
		{
			verbose(LOG_ERR, "Error opening raw output: %s",
				   pcap_geterr(p_handle_traceout));
			free(LIVEPCAP_DATA(source));
			return -1;
		}
	}
	else
		LIVEPCAP_DATA(source)->trace_output = NULL;


	/* Let's check we did things right */
	radclock_get_tsmode(handle, LIVEPCAP_DATA(source)->live_input, &capture_mode);
	switch(capture_mode) {
		case RADCLOCK_TSMODE_SYSCLOCK:
			verbose(LOG_NOTICE, "Capture mode is SYSCLOCK");
			break;
		case RADCLOCK_TSMODE_RADCLOCK:
			verbose(LOG_NOTICE, "Capture mode is RADCLOCK");
			break;
		case RADCLOCK_TSMODE_FAIRCOMPARE:
			verbose(LOG_NOTICE, "Capture mode is FAIRCOMPARE");
			break;
		default:
			verbose(LOG_ERR, "Capture mode UNKNOWN");
			break;
	}

	return 0;
}


static int livepcapstamp_get_next(struct radclock *handle, struct stampsource *source, struct bidir_stamp *stamp)
{
	JDEBUG

	int err;

	/* Ensure default stamp quality before filling timestamps */
	stamp->qual_warning = 0;
	
	// Call for get_bidir_stamp to read through a BPF device
	err = get_bidir_stamp(
			handle,
			(void *)LIVEPCAP_DATA(source),
			get_packet,
			stamp, 
			&source->ntp_stats, 
			LIVEPCAP_DATA(source)->src_ipaddr);

	if (err < 0) {
		/* Used to be EOF or capture break, but now only signals empty buffer */
		return err;
	}
	return 0;
}


static void livepcapstamp_breakloop(struct radclock *handle, struct stampsource *source)
{
	/* Wrapper to the pcap_breakloop() call
	 * This is usually called when the daemon catches a SIGHUP signal. This 
	 * call does not affect other threads. In other words, the pcap_get*() functions
	 * have to be in the main thread. Will not work otherwise
	 */
	pcap_breakloop(LIVEPCAP_DATA(source)->live_input);	
	return;
}


static void livepcapstamp_finish(struct radclock *handle, struct stampsource *source)
{
	if (LIVEPCAP_DATA(source)->trace_output) {
		pcap_dump_flush(LIVEPCAP_DATA(source)->trace_output);
		pcap_dump_close(LIVEPCAP_DATA(source)->trace_output);
	}
	
	pcap_close(LIVEPCAP_DATA(source)->live_input);
	free(LIVEPCAP_DATA(source));
}



static int livepcapstamp_update_filter(struct radclock *handle, struct stampsource *source)
{
	int strsize = 0;
	char fltstr[MAXLINE];               // bpf filter string
	struct bpf_program filter;       

	strsize = build_BPFfilter(fltstr, MAXLINE, handle->conf->hostname, handle->conf->time_server); 
	if ( (strsize < 0) || (strsize > MAXLINE-2) ) {     
		verbose(LOG_ERR, "BPF filter string error (too long?)");
		goto err_out;
	}
	verbose(LOG_NOTICE, "Packet filter      : %s", fltstr);

	// Compile and set up the BPF filter
	// no need to test broadcast addresses
	if ( pcap_compile(LIVEPCAP_DATA(source)->live_input, &filter, fltstr, 0, 0) == -1 ) {   
		verbose(LOG_ERR, "pcap filter compiling failure, pcap says: %s",
							pcap_geterr(LIVEPCAP_DATA(source)->live_input));
		goto pcap_err;
	}
	if ( pcap_setfilter( LIVEPCAP_DATA(source)->live_input,&filter) == -1 )  {
		verbose(LOG_ERR, "pcap filter setting failure, pcap says: %s",
							pcap_geterr(LIVEPCAP_DATA(source)->live_input));
		goto pcap_err;
	}

	return 0;

pcap_err:
	verbose(LOG_ERR, "Things went really wrong with this update on the live source");
	pcap_close(LIVEPCAP_DATA(source)->live_input);
	free(LIVEPCAP_DATA(source));
err_out:
	return -1;
}


static int livepcapstamp_update_dumpout(struct radclock *handle, struct stampsource *source)
{
	if (LIVEPCAP_DATA(source)->trace_output) {
		pcap_dump_flush(LIVEPCAP_DATA(source)->trace_output);
		pcap_dump_close(LIVEPCAP_DATA(source)->trace_output);
	}
	if (strlen(handle->conf->sync_out_pcap) > 0)
	{
		pcap_t *p_handle_traceout;
		p_handle_traceout = pcap_open_dead(DLT_LINUX_SLL, BPF_PACKET_SIZE);
		if (!p_handle_traceout)
		{
			verbose(LOG_ERR, "Error creating pcap handle");
			free(LIVEPCAP_DATA(source));
			return -1;
		}
		
		LIVEPCAP_DATA(source)->trace_output = pcap_dump_open(p_handle_traceout, handle->conf->sync_out_pcap);
		if (!LIVEPCAP_DATA(source)->trace_output)
		{
			verbose(LOG_ERR, "Error opening raw output: %s",
				   pcap_geterr(p_handle_traceout));
			free(LIVEPCAP_DATA(source));
			return -1;
		}
	}
	else
		LIVEPCAP_DATA(source)->trace_output = NULL;

	return 0;
}




struct stampsource_def livepcap_source =
{
	.init 				= livepcapstamp_init,
	.get_next_stamp 	= livepcapstamp_get_next,
	.source_breakloop 	= livepcapstamp_breakloop,
	.destroy 			= livepcapstamp_finish,
	.update_filter  	= livepcapstamp_update_filter,
	.update_dumpout 	= livepcapstamp_update_dumpout,
};

