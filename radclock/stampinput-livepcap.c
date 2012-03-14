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


/**
 * A stamp source for reading from live input
 * Also has the ability to create output
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/in.h>

#include <assert.h>
#include <netdb.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "../config.h"
#ifdef HAVE_IFADDRS_H
# include <ifaddrs.h>
#else
# error Need ifaddrs.h or go back to using the ioctl
#endif

#include "sync_algo.h"
#include "config_mgr.h"
#include "verbose.h"
#include "create_stamp.h"
#include "stampinput.h"
#include "stampinput_int.h"
#include "ntohll.h"
#include "rawdata.h"
#include "radclock.h"
#include "misc.h"
#include "jdebug.h"


/* Defines required by the Linux SLL header */
#define LINUX_SLL_HOST		0
#define LINUX_SLL_BROADCAST	1
#define LINUX_SLL_MULTICAST	3
#define LINUX_SLL_OTHERHOST	3
#define LINUX_SLL_OUTGOING	4


struct livepcap_data
{
	pcap_t *live_input;
	pcap_dumper_t *trace_output;
	struct sockaddr_storage ss_if;
};

#define LIVEPCAP_DATA(x) ((struct livepcap_data *)(x->priv_data))



/*
 * Present a somewhat mac layer independent view of packets to higher layers.
 * This serves several purposes:
 * - sanitize input to synchronisation algorithm.
 * - allow to dump any mac layer into a unique DLT type on drive.
 * - store RAW counter values in abused SLL address field.
 * These are achieved by replacing the link layer header by a Linux SLL one.
 */
int
insert_sll_header(radpcap_packet_t *packet)
{
	struct ether_header *eh;
	linux_sll_header_t *sllh;
	uint16_t ethertype;
	size_t etherlen;
	char *tmpbuffer;
	struct pcap_pkthdr *pcaph;

	JDEBUG

	etherlen = 0;
	
	switch(packet->type) {
	
	/* BSD Loopback interface */
	// TODO a bit ugly, but good enough for now on
	case DLT_NULL:
		switch (*(uint32_t *)packet->payload) { 
		case AF_INET:
			ethertype = ETHERTYPE_IP; 
			break;
		case AF_INET6:
			ethertype = ETHERTYPE_IPV6; 
		default:
			fprintf(stderr, "Non IP protocol on DLT_NULL\n");
			return (1);
		}
		eh = (struct ether_header *)packet->payload;
		etherlen = 4;
		break;

	case DLT_LINUX_SLL:
		/* Nothing to do here */
		return (0);

	case DLT_IEEE802_11:
	case DLT_EN10MB:
		eh = (struct ether_header *)packet->payload;
		ethertype = ntohs(eh->ether_type);
		etherlen = sizeof(struct ether_header);

		/* Ethernet with 802.2 and maybe SNAP header */
		if (ethertype < 0x0600) {
			verbose(LOG_ERR, "Not an ethernet.v2 frame, type not supported.");
			return (1);
		}

		/* It is a bit ugly, but easier for cross-platform defs */
		if (ethertype == ETHERTYPE_VLAN) {
			ethertype = *(uint16_t *)((char *)packet->payload + 16);
			etherlen = 18;
		}

		switch (ethertype) {
		/* IPv4 */
		case (ETHERTYPE_IP):
		/* IPv6 */
		case (ETHERTYPE_IPV6):
		/* IEEE 1588 over Ethernet */
		case (0x88F7):
			break;
		default:
			verbose(LOG_ERR,"It seems we are trying to capture encapsulated packets");
			verbose(LOG_ERR, "Do not support protocol type %u", ethertype);
			return (1);
		}
		break;

	default:
		/* failed */
		verbose(LOG_ERR, "Link Layer DLT type not supported yet");
		return (1);
	}

	/*
	 * Create the new frame using the SLL header. It would have been more
	 * efficient to avoid copying data, but ethernet header smaller than SLL
	 * header. Simpler to maintain continuous memory block with same assumptions
	 * as what has been received from libpcap. 
	 */
	tmpbuffer = (char *) malloc(RADPCAP_PACKET_BUFSIZE);
	JDEBUG_MEMORY(JDBG_MALLOC, tmpbuffer);

	/* Copy the pcap header */
	memcpy(tmpbuffer, packet->header, sizeof(struct pcap_pkthdr));

	/* Create the Linux SLL header */
	sllh = (linux_sll_header_t *) (tmpbuffer + sizeof(struct pcap_pkthdr));
	sllh->pkttype = htons(LINUX_SLL_OTHERHOST);
	sllh->hatype = htons(ARPHRD_ETHER);
	sllh->protocol = htons(ethertype); 

	/* Copy what is encapsulated in ethernet */ 
	pcaph = (struct pcap_pkthdr *)packet->header; 
	memcpy((char *)sllh + sizeof(linux_sll_header_t), (char *)eh + etherlen,
			pcaph->caplen - etherlen);
	
	/* We made a copy so get rid of the former buffer */
	JDEBUG_MEMORY(JDBG_FREE, packet->buffer);
	free(packet->buffer);
	
	/* Reposition radpcap_packet fields to new values */
	packet->buffer	= tmpbuffer;
	packet->header	= tmpbuffer;
	packet->payload = tmpbuffer + sizeof(struct pcap_pkthdr);
	packet->type	= DLT_LINUX_SLL;
	packet->size	= packet->size + sizeof(linux_sll_header_t) - etherlen;
	
	/* Update pcap header */
	pcaph->caplen = pcaph->caplen + sizeof(linux_sll_header_t) - etherlen;
	pcaph->len = pcaph->len + sizeof(linux_sll_header_t) - etherlen;
	return (0);
}


/* 
 * Store the vcount value in place of the MAC adresses in the Linux SLL header 
 */
void
set_vcount_in_sll(radpcap_packet_t *packet, vcounter_t vcount)
{
	vcounter_t network_vcount;

	JDEBUG
	
	/* Format the vcount to write */
	network_vcount = htonll(vcount);
	assert(sizeof(vcounter_t) == sizeof(char)*8);

	/* Hijack the address field to store the vcount */ 
	linux_sll_header_t *hdr = (linux_sll_header_t*) packet->payload;
	memcpy(hdr->addr, &network_vcount, sizeof(network_vcount));
	hdr->halen = htons(8);
}


/* 
 * This is the callback passed to get_bidir_stamp().
 * It takes a radpcap_packet_t and fills this structure with the actual packet
 * read from the live interface.
 * The first trick here is to use radpcap_get_packet() that actually retrieves 
 * the BPF header, the packet captured and the vcount value padded in between. 
 * The second trick, is to write all data retrieved to the output raw file (if
 * any) before passing the data to the sync algo. The link layer header is
 * replaced by a Linux SLL header and the vcount is stored in its address field.
 */
static int
get_packet_livepcap(struct radclock *handle, void *userdata,
		radpcap_packet_t **packet_p)
{
	struct livepcap_data *data;
	pcap_dumper_t *traceoutput;
	radpcap_packet_t *packet;
	vcounter_t vcount;
	vcounter_t vcount_debug;
	int ret;

	JDEBUG

	vcount = 0;
	vcount_debug = 0;
	data = (struct livepcap_data *) userdata;
	traceoutput = data->trace_output;
	packet = *packet_p;

	/* Retrieve the next packet from the raw data buffer */
	ret = deliver_rawdata_ntp(handle, packet, &vcount);
	if (ret < 0) {
		/* Raw data buffer is empty */
		return (ret);
	}

	/* Replace the link layer header by the Linux SLL header for generic
	 * encapsulation of the IP payload */
	if (insert_sll_header(packet)) {
		verbose(LOG_ERR, "Could not insert Linux SLL header");
	}

	/* Store the vcount in the address field of the SLL header */
	set_vcount_in_sll(packet, vcount);
	assert(get_vcount(packet, &vcount_debug) == 0);
	assert(vcount == vcount_debug);

	/* Store interface address in packet */
	packet->ss_if = data->ss_if;

	/* Write out raw data if -w option active in main program */
	if (traceoutput) {
		pcap_dump((u_char *)traceoutput, (struct pcap_pkthdr *)packet->header,
				(u_char *)packet->payload);

		if (pcap_dump_flush(traceoutput) < 0)
			verbose(LOG_ERR, "Error dumping packet");
	}
	*packet_p = packet;

	/* Return packet quality */
	return (ret);
}




/*
 * Get a free interface if none specified
 * Try to find a corresponding interface if a source host is given.
 */
int
get_interface(char* if_name, char* ip_addr)
{
	struct ifaddrs *devs;
	struct ifaddrs *dev;
	struct sockaddr_in *addr;
	int found;

	JDEBUG

	found = 0;
	addr = NULL;
	
	if (getifaddrs(&devs)) {
		perror("Failed to get interfaces");
		return (0);
	}

	/* 3 cases here.
	 * - Either the user did specify an interface, and then we trust him blindly
	 * - If an address has been specified or found before, try to match it to confirm
	 *   everything is fine
	 * - Last do our best ...
	 */
	
	/* An interface was specified */
	if ((!found) && (strlen(if_name) > 0)) {
		dev = devs;
		while(dev) {
			// Look at internet interfaces only
			if (dev->ifa_addr->sa_family == AF_INET) {
				addr = (struct sockaddr_in *)dev->ifa_addr;
				if (strcmp(dev->ifa_name,if_name) == 0) {
					found = 1;
					// TODO this is not protocol independent
					// TODO use getaddrinfo instead
					strcpy(ip_addr, inet_ntoa(addr->sin_addr));
					break;
				}
			}
			dev= dev->ifa_next;
		}
		if (found)
			verbose(LOG_NOTICE, "Found IP address %s based on interface %s",
					ip_addr, if_name);
		else
			verbose(LOG_NOTICE, "Did not find any IP address based on interface %s",
					if_name);
	}

	/* An address was found, specified or not, we check it */
	if ((!found) && (strlen(ip_addr) > 0)) {
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
			verbose(LOG_WARNING, "Found an IP address earlier but no interface "
					"matches ... weird");
		else
			verbose(LOG_NOTICE, "Matched IP address %s to interface %s",
					ip_addr, if_name);
	}

	/* Look for the first configured interface */
	if (!found) {
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
		return (0);
	}
	return (1);
}





/** Get the IP address of the localhost */
int get_address_by_name(char* addr, char* hostname) 
{
	struct hostent *he;
	int lhost = 150;
	struct sockaddr_in* s = (struct sockaddr_in*) malloc(sizeof(struct sockaddr_in));
	JDEBUG_MEMORY(JDBG_MALLOC, s);
	char *host = (char*) malloc(lhost* sizeof(char));
	JDEBUG_MEMORY(JDBG_MALLOC, host);

	int i=0;
	int found = 0;
	char **p_addr = NULL;

	// If not given retrieve the local host name
	if (strlen(hostname) == 0)
	{
		verbose(LOG_NOTICE, "Attempt to discover hostname");
		if (gethostname(host, lhost) < 0) {
			verbose(LOG_ERR, "Can't get localhost name");
			return 1;
		}
		sprintf(hostname, "%s", host);
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

		JDEBUG_MEMORY(JDBG_FREE, host);
		free(host);
		JDEBUG_MEMORY(JDBG_FREE, s);
		free(s);
		return 1;
	}
	strcpy(addr, inet_ntoa(s->sin_addr));

	JDEBUG_MEMORY(JDBG_FREE, host);
	free(host);
	JDEBUG_MEMORY(JDBG_FREE, s);
	free(s);
	return 0;
}




/** Create a BPF filter expression 
 * Filter appends additional rules passed in pattern qualifier 
 * (port number, remote host name, etc) 
 */
// XXX TODO: should accept IP addresses only, and make it IPv6 friendly
int build_BPFfilter(struct radclock *handle, char *fltstr, int maxsize, char *hostname, char *ntp_host)
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
			"(src host %s and dst port %d %s dst host %s and src port %d)",
			hostname,
                        handle->conf->ntp_upstream_port,
                        ntp_filter,
                        hostname,
                        handle->conf->ntp_upstream_port);

	return strsize;
}




/* Open a live device with a BPF filter */
static pcap_t *
open_live(struct radclock *clock, struct livepcap_data *ldata)
{
	pcap_t* p_handle = NULL;
	struct bpf_program filter;
	char fltstr[MAXLINE];               // bpf filter string
	int strsize = 0;
	int promiscuous = 0;
	int bpf_timeout = 5;		// waiting time on BPF before exporting packets (in [ms])
	struct radclock_config *conf;
	char errbuf[PCAP_ERRBUF_SIZE];
	char addr_name[16] = "";
	char addr_if[16] = "";
	int err = 0;

	conf = clock->conf;

	/* Retrieve required IP addresses
	 * - useful to identify right interface to open
	 * - set a valid BPF filter to get rid of packets we don't want
	 */
	err = get_address_by_name(addr_name, conf->hostname);
//	if (err)  { return NULL; }
	
	/* If we have a host, means we supposely know who we are */
	if (strlen(conf->hostname) > 0)
		strcpy(addr_if, addr_name);

	/* In case we have an interface from the config file */
	if (!get_interface(conf->network_device, addr_if)) {
		verbose(LOG_ERR, "Failed to find free device, pcap says: %s",
				pcap_geterr(p_handle));
		return NULL;
	}

	// TODO this code is not protocol independent
	// TODO use getaddrinfo instead
	ldata->ss_if.ss_family = AF_INET;
	inet_pton(AF_INET, addr_if, &((struct sockaddr_in *)&ldata->ss_if)->sin_addr);

	/*
	 * Ok, so now we may have two different IP addresses due to the name and
	 * interface resolution. We need to match packets on the open interface, so
	 * in any cases, favour the address from the interface to build the BPF
	 * filter.
	 */
	verbose(LOG_NOTICE, "Using host name %s and address %s", conf->hostname,
			addr_if);
	verbose(LOG_NOTICE, "Opening device %s", conf->network_device);

	/* Build the BPF filter string
	 */
	strcpy(fltstr, "");
	strsize = build_BPFfilter(clock, fltstr, MAXLINE, addr_if,
			conf->time_server);
	if ((strsize < 0) || (strsize > MAXLINE-2)) {
		verbose(LOG_ERR, "BPF filter string error (too long?)");
		return (NULL);
	}
	verbose(LOG_NOTICE, "Packet filter: %s", fltstr);

	/*
	 * We got the parameters, open the live device Set the timeout to 2ms before
	 * waking up the userland process, no IMMEDIATE mode!
	 */
	if ((p_handle = pcap_open_live(conf->network_device, BPF_PACKET_SIZE,
			promiscuous, bpf_timeout, errbuf)) == NULL) {
		verbose(LOG_ERR, "Open failed on live interface, pcap says:  %s",
				errbuf);
		return (NULL);
	}
	else
		verbose(LOG_NOTICE, "Reading from live interface %s, linktype: %s",
				conf->network_device,
				pcap_datalink_val_to_name(pcap_datalink(p_handle)));


	// Compile and set up the BPF filter
	// no need to test broadcast addresses
	if (pcap_compile(p_handle, &filter, fltstr, 0, 0) == -1) {
		verbose(LOG_ERR, "pcap filter compiling failure, pcap says: %s",
				pcap_geterr(p_handle));
		goto pcap_err;
	}
	if (pcap_setfilter(p_handle,&filter) == -1 )  {
		verbose(LOG_ERR, "pcap filter setting failure, pcap says: %s",
				pcap_geterr(p_handle));
		goto pcap_err;
	}

	return p_handle;
pcap_err:
	pcap_close(p_handle);
	return NULL;
}



static int
livepcapstamp_init(struct radclock *clock, struct stampsource *source)
{
	/* Create the handle to be sure to dump the packet in the right format while
	 * being able to support any link layer type thanks to the LINUX_SLL
	 * encapsulation of the link layer .
	 */
	radclock_tsmode_t capture_mode;
	pcap_t *p_handle_traceout;
	struct radclock_config *conf;

	conf = clock->conf;

	/* Open the handle early to assure we have permissions to access it.
	 * We do not close this, even though for libpcap 1.1.1 it is never used
	 * after the pcap_dump_open() call.  For safety purposes we leave the
	 * handle open incase of libpcap interface change on the pcap_dumper_t
	 * struct which might, in the future, utilize the handle.
	 */
	p_handle_traceout = pcap_open_dead(DLT_LINUX_SLL, BPF_PACKET_SIZE);
	if (!p_handle_traceout) {
		verbose(LOG_ERR, "Error creating pcap handle");
		JDEBUG_MEMORY(JDBG_FREE, LIVEPCAP_DATA(source));
		free(LIVEPCAP_DATA(source));
		return (-1);
	}

	source->priv_data = malloc(sizeof(struct livepcap_data));
	JDEBUG_MEMORY(JDBG_MALLOC, source->priv_data);
	if (!LIVEPCAP_DATA(source)) {
		verbose(LOG_ERR, "Error allocating memory");
		pcap_close(p_handle_traceout);
		return (-1);
	}

	LIVEPCAP_DATA(source)->live_input = open_live(clock, LIVEPCAP_DATA(source));

	if (!LIVEPCAP_DATA(source)->live_input) {
		verbose(LOG_ERR, "Error creating pcap handle");
		JDEBUG_MEMORY(JDBG_FREE, LIVEPCAP_DATA(source));
		free(LIVEPCAP_DATA(source));
		pcap_close(p_handle_traceout);
		return (-1);
	}
	// TODO that could be written in a more simpler way once we clean the sources
	clock->pcap_handle = LIVEPCAP_DATA(source)->live_input;

	/* Set the timestamping mode of the pcap handle for the radclock
	 * It should be RADCLOCK_TSMODE_SYSCLOCK !
	 */
	// TODO move somewhere else or don't use the library
	// if bsd-kernel version < 2 then SYSCLOCK
	// else RADCLOCK
	if (radclock_set_tsmode(clock, LIVEPCAP_DATA(source)->live_input,
			RADCLOCK_TSMODE_RADCLOCK)) {
		verbose(LOG_WARNING, "Could not set RADclock timestamping mode");
		return (-1);
	}

	/* Let's check we did things right */
	radclock_get_tsmode(clock, LIVEPCAP_DATA(source)->live_input, &capture_mode);
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

	/* Test if previous file exists. Rename it if so */
	if (strlen(conf->sync_out_pcap) > 0) {
		FILE* out_fd = NULL;
		if ((out_fd = fopen(conf->sync_out_pcap, "r"))) {
			fclose(out_fd);
			char * backup = (char *) malloc(strlen(conf->sync_out_pcap) + 5);
			JDEBUG_MEMORY(JDBG_MALLOC, backup);
			sprintf(backup, "%s.old", conf->sync_out_pcap);
			if (rename(conf->sync_out_pcap, backup) < 0) {
				verbose(LOG_ERR, "Cannot rename existing output file: %s",
						conf->sync_out_pcap);
				JDEBUG_MEMORY(JDBG_FREE, backup);
				free(backup);
				exit(EXIT_FAILURE);
			}
			verbose(LOG_NOTICE, "Backed up existing output file: %s",
					conf->sync_out_pcap);
			JDEBUG_MEMORY(JDBG_FREE, backup);
			free(backup);
			out_fd = NULL;
		}

		/* pcap_dump_open stores the link layer type in the dump file header */
		LIVEPCAP_DATA(source)->trace_output = pcap_dump_open(p_handle_traceout,
				conf->sync_out_pcap);
		if (!LIVEPCAP_DATA(source)->trace_output) {
			verbose(LOG_ERR, "Error opening raw output: %s",
					pcap_geterr(p_handle_traceout));
			JDEBUG_MEMORY(JDBG_FREE, LIVEPCAP_DATA(source));
			free(LIVEPCAP_DATA(source));
			return (-1);
		}
	} else {
		LIVEPCAP_DATA(source)->trace_output = NULL;
		pcap_close(p_handle_traceout);
	}

	return (0);
}


static int
livepcapstamp_get_next(struct radclock *clock, struct stampsource *source,
	struct stamp_t *stamp)
{
	int err;

	JDEBUG

	/* Ensure default stamp quality before filling timestamps */
	stamp->type = STAMP_NTP;
	stamp->qual_warning = 0;

	err = get_network_stamp(clock, (void *)LIVEPCAP_DATA(source),
			get_packet_livepcap, stamp, &source->ntp_stats);

	return (err);
}



/*
 * Wrapper to the pcap_breakloop() call. This is usually called when the daemon
 * catches a SIGHUP signal. This call does not affect other threads. In other
 * words, the pcap_get*() functions have to be in the main thread. Will not work
 * otherwise
 */
static void
livepcapstamp_breakloop(struct radclock *handle, struct stampsource *source)
{
	pcap_breakloop(LIVEPCAP_DATA(source)->live_input);
	return;
}


static void
livepcapstamp_finish(struct radclock *handle, struct stampsource *source)
{
	if (LIVEPCAP_DATA(source)->trace_output) {
		pcap_dump_flush(LIVEPCAP_DATA(source)->trace_output);
		pcap_dump_close(LIVEPCAP_DATA(source)->trace_output);
	}

	pcap_close(LIVEPCAP_DATA(source)->live_input);
	JDEBUG_MEMORY(JDBG_FREE, LIVEPCAP_DATA(source));
	free(LIVEPCAP_DATA(source));
}



static int
livepcapstamp_update_filter(struct radclock *handle, struct stampsource *source)
{
	struct bpf_program filter;
	char fltstr[MAXLINE];               // bpf filter string
	int strsize;

// TODO XXX: should pass IP addresses only to libpcap and not hostnames!
	strsize = build_BPFfilter(handle, fltstr, MAXLINE, handle->conf->hostname,
			handle->conf->time_server);

	if ((strsize < 0) || (strsize > MAXLINE-2) ) {
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
	if (pcap_setfilter( LIVEPCAP_DATA(source)->live_input,&filter) == -1 ) {
		verbose(LOG_ERR, "pcap filter setting failure, pcap says: %s",
				pcap_geterr(LIVEPCAP_DATA(source)->live_input));
		goto pcap_err;
	}

	return (0);

pcap_err:
	verbose(LOG_ERR, "Things went really wrong with this update on the live source");
	pcap_close(LIVEPCAP_DATA(source)->live_input);
	JDEBUG_MEMORY(JDBG_FREE, LIVEPCAP_DATA(source));
	free(LIVEPCAP_DATA(source));

err_out:
	return (-1);
}


static int
livepcapstamp_update_dumpout(struct radclock *handle, struct stampsource *source)
{
	if (LIVEPCAP_DATA(source)->trace_output) {
		pcap_dump_flush(LIVEPCAP_DATA(source)->trace_output);
		pcap_dump_close(LIVEPCAP_DATA(source)->trace_output);
	}

	if (strlen(handle->conf->sync_out_pcap) > 0) {
		pcap_t *p_handle_traceout;
		/* We never close this handle for future safety if libpcap
		 * changes its interface, and in the future might utilize this
		 * handle.
		 */
		p_handle_traceout = pcap_open_dead(DLT_LINUX_SLL, BPF_PACKET_SIZE);
		if (!p_handle_traceout) {
			verbose(LOG_ERR, "Error creating pcap handle");
			JDEBUG_MEMORY(JDBG_FREE, LIVEPCAP_DATA(source));
			free(LIVEPCAP_DATA(source));
			return (-1);
		}
		
		LIVEPCAP_DATA(source)->trace_output = pcap_dump_open(p_handle_traceout,
				handle->conf->sync_out_pcap);

		if (!LIVEPCAP_DATA(source)->trace_output) {
			verbose(LOG_ERR, "Error opening raw output: %s",
					pcap_geterr(p_handle_traceout));
			JDEBUG_MEMORY(JDBG_FREE, LIVEPCAP_DATA(source));
			free(LIVEPCAP_DATA(source));
			pcap_close(p_handle_traceout);
			return (-1);
		}
	}
	else
		LIVEPCAP_DATA(source)->trace_output = NULL;

	return (0);
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

