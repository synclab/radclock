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



/*
 * This program illustrate the use of functions related to capture network
 * traffic and producing kernel timestamps based on the RADclock.
 *
 * The RADclock daemon should be running for this example to work correctly.
 */ 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h> 
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include <pcap.h>

/* RADclock API and RADclock packet capture API */
#include <radclock.h>


#define BPF_PACKET_SIZE   108






void usage(char *progname)
{
	fprintf(stdout, "%s: [-v] [-i <interface>] -o <filename> \n", progname);
	fflush(stdout);
	exit(-1);
}






pcap_t* initialise_pcap_device(char * network_device)
{
	pcap_t * phandle;
    struct bpf_program filter;
    char errbuf[PCAP_ERRBUF_SIZE];  /* size of error message set in pcap.h */

    /* pcap stuff, need to get access to global RADclock data */
    /* Use pcap to open a bpf device */
    if (network_device == NULL) { //if network device has not been specified by user    
		if ((network_device = pcap_lookupdev(errbuf)) == NULL) { /* Find free device */
			fprintf(stderr,"Failed to find free device, pcap says: %s\n",errbuf);
			exit(EXIT_FAILURE);
		}
		else
			fprintf(stderr, "Found device %s\n", network_device);
    }

	/* No promiscuous mode, timeout on BPF = 5ms */
    if ((phandle = pcap_open_live(network_device, BPF_PACKET_SIZE, 0, 5, errbuf)) == NULL) {
		fprintf(stderr, "Open failed on live interface, pcap says: %s\n", errbuf);
		exit(EXIT_FAILURE);
    }

    /* No need to test broadcast addresses */
    if (pcap_compile(phandle, &filter, "port 123", 0, 0) == -1) {   
		fprintf(stderr, "pcap filter compiling failure, pcap says: %s\n", pcap_geterr(phandle));
		exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(phandle,&filter) == -1 )  {
		fprintf(stderr, "pcap filter setting failure, pcap says: %s\n", pcap_geterr(phandle));
		exit(EXIT_FAILURE);
    }
	return phandle;
}




int main (int argc, char *argv[])
{

    /* RADclock */
	struct radclock *clock_handle;

	/* Pcap */
    pcap_t *pcap_handle 		= NULL; /* pcap handle for interface */
    char *network_device 	= NULL; /* points to physical device, eg xl0, em0, eth0 */

	/* Captured packet */
	struct pcap_pkthdr header;           /* The header that pcap gives us */
	const u_char *packet;                /* The actual packet */ 
	vcounter_t vcount;
    struct timeval tv;
    long double currtime;
	int ret;
    char * output_file = NULL;
    FILE * output_fd = NULL;

	/* Misc */ 
	int verbose_flag = 0;
    int ch;
    long count_pkt = 0;
    long count_pkt_null = 0;

    /* parsing the command line arguments */
    while ((ch = getopt(argc, argv, "vo:i:")) != -1)
	    switch (ch) {
	    case 'o':
		    output_file = optarg;
		    break;
	    case 'v':
		    verbose_flag = 1;
		    break;
	    case 'i':    //  interface to monitor for reference TSs if not default       
			network_device = optarg;
			break;  	   
	default:
		    usage(argv[0]);
	    }

	if ( !output_file ) {
		usage(argv[0]);
		return 1;
	}	


	/* Initialise the pcap capture device */
	pcap_handle = initialise_pcap_device(network_device);


	/* Initialize the clock handle */
	clock_handle = radclock_create();
    if (!clock_handle) {
        fprintf(stderr, "Could create the RADclock handle");
        return -1;
    }
	radclock_init(clock_handle);


    /* Set the capture mode
	 * 2 timestamps are always returned for each packet, a tivemal and a RAW
	 * vcount, options are:
	 * RADCLOCK_TSMODE_SYSCLOCK: system clock timeval, optimised raw vcount 
	 * RADCLOCK_TSMODE_RADCLOCK: RADclock timeval, optimised raw vcount
	 * RADCLOCK_TSMODE_FAIRCOMPARE: system clock timeval, fair vcount
	 */
	radclock_set_tsmode(clock_handle, pcap_handle, RADCLOCK_TSMODE_FAIRCOMPARE);


    /* Open output file to store output */
    if ((output_fd = fopen(output_file,"w")) == NULL) {
		fprintf(stderr, "Open failed on stamp output file- %s\n", output_file);
		exit(-1);
    } else {  /* write out comment header describing data saved */
		fprintf(output_fd, "%% Log of packets timestamps\n");
		fprintf(output_fd, "%% column 3: Time - System clock\n");
		fprintf(output_fd, "%% column 4: Time - RADclock\n");
		fprintf(output_fd, "%% column 2: RAW vcount\n");
		fflush(output_fd);
    }

	/* We do a bit of warm up to heat the IPC socket on slow systems */
	for (ret = 0; ret < 5; ret++ ) { 
		radclock_get_last_stamp(clock_handle, &vcount);
		sleep(1);
	}


	fprintf(stdout, "Starting sniffing NTP packets on port 123 \n");


    /* Collect and store both timestamps for each pkt */
    while (1) {
		int err;

		/* Block until capturing the next packet */
		ret =  radclock_get_packet(clock_handle, pcap_handle, &header, (unsigned char **) &packet, &vcount, &tv);

		if (ret) {
			fprintf(stderr, "WARNING: problem getting packet\n");
			return 0;
		}

		/* Create absolute time from RAD */
		err = radclock_vcount_to_abstime_fp(clock_handle, &vcount, &currtime);


		/* output to file */
		fprintf(output_fd,  "%ld.%.6d %"VC_FMT" %.9Lf\n", tv.tv_sec, (int)tv.tv_usec, vcount, currtime); 
		fflush(output_fd);
	   
			/* in verbose mode also to stdout */
		if (verbose_flag) {
			fprintf(stdout, "%ld.%.6d %"VC_FMT" %.9Lf\n", tv.tv_sec, (int)tv.tv_usec, vcount, currtime); 
		}
		else {
			count_pkt++;
			fprintf(stdout, "\r Number of packets sniffed : %ld (warning: null pkts = %ld)", 
					count_pkt, count_pkt_null);
			fflush(stdout);
		}
    }
}
