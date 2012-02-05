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



#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <errno.h>

#include "../config.h"
#include "radclock.h"
#include "radclock-private.h"
#include "verbose.h"
#include "sync_algo.h"
#include "pthread_mgr.h"
#include "proto_ntp.h"
#include "jdebug.h"
#include "config_mgr.h"



/* This is a revamped version of the API function but using the radclock_data
 * structure to ensure consistency and causality of the different timestamps
 */
static inline void build_timestamp_tval(
		struct radclock *handle, const struct radclock_data *rdata, 
		vcounter_t vcount, struct timeval *tv)
{
	long double base_time = (long double) vcount * (long double) rdata->phat 
		+ rdata->ca;
	
	/* Safe to use the clock handle for this test */
	if ( (handle->local_period_mode == RADCLOCK_LOCAL_PERIOD_ON)
		&& ((RAD_DATA(handle)->status & STARAD_WARMUP) != STARAD_WARMUP) )
	{
		base_time+= 
			(long double)(vcount - rdata->last_changed) * 
			(long double)(rdata->phat_local - rdata->phat);
	}

	tv->tv_sec  = (uint32_t) base_time;
	tv->tv_usec = (uint32_t) (1000000*(base_time - tv->tv_sec) + 0.5);
}


/* 
 * Function run by the global data pthread server for NTP 
 */
void* thread_ntp_server(void *c_handle) 
{

	/* Deal with UNIX signal catching */
	init_thread_signal_mgt();

	/* Clock handle to be able to read global data */
	struct radclock *clock_handle;
	clock_handle = (struct radclock*) c_handle;
	int err;

	/* UNIX Socket structures */
	unsigned int s_server; 
    struct sockaddr_in sin_server, sin_client;
    socklen_t len;

	/* Bytes read */
	int n;

	/* Read timeout, otherwise we will block forever and never quit this thread */
	struct timeval so_timeout;

	/* NTP packets
	 * We don't know what we are receiving (backward compatibility with exotic
	 * NTP clients?) so allocate a big buffer for the receiving side. But in all
	 * cases, reply with minimal packets.
	 * TODO: security issues?
	 */
	char *pkt_in;
	struct ntp_pkt *pkt_out;
	
	pkt_in  = (char*) malloc(sizeof(char)*NTP_PKT_MAX_LEN);
	JDEBUG_MEMORY(JDBG_MALLOC, pkt_in);

	pkt_out = (struct ntp_pkt*) malloc(sizeof(struct ntp_pkt));
	JDEBUG_MEMORY(JDBG_MALLOC, pkt_out);

	/* Timestamps to send:
	 * reftime: last time clock was updated (local time)
	 * org: timestamp from the client
	 * rec: timestamp when receving packet (local time)
	 * xmt: timestamp when sending packet (local time)
	 */
	struct timeval reftime;
	struct timeval org;
	struct timeval rec;
	struct timeval xmt;

	/* Reference quality info */
	double rootdelay;
	double rootdispersion;

	/* RADclock data
	 * Bypass API to ensure consistency
	 */
	struct radclock_data rdata;
	double clockerror;
	vcounter_t vcount = 0;
	int pkt_in_mode;

	
	/* Create the server socket */
	if ((s_server = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0 ) {
		perror("socket");	
		pthread_exit(NULL);
	}

	/* Init data structures */
	memset((char *) &sin_client, 0, sizeof(struct sockaddr_in));
	memset((char *) &sin_server, 0, sizeof(struct sockaddr_in));

	sin_server.sin_family 		= AF_INET;
	sin_server.sin_addr.s_addr 	= htonl(INADDR_ANY);

        /* Listen for requests coming from downstream clients */
	sin_server.sin_port =
            htons((long)clock_handle->conf->ntp_downstream_port);

	/* Set the receive timeout */
	so_timeout.tv_sec 	= 1;
	so_timeout.tv_usec 	= 0;	/* 1 sec */
	setsockopt(s_server, SOL_SOCKET, SO_RCVTIMEO, (void*)(&so_timeout), sizeof(struct timeval)); 

	/* Bind socket */
    if (bind(s_server, (struct sockaddr *)&sin_server, sizeof(struct sockaddr_in)) == -1 ) {
		verbose(LOG_ERR, "Socket bind() error. Killing NTP server thread: %s", strerror(errno));
		pthread_exit(NULL);
	}

	/* Accept connections from clients.
	 * Process request, and send back  data
	 */
	verbose(LOG_NOTICE, "NTP server thread initialised.");
	len = sizeof(sin_client);


	while ( (clock_handle->pthread_flag_stop & PTH_NTP_SERV_STOP) != PTH_NTP_SERV_STOP )
	{
		memset((char *) &reftime, 0, sizeof(struct timeval));
		memset((char *) &org, 0, sizeof(struct timeval));
		memset((char *) &rec, 0, sizeof(struct timeval));
		memset((char *) &xmt, 0, sizeof(struct timeval));
		memset((char *) pkt_out, 0, sizeof(struct ntp_pkt));
		memset((char *) &rdata, 0, sizeof(struct radclock_data));
	
		/* Receive the request 
		 * Need a recvfrom() call, since we need to get client return address
		 */
		n = recvfrom(s_server, (void*) pkt_in, NTP_PKT_MAX_LEN, 0, (struct sockaddr*)&sin_client, &len);
		if (n < 0) {
			/* We timed out, let's start over again */
			continue;
		}
		/* No need to create a thread for connection-less sockets or use a
		 * select().  My guess is that the cost of threading to provide
		 * concurrent services is too much of an overhead compared to the actual
		 * job to do.
		 */

		/* Create receive timestamp, the really first thing to do
		 * If we fail should we really die? 
		 */
		err = radclock_get_vcounter(clock_handle, &vcount);
		if (err < 0)
		{
			verbose(LOG_WARNING, "Failed to read virtual counter to serve NTP client (incoming)");
			continue;
		}


		/* Let's have a look at what we got in here */
		pkt_in_mode = PKT_MODE( ((struct ntp_pkt*)pkt_in)->li_vn_mode ); 
		switch (pkt_in_mode)
		{
			case MODE_UNSPEC:
			case MODE_ACTIVE:
			case MODE_PASSIVE:
			case MODE_SERVER:
			case MODE_BROADCAST:
				/* This is all garbage, should not have received that in the
				 * first place. Let's continue silently
				 */
				continue;

			case MODE_PRIVATE:
			case MODE_CONTROL:
				/* Who is using ntpq or ntpdc? */
				verbose(VERB_DEBUG, "Received an NTP control message. Ignore that.");
				continue;

			case MODE_CLIENT:
				/* We are after that fellow */
				break;
		}

	
		/* Get the radclock data we will use to compute timestamps and errors.
		 * Loop it to ensure consistency
		 */
		do {
			memcpy(&rdata, RAD_DATA(clock_handle), sizeof(struct radclock_data));
		} while ( memcmp(&rdata, RAD_DATA(clock_handle), sizeof(struct radclock_data)) != 0 );

		
		/* NTP specification "seems" to indicate that the dispersion grows linear
		 * at worst case rate error set to 15 PPM. The constant component is twice 
		 * the precision +  the filter dispersion which is a weighted sum of the 
		 * (past?) clock offsets.  The value of 15 PPM is somewhat arbitrary, trying
		 * to reflect the fact that XO are much better than their 500 PPM specs. 
		 * Also precision in here is horrible ntpd linguo meaning "period" for us.
		 * XXX Here I use the clock error as an equivalent to the filter
		 * dispersion, I think it is safe to use the clock_handle for that value
		 * (should be some kind of longer term value anyway)
		 */
		clockerror = RAD_ERROR(clock_handle)->error_bound_avg; 
		rootdispersion 	= SERVER_DATA(clock_handle)->rootdispersion 
							+ clockerror + rdata.phat 
							+ (vcount - rdata.last_changed) * rdata.phat_local * 15e-6;

		rootdelay = SERVER_DATA(clock_handle)->rootdelay 
						+ SERVER_DATA(clock_handle)->serverdelay;
		

		/* Fill the packet
		 * Clearly there are some issues with network and host byte order (stupid refid) 
		 * Fixed point conversion of rootdispersion and rootdelay with up-down round up
		 */
		pkt_out->li_vn_mode		= PKT_LI_VN_MODE(LEAP_NOWARNING, NTP_VERSION, MODE_SERVER);

		/* If we are not in sync, then for sure, our knowledge of time is
		 * screwed. Let's warn clients that we don't feel too good right now
		 */
		if ( HAS_STATUS(clock_handle, STARAD_UNSYNC) )
		{
			pkt_out->stratum	= STRATUM_UNSPEC;
		}
		else {
			pkt_out->stratum	= SERVER_DATA(clock_handle)->stratum + 1;
		}
		pkt_out->ppoll			= ((struct ntp_pkt*)pkt_in)->ppoll;
		pkt_out->precision		= -18;	/* TODO: should pass min(STA_NANO (or mus), phat) in power of 2 or so */
		pkt_out->rootdelay 		= htonl( (uint32_t)(rootdelay * 65536. + 0.5));
		pkt_out->rootdispersion = htonl( (uint32_t)(rootdispersion * 65536. + 0.5));
		pkt_out->refid		= SERVER_DATA(clock_handle)->refid;

		/* Reference time */
		build_timestamp_tval(clock_handle, &rdata, rdata.last_changed, &reftime);
		pkt_out->reftime.l_int = htonl(reftime.tv_sec + JAN_1970);
		pkt_out->reftime.l_fra = htonl(reftime.tv_usec * 4294967296.0 / 1e6);

		/* Origin Timestamp */
		pkt_out->org = ((struct ntp_pkt*)pkt_in)->xmt; 

		/* Receive Timestamp */
		build_timestamp_tval(clock_handle, &rdata, vcount, &rec);
		pkt_out->rec.l_int = htonl(rec.tv_sec + JAN_1970);
		pkt_out->rec.l_fra = htonl(rec.tv_usec * 4294967296.0 / 1e6);

		verbose(VERB_DEBUG, "Reply to NTP client %s with statum=%d rdelay=%.06f rdisp= %.06f "
				"clockerror= %.06f diff= %"VC_FMT" Tb= %d.%06d",
				inet_ntoa(sin_client.sin_addr),
				pkt_out->stratum,
				rootdelay, rootdispersion, clockerror, 
	  			(vcount - rdata.last_changed), rec.tv_sec, rec.tv_usec ); 

		/* Transmit Timestamp
		 * If we fail should we really die? 
		 */
		err = radclock_get_vcounter(clock_handle, &vcount);
		if (err < 0)
		{
			verbose(LOG_WARNING, "Failed to read virtual counter to serve NTP client (incoming)");
			continue;
		}
		build_timestamp_tval(clock_handle, &rdata, vcount, &xmt);
		pkt_out->xmt.l_int = htonl(xmt.tv_sec + JAN_1970);
		pkt_out->xmt.l_fra = htonl(xmt.tv_usec * 4294967296.0 / 1e6);
		

		/* Send data back using the client's address */
		// TODO: So far we send the minimum packet size ... we may change that later 
		if (sendto(s_server, (char*)pkt_out, LEN_PKT_NOMAC, 0, (struct sockaddr *)&sin_client, len) < 0) {
			verbose(LOG_ERR, "NTP Socket send() error: %s", strerror(errno));
		}

		/* Someone told us to die ... sniff */
		if ( clock_handle->ipc_mode == RADCLOCK_IPC_NONE)
			break;
			//pthread_exit(NULL);
	}

	/* Thread exit */
	verbose(LOG_NOTICE, "Thread NTP server is terminating.");
	JDEBUG_MEMORY(JDBG_FREE, pkt_in);
	free(pkt_in);
	JDEBUG_MEMORY(JDBG_FREE, pkt_out);
	free(pkt_out);

	pthread_exit(NULL);
}


