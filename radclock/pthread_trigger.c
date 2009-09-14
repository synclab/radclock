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


#include <unistd.h>
#include <syslog.h>
#include <string.h>

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <radclock.h>
#include "radclock-private.h"
#include "verbose.h"

#include "sync_algo.h"
#include "config_mgr.h"
#include "proto_ntp.h"
#include "pthread_mgr.h"



// TODO: Ok, there are issues on how things should be implemented in here. A
// clean way would be to have the functions ops stored in the client_data struct of
// the clock_handle and initialised at startup ... I have been slack and also
// because I don't know yet what the ops are :)
// That will be compulsory when we (I?) add PPS and 1588 support


int ntp_init(struct radclock* clock_handle)
{
	struct hostent *he;
	struct timeval so_timeout;

	/* Do we have what it takes? */
	if (strlen(clock_handle->conf->time_server) == 0)
	{
		verbose(LOG_ERR, "No NTP server specified, I cannot not be a client!");
		return 1;
	}	

	/* Build server infos */
	CLIENT_DATA(clock_handle)->s_to.sin_family 	= PF_INET;
	CLIENT_DATA(clock_handle)->s_to.sin_port 	= ntohs(NTP_PORT);
	if( (he=gethostbyname(clock_handle->conf->time_server)) == NULL )
	{
		herror("gethostbyname");
		return 1;
	}
	CLIENT_DATA(clock_handle)->s_to.sin_addr.s_addr = *(in_addr_t *)he->h_addr_list[0];
	
	/* Create the socket */
	if ((CLIENT_DATA(clock_handle)->socket = socket(AF_INET, SOCK_DGRAM, 0))<0) {
		perror("socket");
		return 1;
	}
	/* Set a timeout on the recv side to avoid blocking for lost packets. We set
	 * it to 800ms. Don't make me believe you are sync'ing to a server with a
	 * RTT of 800ms, that would be stupid, no? */
	so_timeout.tv_sec = 0;
	so_timeout.tv_usec = 800000;
	setsockopt(CLIENT_DATA(clock_handle)->socket, SOL_SOCKET, 
			SO_RCVTIMEO, (void*)(&so_timeout), sizeof(struct timeval)); 

	return 0;
}



int trigger_init(struct radclock *clock_handle)
{
	JDEBUG
	int err = 0;

	switch (clock_handle->conf->synchro_type)
	{
		case TRIGGER_PIGGY:
			/* Nothing to do */	
			break;

		case TRIGGER_NTP:
			err = ntp_init(clock_handle);
			break;

		case TRIGGER_1588:
		case TRIGGER_PPS:
		default:
			verbose(LOG_ERR, "Init Trigger type not implemented");
			break;
	}
	return err;
}	



/**
 * This one does nothing except sleep and wake up the processing thread every
 * second.
 */
int dummy_client()
{
	JDEBUG
	/* 500 ms */
	usleep(500000);
	return 0;
}



int create_ntp_request(struct radclock *clock_handle, struct ntp_pkt *pkt)
{
	JDEBUG
	struct timeval reftime;
	struct timeval xmt; 
	int i;
	vcounter_t last_vcount;

	pkt->li_vn_mode		= PKT_LI_VN_MODE(LEAP_NOTINSYNC, NTP_VERSION, MODE_CLIENT);
	pkt->stratum		= STRATUM_UNSPEC;
	pkt->stratum		= SERVER_DATA(clock_handle)->stratum + 1;
	pkt->ppoll			= NTP_MINPOLL;
	pkt->precision		= -6;		/* Like ntpdate */
	pkt->rootdelay		= htonl(FP_SECOND);
	pkt->rootdispersion	= htonl(FP_SECOND);
	pkt->refid			= SERVER_DATA(clock_handle)->refid;

	/* Reference time */
	radclock_get_last_stamp(clock_handle, &last_vcount);
	radclock_vcount_to_abstime(clock_handle, &last_vcount, &reftime);
	pkt->reftime.l_int = htonl(reftime.tv_sec + JAN_1970);
	pkt->reftime.l_fra = htonl(reftime.tv_usec * 4294967296.0 / 1e6);

	// TODO: need a more symmetric version of the packet exchange?
	pkt->org.l_int		= 0;
	pkt->org.l_fra		= 0;
	pkt->rec.l_int		= 0;
	pkt->rec.l_fra		= 0;

	/* Trying to get the time 5 times */
	for (i=0 ; i<5 ; i++ )
	{	
		if (radclock_gettimeofday(clock_handle, &xmt) == 0) {
			break;
		}
		usleep(5); 	
		verbose(VERB_DEFAULT, "Failed to get time - run %d", i);
	}

	/* I never understood what the NTP timestamp format actually is. That seems
	 * insane to me, but I believe that is the right way to do it ... maybe.
	 * - NTP timestamps start on 1 Jan 1900
	 * - the frac part uses higher end bits as negative power of two (expressed in sec)
	 */
	verbose(VERB_DEBUG, "Sending NTP request at %lu.%lu", xmt.tv_sec, xmt.tv_usec);
	pkt->xmt.l_int = htonl(xmt.tv_sec + JAN_1970);
	pkt->xmt.l_fra = htonl(xmt.tv_usec * 4294967296.0 / 1e6);

	return 0;
}


/**
 * So far this is a very basic test, we should probably do something a bit
 * smarter at one point
 */
int match_ntp_pair(struct ntp_pkt *spkt, struct ntp_pkt *rpkt)
{
	JDEBUG

	if ( 	(spkt->xmt.l_int == rpkt->org.l_int)
		&& 	(spkt->xmt.l_fra == rpkt->org.l_fra) )
	{
		verbose(VERB_DEBUG, "NTP client send/receive successful"); 
		return 1;
	}
	else
		verbose(LOG_WARNING, "NTP client not matching pair"); 
	return 0;
}




int ntp_client(struct radclock * clock_handle)
{
	JDEBUG

	struct ntp_pkt spkt;
	struct ntp_pkt rpkt;
	unsigned int socklen;
	int ret;
	int attempt = 3;

	socklen = sizeof(struct sockaddr_in);

	/* We are a client so we know nothing happens until we send and receive some
	 * NTP packets in here.
	 * Send a burst of requests at startup
	 */
	if ( clock_handle->server_data->burst > 0 )
	{
		clock_handle->server_data->burst -= 1;
		sleep(BURST_DELAY);
	}
	else
		sleep(clock_handle->conf->poll_period);

	/* Keep trying to send requests that make sense.
	 * The receive call will timeout if we do not get a reply quick enough. This
	 * is good since packets can be lost and we do not want to hang with nobody
	 * on the other end of the line.
	 * On the other hand, we do not want to try continuously if the server is
	 * dead or not reachable. So limit to a certain number of attempts
	 */
	while ( attempt > 0)
	{
		/* Create and send an NTP packet */
		create_ntp_request(clock_handle, &spkt);

		ret = sendto(CLIENT_DATA(clock_handle)->socket, 
				(char *)&spkt, LEN_PKT_NOMAC /* No auth */, 0, 
				(struct sockaddr *) &(CLIENT_DATA(clock_handle)->s_to),
				socklen );

		if ( ret < 0 ) {
			perror("sendto");
			continue;
		}	
		
		verbose(VERB_DEBUG, "Sent NTP request to %s",
				inet_ntoa(CLIENT_DATA(clock_handle)->s_to.sin_addr)); 

		/* This will block then timeout if nothing received 
		 * (see init of the socket) 
		 */
		ret = recvfrom(CLIENT_DATA(clock_handle)->socket, 
				&rpkt, sizeof(struct ntp_pkt), 0, 
				(struct sockaddr*)&CLIENT_DATA(clock_handle)->s_from,
				&socklen );

		/* If we got something, check it is a valid pair. If it is the case,
		 * then our job is finished in here. Otherwise, we send a new request.
		 */
		if (ret > 0) 
		{
			verbose(VERB_DEBUG, "Received NTP reply from %s %d",
				inet_ntoa(CLIENT_DATA(clock_handle)->s_from.sin_addr));

			if ( match_ntp_pair(&spkt, &rpkt) )
				break;
		}
		else
		{
			verbose(LOG_WARNING, "No reply after 800ms. Socket timed out");
		}

		attempt--;
	}

	return 0;
}



int trigger_work(void *c_handle)
{
	JDEBUG

	vcounter_t vcount;
	int err;
	struct radclock *clock_handle = (struct radclock *) c_handle; 

	switch (clock_handle->conf->synchro_type)
	{
		case TRIGGER_PIGGY:
			dummy_client();
			break;

		case TRIGGER_NTP:
			ntp_client(clock_handle);
			break;

		case TRIGGER_1588:
		case TRIGGER_PPS:
		default:
			verbose(LOG_ERR, "Trigger type not implemented");
			break;
	}



	/* Here we have a notion of time elapsed that is not driven by packet input,
	 * so we can act upon starvation periods and set correct clock status if
	 * needed.  
	 * TODO Need to move from STARVING to UNSYNC and clear that either
	 * here or in the sync algo
	 */
	err = radclock_get_vcounter(clock_handle, &vcount);
	if ( err < 0 )
		return err;

	if ((vcount - GLOBAL_DATA(clock_handle)->last_changed)*GLOBAL_DATA(clock_handle)->phat > OUT_SKM / 2) 
	{
		/* Data is quite old */
		ADD_STATUS(clock_handle, STARAD_STARVING);
	}
	else
		/* We are happy with the data */
		DEL_STATUS(clock_handle, STARAD_STARVING);

	return 0;
}

