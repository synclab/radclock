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


#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>
#include <errno.h>

#include "../config.h"
#include "radclock.h"
#include "radclock-private.h"
#include "verbose.h"
#include "sync_algo.h"
#include "config_mgr.h"
#include "proto_ntp.h"
#include "pthread_mgr.h"
#include "jdebug.h"


#define SO_RCV_TIMEOUT 800000

// TODO: Ok, there are issues on how things should be implemented in here. A
// clean way would be to have the functions ops stored in the client_data struct of
// the clock_handle and initialised at startup ... I have been slack and also
// because I don't know yet what the ops are :)
// That will be compulsory when we (I?) add PPS and 1588 support


/* POSIX timer and signal catching mask
 * This requires FreeBSD 7.0 and above for POSIX timers.
 * Also, sigsuspend does not work on Linux in a multi-thread environment
 * (apparently) so use pthread condition wait to sync the thread to SIGALRM
 */
timer_t ntpclient_timerid;
pthread_mutex_t alarm_mutex;
pthread_cond_t alarm_cwait;



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

int virtual_client(struct radclock *clock_handle){
	JDEBUG
	int err;
	useconds_t sleep_time;
	vcounter_t vcount, delta;
	
	RAD_VM(clock_handle)->pull_data(clock_handle);
	err = radclock_get_vcounter(clock_handle, &vcount);
	
	if(vcount < RAD_DATA(clock_handle)->valid_till){
		if(vcount > RAD_DATA(clock_handle)->last_changed){
		    delta = RAD_DATA(clock_handle)->valid_till - vcount; // Calculate amount of time to sleep untill next valid_till
			sleep_time = delta * RAD_DATA(clock_handle)->phat * 1000000;
			usleep(sleep_time);
		} else {
			verbose(LOG_ERR, "Virtual store data not suitable for this counter"); 
		}
	} else { /* We've gone over the valid till point, just keep checking at every 500000us until we are successful */
	//	delta = RAD_DATA(clock_handle)->valid_till - RAD_DATA(clock_handle)->last_changed; /* Poll period */
	//	sleep_time = delta * RAD_DATA(clock_handle)->phat * 1000000 / 100; /* Poll period / 100 */
		usleep(500000);
	}
	return err;
}

/* 
 * Timer handler
 */
void catch_alarm(int sig) 
{
	JDEBUG

	pthread_mutex_lock(&alarm_mutex);
	pthread_cond_signal(&alarm_cwait);
	pthread_mutex_unlock(&alarm_mutex);
}



/* (re)set and arm the POSIX timer */
inline int set_ptimer(timer_t timer, float next, float period)
{
	struct itimerspec itimer_ts;

	itimer_ts.it_value.tv_sec = (int) next;
	itimer_ts.it_value.tv_nsec = 1e9 * (next - (int) next);
	itimer_ts.it_interval.tv_sec = (int) period;
	itimer_ts.it_interval.tv_nsec = 1e9 * (period - (int) period);

	return timer_settime(timer, 0 /*!TIMER_ABSTIME*/, &itimer_ts, NULL);
}


/* Is there a need for change? */
int assess_ptimer(timer_t timer, float period)
{
	JDEBUG

	int err;
	struct itimerspec itimer_ts;
	float timer_next;
	float timer_period;
	
	err = timer_gettime(timer, &itimer_ts);
	if ( err < 0 )
		return err;

	timer_next = itimer_ts.it_value.tv_sec 
				+ (float) itimer_ts.it_value.tv_nsec / 1e9;
	timer_period = itimer_ts.it_interval.tv_sec 
				+ (float) itimer_ts.it_interval.tv_nsec / 1e9;

	if ( timer_period != period )
	   err = set_ptimer(timer, timer_next, period);
	
	return err;
}	




int create_ntp_request(struct radclock *clock_handle, struct ntp_pkt *pkt, struct timeval *xmt)
{
	JDEBUG
	struct timeval reftime;
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
		if (radclock_gettimeofday(clock_handle, xmt) == 0) {
			break;
		}
		usleep(5); 	
		verbose(VERB_DEFAULT, "Failed to get time - run %d", i);
	}

	/* The NTP timestamp format (a bit tricky): 
	 * - NTP timestamps start on 1 Jan 1900
	 * - the frac part uses higher end bits as negative power of two (expressed in sec)
	 */
	pkt->xmt.l_int = htonl(xmt->tv_sec + JAN_1970);
	pkt->xmt.l_fra = htonl(xmt->tv_usec * 4294967296.0 / 1e6);

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
		return 1;
	else
		verbose(LOG_WARNING, "NTP protocal client got a non matching pair"); 
	return 0;
}




int ntp_client(struct radclock * clock_handle)
{
	JDEBUG

	/* Timer and polling grid data */
	float adjusted_period;
	float starve_ratio = 1.0;
	int attempt = 3;

	/* Packet stuff */
	struct ntp_pkt spkt;
	struct ntp_pkt rpkt;
	unsigned int socklen;
	int ret;

	/* Essentially for debug */
	struct timeval xmt;

	socklen = sizeof(struct sockaddr_in);

	/* We are a client so we know nothing happens until we send and receive some
	 * NTP packets in here.
	 * Send a burst of requests at startup complying with ntpd implementation
	 * (to be nice). After burst period, send packets on the adjusted period
	 * grid. A bit of a luxury to benefit from the POSIX timer in here but it
	 * makes the code cleaner ... so why not :)
	 */
	if ( clock_handle->server_data->burst > 0 )
	{
		clock_handle->server_data->burst -= 1;
		adjusted_period = BURST_DELAY;
	}
	else
	{
		/* The logic to change the rate of polling due to starvation is
		 * delegated to the sync algo
		 */

		// TODO implement logic for starvation ratio for sleep defined by the sync algo
		adjusted_period = clock_handle->conf->poll_period / starve_ratio;
	}
	

	/* Limit the number of attempts to be sure attempt*SO_RCV_TIMEOUT never
	 * exceeds the poll period or we end up in unnecessary complex situation. Of
	 * course it doesn't help us in case RTT > RAD_MINPOLL.
	 */ 
	if ( attempt > adjusted_period / (SO_RCV_TIMEOUT * 1e-6) )
	{
		attempt = MAX(1, (int) adjusted_period / (SO_RCV_TIMEOUT * 1e-6));	
	}


	/* Timer will hiccup in the 1-2 ms range if reset */
	assess_ptimer(ntpclient_timerid, adjusted_period);	


	/* Sleep until next grid point. Try to do as less as possible in between
	 * here and the actual sendto() 
	 */
	pthread_mutex_lock(&alarm_mutex);
	pthread_cond_wait(&alarm_cwait, &alarm_mutex);
	pthread_mutex_unlock(&alarm_mutex);


	/* Keep trying to send requests that make sense.
	 * The receive call will timeout if we do not get a reply quick enough. This
	 * is good since packets can be lost and we do not want to hang with nobody
	 * on the other end of the line.
	 * On the other hand, we do not want to try continuously if the server is
	 * dead or not reachable. So limit to a certain number of attempts.
	 */
	while ( attempt > 0)
	{
		/* Create and send an NTP packet */
		create_ntp_request(clock_handle, &spkt, &xmt);

		ret = sendto(CLIENT_DATA(clock_handle)->socket, 
				(char *)&spkt, LEN_PKT_NOMAC /* No auth */, 0, 
				(struct sockaddr *) &(CLIENT_DATA(clock_handle)->s_to),
				socklen );

		if ( ret < 0 ) {
			verbose(LOG_ERR, "NTP request failed, sendto: %s", strerror(errno));
			return 1;
		}	
		
		verbose(VERB_DEBUG, "Sent NTP request to %s at %lu.%lu",
				inet_ntoa(CLIENT_DATA(clock_handle)->s_to.sin_addr),
				xmt.tv_sec, xmt.tv_usec);

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
			verbose(VERB_DEBUG, "Received NTP reply from %s",
				inet_ntoa(CLIENT_DATA(clock_handle)->s_from.sin_addr));

			if ( match_ntp_pair(&spkt, &rpkt) )
				break;
		}
		else
		{
			verbose(VERB_DEBUG, "No reply after 800ms. Socket timed out");
		}

		attempt--;
	}

	return 0;
}



int trigger_work(struct radclock *clock_handle)
{
	JDEBUG

	vcounter_t vcount;
	int err;

	if (VM_SLAVE(clock_handle))
	{
		virtual_client(clock_handle);
	}
	else {
		switch (clock_handle->conf->synchro_type)
		{
			case SYNCTYPE_SPY:
			case SYNCTYPE_PIGGY:
			case SYNCTYPE_PPS:
			case SYNCTYPE_1588:
				dummy_client();
				break;

			case SYNCTYPE_NTP:
				ntp_client(clock_handle);
				break;

			default:
				verbose(LOG_ERR, "Trigger for this sync type is not implemented");
				break;
		}
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

	if ((vcount - RAD_DATA(clock_handle)->last_changed)*GLOBAL_DATA(clock_handle)->phat > OUT_SKM / 2) 
	{
		/* Data is quite old */
		if ( ! HAS_STATUS(clock_handle, STARAD_STARVING ))
		{
			verbose(LOG_WARNING, "Clock is starving. No valid input for a long time!!"); 
			ADD_STATUS(clock_handle, STARAD_STARVING);
		}
	}
	else
		/* We are happy with the data */
		DEL_STATUS(clock_handle, STARAD_STARVING);

	return 0;
}




int ntp_init(struct radclock* clock_handle)
{
	/* Socket data */
	struct hostent *he;
	struct timeval so_timeout;

	/* Signal catching */
	struct sigaction sig_struct;
	sigset_t alarm_mask;

	/* Do we have what it takes? */
	if (strlen(clock_handle->conf->time_server) == 0)
	{
		verbose(LOG_ERR, "No NTP server specified, I cannot not be a client!");
		return 1;
	}	

	/* Build server infos */
	CLIENT_DATA(clock_handle)->s_to.sin_family 	= PF_INET;
	CLIENT_DATA(clock_handle)->s_to.sin_port 	=
            ntohs(clock_handle->conf->ntp_upstream_port);
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
	so_timeout.tv_usec = SO_RCV_TIMEOUT;
	setsockopt(CLIENT_DATA(clock_handle)->socket, SOL_SOCKET, 
			SO_RCVTIMEO, (void*)(&so_timeout), sizeof(struct timeval)); 
	
	
	/* Initialise the signal data */
	sigemptyset(&alarm_mask);
	sigaddset(&alarm_mask, SIGALRM);
	sig_struct.sa_handler 	= catch_alarm; /* Not so dummy handler */
	sig_struct.sa_mask 		= alarm_mask;
	sig_struct.sa_flags 	= 0;
	sigaction(SIGALRM,  &sig_struct, NULL);

	/* Initialize mutex and condition variable objects */
	pthread_mutex_init(&alarm_mutex, NULL);
	pthread_cond_init (&alarm_cwait, NULL);
	
	 /* CLOCK_REALTIME_HR does not exist on FreeBSD */
	if ( timer_create (CLOCK_REALTIME, NULL, &ntpclient_timerid) < 0 )
	{
		verbose(LOG_ERR, "ntp_init: POSIX timer create failed");
		return 1;
	}
	if ( set_ptimer(ntpclient_timerid, 0.5 /* !0 */, 
				(float) clock_handle->conf->poll_period) < 0 )
	{
		verbose(LOG_ERR, "ntp_init: POSIX timer cannot be set");
		return 1;
	}
	return 0;
}



int trigger_init(struct radclock *clock_handle)
{
	JDEBUG
	int err = 0;
	if(!VM_SLAVE(clock_handle)){
		switch (clock_handle->conf->synchro_type)
		{
			case SYNCTYPE_SPY:
			case SYNCTYPE_PIGGY:
				/* Nothing to do */	
				break;

			case SYNCTYPE_NTP:
				err = ntp_init(clock_handle);
				break;

			case SYNCTYPE_1588:
			case SYNCTYPE_PPS:
			default:
				verbose(LOG_ERR, "Init Trigger type not implemented");
				break;
		}
	}
	return err;
}	





