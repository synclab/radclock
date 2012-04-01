/*
 * Copyright (C) 2006-2012, Julien Ridoux <julien@synclab.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
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

#include <arpa/inet.h>

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include "../config.h"
#include "radclock.h"
#include "radclock-private.h"
#include "radclock_daemon.h"
#include "sync_history.h"
#include "sync_algo.h"
#include "config_mgr.h"
#include "create_stamp.h"
#include "verbose.h"
#include "rawdata.h"
#include "jdebug.h"


/* Needed for the spy capture ... cannot pass the handle to the signal catcher */
extern struct radclock_handle *clock_handle;

timer_t spy_timerid;


/*
 * Insert a newly created raw_data_bundle structure (packet or PPS signal...)
 * into the clock_handle raw data linked list.
 * We always insert at the HEAD. Beware, this is made lock free, we rely on the
 * buffer consumer not to do stupid stuff !!
 * IMPORTANT: we do assume libpcap gives us packets in chronological order
 */
inline void
insert_rdb_in_list(struct radclock_handle *handle, struct raw_data_bundle *rdb)
{
	JDEBUG

	// XXX Should get rid of the lock, the chain list is supposed to be lock
	// free ... well, theoretically. It seems that free_and_cherry_pick is
	// actuall messing with this new rdb if hammering with NTP control packets
	pthread_mutex_lock(&handle->rdb_mutex);

	JDEBUG_STR("INSERT: rdb at %p, ->next at %p, end at %p, start at %p",
		rdb, rdb->next, handle->rdb_end, clock_handle->rdb_start);

	if (handle->rdb_start != NULL)
		handle->rdb_start->next = rdb;

	handle->rdb_start = rdb;

	if (handle->rdb_end == NULL)
		handle->rdb_end = rdb;

	pthread_mutex_unlock(&handle->rdb_mutex);
}





/*
 * Really, I have tried to make this as fast as possible
 * but if you have a better implementation, go for it.
 */
void
fill_rawdata_ntp(u_char *c_handle, const struct pcap_pkthdr *pcap_hdr,
		const u_char *packet_data)
{
	struct radclock_handle *handle;
	struct raw_data_bundle *rdb;
	int err;

	JDEBUG

	handle = (struct radclock_handle *) c_handle;

	/* Initialise raw data bundle */
	rdb = (struct raw_data_bundle *) malloc(sizeof(struct raw_data_bundle));
	JDEBUG_MEMORY(JDBG_MALLOC, rdb);
	assert(rdb);

	RD_NTP(rdb)->buf = (void *) malloc( pcap_hdr->caplen * sizeof(char));
	JDEBUG_MEMORY(JDBG_MALLOC, RD_NTP(rdb)->buf);
	assert(RD_NTP(rdb)->buf);

	/* Copy data of interest into the raw data bundle */
	RD_NTP(rdb)->vcount = 0;

	err = extract_vcount_stamp(handle->clock, handle->clock->pcap_handle,
			pcap_hdr, packet_data, &(RD_NTP(rdb)->vcount));

	memcpy(&(RD_NTP(rdb)->pcap_hdr), pcap_hdr, sizeof(struct pcap_pkthdr));
	memcpy(RD_NTP(rdb)->buf, packet_data, pcap_hdr->caplen * sizeof(char));

	rdb->next = NULL;
	rdb->read = 0;		/* Of course not read yet */
	rdb->type = RD_NTP_PACKET;

	/* Insert the new bundle in the linked list */
	insert_rdb_in_list(handle, rdb);
}


/*
 * Get timestamps from the sysclock when the POSIX timer quicks in.
 */
void
fill_rawdata_spy(int sig)
{
	struct raw_data_bundle *rdb;

	JDEBUG

	/* Initialise raw data bundle */
	rdb = (struct raw_data_bundle *) malloc (sizeof(struct raw_data_bundle));
	JDEBUG_MEMORY(JDBG_MALLOC, rdb);

	/* What time is it mister stratum-1? */
	radclock_get_vcounter(clock_handle->clock, &(RD_SPY(rdb)->Ta));
	gettimeofday( &(RD_SPY(rdb)->Tb), NULL);
	gettimeofday( &(RD_SPY(rdb)->Te), NULL);
	radclock_get_vcounter(clock_handle->clock, &(RD_SPY(rdb)->Tf));

	rdb->next = NULL;
	rdb->read = 0;	/* Of course not read yet */
	rdb->type = RD_SPY_STAMP;

	/* Insert the new bundle in the linked list */
	insert_rdb_in_list(clock_handle, rdb);
}


/*
 * Fake loop for capturing spy data.
 * Init a POSIX timer to capture data periodically and check if need
 * to return
 */
int
spy_loop(struct radclock_handle *handle)
{
	struct itimerspec itimer_ts;

	/* Signal catching */
	struct sigaction sig_struct;
	sigset_t alarm_mask;

	JDEBUG

	/* Initialise the signal data */
	sigemptyset(&alarm_mask);
	sigaddset(&alarm_mask, SIGALRM);
	sig_struct.sa_handler = fill_rawdata_spy; /* Not so dummy handler */
	sig_struct.sa_mask = alarm_mask;
	sig_struct.sa_flags = 0;
	sigaction(SIGALRM,  &sig_struct, NULL);

	if (timer_create (CLOCK_REALTIME, NULL, &spy_timerid) < 0) {
		verbose(LOG_ERR, "spy_loop: creation of POSIX timer failed: %s", strerror(errno));
		return (-1);
	}

	itimer_ts.it_value.tv_sec = 0;
	itimer_ts.it_value.tv_nsec = 5e8;
	itimer_ts.it_interval.tv_sec = (int) handle->conf->poll_period;
	itimer_ts.it_interval.tv_nsec = 0;

	if (timer_settime(spy_timerid, 0 /*!TIMER_ABSTIME*/, &itimer_ts, NULL) < 0) {
		verbose(LOG_ERR, "spy_loop: POSIX timer cannot be set: %s", strerror(errno));
		return (-1);
	}

	while ((handle->unix_signal != SIGHUP) && (handle->unix_signal != SIGTERM)) {
		/* Check every second if need to quit */
		usleep(1000000);
	}
	
	verbose(LOG_NOTICE, "Out of spy loop");
	return (0);
}




int
capture_raw_data(struct radclock_handle *handle)
{
	int err;

	JDEBUG

	err = 0;
	switch(handle->run_mode) {

	case RADCLOCK_SYNC_LIVE:
		switch (handle->conf->synchro_type) {
		case SYNCTYPE_SPY:
			err = spy_loop(handle);
			break;

		case SYNCTYPE_PIGGY:
		case SYNCTYPE_NTP:
			/* Call pcap_loop() with number of packet =-1 so that it
			 * actually never returns until error or explicit break.
			 * pcap_loop will block until receiving packets to process.
			 * The fill_rawdata_ntp callback is in charge of extracting
			 * relevant information and inserting raw data bundles in the
			 * linked list known by the clock handle.
			 */
			err = pcap_loop(handle->clock->pcap_handle, -1 /*packet*/,
					fill_rawdata_ntp, (u_char *) handle);
			break;

		case SYNCTYPE_PPS:
		case SYNCTYPE_1588:
			verbose(LOG_ERR, "IMPLEMENT ME!!");
			err = -1;
			break;

		default:
			break;
		}
		break;

	/* Since we are the radclock, we should know which mode we run in !! */	
	case RADCLOCK_SYNC_DEAD:
	case RADCLOCK_SYNC_NOTSET:
	default:
		verbose(LOG_ERR, "Trying to capture data with wrong running mode");
		return (-1);
	}

	/* Error can be -1 (read error) or -2 (explicit loop break) */
	if (err < 0)
		return (err);

	/* Pass here if running in spy_loop for example */
	return (0);
}



/* This function will free the raw_data that has already been read and deliver
 * the next raw data element to read. Remember that the access to the raw data
 * buffer is lock free (e.g., pcap_loop() is adding element to it) !!
 * IMPORTANT: Forbidden to screw up in here, there is no safety net
 */
struct raw_data_bundle *
free_and_cherrypick(struct radclock_handle *handle)
{
	struct raw_data_bundle *rdb, *rdb_tofree;

	JDEBUG

	/* Position at the end of the buffer */
	rdb_tofree = NULL;
	rdb = clock_handle->rdb_end;

	/* Is the buffer empty ? */
	if (rdb == NULL)
		return (rdb);

	/*
	 * Free data that has been read previously. We make sure we never remove the
	 * first element of the list. So that pcap_loop() does not get confused
	 */
	while (rdb != handle->rdb_start) {
		if (rdb->read == 0)
			break;
		else {
			/* Record who is the buddy to kill */
			rdb_tofree = rdb;
			rdb = rdb->next;
			
			/* Position new end of the raw data buffer and nuke */
			// XXX again, should get rid of the locking
			pthread_mutex_lock(&handle->rdb_mutex);
			handle->rdb_end = rdb;
			rdb_tofree->next = NULL;

			if (rdb_tofree->type == RD_NTP_PACKET )
			{
				JDEBUG_MEMORY(JDBG_FREE, RD_NTP(rdb_tofree)->buf);
				free(RD_NTP(rdb_tofree)->buf);
				RD_NTP(rdb_tofree)->buf = NULL;
			}
			JDEBUG_STR( "FREE: rdb at %p, ->next at %p, end at %p, start at %p",
				rdb_tofree, rdb_tofree->next,
				handle->rdb_end, handle->rdb_start);
			JDEBUG_MEMORY(JDBG_FREE, rdb_tofree);
			free(rdb_tofree);
			rdb_tofree = NULL;
			pthread_mutex_unlock(&handle->rdb_mutex);
		}
	}
	/* Remember we never delete the first element of the raw data buffer. So we
	 * can have a lock free add at the HEAD of the list. However, we may have
	 * read the first element, so we don't want get_bidir_stamp() to spin like
	 * a crazy on this return. If we read it before, return error code.
	 * Here, rdb should NEVER be NULL. If we sef fault here, blame the guy who
	 * wrote that ...
	 */
	if (rdb->read == 1)
		return (NULL);

	return (rdb);
}




int
deliver_rawdata_spy(struct radclock_handle *handle, struct stamp_t *stamp)
{
	struct raw_data_bundle *rdb;

	JDEBUG

	/* Do some clean up if needed and gives the current raw data bundle
	 * to process.
	 */
	rdb = free_and_cherrypick(handle);

	/* Check we have something to do */
	if (rdb == NULL)
		return (-1);

	if (rdb->type != RD_SPY_STAMP) {
		verbose(LOG_ERR, "!! Asked to deliver SPY stamps from rawdata but parsing other type !!");
		return (-1);
	}

	BST(stamp)->Ta = RD_SPY(rdb)->Ta;
	BST(stamp)->Tb = (long double) (RD_SPY(rdb)->Tb.tv_sec) + (long double) (RD_SPY(rdb)->Tb.tv_usec / 1e6);
	BST(stamp)->Te = (long double) (RD_SPY(rdb)->Te.tv_sec) + (long double) (RD_SPY(rdb)->Te.tv_usec / 1e6);
	BST(stamp)->Tf = RD_SPY(rdb)->Tf;
	stamp->type = STAMP_SPY;
	stamp->qual_warning = 0;

	/* Mark this raw data element read */
	rdb->read = 1;

	return (0);
}




// XXX TODO XXX this is a bit messy. some parts are specific to the source, maybe that should be in the corresponding file?
// XXX XXX Quite complicated with multiple sources, the chain list management is not re-entrant with multiple sources!!
int
deliver_rawdata_ntp(struct radclock_handle *handle, struct radpcap_packet_t *pkt,
		vcounter_t *vcount)
{
	struct raw_data_bundle *rdb;

	JDEBUG

	/* Do some clean up if needed and gives the current raw data bundle
	 * to process.
	 */
	rdb = free_and_cherrypick(handle);

	/* Check we have something to do */
	if (rdb == NULL)
		return (-1);

	if (rdb->type != RD_NTP_PACKET) {
		verbose(LOG_ERR, "!! Asked to deliver NTP packet from rawdata but "
				"parsing other type !!");
		return (-1);
	}

	/* Copy pcap header and packet payload back-to-back.
	 * The buffer is defined to be way larger than what we need, so
	 * should be safe to copy the captured payload.
	 */
	memcpy(pkt->buffer, &(RD_NTP(rdb)->pcap_hdr), sizeof(struct pcap_pkthdr));
	memcpy(pkt->buffer + sizeof(struct pcap_pkthdr), RD_NTP(rdb)->buf,
			RD_NTP(rdb)->pcap_hdr.caplen);

	/* Position the pointers of the radpcap_packet structure */
	pkt->header = pkt->buffer;
	pkt->payload = pkt->buffer + sizeof(struct pcap_pkthdr);
	pkt->size = RD_NTP(rdb)->pcap_hdr.caplen + sizeof(struct pcap_pkthdr);
	pkt->type = pcap_datalink(handle->clock->pcap_handle);

	/* Fill the vcount */
	*vcount = RD_NTP(rdb)->vcount;

	/* Mark this raw data element read */
	rdb->read = 1;

	return (0);
}

