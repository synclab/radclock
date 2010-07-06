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


#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "../config.h"
#include "sync_algo.h"
#include "create_stamp.h"
#include "radclock.h"
#include "radclock-private.h"
#include "verbose.h"
#include "rawdata.h"
#include "jdebug.h"



/*
 * Insert a newly created raw_data structure (packet or PPS signal...) into
 * the clock_handle raw data buffer.
 * We always insert at the HEAD. Beware, this is made lock free, we rely on the 
 * buffer consumer not to do stupid stuff !!
 * IMPORTANT: we do assume libpcap gives us packets in chronological order
 */
inline void insert_rd_in_buffer(struct radclock *clock_handle, struct raw_data *rd)
{
	JDEBUG

	rd->next = clock_handle->rdb_start;
	rd->prev = NULL;

	if (rd->next != NULL)
		rd->next->prev = rd;

	clock_handle->rdb_start = rd;
	if ( clock_handle->rdb_end == NULL )
		clock_handle->rdb_end = rd;
}





/* Really, I have tried to make this as fast as possible
 * but if you have a better implementation, go for it.
 */
void fill_rawdata_buffer(u_char *c_handle, const struct pcap_pkthdr *pcap_hdr, const u_char *packet_data)
{
	JDEBUG

	struct radclock *clock_handle = (struct radclock *) c_handle;
	struct raw_data *rd;

	/* Initialise rd */
	rd = (struct raw_data *) malloc (sizeof(struct raw_data));
	JDEBUG_MEMORY(JDBG_MALLOC, rd);

	rd->buf = (void *) malloc( pcap_hdr->caplen * sizeof(char));
	JDEBUG_MEMORY(JDBG_MALLOC, rd->buf);

	rd->read 		= 0;	/* Of course not read yet */
	rd->type 		= RD_PACKET;
	rd->vcount 		= 0;		/* if the next one fails, we will see that quickly */

	if ( extract_vcount_stamp(clock_handle->pcap_handle, pcap_hdr, packet_data, &(rd->vcount)) < 0 )
	{
		verbose(LOG_ERR, "Could not extract vcounter from packet timestamped: %l.%l",
			   	pcap_hdr->ts.tv_sec, pcap_hdr->ts.tv_usec); 	
	}

	memcpy( &(rd->pcap_hdr), pcap_hdr, sizeof(struct pcap_pkthdr));
	memcpy( rd->buf, packet_data, pcap_hdr->caplen * sizeof(char) );

	insert_rd_in_buffer(clock_handle, rd);
}





int capture_raw_data( struct radclock *clock_handle)
{
	JDEBUG

	int err;
	/* Call pcap_loop() with number of packet =-1 so that it actually never
	 * returns until error or explicit break. The kernelclock_fill_buffer
	 * callback is in charge of storing capture packets in the clock raw data
	 * buffer (we pass the clock handle as a parameter).
	 */
	switch( clock_handle->run_mode ) {

		case RADCLOCK_RUN_KERNEL:
			err = pcap_loop(clock_handle->pcap_handle, -1 /*packet*/, fill_rawdata_buffer, (u_char *) clock_handle);
			break;
	
		/* Since we are the radclock, we should know which mode we run in !! */	
		case RADCLOCK_RUN_DEAD:
		case RADCLOCK_RUN_NOTSET:
		default:
			verbose(LOG_ERR, "Trying to capture data with wrong running mode");
			return -1;
	}

	/* Error can be -1 (read error) or -2 (explicit loop break) */
	if ( err < 0 )
		return err;

	/* We should probably never go in here anyway */
	return 0; 
}



/* This function will free the raw_data that has already been read and deliver
 * the next raw data element to read. Remember that the access to the raw data
 * buffer is lock free (e.g., pcap_loop() is adding element to it) !!
 * IMPORTANT: Forbidden to screw up in here, there is no safety net 
 */
struct raw_data* free_and_cherrypick(struct radclock *clock_handle) 
{
	JDEBUG

	struct raw_data * rd;
	struct raw_data * tofree;

	/* Position at the end of the buffer */
	rd = clock_handle->rdb_end;

	/* Is the buffer empty ? */
	if (rd == NULL)
		return rd;

	/* Free data that has been read previously. We make sure we never remove the
	 * first element of the list. So that pcap_loop() does not get confused
	 */
	while ( (rd != clock_handle->rdb_start) )
	{
		if (rd->read == 0)
			break;
		else
		{
			/* Record who is the buddy to kill */
			tofree = rd;
			
			/* New end of the raw data buffer */
			rd = rd->prev;
			rd->next = NULL;
			clock_handle->rdb_end = rd;

			/* Kill it */
			tofree->next = NULL;
			tofree->prev = NULL;
			JDEBUG_MEMORY(JDBG_FREE, tofree->buf);
			free(tofree->buf);
			JDEBUG_MEMORY(JDBG_FREE, tofree);
			free(tofree);
		}
	}
	/* Remember we never delete the first element of the raw data buffer. So we
	 * can have a lock free add at the HEAD of the list. However, we may have
	 * read the first element, so we don't want get_bidir_stamp() to spin like
	 * a crazy on this return. If we read it before, return error code.
	 * Here, rd should NEVER be NULL. If we sef fault here, blame the guy who
	 * wrote that ...
	 */
	if (rd->read == 1)
		return NULL;

	return rd;
}


// XXX
// TODO: we should be able to avoid all these copies of packet payload ... on
// the other hand, raw_data, may not be a packet, but a PPS stamp
int deliver_raw_data( struct radclock *clock_handle, struct radpcap_packet_t *pkt, vcounter_t *vcount)
{
	JDEBUG

	struct raw_data *rd;
	rd = free_and_cherrypick(clock_handle);

	/* Check we have something to do */
	if (rd == NULL)
		return -1;

	switch(rd->type) {

		case RD_PACKET:
			// TODO: there has been some overkill in here no? Maybe redefine the
			// TODO: raw data structure
			/* Copy pcap header and packet payload back-to-back.
			 * The buffer is defined to be way larger than what we need, so
			 * should be safe to copy the captured payload.
			 */
			memcpy(pkt->buffer, &rd->pcap_hdr , sizeof(struct pcap_pkthdr));
			memcpy(pkt->buffer + sizeof(struct pcap_pkthdr), rd->buf , rd->pcap_hdr.caplen);

			/* Position the pointers of the radpcap_packet structure */
			pkt->header = pkt->buffer;
			pkt->payload = pkt->buffer + sizeof(struct pcap_pkthdr);
			pkt->size = rd->pcap_hdr.caplen + sizeof(struct pcap_pkthdr);
			pkt->type = pcap_datalink(clock_handle->pcap_handle);

			/* Fill the vcount */
			*vcount = rd->vcount; 

			/* Mark this raw data element read */
			rd->read = 1;
			break;	


		case RD_PPS:
			// TODO: to implement when we know how to read a PPS
			break;	

		case RD_UNKNOWN:
		default:
			verbose(LOG_ERR, "I don't know how to deliver this kind of raw data!!");
	}

	return 0; 
}


