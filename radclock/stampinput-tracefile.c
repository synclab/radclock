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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>

#include "../config.h"
#include "sync_algo.h"
#include "config_mgr.h"
#include "verbose.h"
#include "pcap.h"
#include "create_stamp.h"
#include "stampinput.h"
#include "stampinput_int.h"
#include "jdebug.h"


#define TRACEFILE_DATA(x) ((struct tracefile_data *)(x->priv_data))


struct tracefile_data {
	pcap_t *trace_input;	/* Input trace */
	char src_ipaddr[16];	/* Host source address for get_bidir_stamp() */
	u_int32_t data_link;	/* Link layer type (stored in dump file) */
};


/* This is the callback passed to get_bidir_stamp().
 * It takes a radpcap_packet_t and fills this structure with the actual packet
 * read from the tracefile
 * Return values:
 *  0 on success
 * -1 error to break upper loop
 */
static int
get_packet_tracefile(struct radclock *handle, void *userdata,
		radpcap_packet_t **packet_p)
{
	int ret;
	struct tracefile_data *data = (struct tracefile_data *) userdata;
	radpcap_packet_t *packet = *packet_p;

	/*
	 * Read the packet from the input trace and store pcap header and packet
	 * payload into the buffer one after the other. Use the generic libpcap
	 * function since the vcount is hidden in the ethernet SLL header (seamless)
	 */
	packet->header  = packet->buffer;
	packet->payload = packet->buffer + sizeof(struct pcap_pkthdr);
	ret = pcap_next_ex(data->trace_input,
		(struct pcap_pkthdr**) (&(packet->header)),
		(const u_char*) (&(packet->payload)));

	switch (ret) {
	case -2:
		verbose(LOG_INFO, "End of PCAP trace input");
		return (-2);

	case -1:
		verbose(LOG_ERR, "Error reading packet, pcap_next_ex returned -1");
		return (-1);

	case 0:
		verbose(LOG_ERR, "Should read from trace file but we are live!");
		return (-1);

	case 1:
		/* No errors */
		break;
	default:
		verbose(LOG_ERR, "pcap_next_ex returned unmanaged error code");
		return (-1);
	}

	packet->size = ((struct pcap_pkthdr*)packet->header)->caplen
					+ sizeof(struct pcap_pkthdr);
	packet->type = data->data_link;
	
	*packet_p = packet;
	return (0);
}


static int
tracefilestamp_init(struct radclock *handle, struct stampsource *source)
{
	char errbuf[PCAP_ERRBUF_SIZE];  // size of error message set in pcap.h

	/* Allocate memory for the private data concerning the trace file */
	source->priv_data = malloc(sizeof(struct tracefile_data));
	JDEBUG_MEMORY(JDBG_MALLOC, source->priv_data);
	if (!TRACEFILE_DATA(source)) {
		verbose(LOG_ERR, "Error allocating memory");
		return (-1);
	}

	/* Need to pass a source address to get_bidir_stamp. However, we are
	 * currently replaying a trace file (from any host) so this address
	 * should never match, let's give something silly.
	 */
	strcpy(TRACEFILE_DATA(source)->src_ipaddr, "255.255.255.255");

	/* Open the trace file with libpcap */
	TRACEFILE_DATA(source)->trace_input = pcap_open_offline(handle->conf->sync_in_pcap, errbuf);
	if (!TRACEFILE_DATA(source)->trace_input) {
		verbose(LOG_ERR, "Open failed on raw pcap file, pcap says: %s", errbuf);
		JDEBUG_MEMORY(JDBG_FREE, TRACEFILE_DATA(source));
		free(TRACEFILE_DATA(source));
		return (-1);
	}

	/*
	 * Retrieve the link layer type stored in the trace file header. We are not
	 * reading from live input and it is not carried in each packet, so we have
	 * to store it from here.
	 */
	TRACEFILE_DATA(source)->data_link = pcap_datalink(TRACEFILE_DATA(source)->trace_input);
	if ((TRACEFILE_DATA(source)->data_link != DLT_EN10MB) &&
			(TRACEFILE_DATA(source)->data_link != DLT_LINUX_SLL)) {
		verbose(LOG_ERR, "Unknown link layer type from raw file: %d",
				TRACEFILE_DATA(source)->data_link);
		return (-1);
	}

	return 0;
}


static int
tracefilestamp_get_next(struct radclock *handle, struct stampsource *source,
	struct stamp_t *stamp)
{
	int err;

	stamp->type = STAMP_NTP;
	stamp->qual_warning = 0;

	// Call for get_bidir_stamp to read through a BPF device
	err = get_network_stamp(
			handle,
			(void *)TRACEFILE_DATA(source),
			get_packet_tracefile,
			stamp,
			&source->ntp_stats,
			TRACEFILE_DATA(source)->src_ipaddr);
	
	return (err);
/*
	if (err < 0) {
		verbose(LOG_NOTICE, "Got EOF on read of bpf device.");
		return (-1);
	}
	return 0;
*/
}


static void
tracefilestamp_breakloop(struct radclock *handle, struct stampsource *source)
{
	verbose(LOG_WARNING, "Call to breakloop in tracefile replay has no effect");
	return;
}


static void
tracefilestamp_finish(struct radclock *handle, struct stampsource *source)
{
	pcap_close(TRACEFILE_DATA(source)->trace_input);
	JDEBUG_MEMORY(JDBG_FREE, TRACEFILE_DATA(source));
	free(TRACEFILE_DATA(source));
}


static int
tracefilestamp_update_filter(struct radclock *handle, struct stampsource *source)
{
	/* So far this does nothing .. */
	return (0);
}

static int
tracefilestamp_update_dumpout(struct radclock *handle, struct stampsource *source)
{
	/* So far this does nothing .. */
	return (0);
}


struct stampsource_def filepcap_source =
{
	.init				= tracefilestamp_init,
	.get_next_stamp		= tracefilestamp_get_next,
	.source_breakloop	= tracefilestamp_breakloop,
	.destroy			= tracefilestamp_finish,
	.update_filter		= tracefilestamp_update_filter,
	.update_dumpout		= tracefilestamp_update_dumpout,
};
