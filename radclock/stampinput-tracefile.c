/*
 * Copyright (C) 2006-2012 Julien Ridoux <julien@synclab.org>
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
#include <sys/socket.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>

#include "../config.h"
#include "radclock.h"
#include "radclock-private.h"

#include "radclock_daemon.h"
#include "sync_history.h"
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
	uint32_t data_link;	/* Link layer type (stored in dump file) */
	struct sockaddr_storage ss_if;
};


/* This is the callback passed to get_bidir_stamp().
 * It takes a radpcap_packet_t and fills this structure with the actual packet
 * read from the tracefile
 * Return values:
 *  0 on success
 * -1 error to break upper loop
 */
static int
get_packet_tracefile(struct radclock_handle *handle, void *userdata,
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
		(const u_char **) (&(packet->payload)));

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

	/* Store interface address in packet */
	packet->ss_if = data->ss_if;
	
	*packet_p = packet;
	return (0);
}


static int
tracefilestamp_init(struct radclock_handle *handle, struct stampsource *source)
{
	struct sockaddr_in *sin;
	struct radclock_config *conf;
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
	// TODO this code is not protocol independent
	// TODO use getaddrinfo instead?
	TRACEFILE_DATA(source)->ss_if.ss_family = AF_INET;
	sin = (struct sockaddr_in *)&TRACEFILE_DATA(source)->ss_if;
	inet_pton(AF_INET, "255.255.255.255", &sin->sin_addr);

	/* Open the trace file with libpcap */
	conf = handle->conf;
	TRACEFILE_DATA(source)->trace_input = pcap_open_offline(conf->sync_in_pcap,
			errbuf);
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

	return (0);
}


static int
tracefilestamp_get_next(struct radclock_handle *handle, struct stampsource *source,
	struct stamp_t *stamp)
{
	int err;

	/* Ensure default stamp quality before filling timestamps */
	stamp->type = STAMP_NTP;
	stamp->qual_warning = 0;

	err = get_network_stamp(handle, (void *)TRACEFILE_DATA(source),
			get_packet_tracefile, stamp, &source->ntp_stats);
	
	return (err);
}


static void
tracefilestamp_breakloop(struct radclock_handle *handle, struct stampsource *source)
{

	verbose(LOG_WARNING, "Call to breakloop in tracefile replay has no effect");
}


static void
tracefilestamp_finish(struct radclock_handle *handle, struct stampsource *source)
{
	pcap_close(TRACEFILE_DATA(source)->trace_input);
	JDEBUG_MEMORY(JDBG_FREE, TRACEFILE_DATA(source));
	free(TRACEFILE_DATA(source));
}


static int
tracefilestamp_update_filter(struct radclock_handle *handle, struct stampsource *source)
{
	/* So far this does nothing .. */
	return (0);
}

static int
tracefilestamp_update_dumpout(struct radclock_handle *handle, struct stampsource *source)
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
