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

#include "../config.h"

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "radclock.h"
#include "radclock-private.h"
#include "logger.h"



int
main(int argc, char **argv)
{
	struct radclock *clock;
	struct bpf_program fp;	/* The compiled filter expression */
	radclock_tsmode_t tsmode, tsmode2;
	pcap_t *phandle;
	char fltstr[120];
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	char *if_name;
	int err;


	clock = radclock_create();
	radclock_init(clock);

	/* Open a PCAP device. Look it up if not specified on the command line */
	if_name = pcap_lookupdev(errbuf);
	if (if_name == NULL) {
		fprintf(stderr, "Cannot find free device, pcap says: %s\n", errbuf);
		return (1);
	}
	else
		fprintf(stderr, "Found device %s\n", if_name);

	/* No promiscuous mode, timeout on BPF = 5ms */
	if ((phandle = pcap_open_live(if_name, 170, 0, 5, errbuf)) == NULL) {
		fprintf(stderr, "Open failed on live interface, pcap says: %s\n", errbuf);
		return (1);
	}

	/* No need to test broadcast addresses */
	err = pcap_compile(phandle, &fp, "port 123", 0, 0);
	if (err == -1) {
		fprintf(stderr, "pcap filter compiling failure, pcap says: %s\n",
			pcap_geterr(phandle));
		return (1);
	}

	/* Set filter on pcap handler */
	err = pcap_setfilter(phandle, &fp);
	if (err == -1 ) {
		fprintf(stderr, "pcap filter setting failure, pcap says: %s\n",
			pcap_geterr(phandle));
		return (1);
	}

	tsmode = RADCLOCK_TSMODE_SYSCLOCK;
	err = radclock_set_tsmode(clock, phandle, tsmode);
	if (err == -1 ) {
		fprintf(stderr, "FAILED: radclock_set_tsmode SYSCLOCK\n");
		return (1);
	} else
		fprintf(stderr, "SUCCESS: radclock_set_tsmode SYSCLOCK\n");



	tsmode = RADCLOCK_TSMODE_RADCLOCK;
	err = radclock_set_tsmode(clock, phandle, tsmode);
	if (err == -1 ) {
		fprintf(stderr, "FAILED: radclock_set_tsmode RADCLOCK\n");
		return (1);
	}
		fprintf(stderr, "SUCCESS: radclock_set_tsmode RADCLOCK\n");

	tsmode = RADCLOCK_TSMODE_FAIRCOMPARE;
	err = radclock_set_tsmode(clock, phandle, tsmode);
	if (err == -1 ) {
		fprintf(stderr, "FAILED: radclock_set_tsmode FAIRCOMPARE\n");
		return (1);
	}
		fprintf(stderr, "SUCCESS: radclock_set_tsmode FAIRCOMPARE\n");

	err = radclock_get_tsmode(clock, phandle, &tsmode);
	if (err == -1 ) {
		fprintf(stderr, "radclock_get_tsmode failed\n");
		return (1);
	}

	return (0);
}
