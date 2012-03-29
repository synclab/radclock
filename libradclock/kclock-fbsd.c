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
#ifdef WITH_RADKERNEL_FBSD

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/module.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#ifdef HAVE_SYS_TIMEFFC_H
#include <sys/timeffc.h>
#endif
#include <sys/socket.h>

#include <net/ethernet.h>	// ETHER_HDR_LEN
#include <net/bpf.h>
#include <pcap.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>		// useful?
#include <syslog.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stddef.h>	// offesetof macro

#include "radclock.h"
#include "radclock-private.h"
#include "logger.h"




#ifdef HAVE_SYS_TIMEFFC_H
int
get_kernel_ffclock(struct radclock *clock, struct radclock_data *rad_data)
{
	/*
	 * This is the kernel definition of clock estimates. May be different from
	 * the radclock_data structure
	 */
	struct ffclock_estimate cest;
	int err;
	long double tmp;

	/*
	 * This feature exists since kernel version 2. If kernel too old, don't do
	 * anything and return success
	 */
// XXX FIXME comment above is not quite true, should integrate previous kernel
// clock access into this function !!
	if (clock->kernel_version < 2)
// FIXME: is error code correct? Should it be +1?
		return (-1);

	/* FreeBSD system call */
	err = ffclock_getestimate(&cest);
	if (err < 0) {
// TODO Clean up verbose logging
		logger(RADLOG_ERR, "Clock estimate init from kernel failed");
		fprintf(stdout, "Clock estimate init from kernel failed");
		return (err);
	}

	/* Sanity check to avoid introducing crazy data */
	if ((cest.update_time.sec == 0) || (cest.period == 0)) {
		logger(RADLOG_ERR, "Clock estimate from kernel look bogus - ignored");
		fprintf(stdout, "Clock estimate from kernel look bogus - ignored");
		return (0);
	}

	/*
	 * Cannot push 64 times in a LLU at once. Push twice 32 instead. In this
	 * direction (get and not set), it is ok to do it that way. We do risk to
	 * look heavy digits or resolution. See set_kernel_ffclock() in radclock
	 * code.
	 */
	rad_data->ca = (long double) cest.update_time.sec;
	tmp = ((long double) cest.update_time.frac) / (1LL << 32);
	rad_data->ca += tmp / (1LL << 32);
	
	tmp = (long double) cest.period / (1LLU << 32);
	rad_data->phat_local = (double) (tmp / (1LLU << 32));
	rad_data->phat = rad_data->phat_local;

	rad_data->status = (unsigned int) cest.status;
	rad_data->last_changed = (vcounter_t) cest.update_ffcount;

	fprintf(stdout, "period=%llu  phat = %.10lg, C = %7.4Lf\n",
		(unsigned long long) cest.period, rad_data->phat,
		rad_data->ca);
	fprintf(stdout, "Retrieved clock estimate init from kernel\n");
			
	return (0);
}
#else
int
get_kernel_ffclock(struct radclock *clock, struct radclock_data *rad_data)
{
	return (0);
}
#endif


#endif
