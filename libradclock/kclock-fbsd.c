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

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>	// offesetof macro
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>		// useful?

#include "radclock.h"
#include "radclock-private.h"
#include "kclock.h"
#include "logger.h"


int
init_kernel_clock(struct radclock *clock)
{
	/* Kernel version 0 and 1 variables */
	int fd = -1;
	int devnum;
	char fname[30];

	/* Kernel version 2 variables */
/*
	int err;
	struct module_stat stat;
*/
	switch (clock->kernel_version) {

	case 0:
	case 1:
		/* This is super ugly, we open a second BPF to write the clock data,
		 * generic or fixed point. That's the very old way
		 */
		for (devnum=0; devnum < 255; devnum++) {
			sprintf(fname, "/dev/bpf%d", devnum);
			fd = open(fname, O_RDONLY);
			if (fd != -1) {
				break;
			}
		}
		if (devnum == 254) {
			logger(RADLOG_ERR, "Cannot open a bpf descriptor");
			return (-1);
		}
		PRIV_DATA(clock)->dev_fd = fd;
		break;

	/* ffclock_setestimate syscall offered by kernel through libc */
	case 2:
	case 3:
		break;

	default:
		logger(RADLOG_ERR, "Unknown kernel version");
		return (-1);
	}

	return (0);
}



#ifdef HAVE_SYS_TIMEFFC_H
int
get_kernel_ffclock(struct radclock *clock, struct ffclock_estimate *cest)
{
	/*
	 * This is the kernel definition of clock estimates. May be different from
	 * the radclock_data structure
	 */
	int err;

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
	err = ffclock_getestimate(cest);
	if (err < 0) {
// TODO Clean up verbose logging
		logger(RADLOG_ERR, "Clock estimate init from kernel failed");
		fprintf(stdout, "Clock estimate init from kernel failed");
		return (err);
	}

	/* Sanity check to avoid introducing crazy data */
	if ((cest->update_time.sec == 0) || (cest->period == 0)) {
		logger(RADLOG_ERR, "Clock estimate from kernel look bogus - ignored");
		fprintf(stdout, "Clock estimate from kernel look bogus - ignored");
		return (0);
	}
		
	return (0);
}
#else
int
get_kernel_ffclock(struct radclock *clock, struct ffclock_estimate *cest)
{
	return (0);
}
#endif




/*
 * Function is called every time a new stamp is processed.
 * It assumes that the kernel supports update of the fixedpoint version of the
 * clock estimates and that the last_changed stamp is updated on each call to
 * process_bidir stamp.
 * With this, no need to read the current time, rely on last_changed only.
 * XXX: is the comment above accurate and true?
 */
#ifdef HAVE_SYS_TIMEFFC_H
int
set_kernel_ffclock(struct radclock *clock, struct ffclock_estimate *cest)
{
	int err;

	if (clock->kernel_version < 2) {
		logger(RADLOG_ERR, "set_kernel_ffclock with unfit kernel!");
		return (-1);
	}

	/* Push */
	switch (clock->kernel_version) {

	case 0:
	case 1:
		err = syscall(clock->syscall_set_ffclock, cest);
		break;
	case 2:
	case 3:
		err = ffclock_setestimate(cest);
		break;
	default:
		logger(RADLOG_ERR, "Unknown kernel version");
		return (-1);
	}

	if (err < 0) {
		logger(RADLOG_ERR, "error on syscall set_ffclock: %s", strerror(errno));
		return (-1);
	}

	return (0);
}
#else
int
set_kernel_ffclock(struct radclock *clock, struct ffclock_estimate *cest)
{
	return (0);
}
#endif


/* XXX Deprecated
 * Old kernel patches for feed-forward support versions 0 and 1.
 * Used to add more IOCTL to the BPF device. The actual IOCTL number depends on
 * the OS version, detected in configure script.
 */
/* for setting global clock data */
//#ifndef BIOCSRADCLOCKDATA
//#define BIOCSRADCLOCKDATA	_IOW('B', FREEBSD_RADCLOCK_IOCTL, struct radclock_data)
//#endif

/* for getting global clock data */
//#ifndef BIOCGRADCLOCKDATA
//#define BIOCGRADCLOCKDATA	_IOR('B', FREEBSD_RADCLOCK_IOCTL + 1,
//		struct radclock_data)
//#endif

/* XXX Deprecated
 * for setting fixedpoint clock data
 */
#ifndef BIOCSRADCLOCKFIXED
#define BIOCSRADCLOCKFIXED	_IOW('B', FREEBSD_RADCLOCK_IOCTL + 4, \
		struct radclock_fixedpoint)
#endif


/*
 * XXX Deprecated
 * Old way of pushing clock updates to the kernel.
 * TODO: remove when backward compatibility for kernel versions < 2 is dropped.
 */
int
set_kernel_fixedpoint(struct radclock *clock, struct radclock_fixedpoint *fpdata)
{
	int err;

	switch (clock->kernel_version) {

	case 0:
	case 1:
		err = ioctl(PRIV_DATA(clock)->dev_fd, BIOCSRADCLOCKFIXED, fpdata);
		if (err < 0) {
			logger(RADLOG_ERR, "Setting fixedpoint data failed");
			return (-1);
		}
		break;

	case 2:
	case 3:
		logger(RADLOG_ERR, "set_kernel_fixedpoint but kernel version 2 or higher!!");
		return (-1);

	default:
		logger(RADLOG_ERR, "Unknown kernel version");
		return (-1);
	}

	return (0);
}

#endif
