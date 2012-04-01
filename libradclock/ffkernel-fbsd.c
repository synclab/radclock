/*
 * Copyright (C) 2006-2012, Julien Ridoux <julien@synclab.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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




/* Kernel patches version 2 set the timestamping mode with new IOCTL calls.
 * This is based on CURRENT, but should be standard soon for standard header
 * inclusion, and avoid repeating everything in here.
 */

#ifndef HAVE_SYS_TIMEFFC_H
int ffclock_getcounter(vcounter_t *vcount)
{
	*vcount = 0;
	return EINVAL;
}
#endif


// TODO move out of the library and use IPC call to retrieve the value from
// radclock if needed ??
int
found_ffwd_kernel_version (void)
{
	int ret;
	int version;
	size_t size_ctl;

	size_ctl = sizeof(version);

	/* Sysctl for version 2 and 3*/
	ret = sysctlbyname("kern.sysclock.ffclock.version", &version, &size_ctl,
			NULL, 0);
	if (ret < 0) {

		/* Sysctl for version 1 */
		ret = sysctlbyname("kern.ffclock.version", &version, &size_ctl, NULL, 0);
		
		if (ret < 0) {
			/* The old way we used before explicit versioning. */
			ret = sysctlbyname("net.bpf.bpf_radclock_tsmode", &version,
				&size_ctl, NULL, 0);

			if (ret == 0)
				version = 0;
			/* If all the above failed, no kernel support compiled */
			else
				version = -1;
		}
	}

	if (version == -1)
		logger(RADLOG_WARNING, "No feed-forward kernel support detected");
	else
		logger(RADLOG_NOTICE, "Feed-Forward kernel detected (version: %d)",
			version);

	/* A quick reminder for the administrator. */
	switch (version) {
	/* Version 3 is version 2 with the extended BPF header */
	case 3:
	case 2:
		break;

	case 1:
	case 0:
		logger(RADLOG_WARNING, "The Feed-Forward kernel support is a bit old. "
				"You should update your kernel.");
		break;

	case -1:
	default:
		logger(RADLOG_NOTICE, "No Feed-Forward kernel support detected");
		break;
	}
	return (version);
}



/*
 * Need to check that the passthrough mode is enabled and that the counter can
 * do the job. The latter is a bit "hard coded"
 */
int
has_vm_vcounter(struct radclock *clock)
{
	int ret;
	int passthrough_counter = 0;
	char timecounter[32];
	size_t size_ctl;

	switch (clock->kernel_version) {
// FIXME : sysctl is there but no xen backend in official kernel yet
	case 3:
	case 2:
		size_ctl = sizeof(passthrough_counter);
		ret = sysctlbyname("kern.sysclock.ffclock.ffcounter_bypass",
				&passthrough_counter, &size_ctl, NULL, 0);
		if (ret == -1) {
			logger(RADLOG_ERR, "Cannot find kern.sysclock.ffclock.ffcounter_bypass "
					"in sysctl");
			return (0);
		}
		break;

	case 1:
		size_ctl = sizeof(passthrough_counter);
		ret = sysctlbyname("kern.timecounter.passthrough", &passthrough_counter,
				&size_ctl, NULL, 0);
		if (ret == -1) {
			logger(RADLOG_ERR, "Cannot find kern.timecounter.passthrough in sysctl");
			return (0);
		}
		break;

	case 0:
	default:
		return (0);
	}

	if (passthrough_counter == 0) {
		logger(RADLOG_ERR, "Timecounter not in pass-through mode. Cannot init "
				"virtual machine mode");
		return (0);
	}
	logger(RADLOG_NOTICE, "Found timecounter in pass-through mode");

	size_ctl = sizeof(timecounter);
	ret = sysctlbyname("kern.timecounter.hardware", &timecounter[0],
			&size_ctl, NULL, 0);
	if (ret == -1) {
		logger(LOG_ERR, "Cannot find kern.timecounter.hardware in sysctl");
		return (0);
	}

	if ((strcmp(timecounter, "TSC") != 0) && (strcmp(timecounter, "ixen") != 0))
		logger(RADLOG_WARNING, "Timecounter is neither TSC nor ixen. "
				"There must be something wrong!!");
	else
		logger(RADLOG_WARNING, "Timecounter is %s", timecounter);

	return (1);
}




# ifdef HAVE_RDTSC
#  ifdef HAVE_MACHINE_CPUFUNC_H
#   include <machine/cpufunc.h>
#  else
#   error "FreeBSD with rdtsc() defined but no machine/cpufunc.h header"
#  endif
# else
static inline uint64_t
rdtsc(void)
{
    u_int32_t low, high;
    __asm __volatile("rdtsc" : "=a" (low), "=d" (high));
    return (low | ((u_int64_t)high << 32));
}
# endif

inline
vcounter_t radclock_readtsc(void) {
	return (vcounter_t) rdtsc();
}

// TODO we could afford some cleaning in here
inline int
radclock_get_vcounter_rdtsc(struct radclock *handle, vcounter_t *vcount)
{
	*vcount = radclock_readtsc();
	return 0;
}


int
radclock_init_vcounter_syscall(struct radclock *clock)
{
	struct module_stat stat;
	int err;

	switch (clock->kernel_version) {
	case 0:
	case 1:
		stat.version = sizeof(stat);
		err = modstat(modfind("get_vcounter"), &stat);
		if (err < 0) {
			logger(RADLOG_ERR, "Error on modstat (get_vcounter syscall): %s",
				strerror(errno));
			logger(RADLOG_ERR, "Is the radclock kernel module loaded?");
			return (1);
		}
		clock->syscall_get_vcounter = stat.data.intval;
		logger(RADLOG_NOTICE, "Registered get_vcounter syscall at %d",
			clock->syscall_get_vcounter);
		break;

	/* kernel provides ffclock_getcounter through libc */
	case 2:
	case 3:
		break;

	default:
		return (1);
	}
	return (0);
}


int
radclock_get_vcounter_syscall(struct radclock *handle, vcounter_t *vcount)
{
	int ret;

	if (vcount == NULL)
		return (-1);

	switch (handle->kernel_version) {
	case 0:
	case 1:
		ret = syscall(handle->syscall_get_vcounter, vcount);
		break;
	case 2:
	case 3:
		ret = ffclock_getcounter(vcount);
		break;
	default:
		ret = -1;
		break;
	}

	if (ret < 0) {
		logger(RADLOG_ERR, "error on syscall get_vcounter: %s", strerror(errno));
		return (-1);
	}

	return (0);
}




/*
 * Check to see if we can use fast rdtsc() timestamping from userland.
 * Otherwise fall back to syscalls
 */
int
radclock_init_vcounter(struct radclock *handle)
{
	size_t size_ctl;
	int passthrough_counter;
	int ret;

	passthrough_counter = 0;

	switch (handle->kernel_version) {
	case 0:
		passthrough_counter = 0;
		break;

	case 1:
		size_ctl = sizeof(passthrough_counter);
		ret = sysctlbyname("kern.timecounter.passthrough", &passthrough_counter,
				&size_ctl, NULL, 0);
		if (ret == -1)
		{
			logger(RADLOG_ERR, "Cannot find kern.timecounter.passthrough in sysctl");
			return (-1);
		}
		break;

// FIXME XXX For these two versions, the sysctl has snicked in the official
// kernel withouth the backend support. This test is not discrimating!
	case 2:
	case 3:
		size_ctl = sizeof(passthrough_counter);
		ret = sysctlbyname("kern.sysclock.ffclock.ffcounter_bypass",
			&passthrough_counter, &size_ctl, NULL, 0);
		if (ret == -1) {
			logger(RADLOG_ERR, "Cannot find kern.sysclock.ffclock.ffcounter_bypass");
			passthrough_counter = 0;
			return (-1);
		}
	}

	size_ctl = sizeof(handle->hw_counter);
	ret = sysctlbyname("kern.timecounter.hardware", &handle->hw_counter[0],
		&size_ctl, NULL, 0);
	if (ret == -1) {
		logger(RADLOG_ERR, "Cannot find kern.timecounter.hardware in sysctl");
		return (-1);
	}
	logger(RADLOG_NOTICE, "Timecounter used is %s", handle->hw_counter);

	if ( passthrough_counter == 0) {
		handle->get_vcounter = &radclock_get_vcounter_syscall;
		logger(RADLOG_NOTICE, "Initialising radclock_get_vcounter with syscall.");
		return (0);
	}

	if (strcmp(handle->hw_counter, "TSC") == 0) {
		handle->get_vcounter = &radclock_get_vcounter_rdtsc;
		logger(RADLOG_NOTICE, "Initialising radclock_get_vcounter using rdtsc(). "
			"* Make sure TSC is reliable *");
	} else {
		handle->get_vcounter = &radclock_get_vcounter_syscall;
		logger(RADLOG_NOTICE, "Initialising radclock_get_vcounter using syscall.");
	}

	/* Last, a warning */
	if (passthrough_counter == 1) {
		if ((strcmp(handle->hw_counter, "TSC") != 0)
			&& (strcmp(handle->hw_counter, "ixen") != 0))
			logger(RADLOG_ERR, "Passthrough mode in ON but the timecounter "
					"does not support it!!");
	}

	return (0);
}

#endif
