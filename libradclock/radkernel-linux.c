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
#ifdef WITH_RADKERNEL_LINUX
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <errno.h>
#include <err.h>
#include <string.h>

/* Check for kernel memory mapped capability */
#include <linux/if_packet.h>

#include "radclock.h"
#include "radclock-private.h"
#include "logger.h"


/**
 * TODO LINUX:
 *  Consider moving the vcount stamp to ancilary data
 *  - Would mean moving away from standard pcap (maybe to libtrace, which
 *  already supports ancillary data for the sw stamp, or patching pcap to use
 *  it
 *  - This would avoid 2 syscalls (one of sw stamp, one for vcount stamp)
 *  - UPDATE: new packet MMAP support should solve all of this
 *
 *  Consider moving the mode to a sockopt
 *  - This would just be cleaner and the right thing to do, no performance
 *    benefit
 */

int
found_ffwd_kernel_version (void)
{
	int version = -1;
	FILE *fd = NULL;

	fd = fopen ("/sys/devices/system/ffclock/ffclock0/version", "r");
	if (fd) {
		fscanf(fd, "%d", &version);
		fclose(fd);
		logger(RADLOG_NOTICE, "Feed-Forward kernel support detected "
				"(version: %d)", version);
	}
	else {

		/* This is the old way we used before explicit versioning */
		fd = fopen ("/proc/sys/net/core/radclock_default_tsmode", "r");
		if (fd) {
			fclose(fd);
			logger(RADLOG_NOTICE, "Feed-Forward kernel support detected (version 0)");
			version = 0;
		}
		else
			version = -1;
	}

	/* A quick reminder for the administrator. */
	switch (version) {
	case 1:
		break;

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


/* Need to check that the passthrough mode is enabled and that the counter can
 * do the job. The latter is a bit "hard coded"
 */
int
has_vm_vcounter(struct radclock *handle)
{
	int passthrough_counter = 0;
	char clocksource[32];
	FILE *fd = NULL;

	char *pass;

	pass = "/sys/devices/system/clocksource/clocksource0/passthrough_clocksource";

	fd = fopen (pass, "r");
	if (!fd) {
		logger(RADLOG_ERR, "Cannot open passthrough_clocksource from sysfs");
		return (0);
	}
	fscanf(fd, "%d", &passthrough_counter);
	fclose(fd);

	if ( passthrough_counter == 0)
	{
		logger(RADLOG_ERR, "Clocksource not in pass-through mode. Cannot init virtual machine mode");
		return (0);
	}
	logger(RADLOG_NOTICE, "Found clocksource in pass-through mode");


	fd = fopen ("/sys/devices/system/clocksource/clocksource0/current_clocksource", "r");
	if (!fd)
	{
		logger(RADLOG_WARNING, "Cannot open current_clocksource from sysfs");
		return (1);
	}
	fscanf(fd, "%s", &clocksource[0]);
	fclose(fd);

	if ( (strcmp(clocksource, "tsc") != 0) && (strcmp(clocksource, "xen") != 0) )
		logger(RADLOG_WARNING, "Clocksource is neither tsc nor xen. "
				"There must be something wrong!!");
	else
		logger(RADLOG_WARNING, "Clocksource is %s", clocksource);

	return (1);
}


#if HAVE_RDTSCLL_ASM
# include <asm/msr.h>
#elif HAVE_RDTSCLL_ASM_X86
# include <asm-x86/msr.h>
#elif HAVE_RDTSCLL_ASM_X86_64
# include <asm-x86_64/msr.h>
#else
/* rdtscll not defined ... turn to black magic */
# ifdef __x86_64__
#  define rdtscll(val) do { \
		unsigned int __a,__d; \
		asm volatile("rdtsc" : "=a" (__a), "=d" (__d)); \
		(val) = ((unsigned long)__a) | (((unsigned long)__d)<<32); \
	} while(0)
# endif
# ifdef __i386__
	#define rdtscll(val) __asm__ __volatile__("rdtsc" : "=A" (val))
# endif
#endif

inline vcounter_t
radclock_readtsc(void)
{
	vcounter_t val;
    rdtscll(val);
	return (val);
}

// TODO We could afford some cleaning in here
inline int
radclock_get_vcounter_rdtsc(struct radclock *handle, vcounter_t *vcount)
{
	*vcount = radclock_readtsc();
	return (0);
}


int
radclock_init_vcounter_syscall(struct radclock *handle)
{
	switch ( handle->kernel_version )
	{
	case 0:
	case 1:
		/* From config.h */
		handle->syscall_get_vcounter = LINUX_SYSCALL_GET_VCOUNTER;
		logger(RADLOG_NOTICE, "registered get_vcounter syscall at %d",
				handle->syscall_get_vcounter);
		break;

	case 2:
		/* From config.h */
		handle->syscall_get_vcounter = LINUX_SYSCALL_GET_VCOUNTER;
		logger(RADLOG_NOTICE, "registered get_ffcounter syscall at %d",
				handle->syscall_get_vcounter);
		break;

	default:
		logger(RADLOG_ERR, "Unknown kernel version, cannot register "
				"get_ffcounter syscall");
		return (-1);
	}

	return (0);
}


int
radclock_get_vcounter_syscall(struct radclock *handle, vcounter_t *vcount)
{
	int ret;
	if (vcount == NULL)
		return (-1);

	ret = syscall(handle->syscall_get_vcounter, vcount);
	
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
	int passthrough_counter = 0;
	char clocksource[32];
	FILE *fd = NULL;
	
	if (handle->kernel_version < 1)
		passthrough_counter = 0;
	else {
		fd = fopen ("/sys/devices/system/clocksource/clocksource0/"
				"passthrough_clocksource", "r");
		if (!fd) {
			logger(RADLOG_ERR, "Cannot open passthrough_clocksource from sysfs");
			return (-1);
		}
		fscanf(fd, "%d", &passthrough_counter);
		fclose(fd);
	}

	fd = fopen ("/sys/devices/system/clocksource/clocksource0/"
			"current_clocksource", "r");
	if (!fd) {
		logger(RADLOG_ERR, "Cannot open current_clocksource from sysfs");
		return (-1);
	}
	fscanf(fd, "%s", &clocksource[0]);
	fclose(fd);
	logger(RADLOG_NOTICE, "Clocksource used is %s", clocksource);

	if (passthrough_counter == 0) {
		handle->get_vcounter = &radclock_get_vcounter_syscall;
		logger(RADLOG_NOTICE, "Initialising radclock_get_vcounter with syscall.");
		return (0);
	}

	if (strcmp(clocksource, "tsc") == 0) {
		handle->get_vcounter = &radclock_get_vcounter_rdtsc;
		logger(RADLOG_NOTICE, "Initialising radclock_get_vcounter using rdtsc(). "
						"* Make sure TSC is reliable *");
	} else {
		handle->get_vcounter = &radclock_get_vcounter_syscall;
		logger(RADLOG_NOTICE, "Initialising radclock_get_vcounter using syscall.");
	}

	/* Last, a warning */
	if (passthrough_counter == 1) {
		if ((strcmp(clocksource, "tsc") != 0) && (strcmp(clocksource, "xen") != 0))
			logger(RADLOG_ERR, "Passthrough mode in ON but the clocksource does "
					"not support it!!");
	}

	return (0);
}

#endif
