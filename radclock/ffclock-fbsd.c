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
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <sys/timeffc.h>	// All this should go in the library, set/get ffclock estimates
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "radclock.h"
#include "radclock-private.h"
#include "ffclock.h"
#include "fixedpoint.h"
#include "verbose.h"
#include "jdebug.h"



int init_kernel_support(struct radclock *handle)
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
	switch (handle->kernel_version)
	{

	case 0:
	case 1:
		/* This is super ugly, we open a second BPF to write the clock data,
		 * generic or fixed point. That's the very old way
		 */
		for (devnum=0; devnum < 255; devnum++)
		{
			sprintf(fname, "/dev/bpf%d", devnum);
			fd = open(fname, O_RDONLY);
			if (fd != -1) {
				verbose(LOG_NOTICE, "Found bpf descriptor on /dev/bpf%d", devnum);
				break;
			}
		}
		if ( devnum == 254 )
		{
			verbose(LOG_ERR, "Cannot open a bpf descriptor");
			return -1;
		}
		PRIV_DATA(handle)->dev_fd = fd;
		break;

	case 2:
		/* Use radclock module syscall to update clock data */
/*
		stat.version = sizeof(stat);
		err = modstat(modfind("set_ffclock"), &stat);
		if (err < 0 ) {
			verbose(LOG_ERR, "Error on modstat (set_ffclock syscall): %s", strerror(errno));
			verbose(LOG_ERR, "Is the radclock kernel module loaded?");
			return -1;
		}
		handle->syscall_set_ffclock = stat.data.intval;
		verbose(LOG_NOTICE, "Registered set_ffclock syscall at %d", handle->syscall_set_ffclock);
*/
		// ffclock_setestimate syscall offered by kernel through libc
		break;


	default:
		verbose(LOG_ERR, "Unknown kernel version");
		return -1;
	}


	verbose(LOG_NOTICE, "Feed-Forward Kernel initialised");
	return 0;
}


/* Need to check that the passthrough mode is enabled and that the counter can
 * do the job. The latter is a bit "hard coded"
 */
int has_vm_vcounter(void)
{
	int ret;
	int	passthrough_counter = 0;
	char timecounter[32];
	size_t size_ctl;

	size_ctl = sizeof(passthrough_counter);
	ret = sysctlbyname("kern.timecounter.passthrough", &passthrough_counter, &size_ctl, NULL, 0);
	if (ret == -1)
	{
		verbose(LOG_ERR, "Cannot find kern.timecounter.passthrough in sysctl");
		return 0;
	}

	if ( passthrough_counter == 0)
	{
		verbose(LOG_ERR, "Timecounter not in pass-through mode. Cannot init virtual machine mode");
		return 0;
	}
	verbose(LOG_NOTICE, "Found timecounter in pass-through mode");

	size_ctl = sizeof(timecounter);
	ret = sysctlbyname("kern.timecounter.hardware", &timecounter[0], &size_ctl, NULL, 0);
	if (ret == -1)
	{
		verbose(LOG_ERR, "Cannot find kern.timecounter.hardware in sysctl");
		return 0;
	}

	if ( (strcmp(timecounter, "TSC") != 0) && (strcmp(timecounter, "ixen") != 0) )
		verbose(LOG_WARNING, "Timecounter is neither TSC nor ixen. "
				"There must be something wrong!!");
	else
		verbose(LOG_WARNING, "Timecounter is %s", timecounter);

	return 1;
}


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
//#define BIOCGRADCLOCKDATA	_IOR('B', FREEBSD_RADCLOCK_IOCTL + 1, struct radclock_data)
//#endif

/* XXX Deprecated
 * for setting fixedpoint clock data
 */ 
#ifndef BIOCSRADCLOCKFIXED 
#define BIOCSRADCLOCKFIXED	_IOW('B', FREEBSD_RADCLOCK_IOCTL + 4, struct radclock_fixedpoint)
#endif


/*
 * XXX Deprecated
 * Old way of pushing clock updates to the kernel.
 * TODO: remove when backward compatibility for kernel versions < 2 is dropped.
 */
inline int 
set_kernel_fixedpoint(struct radclock *handle, struct radclock_fixedpoint *fpdata)
{
	JDEBUG
	int err;
	switch (handle->kernel_version)
	{

	case 0:
	case 1:
		err = ioctl(PRIV_DATA(handle)->dev_fd, BIOCSRADCLOCKFIXED, (caddr_t)fpdata);
		if ( err < 0 ) 
		{
			verbose(LOG_ERR, "Setting fixedpoint data failed");
			return -1;
		}
		break;

	case 2:	
		verbose(LOG_ERR, "set_kernel_fixedpoint but kernel version 2!!");
		return -1;

	default:
		verbose(LOG_ERR, "Unknown kernel version");
		return -1;
	}

	return 0;
}




/*
 * Function is called every time a new stamp is processed.
 * It assumes that the kernel supports update of the fixedpoint version of the
 * clock estimates and that the last_changed stamp is updated on each call to
 * process_bidir stamp.
 * With this, no need to read the current time, rely on last_changed only.
 * XXX: is the comment above accurate and true? 
 */

int
set_kernel_ffclock(struct radclock *clock)
{
	JDEBUG

	int err;
	struct ffclock_estimate cest;
	vcounter_t vcount;
	long double time;
	uint64_t period;
	uint64_t period_shortterm;
	uint64_t frac;

	if (clock->kernel_version < 2)
	{
		verbose(LOG_ERR, "set_kernel_ffclock with unfit kernel!");
		return -1;
	}


	/*
	 * Build the data structure to pass to the kernel
	 */
	vcount = RAD_DATA(clock)->last_changed;

	/* Convert vcount to long double time and to bintime */
	if (radclock_vcount_to_abstime_fp(clock, &vcount, &time))
		verbose(LOG_ERR, "Error calculating time");

	/* What I would like to do is: 
	 * cest->time.frac = (time - (time_t) time) * (1LLU << 64);
	 * but cannot push '1' by 64 bits, does not fit in LLU. So push 63 bits,
	 * multiply for best resolution and loose resolution of 1/2^64.
	 * Same for phat.
	 */
	cest.update_time.sec = (time_t) time;
	frac = (time - (time_t) time) * (1LLU << 63);
	cest.update_time.frac = frac << 1;

	period = ((long double) RAD_DATA(clock)->phat) * (1LLU << 63);
	cest.period = period << 1;

	period_shortterm = ((long double) RAD_DATA(clock)->phat_local) * (1LLU << 63);
	cest.period_shortterm = period_shortterm << 1;

	cest.update_ffcount = vcount;
	cest.status = RAD_DATA(clock)->status;
	cest.error_bound_abs = (uint32_t) RAD_ERROR(clock)->error_bound_avg * 1e9;
	// TODO XXX: this should be made an average value of some kind !! and not the
	// 'instantaneous' one
	cest.error_bound_rate = (uint32_t) RAD_DATA(clock)->phat_local_err * 1e9;

	struct timespec ts; 
	bintime2timespec(&(cest.update_time), &ts);
	fprintf(stdout, "\n");
	fprintf(stdout, "Kernel update\n");
	fprintf(stdout, "  count=%llu, period= %llu\n", (long long unsigned)cest.update_ffcount, (long long unsigned)cest.period);

	fprintf(stdout, "  time=%.09Lf, = %ld.%lu\n", time, ts.tv_sec, ts.tv_nsec);
	

	/* Push */
	switch (clock->kernel_version)
	{
	case 0:
	case 1:
		err = syscall(clock->syscall_set_ffclock, &cest);
		break;
	case 2:
		err = ffclock_setestimate(&cest);
		break;
	default:
		verbose(LOG_ERR, "Unknown kernel version");
		return -1;
	}

	if ( err < 0 ) {
		verbose(LOG_ERR, "error on syscall set_ffclock: %s", strerror(errno));
		return -1;
	}

	return 0;
}



#endif /* WITH_RADKERNEL_FBSD */
