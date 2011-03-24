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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/module.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <syslog.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include <pcap.h>

#include <radclock.h>
#include "radclock-private.h"
#include "logger.h"



/* Configure detects FreeBSD version */ 
/* for setting global clock data */ 
#ifndef BIOCSRADCLOCKDATA 
#define BIOCSRADCLOCKDATA	_IOW('B', FREEBSD_RADCLOCK_IOCTL, struct radclock_data)
#endif

/* for getting global clock data */
#ifndef BIOCGRADCLOCKDATA 
#define BIOCGRADCLOCKDATA	_IOR('B', FREEBSD_RADCLOCK_IOCTL + 1, struct radclock_data)
#endif

/* for setting radclock timestamping mode */
#ifndef BIOCSRADCLOCKTSMODE
#define BIOCSRADCLOCKTSMODE	_IOW('B', FREEBSD_RADCLOCK_IOCTL + 2, int8_t)
#endif

/* for getting radclock timestamping mode */
#ifndef BIOCGRADCLOCKTSMODE
#define BIOCGRADCLOCKTSMODE	_IOR('B', FREEBSD_RADCLOCK_IOCTL + 3, int8_t)
#endif

/* for setting fixedpoint clock data */ 
#ifndef BIOCSRADCLOCKFIXED 
#define BIOCSRADCLOCKFIXED	_IOW('B', FREEBSD_RADCLOCK_IOCTL + 4, struct radclock_fixedpoint)
#endif

/* Redefinition of the BPF header as in bpf.h Just to avoid to have to include
 * the file again and define the RADCLOCK symbol at compilation time.  Changed
 * name to avoid redefinition problem. pcap.h includes bpf.h but without the
 * vcount field.
 */

struct vcount_bpf_hdr 
{
	struct timeval bh_tstamp;	/* time stamp */
	bpf_u_int32 bh_caplen;		/* length of captured portion */
	bpf_u_int32 bh_datalen;		/* original length of packet */
	u_short bh_hdrlen;			/* length of bpf header (this struct plus alignment padding) */
	u_short padding;			/* padding to align the fields */
	vcounter_t vcount;			/* raw vcount value for this packet */
};



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
		logger(RADLOG_ERR, "Cannot find kern.timecounter.passthrough in sysctl");
		return 0;
	}

	if ( passthrough_counter == 0)
	{
		logger(RADLOG_ERR, "Timecounter not in pass-through mode. Cannot init virtual machine mode");
		return 0;
	}
	logger(RADLOG_NOTICE, "Found timecounter in pass-through mode");

	size_ctl = sizeof(timecounter);
	ret = sysctlbyname("kern.timecounter.hardware", &timecounter[0], &size_ctl, NULL, 0);
	if (ret == -1)
	{
		logger(RADLOG_ERR, "Cannot find kern.timecounter.hardware in sysctl");
		return 0;
	}

	if ( (strcmp(timecounter, "TSC") != 0) && (strcmp(timecounter, "ixen") != 0) )
		logger(RADLOG_WARNING, "Timecounter is neither TSC nor ixen. "
				"There must be something wrong!!");
	else
		logger(RADLOG_WARNING, "Timecounter is %s", timecounter);

	return 1;
}


int found_ffwd_kernel_version (void) 
{
	int ret;
	int	version;
	size_t size_ctl;

	size_ctl = sizeof(version);
	ret = sysctlbyname("kern.ffclock.version", &version, &size_ctl, NULL, 0);
	
	if ( ret == 0 )
	{
		logger(RADLOG_NOTICE, "Feed-Forward kernel support detected (version: %d)", version);
		return version;
	}

	/* This is the old way we used before explicit versioning */
	ret = sysctlbyname("net.bpf.bpf_radclock_tsmode", &version, &size_ctl, NULL, 0);
	if (ret == 0) 
	{
		logger(RADLOG_NOTICE, "Feed-Forward kernel support detected (version 0)");
		return 0;
	}
	else
	{
		logger(RADLOG_NOTICE, "No Feed-Forward kernel support detected");
		return -1;
	}
}



int radclock_init_vcounter_syscall(struct radclock *handle)
{
	int err;
	struct module_stat stat;

	stat.version = sizeof(stat);
	err = modstat(modfind("get_vcounter"), &stat);
	if (err < 0 ) {
		logger(RADLOG_ERR, "Error on modstat (get_vcounter syscall): %s", strerror(errno));
		logger(RADLOG_ERR, "Is the radclock kernel module loaded?");
		return -1;
	}
	handle->syscall_get_vcounter = stat.data.intval;
	logger(RADLOG_NOTICE, "Registered get_vcounter syscall at %d", handle->syscall_get_vcounter);

	stat.version = sizeof(stat);
	err = modstat(modfind("get_vcounter_latency"), &stat);
	if (err < 0 ) {
		logger(RADLOG_ERR, "Error on modstat (get_vcounter_latency syscall): %s", strerror(errno));
		logger(RADLOG_ERR, "Is the radclock kernel module loaded?");
		return -1;
	}
	handle->syscall_get_vcounter_latency = stat.data.intval;
	logger(RADLOG_NOTICE, "Registered get_vcounter_latency syscall at %d", handle->syscall_get_vcounter_latency);

	return 0;
}


/* 
 * Check to see if we can use fast rdtsc() timestamping from userland.
 * Otherwise fall back to syscalls
 */
int radclock_init_vcounter(struct radclock *handle)
{
	int ret;
	int	passthrough_counter = 0;
	char timecounter[32];
	size_t size_ctl;

	if ( handle->kernel_version < 1 )
		passthrough_counter = 0;
	else
	{
		size_ctl = sizeof(passthrough_counter);
		ret = sysctlbyname("kern.timecounter.passthrough", &passthrough_counter, &size_ctl, NULL, 0);
		if (ret == -1)
		{
			logger(RADLOG_ERR, "Cannot find kern.timecounter.passthrough in sysctl");
			return -1;
		}
	}

	size_ctl = sizeof(timecounter);
	ret = sysctlbyname("kern.timecounter.hardware", &timecounter[0], &size_ctl, NULL, 0);
	if (ret == -1)
	{
		logger(RADLOG_ERR, "Cannot find kern.timecounter.hardware in sysctl");
		return -1;
	}
	logger(RADLOG_NOTICE, "Timecounter used is %s", timecounter);

	if ( passthrough_counter == 0)
	{
		handle->get_vcounter = &radclock_get_vcounter_syscall;
		logger(RADLOG_NOTICE, "Initialising radclock_get_vcounter with syscall.");
		return 0;
	}

	if (strcmp(timecounter, "TSC") == 0)
	{
		handle->get_vcounter = &radclock_get_vcounter_rdtsc;
		logger(RADLOG_NOTICE, "Initialising radclock_get_vcounter using rdtsc(). "
						"* Make sure TSC is reliable *");
	}
	else
	{
		handle->get_vcounter = &radclock_get_vcounter_syscall;
		logger(RADLOG_NOTICE, "Initialising radclock_get_vcounter using syscall.");
	}

	/* Last, a warning */
	if ( passthrough_counter == 1)
	{
		if ( (strcmp(timecounter, "TSC") != 0) && (strcmp(timecounter, "ixen") != 0) )
			logger(RADLOG_ERR, "Passthrough mode in ON but the timecounter does not support it!!");
	}

	return 0;
}





// XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX 
// This is super ugly, we open a second BPF to write the clock data, generic or fixed point.
// TODO fix the kernel to have the clock stored somewhere else and remove that stupid code
int radclock_init_kernel_support(struct radclock *handle)
{
	int fd;
	int devnum;
	char fname[30];

	for (devnum=0; devnum <255; devnum++)
	{
		sprintf(fname, "/dev/bpf%d", devnum);
		fd = open(fname, O_RDONLY);
		if (fd != -1) {
			logger(RADLOG_NOTICE, "Found bpf descriptor on /dev/bpf%d", devnum);
			goto done;
		}
	}
	logger(RADLOG_ERR, "Cannot open a bpf descriptor");
	return -1;
done:
	{
		PRIV_DATA(handle)->dev_fd =  fd;

		logger(RADLOG_NOTICE, "Feed-Forward Kernel initialised");
		return 0;
	}
}



/*
 * Clock Data Routines
 */
inline int set_kernel_fixedpoint(struct radclock *handle, struct radclock_fixedpoint *fpdata)
{
	if (ioctl(PRIV_DATA(handle)->dev_fd, BIOCSRADCLOCKFIXED, (caddr_t)fpdata) == -1) 
	{
		logger(LOG_ERR, "Setting fixedpoint data failed");
		return -1;
	}
	return 0;
}


/* Set global radclock data. */
int radclock_set_kernelclock(struct radclock *handle)
{ 
	int err;
	struct radclock_data knewclock;
	knewclock.phat 				= GLOBAL_DATA(handle)->phat;
	knewclock.phat_err 			= GLOBAL_DATA(handle)->phat_err;
	knewclock.phat_local 		= GLOBAL_DATA(handle)->phat_local;
	knewclock.phat_local_err 	= GLOBAL_DATA(handle)->phat_local_err;
	knewclock.ca 				= GLOBAL_DATA(handle)->ca;
	knewclock.ca_err 			= GLOBAL_DATA(handle)->ca_err;
	knewclock.status 			= GLOBAL_DATA(handle)->status;
	knewclock.last_changed 		= GLOBAL_DATA(handle)->last_changed;
	knewclock.valid_till 		= GLOBAL_DATA(handle)->valid_till;

	if ( (err = ioctl(PRIV_DATA(handle)->dev_fd, BIOCSRADCLOCKDATA, (caddr_t)&knewclock)) == -1) {
		/* Set the status of the clock to error since can't read kernel globaldata */
		DEL_STATUS(handle, STARAD_KCLOCK);
		logger(LOG_ERR, "ioctl BIOCSRADCLOCKDATA failed - %s !!!", strerror(errno));
		return err;
	}
	/* We manage to set the global data */
	ADD_STATUS(handle, STARAD_KCLOCK);
	return 0;
}


/* Read global clock data from the kernel. The structure actually used by the
 * sync algorithm should NEVER be passed to this function. The kernel data may
 * be completely outdated !
 */
int radclock_read_kernelclock(struct radclock *handle)
{    
	int err;
	struct radclock_data currclock;
	err = ioctl(PRIV_DATA(handle)->dev_fd, BIOCGRADCLOCKDATA, (caddr_t)&currclock);
	if ( err == -1) {
		logger(LOG_ERR, "ioctl BIOCGRADCLOCKDATA failed - %s !!!", strerror(errno));
		return err;
	}
	
	GLOBAL_DATA(handle)->phat 			= currclock.phat;
	GLOBAL_DATA(handle)->phat_err 		= currclock.phat_err;
	GLOBAL_DATA(handle)->phat_local 	= currclock.phat_local;
	GLOBAL_DATA(handle)->phat_local_err = currclock.phat_local_err;
	GLOBAL_DATA(handle)->ca 			= currclock.ca;
	GLOBAL_DATA(handle)->ca_err 		= currclock.ca_err;
	GLOBAL_DATA(handle)->status			= currclock.status;
	GLOBAL_DATA(handle)->last_changed	= currclock.last_changed;
	GLOBAL_DATA(handle)->valid_till		= currclock.valid_till;
	
	return 0;
}


int descriptor_set_tsmode(pcap_t *p_handle, int kmode)
{
	if (ioctl(pcap_fileno(p_handle), BIOCSRADCLOCKTSMODE, (caddr_t)&kmode) == -1) 
	{
		logger(LOG_ERR, "Setting capture mode failed");
		return -1;
	}
	return 0;
}


int descriptor_get_tsmode(pcap_t *p_handle, int *kmode)
{
	if (ioctl(pcap_fileno(p_handle), BIOCGRADCLOCKTSMODE, (caddr_t)kmode) == -1)
	{
		logger(LOG_ERR, "Getting timestamping mode failed");
		return -1;
	}
	return 0;
}




inline int extract_vcount_stamp(
			pcap_t *p_handle, 
			const struct pcap_pkthdr *header, 
			const unsigned char *packet,
			vcounter_t *vcount)
{
	/* Data structures that contain extracted vcount and timstamp */
	vcounter_t vcount_ex = 0;
	if (pcap_fileno(p_handle) < 0) //If we're a live capture
		return -1;

	//padding is assumed to be 2
	//E.G.
	//[vcount_bpf_hdr (28 bytes)][padding 2bytes][packet....]
	//I wouldn't be suprised if padding changes, if it does, split
	//into a function and try for different values of padding
	struct vcount_bpf_hdr *hack;
	const int PADDING = 2;
	hack = (struct vcount_bpf_hdr *)(packet - PADDING);
	//place the header pointer back before the packet
	hack--;
	if (hack->bh_hdrlen != sizeof(struct vcount_bpf_hdr) + PADDING
	 || memcmp(hack, header, sizeof(struct pcap_pkthdr) != 0))
	{
		logger(RADLOG_ERR, "Either modified kernel not installed, or bpf interface has changed");
		return -1;
	}
	vcount_ex = hack->vcount;

	*vcount= vcount_ex;
	return 0;
}

#endif
