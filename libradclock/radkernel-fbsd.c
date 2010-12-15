/*
 * Copyright (C) 2006-2010 Julien Ridoux <julien@synclab.org>
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


#include "../config.h"
#ifdef WITH_RADKERNEL_FBSD
#include <stdio.h>
#include <stdlib.h>
//#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/module.h>
//#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <syslog.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include <pcap.h>

#include "radclock.h"
#include "radclock-private.h"
#include "logger.h"



/* XXX Deprecated
 * Old kernel patches for feed-forward support versions 0 and 1.
 * Used to add more IOCTL to the BPF device. The actual IOCTL number depends on
 * the OS version, detected in configure script.
 */ 

/* for setting radclock timestamping mode */
#ifndef BIOCSRADCLOCKTSMODE
#define BIOCSRADCLOCKTSMODE	_IOW('B', FREEBSD_RADCLOCK_IOCTL + 2, int8_t)
#endif

/* for getting radclock timestamping mode */
#ifndef BIOCGRADCLOCKTSMODE
#define BIOCGRADCLOCKTSMODE	_IOR('B', FREEBSD_RADCLOCK_IOCTL + 3, int8_t)
#endif



/* Kernel patches version 2 set the timestamping mode with new IOCTL calls.
 * This is based on CURRENT, but should be standard soon for standard header
 * inclusion, and avoid repeating everything in here.
 */
//#ifndef BIOCGTSTAMP
#define	BIOCGTSTAMP	_IOR('B', 131, u_int)
#define	BIOCSTSTAMP	_IOW('B', 132, u_int)


#define	BPF_T_MICROTIME		0x0000
#define	BPF_T_NANOTIME		0x0001
#define	BPF_T_BINTIME		0x0002
#define	BPF_T_NONE		0x0003
#define	BPF_T_NORMAL		0x0000
#define	BPF_T_FAST		0x0100
#define	BPF_T_MONOTONIC		0x0200
#define	BPF_T_MONOTONIC_FAST	(BPF_T_FAST | BPF_T_MONOTONIC)
#define	BPF_T_FFCLOCK		0x0400

//#endif



/* XXX Can we clean that ??
 * Redefinition of the BPF header as in bpf.h Just to avoid to have to include
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


// TODO move out of the library and use IPC call to retrieve the value from
// radclock if needed ??
int found_ffwd_kernel_version (void) 
{
	int ret;
	int	version = -1;
	size_t size_ctl;

	size_ctl = sizeof(version);
	ret = sysctlbyname("kern.ffclock.version", &version, &size_ctl, NULL, 0);
	
	if ( ret == 0 )
	{
		logger(RADLOG_NOTICE, "Feed-Forward kernel support detected (version: %d)", version);
	}
	else {
		/* This is the old way we used before explicit versioning. */
		ret = sysctlbyname("net.bpf.bpf_radclock_tsmode", &version, &size_ctl, NULL, 0);
		if (ret == 0) 
		{
			logger(RADLOG_NOTICE, "Feed-Forward kernel support detected (version 0)");
			version = 0;
		}
		else
			version = -1;
	}

	/* A quick reminder for the administrator. */	
	switch ( version )
	{
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
	return version;
}


int radclock_init_vcounter_syscall(struct radclock *handle)
{
	int err;
	struct module_stat stat;

	stat.version = sizeof(stat);
	err = modstat(modfind("get_ffcounter"), &stat);
	if (err < 0 ) {
		logger(RADLOG_ERR, "Error on modstat (get_ffcounter syscall): %s", strerror(errno));
		logger(RADLOG_ERR, "Is the radclock kernel module loaded?");
		return -1;
	}
	handle->syscall_get_vcounter = stat.data.intval;
	logger(RADLOG_NOTICE, "Registered get_ffcounter syscall at %d", handle->syscall_get_vcounter);

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






int descriptor_set_tsmode(struct radclock *handle, pcap_t *p_handle, int kmode)
{
	u_int bd_tstamp = 0; 

	switch (handle->kernel_version)
	{

	case 0:
	case 1:
		if (ioctl(pcap_fileno(p_handle), BIOCSRADCLOCKTSMODE, (caddr_t)&kmode) == -1) 
		{
			logger(LOG_ERR, "Setting capture mode failed");
			return -1;
		}
		break;

	case 2:
		/* No more Faircompare mode in kernel version 2, it is identical to
		 * SYSCLOCK
		 */
		switch ( kmode )
		{
			case RADCLOCK_TSMODE_SYSCLOCK:
			case RADCLOCK_TSMODE_FAIRCOMPARE:
				bd_tstamp = BPF_T_MICROTIME;
				break;
			case RADCLOCK_TSMODE_RADCLOCK:
				bd_tstamp = BPF_T_MICROTIME | BPF_T_FFCLOCK | BPF_T_MONOTONIC;
				break;
			default:
				logger(LOG_ERR, "descriptor_set_tsmode: Unknown timestamping mode.");
				return -1;
		}

		if (ioctl(pcap_fileno(p_handle), BIOCSTSTAMP, (caddr_t)&bd_tstamp) == -1) 
		{
			logger(LOG_ERR, "Setting capture mode failed");
			return -1;
		}

		break;

	default:
		logger(LOG_ERR, "Unknown kernel version");
		return -1;

	}
	return 0;
}


int descriptor_get_tsmode(struct radclock *handle, pcap_t *p_handle, int *kmode)
{
	u_int bd_tstamp = 0; 

	switch (handle->kernel_version)
	{

	case 0:
	case 1:
		if (ioctl(pcap_fileno(p_handle), BIOCGRADCLOCKTSMODE, (caddr_t)kmode) == -1)
		{
			logger(LOG_ERR, "Getting timestamping mode failed");
			return -1;
		}
		break;

	case 2:
		if (ioctl(pcap_fileno(p_handle), BIOCGTSTAMP, (caddr_t)(&bd_tstamp)) == -1)
		{
			logger(LOG_ERR, "Getting timestamping mode failed");
			return -1;
		}

		if ( (bd_tstamp & BPF_T_FFCLOCK) == BPF_T_FFCLOCK)
			*kmode = RADCLOCK_TSMODE_RADCLOCK;
		else
			*kmode = RADCLOCK_TSMODE_SYSCLOCK;
		break;

	default:
		logger(LOG_ERR, "Unknown kernel version");
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
