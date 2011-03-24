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

/* Here you go, some dirty tricks */
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
/* TODO This  is broken since naming change, but kept for historical reasons
 * should go away soon-ish
 */
#define NET_CORE_RADCLOCK_DEFAULT_TSMODE 22
#define SIOCSRADCLOCKTSMODE 	0x8907
#define SIOCGRADCLOCKTSMODE 	0x8908
#define SIOCGRADCLOCKSTAMP 		0x894B

#else
/* New SYSCTL on the net.core side and also new
 * IOCTL for timespec timestamps on the socket */
#define NET_CORE_RADCLOCK_DEFAULT_TSMODE 23
#define SIOCSRADCLOCKTSMODE 	0x8908
#define SIOCGRADCLOCKTSMODE 	0x8909
#define SIOCGRADCLOCKSTAMP 		0x894B
#endif


/**
 * TODO LINUX:
 *  Consider moving the vcount stamp to ancilary data
 *  - Would mean moving away from standard pcap (maybe to libtrace, which
 *  already supports ancilary data for the sw stamp, or patching pcap to use
 *  it
 *  - This would avoid 2 syscalls (one of sw stamp, one for vcount stamp)
 *  - UPDATE: new packet MMAP support should solve all of this
 *  
 *  Concider moving the mode to a sockopt
 *  - This would just be cleaner and the right thing to do, no performance benifet
 */



int found_ffwd_kernel_version (void) 
{
	int version = -1;
	FILE *fd = NULL;

	fd = fopen ("/sys/devices/system/ffclock/ffclock0/version", "r");
	if (fd)
	{
		fscanf(fd, "%d", &version);
		fclose(fd);
		logger(RADLOG_NOTICE, "Feed-Forward kernel support detected (version: %d)", version);
	}
	else {

		/* This is the old way we used before explicit versioning */
		fd = fopen ("/proc/sys/net/core/radclock_default_tsmode", "r");
		if (fd)
		{
			fclose(fd);	
			logger(RADLOG_NOTICE, "Feed-Forward kernel support detected (version 0)");
			version = 0;
		}
		else 
			version = -1;
	}

	/* A quick reminder for the administrator. */	
	switch ( version )
	{
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
	return version;
}



int radclock_init_vcounter_syscall(struct radclock *handle)
{
	switch ( handle->kernel_version )
	{
	case 0:
	case 1:
		/* From config.h */
		handle->syscall_get_vcounter = LINUX_SYSCALL_GET_VCOUNTER;
		logger(RADLOG_NOTICE, "registered get_vcounter syscall at %d", handle->syscall_get_vcounter);
		break;

	case 2:
		/* From config.h */
		handle->syscall_get_vcounter = LINUX_SYSCALL_GET_VCOUNTER;
		logger(RADLOG_NOTICE, "registered get_ffcounter syscall at %d", handle->syscall_get_vcounter);
		break;

	default:
		logger(RADLOG_ERR, "Unknown kernel version, cannot register get_ffcounter syscall");
		return -1;
	}

	return 0;
}


/* 
 * Check to see if we can use fast rdtsc() timestamping from userland.
 * Otherwise fall back to syscalls
 */
int radclock_init_vcounter(struct radclock *handle)
{
	int	passthrough_counter = 0;
	char clocksource[32];
	FILE *fd = NULL;
	
	if ( handle->kernel_version < 1 )
		passthrough_counter = 0;
	else
	{
		fd = fopen ("/sys/devices/system/clocksource/clocksource0/passthrough_clocksource", "r");
		if (!fd)
		{
			logger(RADLOG_ERR, "Cannot open passthrough_clocksource from sysfs");
			return -1;
		}
		fscanf(fd, "%d", &passthrough_counter);
		fclose(fd);
	}

	fd = fopen ("/sys/devices/system/clocksource/clocksource0/current_clocksource", "r");
	if (!fd)
	{
		logger(RADLOG_ERR, "Cannot open current_clocksource from sysfs");
		return -1;
	}
	fscanf(fd, "%s", &clocksource[0]);
	fclose(fd);
	logger(RADLOG_NOTICE, "Clocksource used is %s", clocksource);

	if ( passthrough_counter == 0)
	{
		handle->get_vcounter = &radclock_get_vcounter_syscall;
		logger(RADLOG_NOTICE, "Initialising radclock_get_vcounter with syscall.");
		return 0;
	}

	if (strcmp(clocksource, "tsc") == 0)
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
		if ( (strcmp(clocksource, "tsc") != 0) && (strcmp(clocksource, "xen") != 0) )
			logger(RADLOG_ERR, "Passthrough mode in ON but the clocksource does not support it!!");
	}

	return 0;
}



int descriptor_set_tsmode(struct radclock *handle, pcap_t *p_handle, int kmode)
{
	/* int and long imay have different size on 32bit and 64bit architectures.
	 * the kernel expects a long based on IOCTL definition
	 */
	long kmode_long = 0;
	kmode_long += kmode;
	if (ioctl(pcap_fileno(p_handle), SIOCSRADCLOCKTSMODE, (caddr_t)&kmode_long) == -1) 
	{
		logger(RADLOG_ERR, "Setting capture mode failed: %s", strerror(errno));
		return -1;
	}
	return 0;
}


int descriptor_get_tsmode(struct radclock *handle, pcap_t *p_handle, int *kmode)
{
	/* int and long imay have different size on 32bit and 64bit architectures.
	 * the kernel expects a long based on IOCTL definition
	 */
	long kmode_long;
	if (ioctl(pcap_fileno(p_handle), SIOCGRADCLOCKTSMODE, (caddr_t)(&kmode_long)) == -1)
	{
		logger(RADLOG_ERR, "Getting capture mode failed: %s", strerror(errno));
		return -1;
	}
	*kmode = 0;
	*kmode += kmode_long;
	return 0;
}


/* We need to be sure that both the kernel AND libpcap support PACKET_MMAP
 * Otherwise, use 'old' ioctl call to retrieve vcount.
 * Try to make this as quick as possible
 */
#if defined(TPACKET_HDRLEN) && defined (HAVE_PCAP_ACTIVATE) 

inline int extract_vcount_stamp(
			pcap_t *p_handle, 
			const struct pcap_pkthdr *header, 
			const unsigned char *packet,
			vcounter_t *vcount)
{
	char * bp;
	bp = (char*)packet - sizeof(vcounter_t);
	memcpy(vcount, bp, sizeof(vcounter_t)); 
	return 0;
}

#else

inline int extract_vcount_stamp(
			pcap_t *p_handle, 
			const struct pcap_pkthdr *header, 
			const unsigned char *packet,
			vcounter_t *vcount)
{
	if (ioctl(pcap_fileno(p_handle), SIOCGRADCLOCKSTAMP, vcount))
	{
		perror("ioctl");
		logger(RADLOG_ERR, "IOCTL failed to get vcount");
		return -1;
	}
	return 0;
}

#endif


#endif
