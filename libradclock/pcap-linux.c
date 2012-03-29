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


int
descriptor_set_tsmode(struct radclock *handle, pcap_t *p_handle, int kmode)
{
	/* int and long imay have different size on 32bit and 64bit architectures.
	 * the kernel expects a long based on IOCTL definition
	 */
	long kmode_long = 0;
	kmode_long += kmode;
	if (ioctl(pcap_fileno(p_handle), SIOCSRADCLOCKTSMODE,
			(caddr_t)&kmode_long) == -1) {
		logger(RADLOG_ERR, "Setting capture mode failed: %s", strerror(errno));
		return (-1);
	}
	return (0);
}


int
descriptor_get_tsmode(struct radclock *handle, pcap_t *p_handle, int *kmode)
{
	/* int and long imay have different size on 32bit and 64bit architectures.
	 * the kernel expects a long based on IOCTL definition
	 */
	long kmode_long;
	if (ioctl(pcap_fileno(p_handle), SIOCGRADCLOCKTSMODE,
			(caddr_t)(&kmode_long)) == -1) {
		logger(RADLOG_ERR, "Getting capture mode failed: %s", strerror(errno));
		return (-1);
	}
	*kmode = 0;
	*kmode += kmode_long;
	return (0);
}


/* We need to be sure that both the kernel AND libpcap support PACKET_MMAP
 * Otherwise, use 'old' ioctl call to retrieve vcount.
 * Try to make this as quick as possible
 */
#if defined(TPACKET_HDRLEN) && defined (HAVE_PCAP_ACTIVATE)

inline int
extract_vcount_stamp(struct radclock *clock, pcap_t *p_handle,
		const struct pcap_pkthdr *header, const unsigned char *packet,
		vcounter_t *vcount)
{
	char * bp;
	bp = (char*)packet - sizeof(vcounter_t);
	memcpy(vcount, bp, sizeof(vcounter_t));
	return (0);
}

#else

inline int
extract_vcount_stamp(struct radclock *clock, pcap_t *p_handle,
		const struct pcap_pkthdr *header, const unsigned char *packet,
		vcounter_t *vcount)
{
	if (ioctl(pcap_fileno(p_handle), SIOCGRADCLOCKSTAMP, vcount))
	{
		perror("ioctl");
		logger(RADLOG_ERR, "IOCTL failed to get vcount");
		return (-1);
	}
	return (0);
}

#endif

#endif
