/*
 * Copyright (C) 2006-2012, Julien Ridoux <julien@synclab.org>
 * Copyright (C) 2006-2007, Thomas Young <tfyoung@gmail.com>
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
