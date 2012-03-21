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

#ifndef HAVE_SYS_TIMEFFC_H
int ffclock_getcounter(vcounter_t *vcount)
{
	*vcount = 0;
	return EINVAL;
}
#endif

#ifndef BPF_T_MICROTIME
/* Deprecated.
 * Time stamping functions from net/bpf.h.
 * This is useful for compiling code on old kernel (most likely feed forward
 * kernel support versions 0 and 1) 
 * FreeBSD 9.1 and above should have these defines in net/bpf.h
 */
#define	BPF_T_MICROTIME		0x0000
#define	BPF_T_NANOTIME		0x0001
#define	BPF_T_BINTIME		0x0002
#define	BPF_T_NONE		0x0003
#define	BPF_T_FFCOUNTER		0x0004
#define	BPF_T_FORMAT_MAX	0x0004
#define	BPF_T_FORMAT_MASK	0x0007
#define	BPF_T_NORMAL		0x0000
#define	BPF_T_MONOTONIC		0x0100
#define	BPF_T_FLAG_MASK		0x0100
#define	BPF_T_SYSCLOCK		0x0000
#define	BPF_T_FBCLOCK		0x1000
#define	BPF_T_FFCLOCK		0x2000
#define	BPF_T_CLOCK_MAX		0x2000
#define	BPF_T_CLOCK_MASK	0x3000
#define	BPF_T_FORMAT(t)		((t) & BPF_T_FORMAT_MASK)
#define	BPF_T_FLAG(t)		((t) & BPF_T_FLAG_MASK)
#define	BPF_T_CLOCK(t)		((t) & BPF_T_CLOCK_MASK)

/* Same as above for these 2 ioctl */
#define	BIOCGTSTAMP	_IOR('B', 131, u_int)
#define	BIOCSTSTAMP	_IOW('B', 132, u_int)
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
	ret = sysctlbyname("kern.sysclock.ffclock.version", &version, &size_ctl, NULL, 0);
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
	switch ( version ) {
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
	return version;
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
inline int radclock_get_vcounter_rdtsc(struct radclock *handle, vcounter_t *vcount)
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
		if (err < 0 ) {
			logger(RADLOG_ERR, "Error on modstat (get_vcounter syscall): %s",
				strerror(errno));
			logger(RADLOG_ERR, "Is the radclock kernel module loaded?");
			return (-1);
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

	if ( ret < 0 ) {
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
		ret = sysctlbyname("kern.timecounter.passthrough", &passthrough_counter, &size_ctl, NULL, 0);
		if (ret == -1)
		{
			logger(RADLOG_ERR, "Cannot find kern.timecounter.passthrough in sysctl");
			return (-1);
		}
		break;

// FIXME
// XXX For these two versions, the sysctl has snicked in the official kernel
// withouth the backend support. This test is not discrimating!
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
			logger(RADLOG_ERR, "Passthrough mode in ON but the timecounter does not support it!!");
	}

	return (0);
}

#ifdef HAVE_SYS_TIMEFFC_H
int get_kernel_ffclock(struct radclock *handle)
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
	if (handle->kernel_version < 2)
		return 0;

	/* FreeBSD system call */
	err = ffclock_getestimate(&cest);
	if (err < 0) {
// TODO Clean up verbose logging
		logger(RADLOG_ERR, "Clock estimate init from kernel failed");
		fprintf(stdout, "Clock estimate init from kernel failed");
		return err;
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
	RAD_DATA(handle)->ca = (long double) cest.update_time.sec;
	tmp = ((long double) cest.update_time.frac) / (1LL << 32);
	RAD_DATA(handle)->ca += tmp / (1LL << 32);
	
	tmp = (long double) cest.period / (1LLU << 32);
	RAD_DATA(handle)->phat_local = (double) (tmp / (1LLU << 32));
	RAD_DATA(handle)->phat = RAD_DATA(handle)->phat_local;

	RAD_DATA(handle)->status = (unsigned int) cest.status;
	RAD_DATA(handle)->last_changed = (vcounter_t) cest.update_ffcount;
	RAD_ERROR(handle)->error_bound_avg = (double) (cest.errb_abs / 1e9);

	fprintf(stdout, "period=%llu  phat = %.10lg, C = %7.4Lf\n",
	(unsigned long long) cest.period,
	RAD_DATA(handle)->phat,
	RAD_DATA(handle)->ca);
	fprintf(stdout, "Retrieved clock estimate init from kernel\n");
			
	return 0;
}
#else
int get_kernel_ffclock(struct radclock *handle)
{
	return 0;
}
#endif



// FIXME this is kind of a mess, all options need to be double-check for
// backward compatibility
int
descriptor_set_tsmode(struct radclock *handle, pcap_t *p_handle, int kmode)
{
	u_int bd_tstamp;

	bd_tstamp = 0;

	switch (handle->kernel_version) {

	case 0:
	case 1:
		if (ioctl(pcap_fileno(p_handle), BIOCSRADCLOCKTSMODE, (caddr_t)&kmode) == -1) {
			logger(LOG_ERR, "Setting capture mode failed");
			return (-1);
		}
		break;

	case 2:
	case 3:
		/* No more Faircompare mode in kernel version 2, it is identical to
		 * SYSCLOCK
		 */
		switch (kmode) {
			case RADCLOCK_TSMODE_SYSCLOCK:
			case RADCLOCK_TSMODE_FAIRCOMPARE:
				bd_tstamp = BPF_T_MICROTIME;
				break;
			case RADCLOCK_TSMODE_RADCLOCK:
				// TODO this is not very clean, need to do better management of
				// the format flag
				bd_tstamp = BPF_T_FFCOUNTER;
//				bd_tstamp = BPF_T_FFCOUNTER | BPF_T_FFCLOCK;
//				bd_tstamp = BPF_T_MICROTIME | BPF_T_FFCLOCK | BPF_T_MONOTONIC;
				break;
			default:
				logger(LOG_ERR, "descriptor_set_tsmode: Unknown timestamping mode.");
				return (-1);
		}

		if (ioctl(pcap_fileno(p_handle), BIOCSTSTAMP, (caddr_t)&bd_tstamp) == -1) 
		{
			logger(LOG_ERR, "Setting capture mode failed: %s", strerror(errno));
			return (-1);
		}

		break;

	default:
		logger(LOG_ERR, "Unknown kernel version");
		return (-1);

	}

	return (0);
}


int
descriptor_get_tsmode(struct radclock *handle, pcap_t *p_handle, int *kmode)
{
	u_int bd_tstamp;

	bd_tstamp = 0;

	switch (handle->kernel_version) {

	case 0:
	case 1:
		if (ioctl(pcap_fileno(p_handle), BIOCGRADCLOCKTSMODE, (caddr_t)kmode) == -1)
		{
			logger(LOG_ERR, "Getting timestamping mode failed");
			return (-1);
		}
		break;

	case 2:
	case 3:
		if (ioctl(pcap_fileno(p_handle), BIOCGTSTAMP, (caddr_t)(&bd_tstamp)) == -1) {
			logger(LOG_ERR, "Getting timestamping mode failed: %s", strerror(errno));
			return (-1);
		}

		// FIXME: loosy output for debugging 
		switch (bd_tstamp & BPF_T_FORMAT_MASK) {
		case BPF_T_MICROTIME:
			logger(LOG_ERR, "PCAP capture format is MICROTIME");
			break;
		case BPF_T_NANOTIME:
			logger(LOG_ERR, "PCAP capture format is NANOTIME");
			break;
		case BPF_T_BINTIME:
			logger(LOG_ERR, "PCAP capture format is BINTIME");
			break;
		case BPF_T_FFCOUNTER:
			logger(LOG_ERR, "PCAP capture format is FFCOUNTER");
			break;
		
		}

		switch (bd_tstamp & BPF_T_CLOCK_MASK) {
		case BPF_T_SYSCLOCK:
		// FIXME: need to retrieve sysctl clock active
		
		case BPF_T_FBCLOCK:
			logger(LOG_ERR, "Capture clock is SYSCLOCK");
			*kmode = RADCLOCK_TSMODE_SYSCLOCK;
			break;

		case BPF_T_FFCLOCK:
			logger(LOG_ERR, "Capture clock is RADCLOCK");
			*kmode = RADCLOCK_TSMODE_RADCLOCK;
			break;
		}
		break;

	default:
		logger(LOG_ERR, "Unknown kernel version");
		return (-1);
	}
	
	return (0);
}



/*
 * The BPF subsystem adds padding after the bpf header to WORDALIGN the NETWORK
 * layer header, and not the MAC layer. In other words:
 * WORDALIGN( * bpf_hdr->bh_hrdlen + MAC_header ) - MAC_header
 *
 * Let's look at the components of WORDALIGN.
 * Because we add the vcounter_t member at the end of the hacked bpf_header, the
 * compiler adds padding before the vcount to align it on to 64 boundary.
 * Things are architecture dependent.
 *
 * - On 32 bit system, the timeval is twice 32 bit integers, and the original
 * bpf_header is 18 bytes. The compiler adds 6 bytes of padding and the vcounter
 * takes 8 bytes. The hacked header is 32 bytes long.  
 *
 * - On 64 bit systems, the timeval is twice 64 bits integers, and the hacked
 * header is 40 bytes long.
 *
 * The word alignement is based on sizeof(long), which is 4 bytes on i386 system
 * and 8 bytes on amd64 systems.  So the bpf_header is always WORDALIGNED by
 * default as 8*sizeof(long) for i386 and 5*sizeof(long) on amd64.
 *
 * Now, we have always captured packets over Ethernet (without 802.1Q), that is
 * a MAC header of 14 bytes. On both i386 and amd64 that gives a WORDALIGN at 16
 * bytes, and an extra padding of 2 bytes.
 *
 * Example of ethernet capture on amd64:
 * [[bpf_header 40bytes][padding 2bytes]]  [Ether 14bytes]  [IPv4 20 bytes]
 *
 * XXX
 * As soon as we move to capture on other MAC layer or use 802.1Q, things will
 * break, and we need a new implementation that provides the MAC header length
 * base on the DLT of the pcap handler.
 * XXX
 */


// TODO XXX improve the management of kernel support versions. Currently that's
// pretty ugly and not optimised




/* XXX Can we clean that ??
 * Redefinition of the BPF header as in bpf.h Just to avoid to have to include
 * the file again and define the RADCLOCK symbol at compilation time.  Changed
 * name to avoid redefinition problem. pcap.h includes bpf.h but without the
 * vcount field.
 */

struct bpf_hdr_hack_v1 {
	struct timeval bh_tstamp;	/* time stamp */
	bpf_u_int32 bh_caplen;		/* length of captured portion */
	bpf_u_int32 bh_datalen;		/* original length of packet */
	u_short bh_hdrlen;			/* length of bpf header (this struct plus alignment padding) */
	u_short padding;			/* padding to align the fields */
	vcounter_t vcount;			/* raw vcount value for this packet */
};

/*
 * Also make sure we compute the padding inside the hacked bpf header the same
 * way as in the kernel to avoid different behaviour accross compilers.
 */
#define BPF_ALIGNMENT sizeof(long)
#define BPF_WORDALIGN(x) (((x)+(BPF_ALIGNMENT-1))&~(BPF_ALIGNMENT-1))

#define SIZEOF_BPF_HDR_v1(type)	\
	(offsetof(type, vcount) + sizeof(((type *)0)->vcount))

#define BPF_HDR_LEN_v1		\
	(BPF_WORDALIGN(SIZEOF_BPF_HDR_v1(struct bpf_hdr_hack_v1) + ETHER_HDR_LEN) - ETHER_HDR_LEN)

// FIXME inline should be in a header file, d'oh...
// FIXME should convert to void, make these tests once and not on each packet
static inline int
extract_vcount_stamp_v1(pcap_t *p_handle, const struct pcap_pkthdr *header,
		const unsigned char *packet, vcounter_t *vcount)
{
	struct bpf_hdr_hack_v1 *hack;

	/*
	 * Find the beginning of the hacked header starting from the MAC header.
	 * Useful for checking we are doing the right thing.
	 */
	hack = (struct bpf_hdr_hack_v1 *) (packet - BPF_HDR_LEN_v1);

	/* Check we did the right thing by comparing hack and pcap header pointer */
	// TODO: it may be that BPF_FFCOUNTER was not defined in the kernel.
	// it is not a bug anymore, but a new case to handle
	if ((hack->bh_hdrlen != BPF_HDR_LEN_v1)
		|| (memcmp(hack, header, sizeof(struct pcap_pkthdr)) != 0))
	{
		logger(RADLOG_ERR, "Either modified kernel not installed, "
				"or bpf interface has changed");
		return (-1);
	}

	*vcount= hack->vcount;
	return (0);
}




/* XXX this one is based off pcap_pkthdr */
// TODO Clean me !!
//struct bpf_hdr_hack_v2 {
//	union {
//		struct timeval tv;	/* time stamp */
//		vcounter_t vcount;
//	} bh_ustamp;
//	bpf_u_int32 caplen;		/* length of captured portion */
//	bpf_u_int32 len;		/* original length of packet */
//};


// FIXME inline should be in a header file, d'oh...
// FIXME should convert to void, make these tests once and not on each packet to
// improve perfs
static inline int
extract_vcount_stamp_v2(pcap_t *p_handle, const struct pcap_pkthdr *header,
		const unsigned char *packet, vcounter_t *vcount)
{
	vcounter_t *hack;
	hack = (vcounter_t*) &(header->ts);
	*vcount = *hack;
	return (0);
}


// TODO could use system include from bpf.h
struct bpf_hdr_hack_v3 {
	struct timeval bh_tstamp;	/* time stamp */
	vcounter_t vcount;			/* raw vcount value for this packet */
	bpf_u_int32 bh_caplen;		/* length of captured portion */
	bpf_u_int32 bh_datalen;		/* original length of packet */
	u_short bh_hdrlen;			/* length of bpf header (this struct plus alignment padding) */
};


//#define DLT_NULL    0   /* BSD loopback encapsulation */
//#define DLT_EN10MB  1   /* Ethernet (10Mb) */

static int dlt_header_size[] = {
	[DLT_NULL] = 4,
	[DLT_EN10MB] = ETHER_HDR_LEN
};

#define SIZEOF_BPF_HDR_v3(type)	\
	(offsetof(type, bh_hdrlen) + sizeof(((type *)0)->bh_hdrlen))

#define BPF_HDR_LEN_v3(length)		\
	(BPF_WORDALIGN(SIZEOF_BPF_HDR_v3(struct bpf_hdr_hack_v3) + length) - length)

/*
 * Libpcap not (yet) aware of the changed BPF header. So back to basics, with a
 * bit of hacking, taking advantage of the fact the BPF header and the packet
 * captured are in contiguous memory chunks.
 * Tried to be a bit more generic than before and handle multiple header length
 * based on their DLT type.
 */
// FIXME: this is becoming heavier ... can fasten this up?
static inline int
extract_vcount_stamp_v3(pcap_t *p_handle, const struct pcap_pkthdr *header,
		const unsigned char *packet, vcounter_t *vcount)
{
	struct bpf_hdr_hack_v3 *hack;
	int hlen;

	hlen = dlt_header_size[pcap_datalink(p_handle)];

	/*
	 * Find the beginning of the hacked header starting from the MAC header.
	 * Useful for checking we are doing the right thing.
	 */
	hack = (struct bpf_hdr_hack_v3 *) (packet - BPF_HDR_LEN_v3(hlen));

	/*
	 * Check we did the right thing by comparing hack and pcap header pointer
	 * Compare to previous hacks, the pcap packet header and the kernel BPF
	 * header do not match anymore (actually even the idea of a memcmp of the
	 * pointers was quite dodgy, since pcap access the members of the structure
	 * by name.
	 * */
	if (hack->bh_hdrlen != BPF_HDR_LEN_v3(hlen)) {
		logger(RADLOG_ERR, "Feed-forward kernel v3 error: BPF header length mismatch %d vs %d", 
				hack->bh_hdrlen, BPF_HDR_LEN_v3(hlen));
		return (-1);
	}
	if (memcmp(&hack->bh_tstamp, &header->ts, sizeof(struct timeval)) != 0) {
		logger(RADLOG_ERR, "Feed-forward kernel v3 error: BPF headers do not match");
		return (-1);
	}

	*vcount= hack->vcount;
	return (0);
}



int
extract_vcount_stamp(struct radclock *clock, pcap_t *p_handle,
		const struct pcap_pkthdr *header, const unsigned char *packet,
		vcounter_t *vcount)
{
	int err;

	/* Check we are running live */
	if (pcap_fileno(p_handle) < 0)
		return (-1);

	// FIXME : need a function pointer to the correct extract_vcount function
	switch (clock->kernel_version) {
	case 0:
	case 1:
		err = extract_vcount_stamp_v1(clock->pcap_handle, header, packet, vcount);
		break;
	case 2:
		/* This version supports a single timestamp at a time */
		if (clock->tsmode == RADCLOCK_TSMODE_RADCLOCK)
			err = extract_vcount_stamp_v2(clock->pcap_handle, header, packet, vcount);
		else {
			*vcount = 0;
			err = -2;
		}
		break;
	case 3:
		/*
		 * If we are in radclock mode, take a safe path and cast pcap header
		 * timestamp. Otherwise, go dirty.
		 */
		if (clock->tsmode == RADCLOCK_TSMODE_RADCLOCK)
			err = extract_vcount_stamp_v2(clock->pcap_handle, header, packet, vcount);
		else
			err = extract_vcount_stamp_v3(clock->pcap_handle, header, packet, vcount);
		break;
	default:
		err = -1;
		break;
	}

	if (err < 0) {
		logger(RADLOG_ERR, "Cannot extract vcounter from packet timestamped: %ld.%ld",
			header->ts.tv_sec, header->ts.tv_usec);
		if (err == -2)
			logger(RADLOG_ERR, "Timestamping mode should be RADCLOCK");
		return (-1);
	}

	return (0);
}




#endif
