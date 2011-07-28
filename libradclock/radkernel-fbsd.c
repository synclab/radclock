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


#ifndef HAVE_SYS_TIMEFFC_H
int ffclock_getcounter(vcounter_t *vcount)
{
	*vcount = 0;
	return EINVAL;
}
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
#define	BPF_T_FFCLOCK		0x8000
//#endif



/* XXX Can we clean that ??
 * Redefinition of the BPF header as in bpf.h Just to avoid to have to include
 * the file again and define the RADCLOCK symbol at compilation time.  Changed
 * name to avoid redefinition problem. pcap.h includes bpf.h but without the
 * vcount field.
 */

struct bpf_hdr_hack 
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


int radclock_init_vcounter_syscall(struct radclock *handle)
{
	int err;
	struct module_stat stat;

	switch ( handle->kernel_version )
	{

	case 0:
	case 1:
		stat.version = sizeof(stat);
		err = modstat(modfind("get_vcounter"), &stat);
		if (err < 0 ) {
			logger(RADLOG_ERR, "Error on modstat (get_vcounter syscall): %s", strerror(errno));
			logger(RADLOG_ERR, "Is the radclock kernel module loaded?");
			return -1;
		}
		handle->syscall_get_vcounter = stat.data.intval;
		logger(RADLOG_NOTICE, "Registered get_vcounter syscall at %d", handle->syscall_get_vcounter);
		break;

	case 2:
/*
		stat.version = sizeof(stat);
		err = modstat(modfind("get_ffcounter"), &stat);
		if (err < 0 ) {
			logger(RADLOG_ERR, "Error on modstat (get_ffcounter syscall): %s", strerror(errno));
			logger(RADLOG_ERR, "Is the radclock kernel module loaded?");
			return -1;
		}
		handle->syscall_get_vcounter = stat.data.intval;
		logger(RADLOG_NOTICE, "Registered get_ffcounter syscall at %d", handle->syscall_get_vcounter);
*/
		// kernel provides ffclock_getcounter through libc
		break;

	default:
		return -1;
	}
	return 0;
}


int radclock_get_vcounter_syscall(struct radclock *handle, vcounter_t *vcount)
{
	int ret;
	if (vcount == NULL)
		return -1;

	switch ( handle->kernel_version )
	{

	case 0:
	case 1:
		ret = syscall(handle->syscall_get_vcounter, vcount);
		break;
	case 2:
		ret = ffclock_getcounter(vcount);
		break;
	default:
		ret = -1;
		break;	
	}
	
	
	if ( ret < 0 ) {
		logger(RADLOG_ERR, "error on syscall get_vcounter: %s", strerror(errno));
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
	int ret;
	int	passthrough_counter = 0;
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
			// XXX TODO XXX
			// Used to return error here, but easier for kernel dev.
			// May need to reenable it later on
			passthrough_counter = 0;
			// return -1;
		}
	}

	size_ctl = sizeof(handle->hw_counter);
	ret = sysctlbyname("kern.timecounter.hardware", &handle->hw_counter[0], &size_ctl, NULL, 0);
	if (ret == -1)
	{
		logger(RADLOG_ERR, "Cannot find kern.timecounter.hardware in sysctl");
		return -1;
	}
	logger(RADLOG_NOTICE, "Timecounter used is %s", handle->hw_counter);

	if ( passthrough_counter == 0)
	{
		handle->get_vcounter = &radclock_get_vcounter_syscall;
		logger(RADLOG_NOTICE, "Initialising radclock_get_vcounter with syscall.");
		return 0;
	}

	if (strcmp(handle->hw_counter, "TSC") == 0)
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
		if ( (strcmp(handle->hw_counter, "TSC") != 0) && (strcmp(handle->hw_counter, "ixen") != 0) )
			logger(RADLOG_ERR, "Passthrough mode in ON but the timecounter does not support it!!");
	}

	return 0;
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
		logger(RADLOG_ERR, "Clock estimate init from kernel failed");
		fprintf(stdout, "Clock estimate init from kernel failed");
		return err;
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
	RAD_ERROR(handle)->error_bound_avg = (double) (cest.error_bound_abs / 1e9);

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
				bd_tstamp = BPF_T_MICROTIME | BPF_T_FFCLOCK;
//				bd_tstamp = BPF_T_MICROTIME | BPF_T_FFCLOCK | BPF_T_MONOTONIC;
				break;
			default:
				logger(LOG_ERR, "descriptor_set_tsmode: Unknown timestamping mode.");
				return -1;
		}

		if (ioctl(pcap_fileno(p_handle), BIOCSTSTAMP, (caddr_t)&bd_tstamp) == -1) 
		{
			logger(LOG_ERR, "Setting capture mode failed: %s", strerror(errno));
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
			logger(LOG_ERR, "Getting timestamping mode failed: %s", strerror(errno));
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

/* 
 * Also make sure we compute the padding inside the hacked bpf header the same
 * way as in the kernel to avoid different behaviour accross compilers.
 */
#define BPF_ALIGNMENT sizeof(long)
#define BPF_WORDALIGN(x) (((x)+(BPF_ALIGNMENT-1))&~(BPF_ALIGNMENT-1))

#define SIZEOF_BPF_HDR(type)	\
	(offsetof(type, vcount) + sizeof(((type *)0)->vcount))

#define BPF_HDR_LEN		\
	(BPF_WORDALIGN(SIZEOF_BPF_HDR(struct bpf_hdr_hack) + ETHER_HDR_LEN)	- ETHER_HDR_LEN)

inline int
extract_vcount_stamp(pcap_t *p_handle, const struct pcap_pkthdr *header, 
		const unsigned char *packet, vcounter_t *vcount)
{
	struct bpf_hdr_hack *hack; 

	/* Check we are running live */
	if (pcap_fileno(p_handle) < 0)
		return -1;

   	/* 
	 * Find the beginning of the hacked header starting from the MAC header.
	 * Useful for checking we are doing the right thing.
	 */
	hack = (struct bpf_hdr_hack *) (packet - BPF_HDR_LEN);
   
	/* Check we did the right thing by comparing hack and pcap header pointer */
	if ((hack->bh_hdrlen != BPF_HDR_LEN)
		|| (memcmp(hack, header, sizeof(struct pcap_pkthdr)) != 0))
	{
		logger(RADLOG_ERR, "Either modified kernel not installed, "
				"or bpf interface has changed");
	   	return -1;
	}

	*vcount= hack->vcount;
	return 0;
}

#endif
