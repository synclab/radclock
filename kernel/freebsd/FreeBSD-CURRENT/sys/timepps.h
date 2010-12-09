/*-
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@FreeBSD.org> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 *
 * Copyright (C) 2010 The University of Melbourne
 * All rights reserved.
 *
 * Portions of this software were developed by the University of Melbourne
 * under sponsorship from the FreeBSD Foundation.
 *
 * $FreeBSD: src/sys/sys/timepps.h,v 1.19 2005/01/07 02:29:24 imp Exp $
 *
 * The is a FreeBSD version of the RFC 2783 API for Pulse Per Second 
 * timing interfaces.  
 */

#ifndef _SYS_TIMEPPS_H_
#define _SYS_TIMEPPS_H_

#include "opt_ffclock.h"

#include <sys/ioccom.h>
#include <sys/time.h>

#define PPS_API_VERS_1	1

typedef int pps_handle_t;	

typedef unsigned pps_seq_t;

typedef struct ntp_fp {
	unsigned int	integral;
	unsigned int	fractional;
} ntp_fp_t;

typedef union pps_timeu {
	struct timespec	tspec;
	ntp_fp_t	ntpfp;
	unsigned long	longpad[3];
} pps_timeu_t;

typedef struct {
	pps_seq_t	assert_sequence;	/* assert event seq # */
	pps_seq_t	clear_sequence;		/* clear event seq # */
	pps_timeu_t	assert_tu;
	pps_timeu_t	clear_tu;
	int		current_mode;		/* current mode bits */
} pps_info_t;


#ifdef FFCLOCK
typedef union pps_ffcounteru {
	ffcounter_t ffcounter;
} pps_ffcounteru_t;

typedef struct {
	pps_seq_t	assert_sequence;	/* assert event seq # */
	pps_seq_t	clear_sequence;		/* clear event seq # */
	pps_timeu_t	assert_tu;
	pps_timeu_t	clear_tu;
	int		current_mode;		/* current mode bits */
	pps_ffcounteru_t  assert_vcu;
	pps_ffcounteru_t  clear_vcu;
} ffclock_pps_info_t;
#endif	/* FFCLOCK */


#define assert_timestamp        assert_tu.tspec
#define clear_timestamp         clear_tu.tspec

#define assert_timestamp_ntpfp  assert_tu.ntpfp
#define clear_timestamp_ntpfp   clear_tu.ntpfp

#ifdef FFCLOCK
#define assert_ffcounter	assert_vcu.ffcounter
#define clear_ffcounter		clear_vcu.ffcounter
#endif 	/* FFCLOCK */

typedef struct {
	int api_version;			/* API version # */
	int mode;				/* mode bits */
	pps_timeu_t assert_off_tu;
	pps_timeu_t clear_off_tu;
} pps_params_t;

#define assert_offset   assert_off_tu.tspec
#define clear_offset    clear_off_tu.tspec

#define assert_offset_ntpfp     assert_off_tu.ntpfp
#define clear_offset_ntpfp      clear_off_tu.ntpfp


#define PPS_CAPTUREASSERT	0x01
#define PPS_CAPTURECLEAR	0x02
#define PPS_CAPTUREBOTH		0x03

#define PPS_OFFSETASSERT	0x10
#define PPS_OFFSETCLEAR		0x20

#define PPS_ECHOASSERT		0x40
#define PPS_ECHOCLEAR		0x80

#define PPS_CANWAIT		0x100
#define PPS_CANPOLL		0x200

#define PPS_TSFMT_TSPEC		0x1000
#define PPS_TSFMT_NTPFP		0x2000

#define PPS_KC_HARDPPS		0
#define PPS_KC_HARDPPS_PLL	1
#define PPS_KC_HARDPPS_FLL	2

struct pps_fetch_args {
	int tsformat;
	pps_info_t	pps_info_buf;
	struct timespec	timeout;
};

#ifdef FFCLOCK
struct ffclock_pps_fetch_args {
	int tsformat;
	ffclock_pps_info_t	pps_info_buf;
	struct timespec	timeout;
};
#endif	/* FFCLOCK */

struct pps_kcbind_args {
	int kernel_consumer;
	int edge;
	int tsformat;
};

#define PPS_IOC_CREATE		_IO('1', 1)
#define PPS_IOC_DESTROY		_IO('1', 2)
#define PPS_IOC_SETPARAMS	_IOW('1', 3, pps_params_t)
#define PPS_IOC_GETPARAMS	_IOR('1', 4, pps_params_t)
#define PPS_IOC_GETCAP		_IOR('1', 5, int)
#define PPS_IOC_FETCH		_IOWR('1', 6, struct pps_fetch_args)
#define PPS_IOC_KCBIND		_IOW('1', 7, struct pps_kcbind_args)
#ifdef FFCLOCK
#define FFCLOCK_PPS_IOC_FETCH		_IOWR('1', 8, struct ffclock_pps_fetch_args)
#endif 	/* FFCLOCK */

#ifdef _KERNEL

struct pps_state {
	/* Capture information. */
	struct timehands *capth;
	unsigned	capgen;
	unsigned	capcount;

	/* State information. */
	pps_params_t	ppsparam;
	pps_info_t	ppsinfo;
#ifdef FFCLOCK
	ffclock_pps_info_t	ffclock_ppsinfo;
#endif 	/* FFCLOCK */
	int		kcmode;
	int		ppscap;
	struct timecounter *ppstc;
	unsigned	ppscount[3];
};

void pps_capture(struct pps_state *pps);
void pps_event(struct pps_state *pps, int event);
void pps_init(struct pps_state *pps);
int pps_ioctl(unsigned long cmd, caddr_t data, struct pps_state *pps);
void hardpps(struct timespec *tsp, long nsec);

#else /* !_KERNEL */

static __inline int
time_pps_create(int filedes, pps_handle_t *handle)
{
	int error;

	*handle = -1;
	error = ioctl(filedes, PPS_IOC_CREATE, 0);
	if (error < 0) 
		return (-1);
	*handle = filedes;
	return (0);
}

static __inline int
time_pps_destroy(pps_handle_t handle)
{
	return (ioctl(handle, PPS_IOC_DESTROY, 0));
}

static __inline int
time_pps_setparams(pps_handle_t handle, const pps_params_t *ppsparams)
{
	return (ioctl(handle, PPS_IOC_SETPARAMS, ppsparams));
}

static __inline int
time_pps_getparams(pps_handle_t handle, pps_params_t *ppsparams)
{
	return (ioctl(handle, PPS_IOC_GETPARAMS, ppsparams));
}

static __inline int 
time_pps_getcap(pps_handle_t handle, int *mode)
{
	return (ioctl(handle, PPS_IOC_GETCAP, mode));
}

static __inline int
time_pps_fetch(pps_handle_t handle, const int tsformat,
	pps_info_t *ppsinfobuf, const struct timespec *timeout)
{
	int error;
	struct pps_fetch_args arg;

	arg.tsformat = tsformat;
	if (timeout == NULL) {
		arg.timeout.tv_sec = -1;
		arg.timeout.tv_nsec = -1;
	} else
		arg.timeout = *timeout;
	error = ioctl(handle, PPS_IOC_FETCH, &arg);
	*ppsinfobuf = arg.pps_info_buf;
	return (error);
}

#ifdef FFCLOCK
static __inline int
ffclock_pps_fetch(pps_handle_t handle, const int tsformat,
	ffclock_pps_info_t *ppsinfobuf, const struct timespec *timeout)
{
	int error;
	struct ffclock_pps_fetch_args arg;

	arg.tsformat = tsformat;
	if (timeout == NULL) {
		arg.timeout.tv_sec = -1;
		arg.timeout.tv_nsec = -1;
	} else
		arg.timeout = *timeout;
	error = ioctl(handle, FFCLOCK_PPS_IOC_FETCH, &arg);
	*ppsinfobuf = arg.pps_info_buf;
	return (error);
}
#endif 	/* FFCLOCK */

static __inline int
time_pps_kcbind(pps_handle_t handle, const int kernel_consumer,
	const int edge, const int tsformat)
{
	struct pps_kcbind_args arg;

	arg.kernel_consumer = kernel_consumer;
	arg.edge = edge;
	arg.tsformat = tsformat;
	return (ioctl(handle, PPS_IOC_KCBIND, &arg));
}

#endif /* KERNEL */

#endif /* !_SYS_TIMEPPS_H_ */
