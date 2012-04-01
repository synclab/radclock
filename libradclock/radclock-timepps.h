/*
 * Copyright (C) 2006-2012, Julien Ridoux <julien@synclab.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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

#ifndef _RADCLOCK_TIMEPPS_H
#define _RADCLOCK_TIMEPPS_H 

typedef union pps_tcounteru {
	uint64_t tc64;
} pps_tcounteru_t;


typedef struct {
	pps_seq_t	assert_sequence;	/* assert event seq # */
	pps_seq_t	clear_sequence;		/* clear event seq # */
	pps_timeu_t	assert_tu;
	pps_timeu_t	clear_tu;
	int		current_mode;		/* current mode bits */
	pps_tcounteru_t  assert_tcu;
	pps_tcounteru_t  clear_tcu;
} radclock_pps_info_t;

#define assert_tcount       assert_tcu.tc64                                                                  
#define clear_tcount        clear_tcu.tc64                                                                   


struct radclock_pps_fetch_args {
	int tsformat;
	radclock_pps_info_t	pps_info_buf;
	struct timespec	timeout;
};


#define RADCLOCK_PPS_IOC_FETCH		_IOWR('1', 8, struct radclock_pps_fetch_args)

static __inline int
radclock_pps_fetch(pps_handle_t handle, const int tsformat,
	radclock_pps_info_t *ppsinfobuf, const struct timespec *timeout)
{
	int error;
	struct radclock_pps_fetch_args arg;

	arg.tsformat = tsformat;
	if (timeout == NULL) {
		arg.timeout.tv_sec = -1;
		arg.timeout.tv_nsec = -1;
	} else
		arg.timeout = *timeout;
	error = ioctl(handle, RADCLOCK_PPS_IOC_FETCH, &arg);
	*ppsinfobuf = arg.pps_info_buf;
	return (error);
}

#endif /* _RADCLOCK_TIMEPPS_H */
