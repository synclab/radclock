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

