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


#ifndef _FFCLOCK_H
#define _FFCLOCK_H

#include "../config.h"

/*
 * This is very strongly inspired by the bintime structure in FreeBSD. See
 * sys/time.h there for the details.
 */
#if defined (__FreeBSD__)
#include <sys/time.h>
#else
struct bintime {
	int64_t sec;
	uint64_t frac;
};
#endif

#if defined (__FreeBSD__)
#ifdef HAVE_SYS_TIMEFFC_H
#include <sys/timeffc.h>
#else
struct ffclock_estimate
{
    /* Time conversion of ffcounter below */
    struct bintime time;

	/* Timecounter period estimate */
    uint64_t period;

	/* Timecounter short term period estimate (aka plocal) */
    uint64_t period_shortterm;

    /* Last synchronization daemon update or update_ffclock() */
    vcounter_t last_update;
    
	/* Clock status word */
    uint32_t status;
    
	/* Average of clock error bound in [ns] */
    uint32_t error_bound_avg;
};
#endif
#endif


#include "radclock.h"


/**
 * Init the kernel support. 
 * @param  handle The private handle for accessing global data
 * @return 0 on success, non-zero on failure
 */
int init_kernel_support(struct radclock *clock_handle);

int set_kernel_ffclock(struct radclock *clock_handle);

int has_vm_vcounter(void);

#endif 	/* _FFCLOCK_H */
