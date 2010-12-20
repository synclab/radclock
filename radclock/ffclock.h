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


#ifndef _FFCLOCK_H
#define _FFCLOCK_H

#include "../config.h"

/*
 * This is very strongly inspired by the bintime structure in FreeBSD. See
 * sys/time.h there for the details.
 */
#ifdef WITH_RADKERNEL_FBSD
#include <sys/time.h>
#else
struct bintime {
	int64_t sec;
	uint64_t frac;
};
#endif


#include "radclock.h"



struct ffclock_data
{
    /* Time conversion of ffcounter below */
    struct bintime time;

    /* Last synchronization daemon update or update_ffclock() */
    vcounter_t ffcounter;
    
	/* Timecounter period estimate (<< per_shift) */
    uint64_t period;
    
	/* Clock status word */
    uint32_t status;
    
	/* Average of clock error bound in [ns] */
    uint32_t error_bound_avg;
    
};



int set_kernel_ffclock(struct radclock *clock_handle);

int has_vm_vcounter(void);

#endif 	/* _FFCLOCK_H */
