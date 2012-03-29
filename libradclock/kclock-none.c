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
#ifdef WITH_RADKERNEL_NONE

#include <errno.h>

#include "radclock.h"
#include "radclock-private.h"
#include "kclock.h"


int
init_kernel_clock(struct radclock *clock)
{
	return (-ENOENT);
}


int
get_kernel_ffclock(struct radclock *clock, struct ffclock_estimate *cest)
{
	return (-ENOENT);
}


int
set_kernel_ffclock(struct radclock *clock, struct ffclock_estimate *cest)
{
	return (-ENOENT);
}


/*
 * XXX Deprecated
 * Old way of pushing clock updates to the kernel.
 * TODO: remove when backward compatibility for kernel versions < 2 is dropped.
 */
int
set_kernel_fixedpoint(struct radclock *clock, struct radclock_fixedpoint *fpdata)
{
	return (-ENOENT);
}


#endif
