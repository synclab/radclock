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

// TODO this file is really poorly named

#ifndef _MISC_H
#define _MISC_H


int counter_to_time(struct radclock *clock, vcounter_t *vcount, long double *time);

static inline void
timeld_to_timeval(long double *time, struct timeval *tv)
{
	tv->tv_sec  = (uint32_t) *time;
	tv->tv_usec = (uint32_t) (1000000*(*time - tv->tv_sec) + 0.5);
}

#endif
