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



// TODO the set_kernel_ffclock should be in the library too?
int
get_kernel_ffclock(struct radclock *clock, struct radclock_data *rad_data)
{
	logger(RADLOG_ERR, "Not yet getting ffclock data in the kernel");
	if (clock->kernel_version < 2) {
		logger(RADLOG_ERR, "get_kernel_ffclock with unfit kernel!");
		return (-1);
	}

	return (0);
}



#endif
