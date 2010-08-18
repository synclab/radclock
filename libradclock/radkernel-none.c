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



#include "../config.h"
#ifdef WITH_RADKERNEL_NONE

#if defined(__APPLE__) 
#include <machine/types.h>
#elif defined(__FreeBSD__)
#include <sys/types.h>
#elif defined(linux)
#include <asm/types.h>
#endif

#include <sys/socket.h>
#include <unistd.h>
#include <err.h>
#include <stdio.h>
#include <string.h>

#include <errno.h>


#include <radclock.h>
#include "radclock-private.h"
#include "logger.h"


/**
 * A global data that will always fail!
 */


int found_ffwd_kernel_version(void) 
{
	logger(RADLOG_WARNING, "Feed-Forward Kernel support not compiled.");
	return -1;
}

int radclock_init_vcounter_syscall(struct radclock *handle)
{
	handle->syscall_get_vcounter = 0;
	handle->syscall_get_vcounter_latency = 0;
	return 0;
}

int radclock_init_kernel_support(struct radclock *handle)
{
	return -ENOENT;
}

/* Read global clock data */
int radclock_read_kernelclock(struct radclock *handle) 
{
	return -ENOENT;
}


int descriptor_set_tsmode(pcap_t *p_handle, int kmode)
{
	return -ENOENT;
}


int descriptor_get_tsmode(pcap_t *p_handle, int *kmode)
{
	return -ENOENT;
}


int extract_vcount_stamp(
			pcap_t *p_handle, 
			const struct pcap_pkthdr *header, 
			const unsigned char *packet,
			vcounter_t *vcount)
{
	return -ENOENT;
}



/* ** Clock Data Routines ** */
/* Set radclock data. */
int radclock_set_kernelclock(struct radclock *handle) 
{
	return -ENOENT;
}


inline int set_kernel_fixedpoint(struct radclock *handle, struct radclock_fixedpoint *fpdata)
{
	return -ENOENT;
}


#endif

