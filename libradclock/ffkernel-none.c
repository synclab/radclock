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

#include "../config.h"
#ifdef WITH_FFKERNEL_NONE

//#if defined(__APPLE__) 
//#include <machine/types.h>
//#elif defined(__FreeBSD__)
//#include <sys/types.h>
//#elif defined(linux)
//#include <asm/types.h>
//#endif

//#include <sys/socket.h>
//#include <unistd.h>
//#include <err.h>
//#include <stdio.h>
//#include <string.h>
//
#include <errno.h>


#include "radclock.h"
#include "radclock-private.h"
#include "logger.h"


/*
 * No-op functions for systems without kernel support.
 * Useful for data replay. 
 */

int
found_ffwd_kernel_version(void) 
{
	logger(RADLOG_WARNING, "Feed-Forward Kernel support not compiled.");
	return (-1);
}


int
has_vm_vcounter(struct radclock *clock)
{
	return (-ENOENT);
}


int
radclock_init_vcounter_syscall(struct radclock *clock)
{
	clock->syscall_get_vcounter = 0;
	clock->syscall_set_ffclock = 0;
	return (0);
}


int
radclock_init_vcounter(struct radclock *clock)
{
	clock->get_vcounter = NULL;
	return (0);
}

#endif
