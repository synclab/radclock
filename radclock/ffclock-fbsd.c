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
#ifdef WITH_RADKERNEL_FBSD

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <sys/time.h>
#ifdef HAVE_SYS_TIMEFFC_H
#include <sys/timeffc.h>	// All this should go in the library,
							//set/get ffclock estimates
#endif
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "radclock.h"
#include "radclock-private.h"
//#include "radclock_daemon.h"
#include "ffclock.h"
//#include "fixedpoint.h"
#include "misc.h"
//#include "sync_history.h"		// To be able to access boottime 'C'from sync
								// output. TODO add C into radclock_data structure?
//#include "sync_algo.h"			// To be able to access boottime 'C' from sync output.
								// TODO add C into radclock_data structure?
#include "verbose.h"
#include "jdebug.h"




#endif /* WITH_RADKERNEL_FBSD */
