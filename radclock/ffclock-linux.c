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


#include <errno.h>
#include <syslog.h>

#include <netinet/in.h>

#ifdef HAVE_LINUX_GENETLINK_H
# include <linux/genetlink.h>
#elif defined(WITH_LOCAL_GENETLINK_H)
# include "local-genetlink.h"
#else
# error Need a linux/genetlink.h
#endif

#include <linux/rtnetlink.h>
#include <linux/netlink.h>

#include <netlink/netlink.h>
#include <netlink/attr.h>
#include <netlink/utils.h>
#include <netlink/msg.h>

#include <linux/types.h>

#include "radclock.h"
#include "radclock-private.h"
//#include "radclock_daemon.h"
#include "ffclock.h"
#include "fixedpoint.h"
#include "verbose.h"
#include "jdebug.h"



#endif	/* WITH_RADKERNEL_LINUX */
