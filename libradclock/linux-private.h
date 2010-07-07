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


#ifndef _LINUX_PRIVATE_H
#define _LINUX_PRIVATE_H

#include <linux/types.h>



enum {
	RADCLOCK_ATTR_DUMMY,
	RADCLOCK_ATTR_DATA,
	RADCLOCK_ATTR_FIXEDPOINT,
	__RADCLOCK_ATTR_MAX,
};

#define RADCLOCK_ATTR_MAX (__RADCLOCK_ATTR_MAX - 1)

static struct nla_policy radclock_attr_policy[RADCLOCK_ATTR_MAX+1] = {
	[RADCLOCK_ATTR_DUMMY] = { .type = NLA_U16 },
	[RADCLOCK_ATTR_DATA] = { .minlen = sizeof(struct radclock_data) },
	[RADCLOCK_ATTR_FIXEDPOINT] = { .minlen = sizeof(struct radclock_fixedpoint) },
};


enum {
	RADCLOCK_CMD_UNSPEC,
	RADCLOCK_CMD_GETATTR,
	RADCLOCK_CMD_SETATTR,
	__RADCLOCK_CMD_MAX,
};


#define RADCLOCK_CMD_MAX (__RADCLOCK_CMD_MAX - 1)

#define RADCLOCK_NAME "radclock"


#endif
