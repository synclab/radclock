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


#define MAX_MSG 1024
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <radclock.h>

#include "logger.h"

static void (*priv_logger)(int level, char *message);

static void default_log(int level, char *message)
{
	fprintf(stderr, "[libradclock] %s\n", message);
}

int set_logger(void (*logger_funcp)(int level, char *message))
{
	priv_logger = logger_funcp;
	return 0;
}


void logger(int level, char *fmt, ...)
{
	char buf[MAX_MSG];
	va_list arg;
	va_start(arg, fmt);
	vsnprintf(buf, MAX_MSG, fmt, arg);
	va_end(arg);
	if (priv_logger)
		priv_logger(level, buf);
	else
		default_log(level, buf);
}
