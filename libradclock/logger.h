/*
 * Copyright (C) 2006-2009 Julien Ridoux <julien@synclab.org>
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


#ifndef _LOGGER_H
#define _LOGGER_H


//TODO XXX : fix this and a single verbose/logger function, enumerify? 
#define RADLOG_ERR 			3
#define RADLOG_WARNING 		4
#define RADLOG_NOTICE 		5


void logger(int level, char *fmt, ...);

int set_logger(void (*logger_funcp)(int level, char *message));


#endif
