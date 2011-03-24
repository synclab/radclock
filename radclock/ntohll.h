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


#ifndef _NTOHLL_H
#define _NTOHLL_H

#include "../config.h"
#ifdef WORDS_BIGENDIAN

 #define ntohll(x) (x)

 #define htonll(x) (x)

#else

 #define ntohll(x) (((u_int64_t)(ntohl((int)((x << 32) >> 32))) << 32) | \
                     (unsigned int)ntohl(((int)(x >> 32)))) 
 #define htonll(x) ntohll(x)

#endif
#endif
