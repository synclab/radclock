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
#ifdef WITH_RADKERNEL_NONE

#include <errno.h>

#include "radclock.h"


int
descriptor_set_tsmode(struct radclock *clock, pcap_t *p_handle, int kmode)
{
	return -ENOENT;
}


int
descriptor_get_tsmode(struct radclock *clock, pcap_t *p_handle, int *kmode)
{
	return -ENOENT;
}


int
extract_vcount_stamp(struct radclock *clock, pcap_t *p_handle,
		const struct pcap_pkthdr *header, const unsigned char *packet,
		vcounter_t *vcount)
{
	return -ENOENT;
}

#endif
