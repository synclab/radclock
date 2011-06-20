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


#ifndef _SYNC_HISTORY_H
#define _SYNC_HISTORY_H

#include <stddef.h>

typedef unsigned long int index_t;

typedef struct sync_hist
{
	void *buffer;				/* data buffer */
	void *buffer_end;			/* end of data buffer */
	unsigned int buffer_sz;		/* buffer size (max number of elements) */
	unsigned int item_count; 	/* current number of items in the buffer */
	size_t item_sz;				/* size of each item in the buffer */
	void *head;					/* pointer to head */
	void *tail;					/* pointer to tail */
	index_t curr_i;				/* Record of the global index of last item added */ 
} history;

int history_init(history *hist, unsigned int buffer_sz, size_t item_sz);
void history_free(history *hist);
void history_add(history *hist, index_t i, const void *item);
index_t history_end(history *hist);
void *history_find(history *hist, index_t index);
int history_resize(history *hist, unsigned int buffer_sz, unsigned long int index);
index_t history_min(history *hist, index_t j, index_t i);
index_t history_min_slide(history *hist, index_t index_curr,  index_t j, index_t i);
vcounter_t history_min_slide_value(history *hist, index_t min_curr,  index_t j, index_t i);

#endif   /* _SYNC_HISTORY_H */
