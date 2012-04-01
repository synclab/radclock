/*
 * Copyright (C) 2006-2012 Julien Ridoux <julien@synclab.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
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

#ifndef _SYNC_HISTORY_H
#define _SYNC_HISTORY_H


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
