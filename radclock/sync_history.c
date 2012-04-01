/*
 * Copyright (C) 2006-2012, Julien Ridoux <julien@synclab.org>
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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "../config.h"
#include "radclock.h"
#include "verbose.h"
#include "sync_history.h"
#include "jdebug.h"



int history_init(history *hist, unsigned int buffer_sz, size_t item_sz)
{
	hist->buffer = malloc(buffer_sz * item_sz);
	JDEBUG_MEMORY(JDBG_MALLOC, hist->buffer);

	if(hist->buffer == NULL)
	{
		verbose(LOG_ERR, "malloc failed allocating memory");
		return 1;
	}

	memset(hist->buffer, 0, buffer_sz * item_sz);

	hist->buffer_end 	= hist->buffer + (buffer_sz-1) * item_sz;
	hist->buffer_sz 	= buffer_sz;
	hist->item_count 	= 0;
	hist->item_sz 		= item_sz;
	hist->head 			= hist->buffer;
	hist->tail 			= hist->buffer;
	return 0;
}


// XXX TODO ... this is never called ?? Should be used in the peer delete process
void history_free(history *hist)
{
	hist->buffer_end 	= NULL;
	hist->buffer_sz 	= 0;
	hist->item_count 	= 0;
	hist->item_sz 		= 0;
	hist->head 			= NULL;
	hist->tail 			= NULL;
	JDEBUG_MEMORY(JDBG_FREE, hist->buffer);
    free(hist->buffer);
	hist->buffer		= NULL;
}


void history_add(history *hist, index_t i, const void *item)
{
	/* Do we need to wave goodbye to an old one? */
    if ( hist->item_count == hist->buffer_sz )
	{
		if ( hist->tail == hist->buffer_end )
			hist->tail = hist->buffer;
		else
			hist->tail += hist->item_sz;
		hist->item_count--;
	}
	
	/* Add our new friend */
    memcpy( hist->head, item, hist->item_sz );
    hist->item_count++;
	hist->curr_i = i;

	/* Move head away */
	if ( hist->head == hist->buffer_end )
		hist->head = hist->buffer;
	else
		hist->head += hist->item_sz;

}


inline
index_t history_end(history *hist)
{
	/* This is not great because this return a valid but wrong answer if history
	 * is empty. So need to make sure it is never called on empty history.
	 */
	if (hist->item_count == 0)
		return 0;
	else
		return hist->curr_i - hist->item_count + 1; 
}



inline 
void * history_find(history *hist, index_t index)
{
	return hist->buffer + ( index % hist->buffer_sz ) * hist->item_sz;
}


/* Resize history
 * Called when configuration file is parsed and UPDATE flags are raised
 * Copy elements to a new history buffer, whose size may differ from the
 * existing one. Only write existing item that fit in new buffer, trash old ones
 * if they do not fit.
 * One side effect: we deal with global algo index ... so far, so good
 */
int history_resize(history *hist, unsigned int buffer_sz, unsigned long int index)
{
	unsigned long int last_index;
	unsigned long int j;
	void *new_buffer;
	void *src;
	void *dst;

	/* Allocate a new buffer to copy the correct items. Initialised to 0 */
	new_buffer = malloc(buffer_sz * hist->item_sz);
	JDEBUG_MEMORY(JDBG_MALLOC, new_buffer);

	if(new_buffer == NULL)
	{
		verbose(LOG_ERR, "malloc failed allocating memory");
		return 1;
	}
	memset(new_buffer, 0, buffer_sz * hist->item_sz);

	/* Ensure we find the 1st item available in the array */
	last_index = (hist->item_count > buffer_sz) ? buffer_sz : hist->item_count;
	if (last_index > 0)
		last_index = index - (last_index-1);
	else
		last_index = 0;

	/* If we abandon the use of a global index of the item we store, we may get
	 * rid of this loop, and copy large chunk of the old buffer into the new
	 * one. Until then, using a modulo is the best option to keep the global
	 * index association in here.
	 * Go back until hit `start' of history array, or last value available
	 */
	for ( j=last_index; j<=index; j++ )
	{
		src = hist->buffer + ( j % hist->buffer_sz ) * hist->item_sz;
		dst = new_buffer + ( j % buffer_sz ) * hist->item_sz;
		memcpy ( dst, src, hist->item_sz );
	}

	hist->item_count = (hist->item_count > buffer_sz) ? buffer_sz : hist->item_count;

	/* Head should be the one after the most recent item */
	hist->head = new_buffer + ( index % buffer_sz ) * hist->item_sz;
	if ( hist->head == hist->buffer_end )
		hist->head = hist->buffer;
	else
		hist->head += hist->item_sz;

	hist->tail = new_buffer + ( last_index % buffer_sz ) * hist->item_sz;
	hist->buffer_sz = buffer_sz;
	hist->buffer_end = new_buffer + (buffer_sz-1) * hist->item_sz;

	JDEBUG_MEMORY(JDBG_FREE, hist->buffer);
	free(hist->buffer);
	hist->buffer = new_buffer;
	
	return 0;
}




// TODO ... this is clearly dirty, but transitional .... fixme with history wide
// meaningful ops, since this all assumes comparing vcounter_t values only

/* =============================================================================
 * ROUTINES: MINIMUM DETECTION 
 * =============================================================================
 */

/* Subroutine to find the minimum of a set of contiguous array elements.
 * Finds minimum between j and i inclusive,  j<=i .
 * Does NOT change array elements.
 * Returns index of minimal element.
 * - This version is for 64 bit integers, as needed for RTT times.
 * - i, j, and ind_curr are true indices. They are circularly mapped into 
 *   the array x of length lenx.  It is up to the calling function to ensure
 *   that the values needed are still in the array.
 */
//index_t history_min(vcounter_t *x, index_t j, index_t i, index_t lenx)
index_t history_min(history *hist, index_t j, index_t i)
{
   /* current minimum found and  corresponding index */
	vcounter_t  *min_curr;
	vcounter_t  *tmp;
	index_t  ind_curr;

	if ( i < j ) {
		verbose(LOG_ERR,"Error in history_min,  index range bad, j= %u, i= %u", j,i);
	}

	/* initialise */
//	min_curr = hist->buffer[j % hist->buffer_sz];
	min_curr = (vcounter_t*) history_find(hist, j);  
	ind_curr = j;

	/* if i<=j, already done */
	while ( j < i ) {
		j++;
		//if ( hist->buffer[j % hist->buffer_sz] < min_curr )
		tmp = (vcounter_t*) history_find(hist, j);  
		if ( *tmp < *min_curr )
		{
		//	min_curr = hist->buffer[j % hist->buffer_sz];
			min_curr = tmp;
			ind_curr = j;
		}
	}
	return ind_curr;
}

  
/* Subroutine to find the minimum of a number and a set of contiguous array elements.
 * Array elements given between j and i inclusive,  j<=i
 * Does NOT change array elements.
 * Specialized to efficiently find a minimum of a continuously sliding window over an array.
 * Window slides by 1:  old element j is dropped in favor of new element at i+1 .
 * This version takes the index of the current minimum and returns the new index.
 * - This version is for 64 bit integers, as needed for RTT times.
 * - i, j, and ind_curr are true indices. They are circularly mapped into 
 *   the array x of length lenx.  It is up to the calling function to ensure
 *   that the values needed are still in the array.
 */
index_t history_min_slide(history *hist, index_t index_curr,  index_t j, index_t i)
{
	vcounter_t *tmp_curr;
	vcounter_t *tmp;

	if ( i < j ) {
		verbose(LOG_ERR,"Error in min_slide, window width less than 1: %u %u %u", j,i,i-j+1);
		return i+1;
	}
	/* window only 1 wide anyway, easy */
	if (i == j)
		return i+1;
	/* new one is new min */
//	if ( x[(i+1)%lenx] < x[index_curr%lenx] )
	tmp = history_find(hist, i+1);
	tmp_curr = history_find(hist, index_curr);
	if ( *tmp < *tmp_curr )
		return i+1;
	/* one being dropped was min, must do work */
	if (j == index_curr)
		return history_min(hist, j+1, i);
	/* min_curr inside window and still valid, easy */
	return index_curr;
}

/* Version that operates on values rather than indices
 * Must initialise properly, if the min is not in the window, may never be replaced!
 */
vcounter_t history_min_slide_value(history *hist, index_t min_curr, index_t j, index_t i)
{
	vcounter_t *tmp;
	index_t tmp_i;

	if ( i < j ) {
		verbose(LOG_ERR,"Error in min_slide_value, window width less than 1: %u %u %u", j,i,i-j+1);
		return i+1;
	}
	/* window only 1 wide anyway, easy */
	if (i == j)
	{
		tmp = history_find(hist, i+1);
//		return x[(i+1)%lenx];
		return *tmp;
	}
	/* new one is new min */
//	if ( x[(i+1)%lenx] < min_curr)
	tmp = history_find(hist, i+1);
	if ( *tmp < min_curr )
		return *tmp; 
	/* one being dropped was min, must do work */
//	if ( x[j%lenx] == min_curr )
	tmp = history_find(hist, j);
	if ( *tmp == min_curr )
	{
//		return x[history_min(x,j+1,i,lenx)%lenx];
		tmp_i = history_min(hist, j+1, i);
		tmp = history_find(hist, tmp_i);
		return *tmp;
	}
	/* min_curr inside window and still valid, easy */
	return min_curr;
}


