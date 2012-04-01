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

#ifndef _STAMPINPUT_H
#define _STAMPINPUT_H

/**
 * Prototype handle declaration
 */
struct stampsource;


/**
 * Test if the source given as input is unique and a live one
 */
int is_live_source(struct radclock_handle *handle);


/**
 * Create a stamp source from the given config
 * @param anchor the config to create a source from
 * @param is_live will be set to 1 if the source is a live source
 * @returns NULL on error or the handle
 */
struct stampsource *create_source(struct radclock_handle *handle);

/**
 * Get the next stamp
 *
 * @return 0 on success if stamp was filled
 *  or a negative value on failure.
 */
int get_next_stamp(struct radclock_handle *handle, struct stampsource *source,
struct stamp_t *stamp);

/**
 * Break inpout loop
 *
 * @param The handler to the input source
 * @return void. Error code given by get_next_stamp function
 */
void source_breakloop(struct radclock_handle *handle, struct stampsource *source);

/**
 * Destroy the source once it's no longer required
 */
void destroy_source(struct radclock_handle *handle, struct stampsource *source);

/**
 * Update the BPF filter for the source 
 */
int update_filter_source(struct radclock_handle *handle, struct stampsource *source);

/**
 * Update the RAW file output for the source 
 */
int update_dumpout_source(struct radclock_handle *handle, struct stampsource *source);

#endif
