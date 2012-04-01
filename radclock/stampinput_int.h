/*
 * Copyright (C) 2006-2012, Julien Ridoux <julien@synclab.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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

#ifndef _STAMPINPUT_INT_H
#define _STAMPINPUT_INT_H

#define INPUT_OPS(x) x->def

/*
 * Private stamp source definiton
 * All fields compulsary
 */
struct stampsource_def
{
	/* Initialise the source */
	int (*init)(struct radclock_handle *handle, struct stampsource *source);

	/* Get the next stamp, return 0 on sucess */
	int (*get_next_stamp)(struct radclock_handle *handle,
			struct stampsource *source, struct stamp_t *stamp);

	/* Break blocking loop getting packets */
	void (*source_breakloop)(struct radclock_handle *handle,
		   	struct stampsource *source);
	
	/* Clean up */
	void (*destroy)(struct radclock_handle *handle, struct stampsource *source);

	/* Update source BPF filter */
	int (*update_filter)(struct radclock_handle *handle,
			struct stampsource *source);

	/* Update source RAW file dump out */
	int (*update_dumpout)(struct radclock_handle *handle,
			struct stampsource *source);
};

struct stampsource
{
	/* Sources may use this pointer to store any data */
	void *priv_data;

	/* The current definition. Sources shouldn't need to touch this */
	struct stampsource_def *def;

	struct timeref_stats ntp_stats;
};

#endif
