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

#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "../config.h"
#include "radclock.h"
#include "radclock-private.h"

#include "radclock_daemon.h"

#include "sync_history.h"
#include "sync_algo.h"
#include "config_mgr.h"
#include "verbose.h"
#include "create_stamp.h"
#include "stampinput.h"
#include "stampinput_int.h"
#include "rawdata.h"
#include "jdebug.h"


static int
spystamp_init(struct radclock_handle *handle, struct stampsource *source)
{
	verbose(LOG_NOTICE, "Reading live from spy source");
	source->priv_data = NULL;
	return (0);
}



static int
spystamp_get_next(struct radclock_handle *handle, struct stampsource *source,
	struct stamp_t *stamp)
{
	int err;

	JDEBUG

	err = deliver_rawdata_spy(handle, stamp);
	if (err < 0) {
		/* Signals empty buffer */
		return (err);
	}
	stamp->type = STAMP_SPY;
	stamp->qual_warning = 0;
	source->ntp_stats.ref_count += 2;

	return (0);
}



static void
spystamp_breakloop(struct radclock_handle *handle, struct stampsource *source)
{
	/*
	 * Used to exit the capture loop if a signal has been caught.
	 */
	return;
}


static void
spystamp_finish(struct radclock_handle *handle, struct stampsource *source)
{
	/* Nothing to close */
}


static int
spystamp_update_filter(struct radclock_handle *handle, struct stampsource *source)
{
	/* So far nothing to do */
	return (0);
}


static int
spystamp_update_dumpout(struct radclock_handle *handle, struct stampsource *source)
{
	/* So far nothing to do */
	return (0);
}


struct stampsource_def spy_source =
{
	.init 				= spystamp_init,
	.get_next_stamp 	= spystamp_get_next,
	.source_breakloop 	= spystamp_breakloop,
	.destroy 			= spystamp_finish,
	.update_filter  	= spystamp_update_filter,
	.update_dumpout 	= spystamp_update_dumpout,
};

