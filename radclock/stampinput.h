/*
 * Copyright (C) 2006-2010 Julien Ridoux <julien@synclab.org>
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


#ifndef _STAMPINPUT_H
#define _STAMPINPUT_H

/**
 * Prototype handle declaration
 */
struct stampsource;


/**
 * Test if the source given as input is unique and a live one
 */
int is_live_source(struct radclock *handle);


/**
 * Create a stamp source from the given config
 * @param anchor the config to create a source from
 * @param is_live will be set to 1 if the source is a live source
 * @returns NULL on error or the handle
 */
struct stampsource *create_source(struct radclock *handle);

/**
 * Get the next stamp
 * 
 * @return 0 on success if stamp was filled
 *  or a negative value on failure.
 */
int get_next_stamp(struct radclock *handle, struct stampsource *source, struct bidir_stamp *stamp);

/**
 * Break inpout loop
 *
 * @param The handler to the input source
 * @return void. Error code given by get_next_stamp function
 */
void source_breakloop(struct radclock *handle, struct stampsource *source);

/**
 * Destroy the source once it's no longer required
 */
void destroy_source(struct radclock *handle, struct stampsource *source);

/**
 * Update the BPF filter for the source 
 */
int update_filter_source(struct radclock *handle, struct stampsource *source);

/**
 * Update the RAW file output for the source 
 */
int update_dumpout_source(struct radclock *handle, struct stampsource *source);

#endif
