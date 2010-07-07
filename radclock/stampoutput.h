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


#ifndef _STAMPOUTPUT_H
#define _STAMPOUTPUT_H
/*
 * Exported functions
 */



int open_output_stamp(struct radclock *clock_handle) ;
void close_output_stamp(struct radclock *clock_handle) ;

int open_output_matlab(struct radclock *clock_handle) ;
void close_output_matlab(struct radclock *clock_handle) ;

void print_out_files(struct radclock *clock_handle, struct bidir_stamp *tuple) ;




#endif
