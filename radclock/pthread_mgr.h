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


#ifndef _PTHREAD_MGR_H
#define _PTHREAD_MGR_H


/* Pthread description for their IDs
 * Check we have enough space allocated in radclock structure
 * for the pthread IDs
 */
#define PTH_IPC_SERV	0
#define PTH_DATA_PROC	1
#define PTH_TRIGGER		2
#define PTH_FIXEDPOINT	3
#define PTH_NTP_SERV	4


/**
 * Flags to signal threads they have to commit suicide
 */
#define PTH_IPC_SERV_STOP	0x00001
#define PTH_DATA_PROC_STOP	0x00010
#define PTH_TRIGGER_STOP	0x00100
#define PTH_FIXEDPOINT_STOP	0x01000
#define PTH_NTP_SERV_STOP	0x10000
#define PTH_STOP_ALL		(PTH_IPC_SERV_STOP|PTH_DATA_PROC_STOP|PTH_TRIGGER_STOP|PTH_FIXEDPOINT_STOP|PTH_NTP_SERV_STOP)


/**
 *  Threads starters
 */
int start_thread_IPC_SERV(struct radclock *clock_handle);
int start_thread_DATA_PROC(struct radclock *clock_handle);
int start_thread_TRIGGER(struct radclock *clock_handle);
int start_thread_FIXEDPOINT(struct radclock *clock_handle);
int start_thread_NTP_SERV(struct radclock *clock_handle);


/**
 * Threads starters init functions
 */
void* thread_data_processing(void *c_handle);
void* thread_trigger(void *c_handle);
void* thread_ipc_server(void *c_handle);
void* thread_ntp_server(void *c_handle);

int trigger_work(struct radclock *clock_handle); 
int process_rawdata(struct radclock *clock_handle, struct bidir_peer *peer);


/**
 * Threads initialisation
 */
void init_thread_signal_mgt();
int trigger_init(struct radclock *clock_handle);


#endif
