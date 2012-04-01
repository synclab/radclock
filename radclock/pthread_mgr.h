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

#ifndef _PTHREAD_MGR_H
#define _PTHREAD_MGR_H


/* Pthread description for their IDs
 * Check we have enough space allocated in radclock structure
 * for the pthread IDs
 */
#define PTH_NONE		0
#define PTH_DATA_PROC	1
#define PTH_TRIGGER		2
#define PTH_NTP_SERV	3
#define PTH_FIXEDPOINT	4


/**
 * Flags to signal threads they have to commit suicide
 */
#define PTH_DATA_PROC_STOP	0x00001
#define PTH_TRIGGER_STOP	0x00010
#define PTH_NTP_SERV_STOP	0x00100
#define PTH_FIXEDPOINT_STOP	0x01000
#define PTH_STOP_ALL		(PTH_DATA_PROC_STOP|PTH_TRIGGER_STOP|PTH_FIXEDPOINT_STOP|PTH_NTP_SERV_STOP)


/**
 *  Threads starters
 */
int start_thread_DATA_PROC(struct radclock_handle *handle);
int start_thread_TRIGGER(struct radclock_handle *handle);
int start_thread_NTP_SERV(struct radclock_handle *handle);
int start_thread_FIXEDPOINT(struct radclock_handle *handle);


/**
 * Threads starters init functions
 */
void* thread_data_processing(void *c_handle);
void* thread_trigger(void *c_handle);
void* thread_ntp_server(void *c_handle);

int trigger_work(struct radclock_handle *handle); 
int process_rawdata(struct radclock_handle *handle, struct bidir_peer *peer);


/**
 * Threads initialisation
 */
void init_thread_signal_mgt();
int trigger_init(struct radclock_handle *handle);


#endif
