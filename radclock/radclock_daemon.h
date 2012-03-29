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

#ifndef _RADCLOCK_DAEMON_H
#define _RADCLOCK_DAEMON_H


#ifdef VC_FMT
#undef VC_FMT
#endif
#if defined (__LP64__) || defined (__ILP64__)
#define VC_FMT "lu"
#else
#define VC_FMT "llu"
#endif



// TODO : should provide methods for modify this? 
typedef enum { RADCLOCK_SYNC_NOTSET, RADCLOCK_SYNC_DEAD, RADCLOCK_SYNC_LIVE } radclock_runmode_t;
typedef enum { RADCLOCK_UNIDIR, RADCLOCK_BIDIR} radclock_syncalgo_mode_t;


struct radclock_handle;

/* (NTP) Protocol related stuff on the client side */
struct radclock_client_data {
	int socket;
	struct sockaddr_in s_to;
	struct sockaddr_in s_from;
};


/**
 * NTP protocol specifics for being a server
 */
// TODO this could be renamed in a more generic network layer data structure in
// the future ...
struct radclock_ntpserver_data {
	int burst;
	uint32_t refid;
	unsigned int stratum;
	double serverdelay; 	/* RTThat to the server we sync to */
	double rootdelay;		/* Cumulative RTThat from top of stratum hierarchy */
	double rootdispersion;	/* Cumulative clock error from top of stratum hierarchy */
};



/*
 * Virtual machine environment data
 * Mode run in, push and pull struct radclock_data
 */
struct radclock_vm
{
	int (*pull_data) (struct radclock_handle *handle);
	int (*push_data) (struct radclock_handle *handle);
	void *store_handle;
	int sock;
	struct sockaddr_in server_addr;
};



struct radclock_handle {

	/* Library radclock structure */
	struct radclock *clock;

	/* Clock data, the real stuff */
	struct radclock_data rad_data;

	/* Clock error estimates */
	struct radclock_error rad_error;

	/* Virtual Machine management */
	struct radclock_vm rad_vm;

	/* Protocol related stuff on the client side (NTP, 1588, ...) */
	struct radclock_client_data *client_data;
	
	/* Protol related stuff (NTP, 1588, ...) */
	struct radclock_ntpserver_data *server_data;
	
	/* Raw data capture buffer */
	struct raw_data_bundle *rdb_start;
	struct raw_data_bundle *rdb_end;

	/* Common data for the daemon */
	int is_daemon;
	radclock_runmode_t 		run_mode;

	/* UNIX signals */
	unsigned int unix_signal;

	/* Output file descriptors */
	FILE* stampout_fd;
	FILE* matout_fd;

	/* Threads */
	pthread_t threads[8];		/* TODO: quite ugly implementation ... */
	int	pthread_flag_stop;
	pthread_mutex_t globaldata_mutex;
	int wakeup_data_ready;
	pthread_mutex_t wakeup_mutex;
	pthread_cond_t wakeup_cond;
	pthread_mutex_t rdb_mutex;	// XXX arbiter between insert_rdb_in_list and free_and_cherry_pick
   								// XXX Should not need a lock, but there is
								// XXX quite some messing around if hammering
								// XXX NTP control packets	

	/* Configuration */
	struct radclock_config *conf;

	/* Algo output */
	radclock_syncalgo_mode_t syncalgo_mode;
	void *algo_output; 	/* Defined as void* since not part of the library */

	/* Stamp source */
	void *stamp_source; /* Defined as void* since not part of the library */

	/* Synchronisation Peers */
	void *active_peer; 	/* Peers are of different nature (bidir, oneway) will cast */
	
};


#define CLIENT_DATA(x) (x->client_data)
#define SERVER_DATA(x) (x->server_data)
#define RAD_DATA(x) (&(x->rad_data))
#define RAD_ERROR(x) (&(x->rad_error))
#define RAD_VM(x) (&(x->rad_vm))

#define ADD_STATUS(x,y) (RAD_DATA(x)->status = RAD_DATA(x)->status | y ) 
#define DEL_STATUS(x,y) (RAD_DATA(x)->status = RAD_DATA(x)->status & ~y ) 
#define HAS_STATUS(x,y) ((RAD_DATA(x)->status & y ) == y ) 



int init_virtual_machine_mode(struct radclock_handle *handle);

#endif
