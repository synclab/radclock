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


#ifndef _RADCLOCK_PRIVATE_H
#define _RADCLOCK_PRIVATE_H

#include <netinet/in.h>
#include <pthread.h>
#include <pcap.h>


/* Defines bound on SKM scale. A bit redundant with other defines but easy to
 * fix if needed.
 */
#define OUT_SKM	1024

#define	RAD_MINPOLL	1		/* min poll interval (s) */
#define	RAD_MAXPOLL	1024	/* max poll interval (s) */


// TODO : should provide methods for modify this? 
typedef enum { RADCLOCK_SYNC_NOTSET, RADCLOCK_SYNC_DEAD, RADCLOCK_SYNC_LIVE } radclock_runmode_t;
typedef enum { RADCLOCK_IPC_CLIENT, RADCLOCK_IPC_SERVER, RADCLOCK_IPC_NONE} radclock_IPC_mode_t;
typedef enum { RADCLOCK_UNIDIR, RADCLOCK_BIDIR} radclock_syncalgo_mode_t;


/* Data related to the clock maintain out of the kernel but
 * specific to FreeBSD
 */
struct radclock_impl_bsd
{
	int dev_fd;
};

struct radclock_impl_linux {
	int radclock_gnl_id;
};


/* Protocol related stuff on the client side */
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



/**
 * Structure representing the radclock parameters
 */
struct radclock_data {
	double phat;
	double phat_err;
	double phat_local;
	double phat_local_err;
	long double ca;
	double ca_err;
	unsigned int status;
	vcounter_t last_changed;
	vcounter_t valid_till;
};

/* TODO: split it in 2, clock errors and peer clock tracking, recompose with
 * others for per peer algo
 */ 
struct radclock_error
{
	double error_bound;
	double error_bound_avg;
	double error_bound_std;
	double min_RTT;
	// ---------------- //
	double Ebound_min_last;
	long nerror;
	double cumsum;
	double sq_cumsum;
	long nerror_hwin;
	double cumsum_hwin;
	double sq_cumsum_hwin;
};

/*
 * Structure representing radclock data and exposed to system processes via IPC
 * shared memory.
 */
struct radclock_shm {
	int version;
	int status;
	int clockid;
	unsigned int gen;
	size_t data_off;
	size_t data_off_old;
	size_t error_off;
	size_t error_off_old;
	struct radclock_data bufdata[2];
	struct radclock_error buferr[2];
};

#define SHM_DATA(x)		((struct radclock_data *)((void *)x + x->data_off))
#define SHM_ERROR(x)	((struct radclock_error *)((void *)x + x->error_off))


/*
 * Virtual machine environment data
 * Mode run in, push and pull struct radclock_data
 */
struct radclock_vm
{
	int (*pull_data) (struct radclock *clock_handle);
	int (*push_data) (struct radclock *clock_handle);
	void *store_handle;
	int sock;
	struct sockaddr_in server_addr;
};



struct radclock 
{
	/* Clock data, the real stuff */
	struct radclock_data rad_data;

	/* Clock error estimates */
	struct radclock_error rad_error;

	/* Virtual Machine management */
	struct radclock_vm rad_vm;

	/* System specific stuff */
	union {
		struct radclock_impl_bsd 	bsd_data;
		struct radclock_impl_linux 	linux_data;
	};
	int kernel_version;

	/* UNIX signals */
	unsigned int unix_signal;

	/* Common data for the daemon */
	// TODO some cleanup in this
	int is_daemon;
	int ipc_socket;
	char *ipc_socket_path;
	radclock_autoupdate_t 	autoupdate_mode;
	radclock_local_period_t	local_period_mode;
	radclock_runmode_t 		run_mode;
	radclock_IPC_mode_t 	ipc_mode;

	/* Protocol related stuff on the client side (NTP, 1588, ...) */
	struct radclock_client_data *client_data;
	
	/* Protol related stuff (NTP, 1588, ...) */
	struct radclock_ntpserver_data *server_data;
	
	/* IPC socket and shared memory */
	int ipc_requests;	// request bound. TODO cleanup?
	int ipc_shm_id;
	void *ipc_shm;

	/* Description of current counter */
	char hw_counter[32];

	/* Pcap handler for the RADclock only */
	pcap_t *pcap_handle;

	/* Syscalls */
	int syscall_set_ffclock;	/* FreeBSD specific, so far */
	int syscall_get_vcounter;

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

	/* Raw data capture buffer */
	struct raw_data_bundle *rdb_start;
	struct raw_data_bundle *rdb_end;

	/* Configuration */
	struct radclock_config *conf;

	/* Algo output */
	radclock_syncalgo_mode_t syncalgo_mode;
	void *algo_output; 	/* Defined as void* since not part of the library */

	/* Stamp source */
	void *stamp_source; /* Defined as void* since not part of the library */

	/* Synchronisation Peers */
	void *active_peer; 	/* Peers are of different nature (bidir, oneway) will cast */
	
	/* Read Feed-Forward counter */
	int (*get_vcounter) (struct radclock *handle, vcounter_t *vcount);
};


#define CLIENT_DATA(x) (x->client_data)
#define SERVER_DATA(x) (x->server_data)
#define RAD_DATA(x) (&(x->rad_data))
#define RAD_ERROR(x) (&(x->rad_error))
#define RAD_VM(x) (&(x->rad_vm))

#define PRIV_USERDATA(x) (&(x->user_data))
#ifdef linux
# define PRIV_DATA(x) (&(x->linux_data))
#else
# define PRIV_DATA(x) (&(x->bsd_data))
#endif

#define ADD_STATUS(x,y) (RAD_DATA(x)->status = RAD_DATA(x)->status | y ) 
#define DEL_STATUS(x,y) (RAD_DATA(x)->status = RAD_DATA(x)->status & ~y ) 
#define HAS_STATUS(x,y) ((RAD_DATA(x)->status & y ) == y ) 


/* IPC using datagram UNIX sockets
 * Types and messages for communication with the thread serving global data 
 * We can imagine several messages in the future ...
 */
// TODO: somewhere else if not running as a daemon with root access?

/* Socket for IPC used by the gb_pthread */
#define RADCLOCK_RUN_DIRECTORY		"/var/run/radclock"
#define IPC_SHARED_MEMORY			( RADCLOCK_RUN_DIRECTORY "/radclock.shm" )
#define IPC_SOCKET_SERVER			( RADCLOCK_RUN_DIRECTORY "/radclock.socket" )
#define IPC_SOCKET_CLIENT			"/tmp/radclock-client"

#define IPC_MAGIC_NUMBER		31051978
#define IPC_REQ_RAD_DATA		1
#define IPC_REQ_RAD_ERROR		2

struct ipc_request {
	unsigned int magic_number;
	unsigned int request_type;
};

struct ipc_reply {
	unsigned int reply_type;
	union {
		struct radclock_data rad_data;
		struct radclock_error rad_error;
	};
};



/**
 * Detect possible kernel support for the RADclock prior initialisation 
 * @return The run mode the clock should be initialise to 
 */
int found_ffwd_kernel_version(void);


/**
 * Retrieves clock estimates from the kernel 
 * @param  handle The private handle for accessing global data
 * @return 0 on success, non-zero on failure
 */
int get_kernel_ffclock(struct radclock *handle);


/**
 * Check if the parameters in the userland clock handle are outdated and update
 * them if it is the case.
 * The outdated criterion relies on the comparison of the vcount stamps stored in
 * the global data structure.
 * @param  handle The private handle for accessing global data
 * @param  vc A pointer to the current timestamp, or NULL 
 * @param  req_type Type of IPC request 
 * @return 0 on success, non-zero on failure
 */ 
int radclock_check_outdated(struct radclock *handle, vcounter_t *vc, int req_type);


/* TODO add comments */
int raddata_quality(vcounter_t now, vcounter_t last, vcounter_t valid, double phat);


/**
 * System specific call for getting the capture mode on the pcap capture device.
 */
int descriptor_get_tsmode(struct radclock *handle, pcap_t *p_handle, int *kmode);


/**
 * System specific call for setting the capture mode on the pcap capture device.
 */
int descriptor_set_tsmode(struct radclock *handle, pcap_t *p_handle, int kmode);


/**
 * System specific call for getting the capture mode on the pcap capture device.
 */
int extract_vcount_stamp(
		pcap_t *p_handle, 
		const struct pcap_pkthdr *header, 
		const unsigned char *packet,
		vcounter_t *vcount);

// FIXME: try to get rid of this via, function pointer
int
extract_vcount_stamp_v2( pcap_t *p_handle, const struct pcap_pkthdr *header,
	const unsigned char *packet, vcounter_t *vcount);




int init_virtual_machine_mode(struct radclock *clock_handle);

int radclock_init_vcounter_syscall(struct radclock *handle);
int radclock_init_vcounter(struct radclock *handle);
int radclock_get_vcounter_syscall(struct radclock *handle, vcounter_t *vcount);
int radclock_get_vcounter_rdtsc(struct radclock *handle, vcounter_t *vcount);


#endif
