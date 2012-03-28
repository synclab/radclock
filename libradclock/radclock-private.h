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

/* 
 * Visible error metrics 
 */ 
struct radclock_error
{
	double error_bound;
	double error_bound_avg;
	double error_bound_std;
	double min_RTT;
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


struct radclock {

	/* System specific stuff */
	union {
		struct radclock_impl_bsd 	bsd_data;
		struct radclock_impl_linux 	linux_data;
	};

	/* IPC shared memory */
	int ipc_shm_id;
	void *ipc_shm;

	/* Description of current counter */
	char hw_counter[32];
	int kernel_version;

	radclock_local_period_t	local_period_mode;

	/* Pcap handler for the RADclock only */
	pcap_t *pcap_handle;
	int tsmode;

	/* Syscalls */
	int syscall_set_ffclock;	/* FreeBSD specific, so far */
	int syscall_get_vcounter;

	/* Read Feed-Forward counter */
	int (*get_vcounter) (struct radclock *handle, vcounter_t *vcount);
};

#define PRIV_USERDATA(x) (&(x->user_data))
#ifdef linux
# define PRIV_DATA(x) (&(x->linux_data))
#else
# define PRIV_DATA(x) (&(x->bsd_data))
#endif


/*
 * IPC using shared memory 
 */
#define RADCLOCK_RUN_DIRECTORY		"/var/run/radclock"
#define IPC_SHARED_MEMORY			( RADCLOCK_RUN_DIRECTORY "/radclock.shm" )


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
int get_kernel_ffclock(struct radclock *clock, struct radclock_data *rad_data);


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
		struct radclock *clock,
		pcap_t *p_handle, 
		const struct pcap_pkthdr *header, 
		const unsigned char *packet,
		vcounter_t *vcount);


int init_virtual_machine_mode(struct radclock *clock_handle);

int radclock_init_vcounter_syscall(struct radclock *handle);
int radclock_init_vcounter(struct radclock *handle);
int radclock_get_vcounter_syscall(struct radclock *handle, vcounter_t *vcount);
int radclock_get_vcounter_rdtsc(struct radclock *handle, vcounter_t *vcount);


#endif
