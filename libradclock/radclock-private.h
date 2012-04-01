/*
 * Copyright (C) 2006-2012 Julien Ridoux <julien@synclab.org>
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

#ifndef _RADCLOCK_PRIVATE_H
#define _RADCLOCK_PRIVATE_H

#include <netinet/in.h>
#include <pcap.h>


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
	int (*get_vcounter) (struct radclock *clock, vcounter_t *vcount);
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
 * System specific call for getting the capture mode on the pcap capture device.
 */
int descriptor_get_tsmode(struct radclock *clock, pcap_t *p_handle, int *kmode);


/**
 * System specific call for setting the capture mode on the pcap capture device.
 */
int descriptor_set_tsmode(struct radclock *clock, pcap_t *p_handle, int kmode);


/**
 * System specific call for getting the capture mode on the pcap capture device.
 */
int extract_vcount_stamp(
		struct radclock *clock,
		pcap_t *p_handle, 
		const struct pcap_pkthdr *header, 
		const unsigned char *packet,
		vcounter_t *vcount);

int radclock_init_vcounter_syscall(struct radclock *clock);
int radclock_init_vcounter(struct radclock *clock);
int radclock_get_vcounter_syscall(struct radclock *clock, vcounter_t *vcount);
int radclock_get_vcounter_rdtsc(struct radclock *clock, vcounter_t *vcount);

int has_vm_vcounter(struct radclock *clock);
int init_kernel_clock(struct radclock *clock_handle);

int shm_init_writer(struct radclock *clock);
int shm_detach(struct radclock *clock);


static inline void 
counter_to_time(struct radclock_data *rad_data, vcounter_t *vcount, long double *time)
{
	vcounter_t last;

	do {
		/* Quality ingredients */
		last  = rad_data->last_changed;
		*time = *vcount * (long double)rad_data->phat + rad_data->ca;
		*time += (*vcount - last) * (long double)rad_data->phat_local -
			rad_data->phat;
	} while (last != rad_data->last_changed);
}


#endif
