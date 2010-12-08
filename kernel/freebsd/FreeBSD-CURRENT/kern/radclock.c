/*-
 * Copyright (C) 2010 University of Melbourne
 * All rights reserved.
 *
 * This software was developed by the University of Melbourne under sponsorship from
 * the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


/*
 * System calls to access the cumulative virtual timecounter
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/sysproto.h>
#include <sys/bus.h>
#include <sys/sysctl.h>


extern struct feedforward_clock ffclock;

static struct mtx ffclock_mtx;	/* lock against concurrent updates of the ffclock estimates */

/*
 * Sysctl
 */
static int ffclock_version = 2;

SYSCTL_NODE(_kern, OID_AUTO, ffclock, CTLFLAG_RW, 0, "Feed-Forward Clock Support");
SYSCTL_INT(_kern_ffclock, OID_AUTO, version, CTLFLAG_RD, &ffclock_version, 0, "Version of Feed-Forward Clock Support");


/*
 * First system call is get_ffcounter to retrieve the current value
 * of the cumulative vritual counter from the timecounter interface
 */

struct get_ffcounter_args {
	ffcounter_t *ffcounter;
};

static int
get_ffcounter(struct proc *td, void *syscall_args)
{
	ffcounter_t ffcounter = 0;
	int error = 0;
	struct get_ffcounter_args *uap;

	uap = (struct get_ffcounter_args *) syscall_args;
	if ( uap->ffcounter == NULL )
		return -1;
	
	ffcounter = read_ffcounter();
	error = copyout(&ffcounter, uap->ffcounter, sizeof(ffcounter_t));
	
	if ( ffcounter == 0 ) 
		error = -1;

	return(error);
}


static struct sysent get_ffcounter_sysent = {
	1,
	(sy_call_t *) get_ffcounter,
	AUE_NULL, 
	NULL, 
	0, 
	0 
};


static int get_ffcounter_offset = NO_SYSCALL;

static int
get_ffcounter_load (struct module *module, int cmd, void *arg)
{
	int error = 0;
	switch (cmd) {
		case MOD_LOAD :
			printf("get_ffcounter syscall loaded at %d \n", get_ffcounter_offset);
		break;
		case MOD_UNLOAD :
			printf("get_ffcounter syscall unloaded from %d\n", get_ffcounter_offset);
		break;
		default :
			error = EINVAL;
		break;
	}
	return error;
}

/*
 * XXX we used to call SYSCALL_MODULE to help us with declaring the modules.
 * Starting with FreeBSD 8.1, the module name was prepended with "sys/" in the
 * moduledata_t structure. To avoid yet another naming issues, we do
 * SYSCALL_MODULE's work instead and overwrite this convention.
 * See /usr/src/sys/sys/sysent.h for the details.
 *
 * Hopefully, this will disappear once we go mainstream
 */
//SYSCALL_MODULE(get_ffcounter, &get_ffcounter_offset, &get_ffcounter_sysent, get_ffcounter_load, NULL);

static struct syscall_module_data get_ffcounter_syscall_mod = {
	get_ffcounter_load,
	NULL,
	&get_ffcounter_offset,
	&get_ffcounter_sysent,
	{ 0, NULL, AUE_NULL}
};

static moduledata_t get_ffcounter_mod = {
	"get_ffcounter",
	syscall_module_handler,
	&get_ffcounter_syscall_mod
};

DECLARE_MODULE(get_ffcounter, get_ffcounter_mod, SI_SUB_SYSCALLS, SI_ORDER_MIDDLE);




/*
 * Second system call is get_ffcounter_latency to compute the latency of
 * the timecounter interface from within the kernel
 *
 * XXX: of course this makes sense ONLY if we have a stable TSC
 * (i.e. no SMP, no power management, no frequency jumps etc.) 
 */

struct get_ffcounter_latency_args {
	ffcounter_t *ffcounter;
	uint64_t *ffcounter_lat;
	uint64_t *tsc_lat;
};

static int
get_ffcounter_latency(struct proc *td, void *syscall_args)
{
	uint64_t tsc1 = 0, tsc2 = 0, tsc3 = 0, ffcounter_lat = 0, tsc_lat = 0;
	ffcounter_t ffcounter;
	int error = 0;
	struct get_ffcounter_latency_args *uap;

	uap = (struct get_ffcounter_latency_args *) syscall_args;

	/* One for fun and warmup */
	tsc1 = rdtsc();
	__asm __volatile("lfence" ::: "memory");
	tsc1 = rdtsc();
	__asm __volatile("lfence" ::: "memory");
	tsc2 = rdtsc();
	__asm __volatile("lfence" ::: "memory");
	ffcounter = read_ffcounter();
	__asm __volatile("lfence" ::: "memory");
	tsc3 = rdtsc();
	__asm __volatile("lfence" ::: "memory");

	tsc_lat = tsc2 - tsc1;
	ffcounter_lat = tsc3 - tsc2;

	error += copyout(&ffcounter, uap->ffcounter, sizeof(ffcounter_t));
	error += copyout(&ffcounter_lat, uap->ffcounter_lat, sizeof(uint64_t));
	error += copyout(&tsc_lat, uap->tsc_lat, sizeof(uint64_t));

	return(error);
}


static struct sysent get_ffcounter_latency_sysent = {
	3,
	(sy_call_t *) get_ffcounter_latency,
	AUE_NULL, 
	NULL, 
	0, 
	0 
};


static int get_ffcounter_latency_offset = NO_SYSCALL;

static int
get_ffcounter_latency_load (struct module *module, int cmd, void *arg)
{
	int error = 0;
	switch (cmd) {
		case MOD_LOAD :
			printf("get_ffcounter_latency syscall loaded at %d \n", get_ffcounter_latency_offset);
		break;
		case MOD_UNLOAD :
			printf("get_ffcounter_latency syscall unloaded from %d\n", get_ffcounter_latency_offset);
		break;
		default :
			error = EINVAL;
		break;
	}
	return error;
}

/* See comment above for use of SYSCALL_MODULE before 8.1 */
//SYSCALL_MODULE(get_ffcounter_latency, &get_ffcounter_latency_offset, &get_ffcounter_latency_sysent, get_ffcounter_latency_load, NULL);

static struct syscall_module_data get_ffcounter_latency_syscall_mod = {
	get_ffcounter_latency_load,
	NULL,
	&get_ffcounter_latency_offset,
	&get_ffcounter_latency_sysent,
	{ 0, NULL, AUE_NULL}
};

static moduledata_t get_ffcounter_latency_mod = {
	"get_ffcounter_latency",
	syscall_module_handler,
	&get_ffcounter_latency_syscall_mod
};

DECLARE_MODULE(get_ffcounter_latency, get_ffcounter_latency_mod, SI_SUB_SYSCALLS, SI_ORDER_MIDDLE);




/*
 * System call to push clock parameters to the kernel 
 */

struct set_ffclock_args {
	struct ffclock_data *cdata;
};


/*
 * Adjust the ffclock by writing down the clock estimates passed from userland.
 * Hold ffclock_mtx to prevent several instances to update concurrently,
 * essentially to protect from user's bad practice.
 * update_ffclock() may bump the generation number without us knowing. 
 *
 * XXX update comment to reflect what the code does.
 * mention that updates are acted upon during tc_windup, leading to a delay <= 1/HZ
 */
static int set_ffclock(struct proc *td, void *syscall_args)
{
	int error = 0;
	struct set_ffclock_args *uap;

	uap = (struct set_ffclock_args *) syscall_args;
	if ( uap->cdata == NULL )
		return -1;

	mtx_lock(&ffclock_mtx);
	error = copyin(uap->cdata, &(ffclock.ucest->cdata), sizeof(struct ffclock_data));
	ffclock.updated = 1;
	mtx_unlock(&ffclock_mtx);

	return(error);
}


static struct sysent set_ffclock_sysent = {
	1,
	(sy_call_t *) set_ffclock,
	AUE_NULL, 
	NULL, 
	0, 
	0 
};


static int set_ffclock_offset = NO_SYSCALL;

static int
set_ffclock_load (struct module *module, int cmd, void *arg)
{
	int error = 0;
	switch (cmd) {
		case MOD_LOAD :
			mtx_init(&ffclock_mtx, "ffclock lock", NULL, MTX_DEF);
			printf("set_ffclock syscall loaded at %d \n", set_ffclock_offset);
		break;
		case MOD_UNLOAD :
			mtx_destroy(&ffclock_mtx);
			printf("set_ffclock syscall unloaded from %d\n", set_ffclock_offset);
		break;
		default :
			error = EINVAL;
		break;
	}
	return error;
}

/*
 * XXX we used to call SYSCALL_MODULE to help us with declaring the modules.
 * Starting with FreeBSD 8.1, the module name was prepended with "sys/" in the
 * moduledata_t structure. To avoid yet another naming issues, we do
 * SYSCALL_MODULE's work instead and overwrite this convention.
 * See /usr/src/sys/sys/sysent.h for the details.
 *
 * Hopefully, this will disappear once we go mainstream
 */
//SYSCALL_MODULE(set_ffclock, &set_ffclock_offset, &set_ffclock_sysent, set_ffclock_load, NULL);

static struct syscall_module_data set_ffclock_syscall_mod = {
	set_ffclock_load,
	NULL,
	&set_ffclock_offset,
	&set_ffclock_sysent,
	{ 0, NULL, AUE_NULL}
};

static moduledata_t set_ffclock_mod = {
	"set_ffclock",
	syscall_module_handler,
	&set_ffclock_syscall_mod
};

DECLARE_MODULE(set_ffclock, set_ffclock_mod, SI_SUB_SYSCALLS, SI_ORDER_MIDDLE);


