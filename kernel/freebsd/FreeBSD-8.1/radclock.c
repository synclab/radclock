/*
 * System calls to access the cumulative virtual timecounter
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/sysproto.h>
#include <sys/bus.h>


/*
 * First system call is get_vcounter to retrieve the current value
 * of the cumulative vritual counter from the timecounter interface
 */

struct get_vcounter_args {
	vcounter_t *vcount;
};

static int
get_vcounter(struct proc *td, void *syscall_args)
{
	vcounter_t vcount = 0;
	int error = 0;
	struct get_vcounter_args *uap;

	uap = (struct get_vcounter_args *) syscall_args;
	if ( uap->vcount == NULL )
		return -1;
	
	vcount = read_vcounter();
	error = copyout(&vcount, uap->vcount, sizeof(vcounter_t));
	
	if ( vcount == 0 ) 
		error = -1;

	return(error);
}


static struct sysent get_vcounter_sysent = {
	1,
	(sy_call_t *) get_vcounter,
	AUE_NULL, 
	NULL, 
	0, 
	0 
};


static int get_vcounter_offset = NO_SYSCALL;

static int
get_vcounter_load (struct module *module, int cmd, void *arg)
{
	int error = 0;
	switch (cmd) {
		case MOD_LOAD :
			printf("get_vcounter syscall loaded at %d \n", get_vcounter_offset);
		break;
		case MOD_UNLOAD :
			printf("get_vcounter syscall unloaded from %d\n", get_vcounter_offset);
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
//SYSCALL_MODULE(get_vcounter, &get_vcounter_offset, &get_vcounter_sysent, get_vcounter_load, NULL);

static struct syscall_module_data get_vcounter_syscall_mod = {
	get_vcounter_load,
	NULL,
	&get_vcounter_offset,
	&get_vcounter_sysent,
	{ 0, NULL, AUE_NULL}
};

static moduledata_t get_vcounter_mod = {
	"get_vcounter",
	syscall_module_handler,
	&get_vcounter_syscall_mod
};

DECLARE_MODULE(get_vcounter, get_vcounter_mod, SI_SUB_SYSCALLS, SI_ORDER_MIDDLE);




/*
 * Second system call is get_vcounter_latency to compute the latency of
 * the timecounter interface from within the kernel
 *
 * XXX: of course this makes sense ONLY if we have a stable TSC
 * (i.e. no SMP, no power management, no frequency jumps etc.) 
 */

struct get_vcounter_latency_args {
	vcounter_t *vcount;
	uint64_t *vcount_lat;
	uint64_t *tsc_lat;
};

static int
get_vcounter_latency(struct proc *td, void *syscall_args)
{
	uint64_t tsc1 = 0, tsc2 = 0, tsc3 = 0, vcount_lat = 0, tsc_lat = 0;
	vcounter_t vcount;
	int error = 0;
	struct get_vcounter_latency_args *uap;

	uap = (struct get_vcounter_latency_args *) syscall_args;

	/* One for fun and warmup */
	tsc1 = rdtsc();
	__asm __volatile("lfence" ::: "memory");
	tsc1 = rdtsc();
	__asm __volatile("lfence" ::: "memory");
	tsc2 = rdtsc();
	__asm __volatile("lfence" ::: "memory");
	vcount = read_vcounter();
	__asm __volatile("lfence" ::: "memory");
	tsc3 = rdtsc();
	__asm __volatile("lfence" ::: "memory");

	tsc_lat = tsc2 - tsc1;
	vcount_lat = tsc3 - tsc2;

	error += copyout(&vcount, uap->vcount, sizeof(vcounter_t));
	error += copyout(&vcount_lat, uap->vcount_lat, sizeof(uint64_t));
	error += copyout(&tsc_lat, uap->tsc_lat, sizeof(uint64_t));

	return(error);
}


static struct sysent get_vcounter_latency_sysent = {
	3,
	(sy_call_t *) get_vcounter_latency,
	AUE_NULL, 
	NULL, 
	0, 
	0 
};


static int get_vcounter_latency_offset = NO_SYSCALL;

static int
get_vcounter_latency_load (struct module *module, int cmd, void *arg)
{
	int error = 0;
	switch (cmd) {
		case MOD_LOAD :
			printf("get_vcounter_latency syscall loaded at %d \n", get_vcounter_latency_offset);
		break;
		case MOD_UNLOAD :
			printf("get_vcounter_latency syscall unloaded from %d\n", get_vcounter_latency_offset);
		break;
		default :
			error = EINVAL;
		break;
	}
	return error;
}

/* See comment above for use of SYSCALL_MODULE before 8.1 */
//SYSCALL_MODULE(get_vcounter_latency, &get_vcounter_latency_offset, &get_vcounter_latency_sysent, get_vcounter_latency_load, NULL);

static struct syscall_module_data get_vcounter_latency_syscall_mod = {
	get_vcounter_latency_load,
	NULL,
	&get_vcounter_latency_offset,
	&get_vcounter_latency_sysent,
	{ 0, NULL, AUE_NULL}
};

static moduledata_t get_vcounter_latency_mod = {
	"get_vcounter_latency",
	syscall_module_handler,
	&get_vcounter_latency_syscall_mod
};

DECLARE_MODULE(get_vcounter_latency, get_vcounter_latency_mod, SI_SUB_SYSCALLS, SI_ORDER_MIDDLE);



