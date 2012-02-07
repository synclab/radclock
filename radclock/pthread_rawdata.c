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


#include <string.h>
#include <math.h>
#include <syslog.h>
#include <time.h>

#include "../config.h"
#include "sync_algo.h"
#include "radclock.h"
#include "radclock-private.h"
#include "ffclock.h"
#include "fixedpoint.h"
#include "misc.h"
#include "verbose.h"
#include "proto_ntp.h"
#include "stampinput.h"
#include "stampoutput.h"
#include "config_mgr.h"
#include "pthread_mgr.h"
#include "jdebug.h"

#include <sys/sysctl.h>		// TODO remove when pushing sysctl code within arch specific code


#ifdef WITH_RADKERNEL_NONE
int update_system_clock(struct radclock *clock_handle) { return 0; }
#else

#ifdef WITH_RADKERNEL_FBSD
#include <sys/timex.h>
#define NTP_ADJTIME(x)	ntp_adjtime(x)
#endif

#ifdef WITH_RADKERNEL_LINUX
#include <sys/timex.h>
#define NTP_ADJTIME(x)	adjtimex(x)
#endif

#ifndef SHIFT_USEC
#define SHIFT_USEC 16
#endif

/* Make TIME_CONSTANT smaller for faster convergence but keep diff between nano
 * and not nano = 4
 */
#ifdef STA_NANO
#define KERN_RES	1e9
#define TIME_CONSTANT	6
#define TX_MODES	( MOD_OFFSET | MOD_STATUS | MOD_NANO )
#else
#define KERN_RES	1e6
#define TIME_CONSTANT	2
#define TX_MODES	( MOD_OFFSET | MOD_STATUS )
#endif


/*
 * Update IPC shared memory segment.
 * Swap pointers and bump generation number to ensure consistency.
 */
static int
update_ipc_shared_memory(struct radclock *clock)
{
	JDEBUG

	struct radclock_shm *shm;
	size_t offset_tmp;	
	unsigned int generation;

	shm = (struct radclock_shm *) clock->ipc_shm;

	memcpy((void *)shm + shm->data_off_old, &clock->rad_data,
			sizeof(struct radclock_data));
	memcpy((void *)shm + shm->error_off_old, &clock->rad_data,
			sizeof(struct radclock_error));
	generation = shm->gen;

	shm->gen = 0;

	/* Swap current and old buffer offsets in the mapped SHM */
	offset_tmp = shm->data_off;
	shm->data_off = shm->data_off_old;
	shm->data_off_old = offset_tmp;

	offset_tmp = shm->error_off;
	shm->error_off = shm->error_off_old;
	shm->error_off_old = offset_tmp;

	if (generation++ == 0)
		generation = 1;
	shm->gen = generation;

	return (0);
}



/* Report back to back timestamps of RADclock and system clock */
static inline void
read_clocks(struct radclock *clock_handle, struct timeval *sys_tv,
	struct timeval *rad_tv, vcounter_t *counter)
{
	vcounter_t before;
	vcounter_t after;
	long double time;
	int i;

	/*
	 * Make up to 5 attempts to bracket a reading of the system clock. A system
	 * call is in the order of 1-2 mus, here we have 3 of them. Pick up an
	 * (arbitrary) bracket threshold: 5 mus.
	 */
	for (i=0; i<5; i++) {
		radclock_get_vcounter(clock_handle, &before);
		gettimeofday(sys_tv, NULL);
		radclock_get_vcounter(clock_handle, &after);

		if ((after - before) < (5e-6 / RAD_DATA(clock_handle)->phat))
			break;
	}
	verbose(VERB_DEBUG, "System clock read_clocks bracket: "
		"%"VC_FMT" [cycles], %.03f [mus]",
		(after - before),
		(after - before) * RAD_DATA(clock_handle)->phat * 1e6 );

	*counter = (vcounter_t) ((before + after)/2);
	counter_to_time(clock_handle, counter, &time);
	timeld_to_timeval(&time, rad_tv);
}


/* Subtract two timeval */
void
subtract_tv(struct timeval *delta, struct timeval tv1, struct timeval tv2)
{
	int nsec;

	/* Perform the carry */
	if (tv1.tv_usec < tv2.tv_usec) {
		nsec = (tv2.tv_usec - tv1.tv_usec) / 1000000 + 1;
		tv2.tv_usec -= 1000000 * nsec;
		tv2.tv_sec += nsec;
	}
	if (tv1.tv_usec - tv2.tv_usec > 1000000) {
		nsec = (tv1.tv_usec - tv2.tv_usec) / 1000000;
		tv2.tv_usec += 1000000 * nsec;
		tv2.tv_sec -= nsec;
	}

	/* Subtract */ 
	delta->tv_sec = tv1.tv_sec - tv2.tv_sec;
	delta->tv_usec = tv1.tv_usec - tv2.tv_usec;
}


/*	There are a few assumptions on the kernel capabilities, i.e. RFC1589
 *	compatible. Should be fairly safe with recent systems these days.
 *	The code in here is in packets chronological order, could have made it
 *	prettier with a little state machine.
 */
int
update_system_clock(struct radclock *clock)
{
	long double time;
	vcounter_t vcount;
	struct timeval rad_tv;
	struct timeval sys_tv;
	struct timeval delta_tv;
	struct timex tx;
	double offset; 		/* [sec] */
	double freq; 		/* [PPM] */
	static vcounter_t sys_init;
	static struct timeval sys_init_tv;
	static int next_stamp;
	int poll_period;
	int err;

	memset(&tx, 0, sizeof(struct timex));

	/* At the very beginning, we are sending a few packets in burst. Let's be
	 * patient to have a decent radclock data and simply mark initialisation.
	 */
	if ( ((struct bidir_output*)clock->algo_output)->n_stamps < NTP_BURST )
	{
		sys_init = 0;
		return 0;
	}

	/* Set the clock at the end of burst phase. Yes it is a bit harsh since it
	 * can break causality but not worst than using ntpdate or equivalent (and
	 * we do that only once).
	 */
	if ( ((struct bidir_output*)clock->algo_output)->n_stamps == NTP_BURST )
	{
		radclock_get_vcounter(clock, &vcount);
		counter_to_time(clock, &vcount, &time);
		timeld_to_timeval(&time, &rad_tv);
		err = settimeofday(&rad_tv, NULL);
		if ( err < 0 )
			verbose(LOG_WARNING, "System clock update failed on settimeofday()");
		else
			verbose(VERB_CONTROL, "System clock set to %d.%06d [sec]", rad_tv.tv_sec, rad_tv.tv_usec);
			
		
		memset(&tx, 0, sizeof(struct timex));
			tx.modes = MOD_FREQUENCY | MOD_STATUS;
			tx.status = STA_UNSYNC;
			tx.freq = 0;
			err = ntp_adjtime(&tx);
		return err;
	}

	/* Want to make sure we never pass here after freq estimation has started.
	 * The condition here should do the trick
	 */
	if (sys_init == 0) 
	{	
		/* Use legacy adjtime to bring system clock as close as possible but
		 * with respecting causality and a monotonic clock.  
		 */
		read_clocks(clock, &sys_tv, &rad_tv, &vcount); 
		subtract_tv(&delta_tv, rad_tv, sys_tv);
		offset = delta_tv.tv_sec + (double)delta_tv.tv_usec / 1e6;

		err = adjtime(&delta_tv, NULL);
		if ( err < 0)
			verbose(LOG_WARNING, "System clock update failed on adjtime()");
		else
		{
			verbose(VERB_DEBUG, "System clock update adjtime(%d.%06d) [s]", 
					delta_tv.tv_sec, delta_tv.tv_usec); 
		}
	
		memset(&tx, 0, sizeof(struct timex));
		err = ntp_adjtime(&tx);
		verbose(VERB_DEBUG, "System clock stats (offset freq status) %.09f %.2f %d",
				(double)(tx.offset/KERN_RES), (double)tx.freq/(1L<<SHIFT_USEC), tx.status);

		/* If we have reach a fairly good quality and brought the system clock
		 * close enough, set clock UNSYNC and make freq estimate over ~ 60 sec.
		 * Once the freq skew is set to 0 the clock is potentially running
		 * frantically. The worst case should be a drift clamped down to 500 PPM
		 * by the kernel. Over 60 sec we accumulate about 30 ms of error which
		 * is still acceptable.  Rounding to upper value should deal with poll
		 * periods > 60 sec ...  you can ask "what about the drift then?" Also,
		 * clean up the possible broken estimate of counter frequency skew. As
		 * mentioned in ntpd code, it is equivalent to removing any corrupted
		 * drift file.
		 */
		if ( RAD_DATA(clock)->phat_err < 5e-7  && ( fabs(offset) < 1e-3) )
		{
			next_stamp = (int) (60 / clock->conf->poll_period) + 1;
			next_stamp = next_stamp + ((struct bidir_output*)clock->algo_output)->n_stamps;

			memset(&tx, 0, sizeof(struct timex));
			tx.modes = MOD_FREQUENCY | MOD_STATUS;
			tx.status = STA_UNSYNC;
			tx.freq = 0;
			err = ntp_adjtime(&tx);

			verbose(VERB_DEBUG, "System clock stats (offset freq status) %.09f %.2f %d",
				(double)(tx.offset/KERN_RES), (double)tx.freq/(1L<<SHIFT_USEC), tx.status);

			/* Left hand side of freq skew estimation */	
			read_clocks(clock, &sys_tv, &rad_tv, &vcount); 
			sys_init_tv = sys_tv;
			sys_init = vcount;
			verbose(VERB_DEBUG, "System clock frequency skew estimation start (%d.%.06d | %"VC_FMT")",
					sys_init_tv.tv_sec, sys_init_tv.tv_usec, sys_init);
		}

		return err;
	}


	/* In here we wait for the freq skew estimation period to elapse. Do not try to
	 * adjust the freq skew in here, that would lead to disastrous results with
	 * a meaningless estimate (I tried ;-))
	 */
	if (((struct bidir_output*)clock->algo_output)->n_stamps < next_stamp)
		return 0;

	/* End of the skew period estimation. Compute the freq skew and pass it to
	 * the kernel. Go on directly into STA_PLL.
	 */
	if (((struct bidir_output*)clock->algo_output)->n_stamps == next_stamp) {
		read_clocks(clock, &sys_tv, &rad_tv, &vcount);
		subtract_tv(&delta_tv, sys_tv, sys_init_tv);
		offset = delta_tv.tv_sec + (double)delta_tv.tv_usec / 1e6;
		freq = ((RAD_DATA(clock)->phat * ((vcount - sys_init) / offset)) - 1) * 1e6;

		subtract_tv(&delta_tv, rad_tv, sys_tv);
		offset = delta_tv.tv_sec + (double)delta_tv.tv_usec / 1e6;

		tx.modes = TX_MODES | MOD_FREQUENCY;
		tx.offset = (int32_t) (offset * KERN_RES);
		tx.status = STA_PLL | STA_FLL;
		tx.freq = freq * (1L << SHIFT_USEC);
		err = ntp_adjtime(&tx);

		verbose(VERB_DEBUG, "System clock frequency skew estimation end "
			"(%d.%.06d | %"VC_FMT")",
			sys_tv.tv_sec, sys_tv.tv_usec, vcount);

		/* Make up for the frantic run */
		read_clocks(clock, &sys_tv, &rad_tv, &vcount);
		subtract_tv(&delta_tv, rad_tv, sys_tv);
		err = adjtime(&delta_tv, NULL);

		memset(&tx, 0, sizeof(struct timex));
		err = NTP_ADJTIME(&tx);
		verbose(VERB_DEBUG, "System clock freq skew estimated "
			"(offset freq status) %.09f %.2f %d",
			(double)(tx.offset / KERN_RES), (double)tx.freq / (1L<<SHIFT_USEC),
			tx.status);
	}

	/* Here is the normal mode of operation for updating the system clock. Use
	 * the ntp_time interface to the kernel to pass offset estimates and let the
	 * kernel PLL infer the corresponding freq skew.
	 */
	read_clocks(clock, &sys_tv, &rad_tv, &vcount); 
	subtract_tv(&delta_tv, rad_tv, sys_tv);
	offset = delta_tv.tv_sec + (double)delta_tv.tv_usec / 1e6;

	tx.modes = TX_MODES | MOD_MAXERROR | MOD_ESTERROR | MOD_TIMECONST;
	tx.offset = (int32_t) (offset * KERN_RES);
	tx.status = STA_PLL;
	tx.maxerror = (long) ((SERVER_DATA(clock)->rootdelay/2 + SERVER_DATA(clock)->rootdispersion) * 1e6);
	tx.esterror = (long) (RAD_DATA(clock)->phat * 1e6);	/* TODO: not the right estimate !! */
	
	/* Play slightly with the rate of convergence of the PLL in the kernel. Try
	 * to converge faster when it is further away
	 * Also set a the status of the sysclock when it gets very good.
	 */
	if (fabs(offset) > 100e-6) {
		tx.constant = TIME_CONSTANT - 2;
		DEL_STATUS(clock, STARAD_SYSCLOCK);
	} else {
		ADD_STATUS(clock, STARAD_SYSCLOCK);
		if (fabs(offset) > 40e-6)
			tx.constant = TIME_CONSTANT - 1;
		else
			tx.constant = TIME_CONSTANT;
	}

	err = NTP_ADJTIME(&tx);

	verbose(VERB_DEBUG, "System clock PLL adjusted "
		"(offset freq status maxerr esterr) %.09f %.2f %d %.06f %.06f",
		(double)(tx.offset/KERN_RES), (double)tx.freq/(1L<<SHIFT_USEC), 
		tx.status, (double)tx.maxerror/1e6, (double)tx.esterror/1e6 );

	poll_period = ((struct bidir_peer*)(clock->active_peer))->poll_period;

	if (VERB_LEVEL && !(OUTPUT(clock, n_stamps) % (int)(3600*6/poll_period))) {
		verbose(VERB_CONTROL, "System clock PLL adjusted (offset freq status "
			"maxerr esterr) %.09f %.2f %d %.06f %.06f",
			(double)(tx.offset / KERN_RES), (double)tx.freq / (1L<<SHIFT_USEC),
			tx.status, (double)tx.maxerror / 1e6, (double)tx.esterror / 1e6 );
	}

	return err;
}

#endif /* KERNEL_NONE */




/*
 * Check stamps are not insane. The world is divided in black, white and ...
 * grey. White stamps are clean. Grey stamps have a qual_warning problem, but it
 * is not clear what to do, and that's up to the algo to deal with them. Black
 * stamps are insane and could break processing (e.g. induce zero division, NaN
 * results, etc.). We get rid of them here.
 */
int insane_bidir_stamp(struct stamp_t *stamp, struct stamp_t *laststamp)
{
	/* Sanity check if two consecutive stamps are identical
	 *
	 * Two identical bidirectional stamps are physically impossible since it
	 * would require to read twice the same counter value on the outgoing
	 * packet.  This can only happen if we made something stupid when creating
	 * stamp or if we replay a bogus data file. In such a case we skip all the
	 * algo.  
	 * note: laststamp initialised at i=0, so can only compare if i>0,
	 * implies we cannot check the stamp at i=0 (but that is obviously OK)
	 */

	if ( stamp->type != laststamp->type )
	{
		verbose(LOG_ERR, "Trying to compare two stamps of different types %d and %d",
				stamp->type, laststamp->type);
		return 1;
	}

	if ( memcmp(stamp, laststamp, sizeof(struct stamp_t)) == 0 ) {
		verbose(LOG_WARNING, "Two identical consecutive stamps detected");
		return 1;
	}

	/* Non existent stamps */
	if ( 	(BST(stamp)->Ta == 0) || (BST(stamp)->Tb == 0) || 
			(BST(stamp)->Te == 0) || (BST(stamp)->Tf == 0) ) 
	{
		verbose(LOG_WARNING, "bidir stamp with at least one 0 raw stamp");
		return 1;
	}

	/* Check for strict increment of counter based on previous stamp
	 * note: maybe we should allow overlap, i.e.
	 * 		stamp->Ta <= laststamp->Ta
	 * but unlikely in reality so, keep the stronger test
	 */
	if ( BST(stamp)->Ta <= BST(laststamp)->Tf ) {
		verbose(LOG_WARNING, "Stamp with not strictly increasing counter");
		return 1;
	}

	/* RAW stamps completely messed up */
	if ((BST(stamp)->Tf < BST(stamp)->Ta) || (BST(stamp)->Te < BST(stamp)->Tb)) 
	{
		verbose(LOG_WARNING, "bidir stamp broke local causality");
		return 1;
	}

	/* This does not apply to SPY_STAMP for example */ 
	if ( stamp->type == STAMP_NTP )
	{
		/* Sanity checks on null or too small RTT.
		 * Smallest RTT ever: 100 mus
		 * Slowest counter  : 1193182 Hz
		 * Cycles :  ceil( 100e-6 * 1193182 ) = 120
		 * 		i8254 =   1193182
		 * 		 ACPI =   3579545
		 * 		 HPET =  14318180
		 * 		 TSC  > 500000000
		 */
		if ( (BST(stamp)->Tf - BST(stamp)->Ta) < 120 ) { 
			verbose(LOG_WARNING, "bidir stamp with RTT impossibly low (< 120)"
					": %"VC_FMT" cycles", BST(stamp)->Tf - BST(stamp)->Ta);
			return 1;
		}
	}

	/* If we pass all sanity checks */
	return 0;
}




/**
 * XXX TODO: so far we suppose bidir paradigm only and a single source at a time!!
 */
int
process_rawdata(struct radclock *clock_handle, struct bidir_peer *peer)
{
	JDEBUG

	/* Bi-directionnal stamp passed to the algo for processing */
	struct stamp_t stamp;
	static struct stamp_t laststamp;
	uint64_t stamp_id		= 0;

	/* Error control logging */
	long double currtime 	= 0;
	double min_RTT 			= 0;
	double timediff 		= 0;
	double error_bound 		= 0;
	double error_bound_avg 	= 0;
	double error_bound_std 	= 0;
	int poll_period = 0;	
	int err;
	
	/* Check hardware counter has not changed */
	// XXX TODO this is freebsd specific, should be put with arch specific code
	char hw_counter[32];
	size_t size_ctl;

	/* Generic call for creating the stamps depending on the type of the 
	 * input source.
	 */
	err = get_next_stamp(clock_handle, (struct stampsource *)clock_handle->stamp_source, &stamp, &stamp_id);
	if (err < 0)
		// TODO why inverting the error code logic in here !!! XXX FIXME XXX
		return 1;
	else
		/*
		 * Found a stamp, the trigger thread did not woke us up in vain. Signal
		 * we grabed something so that it stops signalling us something data is
		 * there. The caller will call us until we return an error on empty raw
		 * data buffer
		 */ 
		clock_handle->wakeup_data_ready = 0;


	/* If the new stamp looks insane just don't pass it for processing, keep
	 * going and look for the next one. Otherwise, record it.
	 */
	// TODO: this should be stored in a proper structure under the clock handle
	if ( ((struct bidir_output*)clock_handle->algo_output)->n_stamps > 1)
	{
		if ( insane_bidir_stamp(&stamp, &laststamp) )
			return 0;
	}
	memcpy(&laststamp, &stamp, sizeof(struct stamp_t));

	// TODO: this should be stored in a proper structure under the clock handle
	/* Stamp obtained, increase total counter and process the stamp */
	((struct bidir_output*)clock_handle->algo_output)->n_stamps++;
	
	/* Update calibration using new stamp */ 
	process_bidir_stamp(clock_handle, peer, BST(&stamp), stamp.qual_warning);

	/*
	 * Update IPC shared memory segment for all processes to get accurate
	 * clock parameters
	 */
  	if ((clock_handle->run_mode == RADCLOCK_SYNC_LIVE) &&
			(clock_handle->conf->server_ipc == BOOL_ON)) {
		if (!HAS_STATUS(clock_handle, STARAD_UNSYNC))
			update_ipc_shared_memory(clock_handle);
	}

	/* To improve data accuracy, we kick a fixed point data update just after we
	 * have preocessed a new stamp. Locking is handled by the kernel so we should
	 * not have concurrency issue with the two threads updating the data
	 */
  	if ((clock_handle->run_mode == RADCLOCK_SYNC_LIVE) &&
			(clock_handle->conf->adjust_sysclock == BOOL_ON)) {
			if ( clock_handle->kernel_version < 2 )
		{	
			update_kernel_fixed(clock_handle);
			verbose(VERB_DEBUG, "Sync pthread updated fixed point data to kernel.");
		}
		else {
			/* If we are starting (or restarting), the last estimate in the kernel
			 * may be better than ours after the very first stamp. Let's make sure we do
			 * not push something too stupid
			 */
			if (HAS_STATUS(clock_handle, STARAD_UNSYNC))
				return 0;

			/* If hardware counter has changed, restart over again */
			size_ctl = sizeof(hw_counter);
			err = sysctlbyname("kern.timecounter.hardware", &hw_counter[0], &size_ctl, NULL, 0);
			if (err == -1) {
				verbose(LOG_ERR, "Cannot find kern.timecounter.hardware in sysctl");
				return 1;
			}
			
			if (strcmp(clock_handle->hw_counter, hw_counter) != 0) {
				verbose(LOG_WARNING, "Hardware counter has changed (%s -> %s)."
					" Reinitialising radclock.", clock_handle->hw_counter,
					hw_counter);
				OUTPUT(clock_handle, n_stamps) = 0;
				peer->stamp_i = 0;
				clock_handle->server_data->burst = NTP_BURST;
				strcpy(clock_handle->hw_counter, hw_counter);
// XXX TODO: Reinitialise the stats structure as well?

				return 0;
			}

			set_kernel_ffclock(clock_handle);
			verbose(VERB_DEBUG, "Feed-forward kernel clock has been set.");
		}
	}

	/* Update any virtual machine store if configured */
  	if ((clock_handle->run_mode == RADCLOCK_SYNC_LIVE) &&
			(clock_handle->conf->adjust_sysclock == BOOL_ON))
	{
		RAD_VM(clock_handle)->push_data(clock_handle);
	}

	/* Adjust the system clock, we only pass in here if we are not piggybacking
	 * on ntp daemon.
	 */
  	if ( (clock_handle->run_mode == RADCLOCK_SYNC_LIVE) && (clock_handle->conf->adjust_sysclock == BOOL_ON) )
	{
		// TODO: catch errors
		update_system_clock(clock_handle);
	}


	/* Write algo output to matlab file, much less urgent than previous tasks */
	print_out_files(clock_handle, &stamp, stamp_id);
	
	/* View updated RADclock data and compare with NTP server stamps in nice
	 * format. The first 10 then every 6 hours (poll_period can change, but
	 * should be fine with a long term average, do not have to be very precise
	 * anyway).
	 * Note: ->n_stamps has been incremented by the algo to prepare for next
	 * stamp.
	 */
	poll_period = ((struct bidir_peer*)(clock_handle->active_peer))->poll_period;
	if (VERB_LEVEL &&   ( (OUTPUT(clock_handle, n_stamps) < 10)
					|| !(OUTPUT(clock_handle, n_stamps) % ((int)(3600*6/poll_period))) )) 
	{
		counter_to_time(clock_handle, &(RAD_DATA(clock_handle)->last_changed), &currtime);
		min_RTT = RAD_ERROR(clock_handle)->min_RTT;
		timediff = (double) (currtime - (long double) BST(&stamp)->Te);

		verbose(VERB_CONTROL, "i=%ld: NTPserver stamp %.6Lf, RAD - NTPserver = %.3f [ms], RTT/2 = %.3f [ms]",
				((struct bidir_output*)clock_handle->algo_output)->n_stamps - 1,
				BST(&stamp)->Te, timediff * 1000, min_RTT / 2 * 1000);

		error_bound = RAD_ERROR(clock_handle)->error_bound;
		error_bound_avg = RAD_ERROR(clock_handle)->error_bound_avg;
		error_bound_std = RAD_ERROR(clock_handle)->error_bound_std;
		verbose(VERB_CONTROL, "i=%ld: Clock Error Bound (cur,avg,std) %.6f %.6f %.6f [ms]",
				((struct bidir_output*)clock_handle->algo_output)->n_stamps - 1,
				error_bound * 1000, error_bound_avg * 1000, error_bound_std * 1000);
	}

	/* Plocal 
	 * We don't want to reinit plocal each time we receive a packet, but only 
	 * on reload of the configuration file. So this does the trick.
	 */
	if (clock_handle->conf->start_plocal == PLOCAL_RESTART)
			clock_handle->conf->start_plocal = PLOCAL_START;

	/* Set initial state of 'signals' - important !! 
	 * Has to be placed here, after the algo handled the possible new
	 * parameters, with the next packets coming.
	 */
	clock_handle->conf->mask = UPDMASK_NOUPD;


	JDEBUG_RUSAGE

	return 0;
}


