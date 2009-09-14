/*
 * Copyright (C) 2006-2009 Julien Ridoux <julien@synclab.org>
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


#include "../config.h"
#include <string.h>
#include <math.h>
#include <syslog.h>
#include <time.h>

#include "sync_algo.h"
#include <radclock.h>
#include "radclock-private.h"
#include "fixedpoint.h"
#include "verbose.h"
#include <proto_ntp.h>

#include "stampinput.h"
#include "stampoutput.h"
#include "config_mgr.h"

#include "pthread_mgr.h"



#ifdef WITH_RADKERNEL_NONE
int update_system_clock(struct radclock *clock_handle) {}
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




/* Report back to back timestamps of RADclock and system clock */
static inline void read_clocks(struct radclock *clock_handle, 
		struct timeval *sys_tv, struct timeval *rad_tv, vcounter_t *rad_vc)
{
	vcounter_t vc;
	int i;

	for (i=0; i<5; i++)
	{
		radclock_get_vcounter(clock_handle, &vc);
		gettimeofday(sys_tv, NULL);
		radclock_get_vcounter(clock_handle, rad_vc);

		/* A system call is in the order of 1-2 mus, here we have 3 of them plus a
		 * reasonable safety bound ... 5 mus?
		 */
		if ( (*rad_vc - vc) < ( 5e-6 / GLOBAL_DATA(clock_handle)->phat ) )
			break;
	}
	verbose(VERB_DEBUG, "System clock read_clocks vc= %"VC_FMT" rad_vc= %"VC_FMT" delay= %.03f [mus]",
			vc, *rad_vc, (*rad_vc - vc) * GLOBAL_DATA(clock_handle)->phat * 1e6 );

	*rad_vc = (vcounter_t) ((vc + *rad_vc)/2);
	radclock_vcount_to_abstime(clock_handle, rad_vc, rad_tv);
}


/* Subtract two timeval */
void subtract_tv (struct timeval *delta, struct timeval tv1, struct timeval tv2)
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
int update_system_clock(struct radclock *clock_handle)
{
	vcounter_t vcount;
	struct timeval rad_tv;
	struct timeval sys_tv;
	struct timeval delta_tv;
	struct timex tx;
	double offset; 		/* [sec] */
	double freq; 		/* [PPM] */
	int err;
	static vcounter_t sys_init;
	static struct timeval sys_init_tv;
	static int next_stamp;

	memset(&tx, 0, sizeof(struct timex));

	/* At the very beginning, we are sending a few packets in burst. Let's be
	 * patient to have a decent radclock data and simply mark initialisation.
	 */
	if ( ((struct bidir_output*)clock_handle->algo_output)->n_stamps < NTP_BURST )
	{
		sys_init = 0;
		return 0;
	}

	/* Set the clock at the end of burst phase. Yes it is a bit harsh since it
	 * can break causality but not worst than using ntpdate or equivalent (and
	 * we do that only once).
	 */
	if ( ((struct bidir_output*)clock_handle->algo_output)->n_stamps == NTP_BURST )
	{
		radclock_gettimeofday(clock_handle, &rad_tv);
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
		read_clocks(clock_handle, &sys_tv, &rad_tv, &vcount); 
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
		if ( GLOBAL_DATA(clock_handle)->phat_err < 5e-7  && ( fabs(offset) < 1e-3) )
		{
			next_stamp = (int) (60 / clock_handle->conf->poll_period) + 1;
			next_stamp = next_stamp + ((struct bidir_output*)clock_handle->algo_output)->n_stamps;

			memset(&tx, 0, sizeof(struct timex));
			tx.modes = MOD_FREQUENCY | MOD_STATUS;
			tx.status = STA_UNSYNC;
			tx.freq = 0;
			err = ntp_adjtime(&tx);

			verbose(VERB_DEBUG, "System clock stats (offset freq status) %.09f %.2f %d",
				(double)(tx.offset/KERN_RES), (double)tx.freq/(1L<<SHIFT_USEC), tx.status);

			/* Left hand side of freq skew estimation */	
			read_clocks(clock_handle, &sys_tv, &rad_tv, &vcount); 
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
	if ( ((struct bidir_output*)clock_handle->algo_output)->n_stamps < next_stamp )
		return 0;


	/* End of the skew period estimation. Compute the freq skew and pass it to
	 * the kernel. Go on directly into STA_PLL.
	 */
	if ( ((struct bidir_output*)clock_handle->algo_output)->n_stamps == next_stamp )
	{
		read_clocks(clock_handle, &sys_tv, &rad_tv, &vcount); 
		subtract_tv(&delta_tv, sys_tv, sys_init_tv);
		offset = delta_tv.tv_sec + (double)delta_tv.tv_usec / 1e6;
		freq = (( GLOBAL_DATA(clock_handle)->phat * ((vcount - sys_init) / offset) ) - 1 ) * 1e6; 

		subtract_tv(&delta_tv, rad_tv, sys_tv);
		offset = delta_tv.tv_sec + (double)delta_tv.tv_usec / 1e6;

		tx.modes = TX_MODES | MOD_FREQUENCY;
		tx.offset = (int32_t) (offset * KERN_RES);
		tx.status = STA_PLL | STA_FLL;
		tx.freq = freq * (1L << SHIFT_USEC);
		err = ntp_adjtime(&tx);
		
		verbose(VERB_DEBUG, "System clock frequency skew estimation end (%d.%.06d | %"VC_FMT")",
					sys_tv.tv_sec, sys_tv.tv_usec, vcount);

		/* Make up for the frantic run */
		read_clocks(clock_handle, &sys_tv, &rad_tv, &vcount); 
		subtract_tv(&delta_tv, rad_tv, sys_tv);
		err = adjtime(&delta_tv, NULL);
	
		memset(&tx, 0, sizeof(struct timex));
		err = NTP_ADJTIME(&tx);
		verbose(VERB_DEBUG, "System clock freq skew estimated (offset freq status) %.09f %.2f %d",
				(double)(tx.offset/KERN_RES), (double)tx.freq/(1L<<SHIFT_USEC), tx.status);
	}

	
	/* Here is the normal mode of operation for updating the system clock. Use
	 * the ntp_time interface to the kernel to pass offset estimates and let the
	 * kernel PLL infer the corresponding freq skew.
	 */
	read_clocks(clock_handle, &sys_tv, &rad_tv, &vcount); 
	subtract_tv(&delta_tv, rad_tv, sys_tv);
	offset = delta_tv.tv_sec + (double)delta_tv.tv_usec / 1e6;

	tx.modes = TX_MODES | MOD_MAXERROR | MOD_ESTERROR | MOD_TIMECONST;
	tx.offset = (int32_t) (offset * KERN_RES);
	tx.status = STA_PLL;
	tx.maxerror = (long) ((SERVER_DATA(clock_handle)->rootdelay/2 + SERVER_DATA(clock_handle)->rootdispersion) * 1e6);
	tx.esterror = (long) (GLOBAL_DATA(clock_handle)->phat * 1e6);	/* TODO: not the right estimate !! */
	
	/* Play slightly with the rate of convergence of the PLL in the kernel. Try
	 * to converge faster when it is further away
	 * Also set a the status of the sysclock when it gets very good.
	 */
	if (fabs(offset) > 50e-6) 
	{
		tx.constant = TIME_CONSTANT - 2;
		DEL_STATUS(clock_handle, STARAD_SYSCLOCK);
	}
	else {
		if (fabs(offset) > 20e-6) 
		{
			tx.constant = TIME_CONSTANT - 1;
			DEL_STATUS(clock_handle, STARAD_SYSCLOCK);
		}
		else
		{
			tx.constant = TIME_CONSTANT;
			ADD_STATUS(clock_handle, STARAD_SYSCLOCK);
		}
	}

	err = NTP_ADJTIME(&tx);

	verbose(VERB_DEBUG, "System clock PLL adjusted (offset freq status maxerr esterr) %.09f %.2f %d %.06f %.06f",
				(double)(tx.offset/KERN_RES), (double)tx.freq/(1L<<SHIFT_USEC), 
				tx.status, (double)tx.maxerror/1e6, (double)tx.esterror/1e6 );

	if (VERB_LEVEL && (!(((struct bidir_output*)clock_handle->algo_output)->n_stamps-1)%200) ) 
		verbose(VERB_CONTROL, "System clock PLL adjusted (offset freq status maxerr esterr) %.09f %.2f %d %.06f %.06f",
				(double)(tx.offset/KERN_RES), (double)tx.freq/(1L<<SHIFT_USEC), 
				tx.status, (double)tx.maxerror/1e6, (double)tx.esterror/1e6 );

	return err;
}

#endif /* KERNEL_NONE */





int insane_bidir_stamp(struct bidir_stamp* stamp, struct bidir_stamp* laststamp)
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
	if ( memcmp(stamp, laststamp, sizeof(struct bidir_stamp)) == 0 ) {
		verbose(LOG_WARNING, "Two identical consecutive stamps detected");
		return 1;
	}

	/* Non existent stamps */
	if ( (stamp->Ta == 0) || (stamp->Tb == 0) || (stamp->Te == 0) || (stamp->Tf == 0) ) {
		verbose(LOG_WARNING, "bidir stamp with at least one 0 raw stamp");
		return 1;
	}

	/* Check for strict increment of counter based on previous stamp
	 * note: maybe we should allow overlap, i.e.
	 * 		stamp->Ta <= laststamp->Ta
	 * but unlikely in reality so, keep the stronger test
	 */
	if ( stamp->Ta <= laststamp->Tf ) {
		verbose(LOG_WARNING, "Stamp with not strictly increasing counter");
		return 1;
	}

	/* RAW stamps completely messed up */
	if ( (stamp->Tf < stamp->Ta) || (stamp->Te < stamp->Tb) ) {
		verbose(LOG_WARNING, "bidir stamp broke local causality");
		return 1;
	}

	/* Sanity checks on null or too small RTT.
	 * Smallest RTT ever: 100 mus
	 * Slowest counter  : 1193182 Hz
	 * Cycles :  ceil( 100e-6 * 1193182 ) = 120
	 * 		i8254 =   1193182
	 * 		 ACPI =   3579545
	 * 		 HPET =  14318180
	 * 		 TSC  > 500000000
	 */
	if ( (stamp->Tf - stamp->Ta) < 120 ) { 
		verbose(LOG_WARNING, "bidir stamp with RTT impossibly low (< 120)");
		return 1;
	}

	/* If we pass all sanity checks */
	return 0;
}


 	

/**
 * XXX TODO: so far we suppose bidir paradigm only
 */
int process_rawdata(void *c_handle)
{
	JDEBUG

	struct radclock *clock_handle = (struct radclock *) c_handle; 

	/* Bi-directionnal stamp passed to the algo for processing */
	struct bidir_stamp stamp;
	static struct bidir_stamp laststamp;


	// TODO; fixme
	/* Stuff */
	char ctime_buf[27]	= "";
	long double currtime;
	time_t currsec;

	int err;

	/* Generic call for creating the stamps depending on the type of the 
	 * input source.
	 */
	if ( (err = get_next_stamp(clock_handle, (struct stampsource *)clock_handle->stamp_source, &stamp)) < 0 )
	{
		return 1;
	}

	/* If the new stamp looks insane just don't pass it for processing, keep
	 * going and look for the next one. Otherwise, record it.
	 */
	if ( insane_bidir_stamp(&stamp, &laststamp) )
		return 0;
	memcpy(&laststamp, &stamp, sizeof(struct bidir_stamp));

	// TODO: this should be stored in a proper structure under the clock handle
	/* Stamp obtained, increase total counter and process the stamp */
	((struct bidir_output*)clock_handle->algo_output)->n_stamps++;
	
	/* Update calibration using new stamp */ 
	process_bidir_stamp(clock_handle, &stamp);

	/* Update the radclock i.e. the global data 
	 * Done only in the case of reading from a live device and if 
	 * the update flag is on.
	 */
	if ( (clock_handle->run_mode == RADCLOCK_RUN_KERNEL) && (clock_handle->ipc_mode == RADCLOCK_IPC_SERVER) ) 
	{
		// Use the clock we just created to update the global data
		if ( (radclock_set_kernelclock(clock_handle)) < 0) {
			verbose(LOG_ERR, "Could not SET global data to the kernel clock");
		}
		else {
			verbose(VERB_DEBUG, "Kernel clock updated");
		}
		if (VERB_LEVEL > 1) {
			struct radclock *tmp_clock; 
			tmp_clock = radclock_create();
			*(PRIV_DATA(tmp_clock)) = *(PRIV_DATA(clock_handle));
 
			// This is an explicit call for an update of the user clock
			if ( (radclock_read_kernelclock(tmp_clock)) < 0) {
				verbose(LOG_ERR, "Could not GET global data from the kernel and update the user clock");
			}
			else {
				verbose(VERB_DEBUG, "Kernel clock: last vcounter= %llu   p= %15.9lg   Ca= %22.9Lf",
						GLOBAL_DATA(tmp_clock)->last_changed, GLOBAL_DATA(tmp_clock)->phat, GLOBAL_DATA(tmp_clock)->ca);
			}
			radclock_destroy(tmp_clock);
		}
	}

	/* To improve data accuracy, we kick a fixed point data update just after we
	 * have preocessed a new stamp. Locking is handled by the kernel so we should
	 * not have concurrency issue with the two threads updating the data
	 */ 	
	if ( (clock_handle->run_mode != RADCLOCK_RUN_DEAD) && (clock_handle->ipc_mode == RADCLOCK_IPC_SERVER) ) {
		update_kernel_fixed(clock_handle);
		verbose(VERB_DEBUG, "Sync thread updated fixed point data to kernel.");
	}

	/* Adjust the system clock, we only pass in here if we are not piggybacking
	 * on ntp daemon.
	 */
  	if ( (clock_handle->run_mode == RADCLOCK_RUN_KERNEL) && (clock_handle->conf->adjust_sysclock == BOOL_ON) )
	{
		// TODO: catch errors
		update_system_clock(clock_handle);	
	}


	/* Write algo output to matlab file, much less urgent than previous tasks */
	print_out_files(clock_handle, &stamp);
	
	/* View updated RADclock data and compare with NTP server stamps in nice format */
	long double  timediff=0;    // difference between Te and C(tf)
	if (VERB_LEVEL &&   (((struct bidir_output*)clock_handle->algo_output)->n_stamps<4 
					|| !((((struct bidir_output*)clock_handle->algo_output)->n_stamps-1)%200)) ) 
	{

		currtime = stamp.Te;
		currsec = (time_t)(floor(currtime));      
		verbose(VERB_CONTROL, "Comparing clocks on packet %ld",((struct bidir_output*)clock_handle->algo_output)->n_stamps);
		ctime_r(&currsec, ctime_buf);
		*(strchr(ctime_buf, '\n')) = '\0';
		verbose(VERB_CONTROL, " NTPserver: (%9.3Lf [ms] past)  %s",(currtime-currsec)*1000,ctime_buf);

		radclock_vcount_to_abstime_fp(clock_handle, &(GLOBAL_DATA(clock_handle)->last_changed), &currtime);
		
		currsec = (time_t)(currtime);
		timediff = currtime - (long double)stamp.Te;
		ctime_r(&currsec, ctime_buf);
		*(strchr(ctime_buf, '\n')) = '\0';
		verbose(VERB_CONTROL, " RADclock:  (%9.3Lf [ms] past)  %s",(currtime-currsec)*1000,ctime_buf);
		verbose(VERB_CONTROL, " RAD - NTP  = %9.3Lf [ms] (compare to RTT/2)",timediff*1000);
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
	return 0;
}


