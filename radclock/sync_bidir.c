/*
 * Copyright (C) 2006 Darryl Veitch <dveitch@unimelb.edu.au> 
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


/* This comment should be on line 22 and nothing above except the copyright
 * notice. This is useful for the remove_comments script
 */

/* Bidirectional algo */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <syslog.h>
#include <pthread.h>
#include <pcap.h>
#include <string.h>
#include <math.h>

#include <radclock.h>
/* The algo needs access to the global_data structure to update the user level clock */
#include "radclock-private.h"

#include "verbose.h"
#include <sync_algo.h>
#include "config_mgr.h"



/* =============================================================================
 * CONSTANTS 
 * =============================================================================
 */
/* number of seconds in a day */
const double s2Day=3600*24.;



/* =============================================================================
 * ROUTINES: MINIMUM DETECTION 
 * =============================================================================
 */

/* Subroutine to find the minimum of a set of contiguous array elements.
 * Finds minimum between j and i inclusive,  j<=i .
 * Does NOT change array elements.
 * Returns index of minimal element.
 * - This version is for 64 bit integers, as needed for RTT times.
 * - i, j, and ind_curr are true indices. They are circularly mapped into 
 *   the array x of length lenx.  It is up to the calling function to ensure
 *   that the values needed are still in the array.
 */
static u_int32_t  min(u_int64_t *x, u_int32_t j, u_int32_t i, u_int32_t lenx)
{
   /* current minimum found and  corresponding inde */
	u_int64_t  min_curr;
	u_int32_t  ind_curr;

	if ( i < j ) {
		verbose(LOG_ERR,"Error in min,  index range bad, j= %u, i= %u", j,i);
	}

	/* initialise */
	min_curr = x[j%lenx];
	ind_curr = j;

	/* if i<=j, already done */
	while ( j < i ) {
		j++;
		if ( x[j%lenx] < min_curr ) {
			min_curr = x[j%lenx];
			ind_curr = j;
		}
	}
	return ind_curr;
}

  
/* Subroutine to find the minimum of a number and a set of contiguous array elements.
 * Array elements given between j and i inclusive,  j<=i
 * Does NOT change array elements.
 * Specialized to efficiently find a minimum of a continuously sliding window over an array.
 * Window slides by 1:  old element j is dropped in favor of new element at i+1 .
 * This version takes the index of the current minimum and returns the new index.
 * - This version is for 64 bit integers, as needed for RTT times.
 * - i, j, and ind_curr are true indices. They are circularly mapped into 
 *   the array x of length lenx.  It is up to the calling function to ensure
 *   that the values needed are still in the array.
 */
static u_int32_t  min_slide(u_int64_t *x, u_int32_t index_curr,  u_int32_t j, u_int32_t i, u_int32_t lenx)
{
	if ( i < j ) {
		verbose(LOG_ERR,"Error in min_slide, window width less than 1: %u %u %u", j,i,i-j+1);
		return i+1;
	}
	/* window only 1 wide anyway, easy */
	if (i == j)
		return i+1;
	/* new one is new min */
	if ( x[(i+1)%lenx] < x[index_curr%lenx] )
		return i+1;
	/* one being dropped was min, must do work */
	if (j == index_curr)
		return min(x,j+1,i,lenx);
	/* min_curr inside window and still valid, easy */
	return index_curr;
}

/* Version that operates on values rather than indices
 * Must initialise properly, if the min is not in the window, may never be replaced!
 */
static u_int64_t min_slide_value(u_int64_t *x, u_int64_t min_curr,  u_int32_t j, u_int32_t i, u_int32_t lenx)
{
	if ( i < j ) {
		verbose(LOG_ERR,"Error in min_slide_value, window width less than 1: %u %u %u", j,i,i-j+1);
		return i+1;
	}
	/* window only 1 wide anyway, easy */
	if (i == j)
		return x[(i+1)%lenx];
	/* new one is new min */
	if ( x[(i+1)%lenx] < min_curr)
		return x[(i+1)%lenx];
	/* one being dropped was min, must do work */
	if ( x[j%lenx] == min_curr )
		return x[min(x,j+1,i,lenx)%lenx];
	/* min_curr inside window and still valid, easy */
	return min_curr;
}


/*
 *  Function to copy a stamp
 */
static void copystamp(struct bidir_stamp *orig, struct bidir_stamp *copy)
{
	memcpy(copy, orig, sizeof(struct bidir_stamp));
}





/* =============================================================================
 * ALGO INITIALISATION ROUTINES
 * =============================================================================
 */


static void set_algo_windows(struct radclock_phyparam *phyparam, 
								int poll_period, 
								u_int32_t history_scale, 
								u_int32_t *h_win,
								u_int32_t *shift_win,
								u_int32_t *offset_win,
								u_int32_t *plocal_win) 
{
	/* top level window, must forget past */
	*h_win 		= (u_int32_t) ( history_scale / poll_period );

  	/* shift detection. Ensure min of 100 samples (reference poll=16).
	 * TODO: right function? 
	 */
	*shift_win 	= MAX( (u_int32_t)ceil((10*phyparam->TSLIMIT/1e-7)/poll_period), 100 );

	/* offset estimation, based on SKM scale (don't allow too small) */
	*offset_win = (u_int32_t) MAX( (phyparam->SKM_SCALE/poll_period), 2 );

	/* local period, not the right function! should be # samples and time based */ 
	*plocal_win = (u_int32_t) MAX( ceil(*offset_win*5), 4);
/*	*plocal_win = (u_int32_t) MAX( ceil(*offset_win*4), 4);  // XXX Tuning purposes SIGCOMM */ 
}


/* Adjust window values to avoid window mismatches generating unnecessary complexity
 * This version initialises Warmup_win on the first pkt, otherwise, after a parameter reload,
 * it takes the new algo windows and again increases the warmup period if necessary.
 * it will never decrease it in time to avoid problems, so there will always be more stamps to serve.
 * it will always recommend keeping existing packets so warmup history is not lost.
 * It also ensures that h_win is large enough.
 */ 
static void adjust_Warmup_win(u_int32_t i, 
								int poll_period, 
								u_int32_t *Warmup_win,
								u_int32_t *h_win,
								u_int32_t *shift_win,
								u_int32_t *offset_win,
								u_int32_t *plocal_win,
								u_int32_t plocal_winratio) 
{
	u_int32_t win;
	double WU_dur;

	verbose(VERB_CONTROL,"Adjusting Warmup window");
	win = MAX(*offset_win,MAX(*shift_win,*plocal_win + *plocal_win/(plocal_winratio/2) ));

	if (i==0) {
		if ( win > *Warmup_win ) {
			/* simply full algo a little */
			verbose(VERB_CONTROL, "Warmup window smaller than algo windows, increasing "
					"from %u to %u stamps", *Warmup_win,win);
			*Warmup_win = win;
		} 
	} else {
		/* Simply adds on an entire new Warmup using new parameters: code can't fail
		 * WU_dur: [sec] of new warmup remaining to serve
		 */
		WU_dur = (double)(win*poll_period);
		*Warmup_win = (u_int32_t) ceil(WU_dur/poll_period) + i;
		verbose(VERB_CONTROL, 
				"After adjustment, %4.1lf [sec] of warmup left to serve, or %u stamps. Warmup window now %u", 
				WU_dur, (u_int32_t) ceil(WU_dur/poll_period), *Warmup_win);
	}

	/* Corollary of the following is that both warmup and shift windows are < h_win/2 , nice */
	if ( *Warmup_win+*shift_win > *h_win/2 ) {
		/* can neglect history window in warmup phase */
		verbose(VERB_CONTROL,
				"Warmup + shift window hits history half window, increasing history window from %u to %u", 
				*h_win, (*Warmup_win+*shift_win)*2+1);
		/* small history is bad, make is 3* the minimum possible */
		*h_win = 3*( (*Warmup_win+*shift_win)*2+1 );
	}

	verbose(VERB_CONTROL,"Warmup Adjustment Complete");
}





/* Resize history windows
 * This function takes care of an implementation issue: increasing or decreasing the size of history kept.
 * The calling program decides on the history size it wants, here we just ensure that the existing elements
 * are copied to the new size in a sensible way: 
 *    - writing every element that is really there, but no more (_win and _win_old are true stamp indices)
 *    - only writing what fits in
 *    - updating record of earliest stamp available ( RTT_end etc )
 * How the algos handle perhaps not having the elements they need available in the history is not handled here..
 */
static void resize_histories(u_int32_t i,
struct bidir_stamp **st_hist,      u_int32_t st_win,      u_int32_t st_win_old,      u_int32_t *st_end,
	 u_int64_t **RTT_hist,     u_int32_t RTT_win,     u_int32_t RTT_win_old,     u_int32_t *RTT_end,
	 u_int64_t **RTThat_hist,  u_int32_t RTThat_win,  u_int32_t RTThat_win_old,  u_int32_t *RTThat_end,
	    double **thnaive_hist, u_int32_t thnaive_win, u_int32_t thnaive_win_old, u_int32_t *thnaive_end ) 
{
	/* True stamp indices >= 0 
	* j: loop index needs to be signed to avoid problem when j hits zero
	* jmin: oldest stamp that will fit, past back as the new _end variable 
	*/
	signed long int j;
	u_int32_t   jmin;

	/* pointers to new histories malloc'd here */
	struct bidir_stamp *st;
	u_int64_t  *RTT, *RTThat;
	double     *th;

	verbose(VERB_CONTROL,"Resizing Histories");

	/* stamps */
	if (st_win != st_win_old) {
		verbose(VERB_CONTROL, "Resizing st_win history from %u to %u. Current stamp range is [%u %u]",
			st_win_old,st_win,*st_end,i); 
		st = (struct bidir_stamp*) malloc(st_win*sizeof(struct bidir_stamp));
		/* ensure jmin don't go past 1st stamp
		* then go back until hit `start' of history array, or last value available
		* finally update st_end, the index of last stamp
		*/
		jmin = (u_int32_t) MAX(0, (long)i-(long)st_win+1);
		jmin = MAX(jmin, *st_end);
		*st_end = jmin;
		for ( j=(long)i; j>=(long)jmin; j-- ) {
			copystamp( &(*st_hist)[j%st_win_old], &st[j%st_win] );
		}
		free(*st_hist);
		*st_hist = st;
		verbose(VERB_CONTROL, "Range on exit: [%u %u]", *st_end,i);
	}

	/* RTT */
	if (RTT_win != RTT_win_old) {
		verbose(VERB_CONTROL, "Resizing RTT_win history from %u to %u. Current stamp range is [%u %u]", 
				RTT_win_old, RTT_win, *RTT_end, i);
		RTT = (u_int64_t*) malloc(RTT_win*sizeof(u_int64_t));
		/* ensure jmin don't go past 1st stamp
		* then go back until hit `start' of history array, or last value available
		* finally update st_end, the index of last stamp
		*/
		jmin = (u_int32_t) MAX(0, (long)i-(long)RTT_win+1);
		jmin = MAX(jmin,*RTT_end);
		*RTT_end = jmin;
		for ( j=(long)i; j>=(long)jmin; j-- ) {
			RTT[j%RTT_win] = (*RTT_hist)[j%RTT_win_old];
		}
		free(*RTT_hist);
		*RTT_hist = RTT;
		verbose(VERB_CONTROL, "Range on exit: [%u %u]", *RTT_end,i);
	}

	/* RTThat */
	if (RTThat_win != RTThat_win_old) {
		verbose(VERB_CONTROL, "Resizing RTThat_win history from %u to %u. Current stamp range is [%u %u]", 
				RTThat_win_old, RTThat_win, *RTThat_end, i);
		RTThat =  (u_int64_t*) malloc(RTThat_win*sizeof(u_int64_t));
		/* ensure jmin don't go past 1st stamp
		* then go back until hit `start' of history array, or last value available
		* finally update st_end, the index of last stamp
		*/
		jmin = (u_int32_t) MAX(0, (long)i-(long)RTThat_win+1);
		jmin = MAX(jmin,*RTThat_end);
		*RTThat_end = jmin;
			for ( j=(long)i; j>=(long)jmin; j-- ) {
		RTThat[j%RTThat_win] = (*RTThat_hist)[j%RTThat_win_old];
		}
		free(*RTThat_hist);
		*RTThat_hist = RTThat;
		verbose(VERB_CONTROL, "Range on exit: [%u %u]", *RTThat_end,i);
	}

	/* thnaive */
	if (thnaive_win != thnaive_win_old) {
		verbose(VERB_CONTROL, "Resizing thnaive_win history from %u to %u.  Current stamp range is [%u %u]",
				thnaive_win_old, thnaive_win, *thnaive_end, i);
		th = (double*) malloc(thnaive_win*sizeof(double));
		/* ensure jmin don't go past 1st stamp
		* then go back until hit `start' of history array, or last value available
		* finally update st_end, the index of last stamp
		*/
		jmin = (u_int32_t) MAX(0, (long)i-(long)thnaive_win+1);
		jmin = MAX(jmin,*thnaive_end);
		*thnaive_end = jmin;
		for (j=(long)i;j>=(long)jmin;j--) {
			th[j%thnaive_win] = (*thnaive_hist)[j%thnaive_win_old];
		}
		free(*thnaive_hist);
		*thnaive_hist = th;
		verbose(VERB_CONTROL, "Range on exit: [%u %u]", *thnaive_end,i);
	}

	verbose(VERB_CONTROL, "Resizing Complete");
}


/* Initialization function for normal plocal algo
 * 		Resets wwidth as well as finding near and far pkts 
 * 		poll_period dependence:  via plocal_win
 */
static void init_plocal(u_int32_t plocal_win, u_int32_t plocal_winratio,
						u_int64_t *RTT_hist,u_int32_t RTT_win, u_int32_t i,
						u_int32_t *ww, u_int32_t *far_i, u_int32_t *near_i)
{
	/* XXX Tuning ... Accept too few packets in the window makes plocal varies
	 * a lot. Let's accept more packets to increase quality.
	 * 		*ww = MAX(1,plocal_win/plocal_winratio);
	 */
	/* not used again for phat */
	*ww = MAX(4,plocal_win/plocal_winratio);
	*far_i  = min(RTT_hist, i-plocal_win+1-*ww/2, i-plocal_win+*ww-*ww/2, RTT_win);
	*near_i = min(RTT_hist,i-*ww+1,i, RTT_win);
	verbose(VERB_CONTROL, "Initializing full plocal algo, wwidth= %u, (far_i,near_i) = (%u,%u)",
			*ww, *far_i,*near_i);
}



/* Initialise the error threshold.
 * This procedure is a trick to modify static variables on 
 * reception of the first packet only.
 */
static void init_errthresholds( struct radclock_phyparam *phyparam, 
	double *Eshift, double *Ep, double *Ep_qual, double *Ep_sanity, 
	double *Eplocal_qual, double *Eplocal_sanity,
	double *Eoffset, double *Eoffset_qual, double *Eoffset_sanity_min, double *Eoffset_sanity_rate)
{
	/* XXX Tuning history:
	 * original: 10*TSLIMIT = 150 mus
	 * 		*Eshift			=  35*phyparam->TSLIMIT;  // 525 mus for Shouf Shouf?
	 */
	*Eshift					=  10*phyparam->TSLIMIT;
	*Ep						=   3*phyparam->TSLIMIT;
	*Ep_qual				=     phyparam->RateErrBOUND/5;
	*Ep_sanity				=   3*phyparam->RateErrBOUND;
	/* XXX Tuning history:
	 * 		*Eplocal_qual	=   4*phyparam->BestSKMrate;  // Original
	 * 		*Eplocal_qual	=   4*2e-7; 		// Big Hack during TON paper
	 * 		*Eplocal_qual	=   40*1e-7;		// Tuning for Shouf Shouf tests ??
	 * but finally introduced a new parameter in the config file
	 */
	*Eplocal_qual			=     phyparam->plocal_quality;
	*Eplocal_sanity			=   3*phyparam->RateErrBOUND;

	/* XXX Tuning history:
	 * 		*Eoffset		=   6*phyparam->TSLIMIT;  // Original
	 * but finally introduced a new parameter in the config file
	 */
	*Eoffset				=     phyparam->offset_ratio * phyparam->TSLIMIT;

	/* XXX Tuning history: 
	 * We should decouple Eoffset and Eoffset_qual ... conclusion of shouf shouf analysis 
	 * Added the effect of poll period as a first try (~ line 740) 
	 * [UPDATE] - reverted ... see below
	 */
	*Eoffset_qual			=   3*(*Eoffset);
	*Eoffset_sanity_min  	= 100*phyparam->TSLIMIT;
	*Eoffset_sanity_rate 	=  20*phyparam->RateErrBOUND;
}







/* =============================================================================
 * CLOCK SYNCHRONISATION ALGORITHM
 * =============================================================================
 */



/* TODO:
 * - Slowly move static variables into static structures, especially look at the
 * ones involved in the stat_phat log, they may be the first ones to be made
 * pure locals again 
 * - make input const
 */


#define OUTPUT(clock, x) ((struct bidir_output*)clock->algo_output)->x


/* This routine takes in a new bi-directional stamp and uses it to update the
 * estimates of the clock calibration.   It implements the full `algorithm' and
 * is abstracted away from the lower and interface layers.  It should be
 * entirely portable.  It returns updated clock in the global clock format,
 * pre-corrected.
 */
int process_bidir_stamp(struct radclock *clock_handle, struct bidir_stamp *input_stamp)
{
	JDEBUG

	/* Allocate some data structure needed below */
	struct bidir_stamp *stamp = input_stamp;
	struct radclock_phyparam *phyparam = &(clock_handle->conf->phyparam);
	struct radclock_config *conf = clock_handle->conf;
	int poll_period = conf->poll_period;
	int sig_plocal = conf->start_plocal;


/* Synchronisation algorithm parameters */

 static u_int32_t history_scale=3600*24*7; // time-scale of top level window

 /* window sizes, measured in [pkt index] These control algorithm, independent of implementation */
 static u_int32_t Warmup_win = 100;      // RTT estimation (indep of time and CPU, need samples)
 static u_int32_t h_win;                 // top level window, must forget past
 static u_int32_t shift_win, shift_end;  // shift detection:  window size, record of oldest pkt in it
 static u_int32_t plocal_win, plocal_end;// local period estimation, based on SKM scale, oldest pkt
 static u_int32_t offset_win;            // offset estimation, based on SKM scale (don't allow too small)

 /* Set history array sizes */
 static u_int32_t st_win, st_win_old;                        // stamp    history depth
 static u_int32_t RTT_win, RTT_win_old;                      // RTT      history 
 static u_int32_t RTThat_win, RTThat_win_old;                // RTThat   history 
 static u_int32_t thnaive_win, thnaive_win_old;              // th_naive history 
 static u_int32_t st_end, RTT_end, RTThat_end, thnaive_end;  // indices of last pkts in history

 /* error thresholds, measured in [sec], or unitless */
 static double Eshift;			// threshold for detection of upward level shifts (should adapt to variability)
 static double Ep;				// point error threshold for phat
 static double Ep_qual;			// [unitless] quality threshold for phat (value after 1st window) 
 static double Ep_sanity;		// [unitless] sanity check threshold for phat
 static double Eplocal_qual;	// [unitless] quality      threshold for plocal 
 static double Eplocal_sanity;  // [unitless] sanity check threshold for plocal

 static double Eoffset;				// quality band in weighted theta estimate
 static double Eoffset_qual;	    // weighted quality threshold for offset, choose with Gaussian decay in mind!! small multiple of Eoffset
 static double Eoffset_sanity_min;	// was absolute sanity check threshold for offset (should adapt to data)
 static double Eoffset_sanity_rate;	// [unitless] sanity check threshold per unit time [sec] for offset

 /* Basic, misc */
 static struct bidir_stamp laststamp;    // record previous stamp
 static u_int32_t i = 0;                 // unique stamp index (C notation [ 0 1 2 ...])  (136 yrs @ 1 stamp/[sec] if 32bit)
 signed long int j;                      // loop index, needs to be signed to avoid problem when j hits zero
        u_int32_t jmin  = 0;             // index that hits low end of loop
        u_int32_t jbest = 0;			 // record best packet selected in window 
 static u_int64_t vcount_init;              // vcount origin at beginning of calibration
 static long double t_init;              // duration so far of calibration
 static u_int32_t poll_old, lastpoll_i;  // used to detect change in poll_period: last value, first stamp after change

 /* RTT (in vcount units to avoid pb if phat bad), history window, and level shift */
 static struct bidir_stamp *st_hist;     // history of past stamp records
 static u_int64_t *RTT_hist;             // history of past RTT    values in vcount units; RTTmin values
 static u_int64_t *RTThat_hist;          // history of past RTThat values in vcount units; RTTmin values

 static u_int64_t RTT, RTTlast;          //  current RTT value, last pkt's value
 static u_int64_t RTThat;                //  current estimate of minimal RTT; 
 static u_int32_t RTThat_i;              //   corresponding index
 static u_int64_t RTThat_new=0;          //  RTT estimate beginning from middle of history window
 static u_int64_t RTThat_sh=0;           //  sliding window RTT estimate for upward level shift detection
 static u_int64_t sh_thres;              //  threshold in [vcount] units for triggering upward shift detection
 static u_int32_t lastshift=0;           //  index of first stamp after last detected upward shift 
 static u_int32_t history_begin, history_end;  // history window is i in [begin end]

 /* vcount period estimation phat */
 static double phat, phat_new; 			// period estimates
 		double phat_b, phat_f; 			// period estimates
 static double perr; 					// estimate of total error of current phat [unitless]
 static	double perr_ij;					// estimate of error of phat using given stamp pair [i,j]
 		long double DelTb, DelTe; 		// Time between j and i based on each NTP timestamp
		u_int64_t DelTa, DelTf;			// Time between j and i based on each NTP timestamp
 static double baseerr;                  // holds difference in quality RTTmin values at different stamps
 static u_int32_t jsearch_win;           // window width for choosing pkt j 
 static u_int32_t jcount;                // counter for search window
 static u_int32_t newpkt_j, pkt_j, pkt_i=0;   // pkt indices used for phat algo;  Zero records if never had a pkt_i for this pkt_j
 static double newperr_j, perr_j;      // corresponding point errors [sec]
 		double perr_i;
 static u_int64_t newRTTj, newRTThatj,  RTTj, RTThatj;     // and RTT and RTThat values used at the time
 static struct bidir_stamp newstampj, stampj; // and stamps
 static u_int32_t phat_sanity_count;

 /* Warmup */
 static unsigned int warmup_winratio=4; // gives fraction of Delta(t) sacrificed to near and far search windows
 static u_int32_t wwidth;               // width of end windows in pkt units (also used for plocal)
 static u_int32_t near_i, far_i;        // indices of minimal RTT within near and far windows 

 /* plocal */
 /* XXX: Tuning 
  * 	static unsigned int plocal_winratio=30;// gives fraction of Delta(t) sacrificed to near and far search windows
  */
 static unsigned int plocal_winratio=5;// gives fraction of Delta(t) sacrificed to near and far search windows
 static double plocal, plocal_new;
 static double plocalerr;               // estimate of total error of current plocal [unitless]
 static u_int32_t plocal_sanity_count;
 static int using_plocal, plocal_restartscheduled = 0; // state variable for plocal refinement of algo:  1 = ON, 0 = OFF, if plocal reinit required

 /* C(t) offset estimation   C(t) = vcount(t)*phat + C,   theta(t) = C(t) - t */
 static long double C; // long double since must hold [sec] since timescale origin, and at least 1mus precision
 static double thetahat, thetahat_new;             // double ok since this corrects clock which is already almost right
 static double* thnaive_hist;                      // history of past th_naive values
 double errTa =0, errTf =0;                        // calculate causality errors for correction of thetahat
 double  wj, wsum=0, th_naive=0, ET=0, minET=0;	   // weight of pkt i;  sum of weights; naive estimate
 static double minET_last;                          // previous estimate kept for diagnosis
 double gapsize;                                   // size in seconds between pkts, used to track widest gap in offset_win
 static u_int32_t lastthetahat;                    // index of last RELIABLE thetahat 
 		int gap=0;                                 // logical: 1 = have found a large gap at THIS stamp
 static struct bidir_stamp lastthetastamp;         // record stamp at i=lastthethahat
 static u_int32_t  offset_sanity_count, offset_quality_count;  // counters of error conditions
 static u_int32_t  poll_transition_th, adj_win;       // counter for transition period for thetahat after change in poll_period; adjusted window
 static double poll_ratio;                         // record of poll_period/old_poll made when period changes


 /* Statistic string buffers */
 #define STAT_SZ 250 
 static char *stat_phat;

/* Sanity checks on input stamp is supposed to be done before this function is
 * called
 */
 


/* =============================================================================
 * UNIX SIGNALS
 * =============================================================================
 */


/* React to signals passed at startup or in case the daemon rehashed the
 * configuration file
 */

/* UPDMASK_PLOCAL */
/* Here is the tricky semantic part If sig_plocal is set to 0 and 1, we check
 * first is the value just changed.  If sig_local is set to 2, we may be willing
 * to restart consecutively several times without a change in the configuration
 * file.  For this reason, the main program falls back to PLOCAL_START, then a
 * reload of the conf file with plocal set to 2 but inchanged restart plocal. 
 */
if ( i==0 || HAS_UPDATE(conf->mask, UPDMASK_PLOCAL) ) {
	/* Adjust state of plocal according to signal */
	if (sig_plocal == PLOCAL_START || sig_plocal == PLOCAL_RESTART)
		using_plocal = 1;
	/* PLOCAL_STOP or anything else
	 * (variable plocal not used in any way, no further action required)
	 */
 	else
		using_plocal = 0;
}



/* Initialize key algorithm variables:
 * algo parameters, window sizes, history structures, states, poll period effects
 * triggered on first stamp or on config update for UPDMASK_POLLPERIOD
 * and UPDMASK_TEMPQUALITY 
 */
if ( HAS_UPDATE(conf->mask, UPDMASK_POLLPERIOD) || HAS_UPDATE(conf->mask, UPDMASK_TEMPQUALITY))
{
	 /* Initialize the error thresholds */
	init_errthresholds( phyparam, &Eshift, &Ep, &Ep_qual, &Ep_sanity,
			&Eplocal_qual, &Eplocal_sanity,
			&Eoffset, &Eoffset_qual,
			&Eoffset_sanity_min, &Eoffset_sanity_rate);

	/* Set pkt-index algo windows.
	 * These control the algo, independent of implementation.
	 */
	set_algo_windows( phyparam, poll_period, 
			history_scale, &h_win, &shift_win, 
			&offset_win, &plocal_win );

	/* Ensure Warmup_win consistent with algo windows for easy 
	 * initialisation of main algo after warmup 
	 */
	if (i < Warmup_win)
		/* XXX Tuning: fine tune these */
		adjust_Warmup_win(i, poll_period, &Warmup_win, 
				&h_win, &shift_win, &offset_win, 
				&plocal_win, plocal_winratio);
	else {
		/* Re-init shift window from stamp i-1 back
		 * ensure don't go past 1st stamp
		 * find history constraint (follows that of RTThat already tracked)
		 * window was reset, not 'slid'
		 */
		shift_end = (u_int32_t) MAX(0, ((long)i-1) - (long)shift_win+1);
		shift_end = MAX(shift_end, RTT_end);
		RTThat_sh = RTT_hist[ min(RTT_hist, shift_end, i-1, RTT_win)%RTT_win ];
	}

	/* Set history array sizes.
	 * If warmup is to be sacred, each must be larger than the 
	 * current Warmup_win here 
	 * NOTE:  if set right, new histories will be big enough 
	 * for future needs, doesn't mean required data is in them 
	 * after window resize!! */
	if (i < Warmup_win) {
		st_win 		= Warmup_win;
		RTT_win 	= Warmup_win;
		RTThat_win 	= Warmup_win;
		thnaive_win = Warmup_win;
	}
	else {
		/* RTTHat_win and thnaive_win need >= offset_win */
		st_win 		= MAX(plocal_win + plocal_win/(plocal_winratio/2), offset_win);
		RTT_win 	= MAX(plocal_win + plocal_win/(plocal_winratio/2), MAX(offset_win, shift_win));
		RTThat_win 	= offset_win;
		thnaive_win = offset_win;
	}

	/* Allocate memory for histories.
	 * Each history has its own window length used for wrapped indexing
	 * if i==0 then it is the first memory allocation
	 * else, resize histories since parameters and therefore 
	 *  algo windows have changed, MAY need more space 
	 *  note: currently stamps [_end,i-1] in history, i not yet processed
	 */
	resize_histories(i-1, &st_hist, st_win, st_win_old, &st_end,
				&RTT_hist, RTT_win, RTT_win_old, &RTT_end,
				&RTThat_hist, RTThat_win, RTThat_win_old, &RTThat_end,
				&thnaive_hist, thnaive_win, thnaive_win_old, &thnaive_end);

	/* record current history windows */
	st_win_old 		= st_win;
	RTT_win_old 	= RTT_win;
	RTThat_win_old 	= RTThat_win;
	thnaive_win_old = thnaive_win;

	/* Ensure poll_period changes dealt with 
	 * poll_transition_th: could be off by one depending on 
	 *   when NTP pkt rate changed, but not important
	 * lastpoll_i: index of last change
	 */
	if ( poll_period != poll_old ) {
		poll_transition_th = offset_win;
		poll_ratio = (double)poll_period/(double)poll_old;
		poll_old = poll_period;
		lastpoll_i = i;
	}

	/* Print out summary of parameters:
	 * physical, network, thresholds, and sanity 
	 */
	verbose(VERB_CONTROL, "Machine Parameters:  TSLIMIT: %g, SKM_SCALE: %d, RateErrBOUND: %lg, BestSKMrate: %lg",
			phyparam->TSLIMIT, (int)phyparam->SKM_SCALE, phyparam->RateErrBOUND, phyparam->BestSKMrate);
	verbose(VERB_CONTROL, "Network Parameters:  poll_period: %u, h_win: %d ", poll_period, h_win);
	verbose(VERB_CONTROL, "Windows (in pkts):   warmup: %u, history: %u, shift: %u "
			"(thres = %4.0lf [mus]), plocal: %u, offset: %u (SKM scale is %u)",
			Warmup_win,h_win, shift_win, Eshift*1000000,plocal_win, offset_win,
			(u_int32_t) (phyparam->SKM_SCALE/poll_period) );
	verbose(VERB_CONTROL, "Error thresholds :   phat:  Ep %3.2lg [ms], Ep_qual %3.2lg [PPM],    "
			"plocal:  Eplocal_qual %3.2lg [PPM]", 1000*Ep, 1.e6*Ep_qual, 1.e6*Eplocal_qual);
	verbose(VERB_CONTROL, "                     offset:  Eoffset %3.1lg [ms], Eoffset_qual %3.1lg [ms]",
			1000*Eoffset, 1000*Eoffset_qual);
	verbose(VERB_CONTROL, "Sanity Levels:       phat  %5.3lg, plocal  %5.3lg, offset: "
			"absolute:  %5.3lg [ms], rate: %5.3lg [ms]/[sec] ( %5.3lg [ms]/[stamp])",
		   	Ep_sanity, Eplocal_sanity, 1000*Eoffset_sanity_min, 
			1000*Eoffset_sanity_rate, 1000*Eoffset_sanity_rate*poll_period);

}




/* TODO: we should return right after this function-to-be!!! and not go in
 * warmup. Fix code branches ... need define proper states for the algo to
 * rewrite goto statement !!
 */

/* =============================================================================
 * INITIALISATION
 * =============================================================================
 */
if ( i == 0 )
{
	/* UPDATE The following was extracted from the block related to first packet
	 * and reaction to poll period and external environment parameters
	 */

	 /* Initialize the error thresholds */
	init_errthresholds( phyparam, &Eshift, &Ep, &Ep_qual, &Ep_sanity,
			&Eplocal_qual, &Eplocal_sanity,
			&Eoffset, &Eoffset_qual,
			&Eoffset_sanity_min, &Eoffset_sanity_rate);

	/* Set pkt-index algo windows.
	 * These control the algo, independent of implementation.
	 */
	set_algo_windows( phyparam, poll_period, 
			history_scale, &h_win, &shift_win, 
			&offset_win, &plocal_win );

	/* Ensure Warmup_win consistent with algo windows for easy 
	 * initialisation of main algo after warmup 
	 */
	adjust_Warmup_win(i, poll_period, &Warmup_win, 
			&h_win, &shift_win, &offset_win, 
			&plocal_win, plocal_winratio);

	st_win 		= Warmup_win;
	RTT_win 	= Warmup_win;
	RTThat_win 	= Warmup_win;
	thnaive_win = Warmup_win;

	/* Allocate memory for histories.
	 * Each history has its own window length used for wrapped indexing
	 *  note: currently stamps [_end,i-1] in history, i not yet processed
	 */
	/* TODO: these are technically leaked but we'll see once variables reorganised */
	st_hist 		= (struct bidir_stamp*) malloc(st_win*sizeof(struct bidir_stamp) );
	RTT_hist 		= (u_int64_t*) malloc( RTT_win*sizeof(u_int64_t) );
	RTThat_hist 	= (u_int64_t*) malloc( RTThat_win*sizeof(u_int64_t) );
	thnaive_hist 	= (double*) malloc( thnaive_win*sizeof(double) );
	st_end = RTT_end = RTThat_end = thnaive_end = 0;
	
	/* record current history windows */
	st_win_old 		= st_win;
	RTT_win_old 	= RTT_win;
	RTThat_win_old 	= RTThat_win;
	thnaive_win_old = thnaive_win;

	/* poll_transition_th: begin with no transition for thetahat
	 * lastpoll_i: index of last change
	 */
	poll_old = poll_period;
	poll_transition_th = 0;
	lastpoll_i = 0;

	/* Print out summary of parameters:
	 * physical, network, thresholds, and sanity 
	 */
	verbose(VERB_CONTROL, "Machine Parameters:  TSLIMIT: %g, SKM_SCALE: %d, RateErrBOUND: %lg, BestSKMrate: %lg",
			phyparam->TSLIMIT, (int)phyparam->SKM_SCALE, phyparam->RateErrBOUND, phyparam->BestSKMrate);
	verbose(VERB_CONTROL, "Network Parameters:  poll_period: %u, h_win: %d ", poll_period, h_win);
	verbose(VERB_CONTROL, "Windows (in pkts):   warmup: %u, history: %u, shift: %u "
			"(thres = %4.0lf [mus]), plocal: %u, offset: %u (SKM scale is %u)",
			Warmup_win,h_win, shift_win, Eshift*1000000,plocal_win, offset_win,
			(u_int32_t) (phyparam->SKM_SCALE/poll_period) );
	verbose(VERB_CONTROL, "Error thresholds :   phat:  Ep %3.2lg [ms], Ep_qual %3.2lg [PPM],    "
			"plocal:  Eplocal_qual %3.2lg [PPM]", 1000*Ep, 1.e6*Ep_qual, 1.e6*Eplocal_qual);
	verbose(VERB_CONTROL, "                     offset:  Eoffset %3.1lg [ms], Eoffset_qual %3.1lg [ms]",
			1000*Eoffset, 1000*Eoffset_qual);
	verbose(VERB_CONTROL, "Sanity Levels:       phat  %5.3lg, plocal  %5.3lg, offset: "
			"absolute:  %5.3lg [ms], rate: %5.3lg [ms]/[sec] ( %5.3lg [ms]/[stamp])",
		   	Ep_sanity, Eplocal_sanity, 1000*Eoffset_sanity_min, 
			1000*Eoffset_sanity_rate, 1000*Eoffset_sanity_rate*poll_period);


	/* UPDATE: Next is the original code of this block */


	/* Initialise laststamp to default value */
	memset(&laststamp, 0, sizeof(struct bidir_stamp));

	/* Start up only 
	 * vcount_init: vcount origin at beginning of calibration 
	 * t_init: time origin at beginning of calibration
	 * */
	verbose(VERB_SYNC, "Initialising RADclock synchronization");
	vcount_init = stamp->Ta;
	t_init 	 = stamp->Tb;
	verbose(VERB_SYNC, "Initial vcounter value = %llu , t_init = %Lf", vcount_init, t_init);

	/* Print the first timestamp tuple obtained */
	verbose(VERB_SYNC, "Stamp read check: %llu %22.10Lf %22.10Lf %llu",
	stamp->Ta, stamp->Tb, stamp->Te, stamp->Tf);

	verbose(VERB_SYNC, "Assuming 1Ghz oscillator, 1st vcounter stamp is %5.3lf [days] "
			"(%5.1lf [min]) since reset, RTT is %5.3lf [ms], SD %5.3Lf [mus]",
			(double) stamp->Ta * 1e-9/3600/24, (double) stamp->Ta * 1e-9/60, 
			(double) (stamp->Tf - stamp->Ta) * 1e-9*1000, (stamp->Te - stamp->Tb) * 1e6);


	/* MinET_old 
	 * Initialise to 0 on first packet (static variable) 
	 */
	minET_last = 0;

	/* Record stamp 0 */
	copystamp(stamp, &st_hist[i%st_win]);

	/* RTT */
	RTT 	= MAX(1,stamp->Tf - stamp->Ta);
	RTThat 	= RTT;
	RTT_hist[i%RTT_win] = RTT;

	/* vcount period and clock definition.
	 * Once determined, C only altered to correct phat changes 
	 * note: phat unavailable after only 1 stamp, use config value, rough guess of 1Ghz beats zero!
	 */
	phat = clock_handle->conf->phat_init;
	perr = 0;
	/* Initializations for phat warmup algo 
	 * wwidth: initial width of end search windows. 
	 * near_i: index of stamp with minimal RTT in near window  (larger i)
	 * far_i: index of stamp with minimal RTT in  far window  (smaller i)
	 */
	wwidth = 1;
	near_i = 0;
	far_i  = 0;

	/* C now determined.  For now C(t) = t_init */
	C = t_init - (long double)(vcount_init*phat);
	verbose(VERB_SYNC, "i=%u: After initialisation: (far,near)=(%u,%u), "
			"phat = %12.10lg, perr=%5.3lg, C-t_init=%Lf, C: %7.4Lf",
			i, 0, 0, phat,perr, C-t_init, C);

	/* plocal algo 
	 * refinement pointless here, just copy. If not active, never used, no cleanup needed 
	 * TODO: we can probably clean that up and the management of UNIX signal
	 * regarding plocal at the same time. The logic there is cumbersome because
	 * of historical changes ... ways to make it much simpler and better.
	 */
	if (using_plocal)
		plocal = phat;

	/* thetahat algo */
	th_naive = 0;
	/* initialise on-line warmup algo */
	thetahat = th_naive;
	thnaive_hist[0] = th_naive;

	/* Allocate memory for statistic strings */
	stat_phat 		= (char *) malloc(STAT_SZ * sizeof(char));

/* TODO ... to remove once we put that block into a function */
goto record_and_exit;

}


// XXX this should probably go to init functions
/* On second packet, i=1, let's get things started */
if (i==1) {
	/* Set the status of the clock to STARAD_WARMUP */
	verbose(VERB_CONTROL, "Beginning Warmup Phase");
	ADD_STATUS(clock_handle, STARAD_WARMUP);
	ADD_STATUS(clock_handle, STARAD_UNSYNC);
}



/* Arbitrarily, need at least 25 packets to clear UNSYNC status but this should
 * be driven by some quality value. Also should make it reflects long gaps
 * (outside the algo?). So need to clear once we recover from gaps or data
 * starvation. Ideally, should not be right on recovery (i.e. the > test) but
 * when quality gets good. This is however a quick working trick
 */
if (i > 25) {
	/* Set the status of the clock to STARAD_UNSYNC */
	DEL_STATUS(clock_handle, STARAD_UNSYNC);
}






/* =============================================================================
 * BEGIN SYNCHRONISATION
 *
 * First, Some universal processing for all stamps i > 0
 * =============================================================================
 */



/* Current RTT - universal!
 * Avoids zero or negative values in case of corrupted stamps
 */
RTT = MAX(1,stamp->Tf - stamp->Ta);

/* Store history of basics
 * [use circular buffer   a%b  performs  a - (a/b)*b ,  a,b integer]
 * copy stamp i into history immediately, will be used in loops
 */
copystamp(stamp, &st_hist[i%st_win]);
RTT_hist[i%RTT_win] = RTT;

/* track last stamp in window [if full, drop one off, else, doesn't change] */
if ( (i - st_end) == st_win )
	st_end += 1;
if ( (i - RTT_end) == RTT_win )
	RTT_end += 1; 







/* =============================================================================
 * HISTORY WINDOW MANAGEMENT
 * This should only be kicked in when we are out of warmup,
 * but since history window way bigger than warmup, this is safe
 * This resets history prior to stamp i
 * Shift window not affected 
 * =============================================================================
 */

/* Initialize:  middle of very first window */
if ( i == h_win/2 ) {
	/* reset half window estimate - previously  RTThat=RTThat_new */
	RTThat_new = RTTlast;

	/* initiate on-line algo for new pkt_j calculation * [needs to be in surviving half of window!]
	 * record newpkt_j (index), RTT, RTThat, point error and stamp
	 * TODO: jsearch_win should be chosen < ??
	 */
	jsearch_win = Warmup_win;
	jcount = 1;
	newpkt_j = i;
	newRTTj = RTT;
	newRTThatj = RTThat;
	newperr_j = phat*(double)(RTT - RTThat);
	copystamp(stamp, &newstampj);
	/* Now DelTb >= h_win/2,  become fussier */
	Ep_qual /= 10;
	verbose(VERB_CONTROL, "Adjusting history window before normal processing of stamp %u. "
			"FIRST 1/2 window reached",i);
}

	/* at end of history window */
if ( i == history_end ) {
	/* move window ahead by h_win/2 so i is the first stamp in the 2nd half */
	history_begin += h_win/2;
	history_end   += h_win/2;
	/* reset RTT estimate - RTThat_new must have been reset at prior upward * shifts */
	RTThat = RTThat_new;
	/* reset half window estimate - prior shifts irrelevant */
	RTThat_new = RTTlast;
	/* Take care of effects on phat algo
	 * - begin using newpkt_j that has been precalculated in previous h_win/2
	 * - reinitialise on-line algo for new newpkt_j calculation
	 *   Record [index RTT RTThat stamp ]
	 */
	pkt_j 	= newpkt_j;
	RTTj 	= newRTTj;
	RTThatj = newRTThatj;
	perr_j 	= newperr_j;
	copystamp(&newstampj,&stampj);
	jcount = 1;
	newpkt_j 	= i;
	newRTTj 	= RTT;
	newRTThatj 	= RTThat;
	newperr_j 	= phat*(double)(RTT - RTThat);
	copystamp(stamp, &newstampj);
	/* record that no pkt_i matching pkt_j at this point */
	pkt_i = 0;

	verbose(VERB_CONTROL, "Total number of sanity events:  phat: %u, plocal: %u, Offset: %u ",
			phat_sanity_count, plocal_sanity_count, offset_sanity_count);
	verbose(VERB_CONTROL, "Total number of low quality events:  Offset: %u ", offset_quality_count);
	verbose(VERB_CONTROL, "Adjusting history window before normal processing of stamp %u. "
			"New pkt_j = %u ", i, pkt_j);
}




/* =============================================================================
 * GENERIC DESCRIPTION
 *
 * WARMUP MODDE
 * 0<i<Warmup_win
 * pt errors are unreliable, need different algos 
 * RTT:  standard on-line 
 * upward shift detection:  disabled 
 * history window:  no overlap by design, so no need to map stamp indices via  [i%XX_win] 
 * phat:  use plocal type algo, or do nothing if stored value (guarantees value available ASAP), no sanity 
 * plocal:  not used, just copies phat, no sanity.
 * thetahat:  simple on-line weighted average with aging, no SD quality refinement (but non-causal warnings)
 * sanity checks:  switched off except for NAN check (warning in case of offset)
 *
 * FULL ALGO
 * Main body, i >= Warmup_win
 * Start using full algos [still some initialisations left]
 * Start wrapping history vectors   
 * =============================================================================
 */






/* =============================================================================
 * RTT 
 * =============================================================================
 */

if (i < Warmup_win ) {
	/* Record the minimum of RTT and index */
	if ( RTT < RTThat ) {
		RTThat = RTT;
	  	/* TODO: this is only used in phat end of warmup
		 *  can be replaced to avoid possible side effects?
		*/
		RTThat_i = i;
	}
}
else {
	/* Normal RTT updating.
	 * This processes the new RTT=RTT_hist[i] of stamp i
	 * Algos always simple: History transparently handled before stamp i
	 * shifts below after normal i
	 * - RTThat always below or equal RTThat_sh since h_win/2 > shift_win
	 * - RTTHat_new above or below RTThat_sh depending on position in history
	 * - RTTHt_end tracks last element stored
	 */
	RTThat = MIN(RTThat, RTT);
	RTThat_hist[i%RTThat_win] = RTThat;
	RTThat_new = MIN(RTThat_new, RTT);
	if ( (i - RTThat_end) == RTThat_win )
		RTThat_end += 1;

	/* if window (including processing of i) is not full,
	 * keep left hand side (ie shift_end) fixed and add pkt i on the right.
	 * Otherwise, window is full, and min inside it (thanks to reinit), can slide
	 */
	if ( (u_int32_t) MAX(0, (long)i-(long)shift_win+1) < shift_end ) {
		verbose(VERB_CONTROL, "In shift_win transition following window change, "
				"[shift transition] windows are [%u %u] wide", 
				shift_win,i-shift_end+1);
		RTThat_sh =  MIN(RTThat_sh,RTT);     
	} 
	else {
		RTThat_sh = min_slide_value(RTT_hist, RTThat_sh, shift_end, i-1, RTT_win);
		shift_end++;
	}

	/* Upward Shifts. 
	 * This checks for detection over window of width shift_win prior to stamp i 
	 * Detection about reaction to RTThat_sh. RTThat_sh itself is simple, always just a sliding window 
	 * lastshift is the index of first known stamp after shift
	 */
	if ( RTThat_sh > (RTThat + sh_thres) ) { 
		lastshift = i-shift_win + 1;
		verbose(VERB_SYNC, "Upward shift of %5.1lf [mus] triggered when i = %u ! "
				"shift detected at stamp %u", (RTThat_sh-RTThat)*phat*1.e6, i, lastshift);
		/* Recalc from [i-lastshift+1 i] 
		 * - note by design, won't run into last history change 
		 */
		RTThat = RTThat_sh;
		RTThat_new = RTThat;
		/* Recalc necessary for phat
		 * - note pkt_j must be before lastshift by design
		 * - note that phat not the same as before, but that's ok
		 */
		if ( newpkt_j >= lastshift) {
			verbose(VERB_SYNC, "Recalc necessary for newpkt_j = %u", newpkt_j);
			newperr_j 	= phat*(double)(newRTTj - RTThat); 
			newRTThatj 	= RTThat;
		}
		/* Recalc necessary for offset 
		 * typically shift_win >> offset_win, so lastshift won't bite
		 * correct RTThat history back as far as necessary or possible
		 */
		for ( j=(long)i; j>=(long)MAX(lastshift,i-offset_win+1); j--)
			RTThat_hist[j%RTThat_win] = RTThat;
		verbose(VERB_SYNC, "Recalc necessary for RTThat for %u stamps back to i=%u", shift_win,lastshift);
	}
}




/* =============================================================================
 * PHAT ALGO 
 * =============================================================================
 */

if ( i < Warmup_win ) {
	
	/* Select indices for new estimate 
	 * Indices taken from a far window: stamps [0 wwidth-1],  and near window:  [i-wwidth+1 i]
	 * Still works if poll_period changed, but rate increase of end windows can be different
	 * if stamp index not yet a multiple of warmup_winratio: find near_i by sliding along one on RHS
	 * else: increase near and far windows by 1, find index of new min RTT in both, increase window width
	 */
	if ( i%warmup_winratio )
		near_i = min_slide(RTT_hist, near_i, i-wwidth, i-1, RTT_win);
	else {
		if ( RTT_hist[wwidth%RTT_win] < RTT_hist[far_i%RTT_win] )
			far_i = wwidth;
		if ( RTT < RTT_hist[near_i%RTT_win] )
			near_i = i;
		wwidth++;
	}

	/* Compute time intervals between NTP timestamps of selected stamps */
	DelTa = st_hist[near_i%st_win].Ta - st_hist[far_i%st_win].Ta;
	DelTb = st_hist[near_i%st_win].Tb - st_hist[far_i%st_win].Tb;
	DelTe = st_hist[near_i%st_win].Te - st_hist[far_i%st_win].Te;
	DelTf = st_hist[near_i%st_win].Tf - st_hist[far_i%st_win].Tf;

	/* Check for crazy values, and NaN cases induced by DelTa or DelTf equal zero
	 * Log a major error and hope someone will call us
	 */
	if ( ( DelTa <= 0 ) || ( DelTb <= 0 ) || (DelTe <= 0 ) || (DelTf <= 0) ) {
		verbose(LOG_ERR, "i=%u we picked up the same i and j stamp. Contact developer.", i);
	}

	/* Use naive estimates from chosen stamps {i,j}, don't check quality 
	 * forward  (OUTGOING, sender)
	 * backward (INCOMING, receiver)
	 */
	phat_f 		= (double) (DelTb / DelTa);
	phat_b 		= (double) (DelTe / DelTf);
	phat_new 	= (phat_f + phat_b) / 2;

	/* Clock correction
	 * correct C to keep C(t) continuous at time of last stamp
	 */
	if ( phat != phat_new ) {
		C += laststamp.Ta * (long double) (phat - phat_new);
		verbose(VERB_SYNC, "i=%u: phat update (far,near)=(%u,%u), "
				"(phat_new, rel diff, perr): %12.10lg , %7.2lg, %7.2lg, C: %7.4Lf",
				i, far_i, near_i, phat_new, (phat_new-phat)/phat_new, perr, C);
		phat = phat_new;
		perr = phat * (double)((RTT_hist[far_i%RTT_win]-RTThat) 
				+ (RTT_hist[near_i%RTT_win]-RTThat)) / DelTb;
	}
}




else {

	/* on-line calculation of new pkt_j
	 * If we are still in the jsearch window attached to start of current half
	 * h_win then record this stamp if it is of better quality.
	 * Record [index RTT RTThat point-error stamp ]
	 * Only track and record the value that will be used in the next h_win/2
	 * window it is NOT used for computing phat with the current stamp.
	 */
	if ( jcount <= jsearch_win ) {
		jcount++;
		if ( RTT < newRTTj ) {
			newpkt_j 	= i;
			newRTTj 	= RTT;
			newRTThatj 	= RTThat;
			newperr_j 	= phat * (double)(RTT - RTThat);
			copystamp(stamp, &newstampj);
		}
	}

	/* Compute time intervals between NTP timestamps of selected stamps */
	DelTa = stamp->Ta - stampj.Ta;
	DelTb = stamp->Tb - stampj.Tb;
	DelTe = stamp->Te - stampj.Te;
	DelTf = stamp->Tf - stampj.Tf;

	/* Check for crazy values, and NaN cases induced by DelTa or DelTf equal zero
	 * Log a major error and hope someone will call us
	 */
	if ( ( DelTa <= 0 ) || ( DelTb <= 0 ) || (DelTe <= 0 ) || (DelTf <= 0) ) {
		verbose(LOG_ERR, "i=%u we picked up the same i and j stamp. Contact developer.", i);
	}

	/* Determine if quality of i sufficient to bother, if so, if (j,i) sufficient to update phat 
	 * perr_i: point error of i
	 * if error smaller than Ep, quality pkt, proceed, else do nothing
	 */
	perr_i = phat * (double)(RTT - RTThat);
	if ( perr_i < Ep ) {
		/* Point errors (local)
		 * level shifts (global)  (can also correct for error in RTThat assuming no true shifts)
		 * (total err)/Del(t) = (queueing/Delta(vcount))/p  ie  error relative to p
		 */
		perr_ij = fabs(perr_i) + fabs(perr_j);
		baseerr = phat * (double) labs( (long)(RTThat-RTThatj) );
		perr_ij = (perr_ij + baseerr) / DelTb;

		/* If better, or extremely good, update with naive estimate using (j,i) , else do nothing
		 * if extremely good, accept in order to gracefully track
		 * avoids possible lock-in (eg due to 'lucky' error on error estimate)
		 * phat_f: forward  (OUTGOING, sender)*
		 * phat_b: backward (INCOMING, receiver)
		 * perr: record improved quality
		 * pkt_i: record 2nd packet index
		 */
		if ( (perr_ij < perr) || (perr_ij < Ep_qual) ) {
			phat_f 		= (double) (DelTb / DelTa);
			phat_b 		= (double) (DelTe / DelTf);
			phat_new 	= (phat_f + phat_b) / 2;
			perr 		= perr_ij;
			pkt_i 		= i;

			/* Create statistic string, values reflect last time there has been
			 * a candidate found but may not pass sanity check
			*/
			snprintf(stat_phat, STAT_SZ, "phat stats: (j,i)=(%u,%u), "
					"rel diff = %7.2lg, perr = %5.3lg, baseerr = %5.3lg, "
					"DelTb = %5.3Lg [hrs], perr_ij = %5.3lg, C-t_init = %Lf",
					pkt_j, pkt_i, (phat_new-phat)/phat_new, perr, baseerr, DelTb/3600, perr_ij, C-t_init); 

			if  ( fabs((phat_new-phat)/phat_new) > phyparam->RateErrBOUND/3 ) {
				verbose(VERB_SYNC, "i=%u: Jump in phat update", i);
				verbose(VERB_SYNC, "i=%u: phat candidate found, %s", i, stat_phat); 
			}
		}
	}

	/* Clock correction and phat update.
	 * Sanity check applies here 
	 * correct C to keep C(t) continuous at time of last stamp
	 */
	if ( phat != phat_new ) {
		if ( (fabs(phat-phat_new)/phat > Ep_sanity) || stamp->qual_warning ) {
			if (stamp->qual_warning)
				verbose(VERB_QUALITY, "i=%u: qual_warning received, following sanity check for phat", i);
			verbose(VERB_SANITY, "i=%u: phat update fails sanity check: %s", i, stat_phat); 
			phat_sanity_count++;
			ADD_STATUS(clock_handle, STARAD_PERIOD_SANITY);
		}
		else {
			C += laststamp.Ta * (long double) (phat - phat_new);
			phat = phat_new;
			DEL_STATUS(clock_handle, STARAD_PERIOD_QUALITY);
			DEL_STATUS(clock_handle, STARAD_PERIOD_SANITY);
		}
	}

	/* Regular statistics print out */
	if ( !(i%2000) ) {
		verbose(VERB_SYNC, "i=%u: %s", i, stat_phat); 
	}
}





/* =============================================================================
 * PLOCAL ALGO 
 * =============================================================================
 */

if (using_plocal) {

if ( i < Warmup_win ) {
	/* refinement pointless here, just copy.
	 * If not active, never used, no cleanup needed
	 */
	plocal = phat;
}

else {
	/* compute index of stamp we require to be available before proceeding (different usage to shift_end etc!)
	 * if not fully past poll transition and have not history ready then 
	 * 		default to phat copy if problems with data or transitions
	 * 		record a problem, will have to restart when it resolves
	 * else proceed with plocal processing 
	 */
	plocal_end = i - plocal_win+1 - wwidth - wwidth/2;
	if ( plocal_end < MAX(lastpoll_i, MAX(st_end,RTT_end)) ) {
		plocal = phat;
		plocal_restartscheduled = 1;
		verbose(VERB_CONTROL, "plocal problem following parameter changes (desired window "
				"first stamp %u unavailable), defaulting to phat while windows fill", plocal_end);
		verbose(VERB_CONTROL, "[plocal_end, lastpoll_i, st_end, RTT_end] : %u %u %u %u ",
				plocal_end, lastpoll_i,st_end,RTT_end);
	}	
	else {
		/* if told to restart resets wwidth and finds near and far pkts
		 * else compute far_i, near_i  (min_slide takes old win as input)
		 */
		if ( sig_plocal == PLOCAL_RESTART || plocal_restartscheduled ) {
			verbose(VERB_CONTROL, "Restart plocal");
			init_plocal(plocal_win, plocal_winratio, RTT_hist, RTT_win, i, &wwidth, &far_i, &near_i); 
			plocal_restartscheduled = 0;
		} 
		else {
			far_i  = min_slide(RTT_hist, far_i, i-wwidth-plocal_win-wwidth/2, i-1-plocal_win-wwidth/2, RTT_win); 
			near_i = min_slide(RTT_hist, near_i, i-wwidth, i-1, RTT_win); 
		}
	
		/* Compute time intervals between NTP timestamps of selected stamps */
		DelTa = st_hist[near_i%st_win].Ta - st_hist[far_i%st_win].Ta;
		DelTb = st_hist[near_i%st_win].Tb - st_hist[far_i%st_win].Tb;
		DelTe = st_hist[near_i%st_win].Te - st_hist[far_i%st_win].Te;
		DelTf = st_hist[near_i%st_win].Tf - st_hist[far_i%st_win].Tf;

		/* Check for crazy values, and NaN cases induced by DelTa or DelTf equal zero
	 	 * Log a major error and hope someone will call us
		 */
		if ( ( DelTa <= 0 ) || ( DelTb <= 0 ) || (DelTe <= 0 ) || (DelTf <= 0) ) {
			verbose(LOG_ERR, "i=%u we picked up the same i and j stamp. Contact developer.", i);
		}

		/* Use naive estimates from chosen stamps {i,j}, don't check quality 
		 * forward  (OUTGOING, sender)
		 * backward (INCOMING, receiver)
		 */
		phat_f 		= (double) (DelTb / DelTa);
		phat_b 		= (double) (DelTe / DelTf);
		plocal_new 	= (phat_f + phat_b) / 2;

		plocalerr = phat * (double)((RTT_hist[far_i%RTT_win]-RTThat)
					+ (RTT_hist[near_i%RTT_win]-RTThat)) / DelTb;

		/* if quality looks good, continue but refuse to update if result looks insane
		 * else retain previous value
		 */
		if ( fabs(plocalerr) < Eplocal_qual ) {
			if ( (fabs(plocal-plocal_new)/plocal > Eplocal_sanity) || stamp->qual_warning) {
				if (stamp->qual_warning)  
					verbose(VERB_QUALITY, "qual_warning received, i=%u, following sanity check for plocal", i);
				verbose(VERB_SANITY, "plocal update at i=%u fails sanity check: relative "
						"difference is: %5.3lg estimated error was  %5.3lg",
						i, fabs(plocal-plocal_new)/plocal, plocalerr);
				plocal_sanity_count++;
				ADD_STATUS(clock_handle, STARAD_PERIOD_SANITY);
			}
			else {
				plocal = plocal_new;
				DEL_STATUS(clock_handle, STARAD_PERIOD_QUALITY);
				DEL_STATUS(clock_handle, STARAD_PERIOD_SANITY);
			}
		}
		else {
			ADD_STATUS(clock_handle, STARAD_PERIOD_QUALITY);
			verbose(VERB_QUALITY, "i=%u: plocal quality low,  (far_i,near_i) = (%u,%u), "
					"not updating plocalerr = %5.3lg,  Eplocal_qual= %5.3lg ",
					i, far_i, near_i, plocalerr, Eplocal_qual);
		}
	}
}
}





/* =============================================================================
 * THETAHAT ALGO 
 * =============================================================================
 */

if ( i < Warmup_win ) {

	/* During warmup, no plocal refinement, no gap detection, no SD error
	 * correction, only simple sanity warning 
	 */
	if ( (stamp->Te - stamp->Tb) >= RTT*phat*0.95 ) {
		verbose(VERB_SYNC, "i=%d: Apparent server timestamping error, RTT<SD: "
				"RTT = %6.4lg [ms], SD= %6.4lg [ms], SD/RTT= %6.4lg.",
				i, 1000*RTT*phat, 1000*(double)(stamp->Te-stamp->Tb), (double)(stamp->Te-stamp->Tb)/RTT/phat );
	}
	/* Calculate naive estimate at stamp i
	 * Also track last element stored in thnaive_end
	 */
	th_naive = (phat*((long double)stamp->Ta + (long double)stamp->Tf) + (2*C - (stamp->Tb + stamp->Te)))/2.0;
	thnaive_hist[i%thnaive_win] = th_naive;
	if ( (i-thnaive_end) == thnaive_win )
		thnaive_end += 1;

	/* Calculate weighted sum */
	wsum = 0;
	thetahat_new = 0;
	/* Fix old end of thetahat window:  poll_period changes, offset_win changes, history limitations */
	if ( poll_transition_th > 0 ) {
		/* linear interpolation over new offset_win */
		adj_win = (offset_win - poll_transition_th) + (ceil)(poll_transition_th * poll_ratio);
		verbose(VERB_CONTROL, "In offset_win transition following poll_period change, "
				"[offset transition] windows are [%u %u]", offset_win,adj_win);
		jmin = (u_int32_t)MAX(1,(long)i-(long)adj_win+1);
		poll_transition_th--;
	}
	else {
		/* ensure don't go past 1st stamp, and don't use 1st, as thnaive set to
		 * zero there 
		 */
		jmin = (u_int32_t) MAX(1, (long)i-(long)offset_win+1);
	}
	/* find history constraint */
	jmin = MAX(jmin, MAX(RTT_end, thnaive_end));

	for ( j = (long)i; j >= (long)jmin; j-- ) {
		/* Reassess pt errors each time, as RTThat not stable in warmup.
		 * Errors due to phat errors are small
		 * then add aging with pessimistic rate (safer to trust recent)
		 */
		ET  = phat * (double)( RTT_hist[j%RTT_win] - RTThat );
		ET += phat * (double)( stamp->Tf - st_hist[j%st_win].Tf ) * phyparam->BestSKMrate;

		/* Record best in window, smaller the better. When i<offset_win,
		 * bound to be zero since arg minRTT also in win 
		 */
		if ( j == (long)i ) {
			minET = ET;
			jbest = j;
		}
		else {
			if ( ET < minET) {
				minET = ET;
				jbest = j;
			}
		}
		/* calculate weight, is <=1
		 * note: Eoffset initialised to non-0 value, safe to divide
		 */
		wj = exp(- ET * ET / Eoffset / Eoffset);
		wsum += wj;
		thetahat_new = thetahat_new + wj * thnaive_hist[j%thnaive_win];
	}

	/* Check Quality
	 * quality over window looks good, continue
	 * otherwise log out a quality warning
	 */
	gapsize = phat * (double)(stamp->Tf - laststamp.Tf);
	if ( minET < Eoffset_qual ) {
		/* if wsum==0 just copy thetahat to avoid crashing (can't divide by zero)
		 *   this problem must be addressed by operator
		 * else safe to normalise
		 */
		if ( wsum==0 ) {
			verbose(VERB_QUALITY, "i=%u, quality looks good (minET = %lg) yet wsum=0! "
					"Eoffset_qual = %lg may be too large", i, minET, Eoffset_qual);
			thetahat_new = thetahat;
		}
		else {
			thetahat_new /= wsum;
			/* store est'd quality of new estimate */
			minET_last = minET;
		}
		/* if result looks insane, give warning */
		if ( fabs(thetahat - thetahat_new) > (Eoffset_sanity_min + Eoffset_sanity_rate * gapsize) ) {
			verbose(VERB_SANITY, "thetahat update at i=%u fails sanity check: "
					"difference is: %5.3lg [ms], estimated error was  %5.3lg [ms]",
					i, 1000*(thetahat_new-thetahat), 1000*minET);
			offset_sanity_count++;
			ADD_STATUS(clock_handle, STARAD_OFFSET_SANITY);
		}
		else {
			DEL_STATUS(clock_handle, STARAD_OFFSET_QUALITY);
			DEL_STATUS(clock_handle, STARAD_OFFSET_SANITY);
		}

		/* update value of thetahat, even if sanity triggered */
		thetahat = thetahat_new;
	}
	else {
		verbose(VERB_QUALITY, "thetahat: quality over offset window at i=%u very poor (%5.3lg [ms]), "
				"repeating current value", i, 1000*minET);
		ADD_STATUS(clock_handle, STARAD_OFFSET_QUALITY);
	}

	/* errTa - thetahat should be -ve */
	errTa = (double)((long double)stamp->Ta * phat + C - (long double) stamp->Tb);
	if ( errTa > thetahat ) {
		verbose(VERB_CAUSALITY, "i=%u: causality error on C(Ta), errTa = %6.4lg [ms], "
				"thetahat = %6.4lg [ms], diff  %6.4lg [ms] ",
				i, 1000*errTa, 1000*thetahat, 1000*(errTa-thetahat));
	}

	/* errTf - thetahat should be +ve */
	errTf = (double)((long double)stamp->Tf * phat + C - (long double) stamp->Te);
	if ( errTf < thetahat ) {
		verbose(VERB_CAUSALITY, "i=%u: causality error on C(Tf), errTf = %6.4lg [ms], "
				"thetahat = %6.4lg [ms], diff  %6.4lg [ms] ",
				i, 1000*errTf, 1000*thetahat, 1000*(errTf-thetahat));
	}

	/* warmup to warmup is to pass offset_win */
	if ( (i < offset_win*2) || !(i%50) ) {
		verbose(VERB_SYNC, "i=%u: th_naive: %6.3lg [ms], thetahat = %5.3lg [ms], wsum = %7.5lg, "
				"minET = %5.3lg [ms] (RTThat/2 = %5.3lf)", 
				i, 1000*th_naive, 1000*thetahat_new, wsum,1000*minET,1000*phat*RTThat/2.);
	}
}


else {

	if ( (stamp->Te - stamp->Tb) >= RTT*phat*0.95 ) {
		verbose(VERB_SYNC, "i=%d: Apparent server timestamping error, RTT<SD: "
				"RTT = %6.4lg [ms], SD= %6.4lg [ms], SD/RTT= %6.4lg.",
				i, 1000*RTT*phat, 1000*(double)(stamp->Te-stamp->Tb), (double)(stamp->Te-stamp->Tb)/RTT/phat );
	}

	/* Calculate naive estimate at stamp i
	 * Also track last element stored in thnaive_end
	 */
	th_naive = (phat*((long double)stamp->Ta + (long double)stamp->Tf) + (2*C - (stamp->Tb + stamp->Te)))/2.0;
	thnaive_hist[i%thnaive_win] = th_naive;
	if ( (i-thnaive_end) == thnaive_win )
		thnaive_end += 1;

	/* Initialize gapsize
	 * Detect gaps and note large gaps (due to high loss)
	 * Default is no gap, if one, computed below
	 * gapsize is initialized here for this i, to localize big gaps
	 */
	gapsize = phat * (double)(stamp->Tf - laststamp.Tf);

	/* gapsize is in [sec], but here looking for loss events */
	if ( gapsize > (double) poll_period * 4.5 ) {
		verbose(VERB_SYNC, "i=%u, Non-trivial gap found: gapsize = %5.1lf stamps or %5.3lg [sec]", 
				i, gapsize/poll_period, gapsize);
		if ( gapsize > (double) phyparam->SKM_SCALE ) {
			/* note that are in `big gap' mode, mistrust plocal and trust local th more */
			gap = 1;
			verbose(VERB_SYNC, "End of big gap found at i=%u or %7.4Lg days: "
					"width = %5.3lg [day] or %5.2lg [hr]",
					i, (laststamp.Tb-t_init)/s2Day, gapsize/s2Day, gapsize/3600);
		}
	}

	/* Calculate weighted sum */
	wsum = 0;
	thetahat_new = 0;
	/* Fix old end of thetahat window:  poll_period changes, offset_win changes, history limitations */
	if ( poll_transition_th > 0 ) {
		/* linear interpolation over new offset_win */
		adj_win = (offset_win - poll_transition_th) + (ceil)(poll_transition_th * poll_ratio);
		verbose(VERB_CONTROL, "In offset_win transition following poll_period change, "
				"[offset transition] windows are [%u %u]", offset_win, adj_win);
		jmin = (u_int32_t) MAX(1, (long)i-(long)adj_win+1);
		poll_transition_th--;
	}
	else {
		/* ensure don't go past 1st stamp, and don't use 1st, as thnaive set to
		 * zero there 
		 */
		jmin = (u_int32_t) MAX(1, (long)i-(long)offset_win+1);
	}
	/* find history constraint */
	jmin = MAX(jmin, MAX(st_end, MAX(RTT_end, MAX(RTThat_end, thnaive_end))));

	for ( j = (long)i; j >= (long)jmin; j--) {
		/* first one done, and one fewer intervals than stamps
		 * find largest gap between stamps in window
		 */
		if ( j < (long)i-1 )
			gapsize = MAX(gapsize, phat * (double) (st_hist[(j+1)%st_win].Tf - st_hist[j%st_win].Tf));
		/* Don't reassess pt errors (shifts already accounted for)
		 * then add SD quality measure (large SD at small RTT=> delayed Te, distorting th_naive)
		 * then add aging with pessimistic rate (safer to trust recent)
		 * XXX Tuning: SD quality measure may be problematic with kernel
		 * timestamping on the server side (DAG, 1588) and punish good packets
		 */
		ET  = phat * (double) ( RTT_hist[j%RTT_win] - RTThat_hist[j%RTThat_win] );
		ET += st_hist[j%st_win].Te - st_hist[j%st_win].Tb;
		ET += phat * (double) ( stamp->Tf - st_hist[j%st_win].Tf ) * phyparam->BestSKMrate;

		/* Record best in window, smaller the better. When i<offset_win,
		 * bound to be zero since arg minRTT also in win 
		 */
		if ( j == (long)i ) {
			minET = ET;
			jbest = j;
		}
		else {
			if (ET < minET) {
				minET = ET;
				jbest = j;
			}
		}
		/* calculate weight, is <=1
		 * note: Eoffset initialised to non-0 value, safe to divide
		 */
		wj = exp(- ET * ET / Eoffset / Eoffset);
		wsum += wj;
		/* correct phat already used by difference with more locally accurate plocal */
		if (using_plocal)
			thetahat_new += wj 	* (thnaive_hist[j%thnaive_win] - (plocal/phat-1) 
								* phat * (double) (stamp->Tf - st_hist[j%st_win].Tf));
		else
			thetahat_new += wj*thnaive_hist[j%thnaive_win];
	}

	/* Check Quality and Calculate new candidate estimate
	 * quality over window looks good, use weights over window
	 */
	if ( minET < Eoffset_qual ) {
		/* if wsum==0 just copy thetahat to avoid crashing (can't divide by zero)
		 *   this problem must be addressed by operator
		 * else safe to normalise
		 */
		if ( wsum==0 ) {
			verbose(VERB_QUALITY, "i=%u, quality looks good (minET = %lg) yet wsum=0! "
					"Eoffset_qual = %lg may be too large", i, minET,Eoffset_qual);
			thetahat_new = thetahat;
		}
		else {
			thetahat_new /= wsum;
			/* store est'd quality of new estimate */
			minET_last = minET;
		}
	}
	/* quality bad, forget weights (and plocal refinement) and lean on last reliable estimate */
	else {
		/* TODO: dixit Darryl, this is an optimisation that may be too greedy. to trash ? */
		/* if after a large gap, can't ignore local info completely if want
		 * fast adaptation age the last reliable estimate, it was before the gap
		 */
		if (gap) {
			minET = MAX(Ep, minET_last + phat * (double)(stamp->Tf - lastthetastamp.Tf) * phyparam->RateErrBOUND);
			/* get current point error, need in case last estimate very old */
			ET = MAX(Ep, phat * (double)(RTT - RTThat));
			/* use weighted average of reliable + recent
			 * note: in here both ET and minET != 0, safe to divide
			 */
			thetahat_new = ( thetahat/minET + (th_naive/ET) ) / (1./minET + 1./ET);
			/* store est'd quality of new estimate */
			minET_last = 2 * minET * ET / (minET + ET);
			verbose(VERB_QUALITY, "thetahat: quality very poor at i=%u. [wsum;curr err,old]: "
					"[%5.3lg,%5.3lg,%5.3lg] old inflated,pt err, [%5.3lg,%5.3lg] [ms]",
					i, wsum,1000*minET, 1000*minET_last, 1000*minET, 1000*ET);  
		}

		/* no gap just repeat. Will not get lockout.
		 * Will use new estimate as soon as quality returns
		 */
		else {
			/* if this executes, sanity can't be triggered! quality so bad, simply can't update */
			thetahat_new = thetahat;
			verbose(VERB_QUALITY, "thetahat: quality very poor at i=%u. [wsum;curr err,old]: "
					"[%5.3lg,%5.3lg,%5.3lg]  This pt-err: [%5.3lg] [ms]", 
					i, wsum, 1000*minET, 1000*minET_last, 1000*ET);  
		}
		offset_quality_count++;
		ADD_STATUS(clock_handle, STARAD_OFFSET_QUALITY);
	}

	/* errTa - thetahat should be -ve */
	errTa = (double)((long double)stamp->Ta * phat + C - (long double) stamp->Tb);
	if ( errTa > thetahat )
		verbose(VERB_CAUSALITY, "i=%u: causality error uncorrected on C(Ta), errTa = %6.4lg [ms], "
				"thetahat_new = %6.4lg [ms], diff  %6.4lg [ms]",
				i, 1000*errTa, 1000*thetahat_new, 1000*(errTa-thetahat_new));
	
	/* errTf - thetahat should be +ve */
	errTf = (double)((long double)stamp->Tf * phat + C - (long double) stamp->Te);
	if ( errTf < thetahat )
		verbose(VERB_CAUSALITY, "i=%u: causality error uncorrected on C(Tf), errTf = %6.4lg [ms], "
				"thetahat_new = %6.4lg [ms], diff  %6.4lg [ms]",
				i, 1000*errTf, 1000*thetahat_new,1000*(errTf-thetahat_new));

	/* Apply Sanity Check 
	 * sanity also relative to duration of lockouts due to low quality
	 */
	gapsize = MAX(gapsize, phat * (double)(stamp->Tf - lastthetastamp.Tf) );
	/* if looks insane given gapsize, refuse update */
	if ( ( fabs(thetahat-thetahat_new) > (Eoffset_sanity_min + Eoffset_sanity_rate * gapsize))
			|| stamp->qual_warning)
	{
		if (stamp->qual_warning)
			verbose(VERB_QUALITY, "i=%u qual_warning received, following sanity check for thetahat", i);
		verbose(VERB_SANITY, "i=%u: thetahat update fails sanity check: diff= %5.3lg [ms], "
				"est''d err= %5.3lg [ms], sanity level: %5.3lg [ms] with total gapsize = %7.0lf [sec]",
				i, 1000*(thetahat_new-thetahat), 1000*minET, 1000*(Eoffset_sanity_min+Eoffset_sanity_rate*gapsize), gapsize);
		offset_sanity_count++;
		ADD_STATUS(clock_handle, STARAD_OFFSET_SANITY);
	}
	else {
		/* it passes! update current value 
		 * both sane and quality, then a `true' update, record event for sanity test
		 */
		thetahat = thetahat_new;
		if ( ( minET < Eoffset_qual ) && ( wsum != 0 ) ) {
			lastthetahat = i;
			copystamp(stamp, &lastthetastamp);
		}
		DEL_STATUS(clock_handle, STARAD_OFFSET_QUALITY);
		DEL_STATUS(clock_handle, STARAD_OFFSET_SANITY);
	}

	if (!(i%2000))
		verbose(VERB_SYNC, "i=%u,  th_naive: %6.4lg [ms], thetahat = %6.4lg [ms], "
				"wsum = %7.5lg, minET = %5.3lg [ms] (RTThat/2 = %5.3lf)", 
				i, 1000*th_naive, 1000*thetahat, wsum,1000*minET, 1000*phat*RTThat/2.);

}










/* =============================================================================
 * END OF WARMUP INITIALISATION 
 * =============================================================================
 */

/* RTT Initializations for normal history and level_shift code */
if (i == Warmup_win-1) {
	/* begin now instead of in middle of 1st window (but not used until then) */
	RTThat_new = RTThat;
	shift_end = (u_int32_t)MAX(0,(long)i-(long)shift_win+1);
	/* shift_end = i-shift_win+1  should be enough in warmup, but easy to be careful */
	shift_end = MAX(shift_end,RTT_end);
	/* minimum won't go before 1st stamp */
	RTThat_sh  = RTT_hist[(min(RTT_hist,shift_end,i,RTT_win))%RTT_win];
	history_begin = 0;
	history_end = h_win - 1;

	/* Adjust parameters based on nearby/far away server.
	 * Nearby server is less than 3ms of RTT away 
	 * TODO: this is a bit ugly since Eshift should be set directly to the 
	 * correct value, but ... we will probably have other parameters to 
	 * adjust at the end of warmup. 
	 * Let's create a function for that when we have a list of them
	 */
	if ( RTThat < (3e-3 / phat) ) {
		verbose(VERB_CONTROL, "Detected close server based on minimum RTT");
		/* make sh_thres constant to avoid possible phat dynamics */
		sh_thres = (u_int64_t)ceil(Eshift/phat);
		/* Decoupling Eoffset and Eoffset_qual .. , for nearby servers, the
		 * looser quality has no (or very small?) effect
		 */
		Eoffset_qual = 3 * Eoffset;
	}
	else {
		verbose(VERB_CONTROL, "Detected far away server based on minimum RTT");
		sh_thres = (u_int64_t)ceil(3*Eshift/phat);

		/* Decoupling Eoffset and Eoffset_qual .. , for far away servers, increase the number
		 * of points accepted for preocessing. The bigger the pool period the looser we
		 * have to be. Provide here a rough estimate of the increase of the window based
		 * on data observed with sugr-glider and shouf shouf plots 
		 * 		Eoffset_qual =  exp(log((double) poll_period)/2)/2 * 3 * Eoffset;
		 * [UPDATE]: actually doesn't work because the gaussian penalty function makes these 
		 * additional points be insignificant. Reverted back
		 */
		Eoffset_qual = 6 * Eoffset;
	}
	verbose(VERB_CONTROL, "Upward shift detection activated, threshold set at %llu [vcounter] "
			"(%4.0lf [mus])", sh_thres, sh_thres*phat*1000000);
	verbose(VERB_CONTROL, "Adjusted Eoffset_qual %3.1lg [ms] (Eoffset %3.1lg [ms])", 
			1000*Eoffset_qual, 1000*Eoffset);
}



/* Initializations for normal phat algo 
 * Need: reliable phat, estimate of its error, initial quality pkt j and associated data
 * Approximate error of current estimate from warmup algo, must be beaten before phat updated
 */

if (i == Warmup_win-1) {
	/* on-line version, was min(RTT_hist, 0, i, RTT_win);
	 * initialize 1st pkt to index of current RTThat
	 */
	pkt_j = RTThat_i;
	/* pkt is `perfect', error due to poor RTT estimate will be picked in `global' error component baseerr */
	perr_j = 0;
	/* not local to pkt_j, but this is what was used */
	RTTj = RTThat;
	RTThatj = RTTj;
	copystamp(&st_hist[pkt_j%st_win],&stampj);
	jcount = 1;
 	/* switch off pkt_j search until initialised at h_win/2 */
	jsearch_win = 0;
	/* since RTTs unreliable, don't use local point errors here. */
	perr = phat*(double)((RTT_hist[far_i%RTT_win]-RTThat) + (RTT_hist[near_i%RTT_win]-RTThat)) / (st_hist[near_i%st_win].Tb - st_hist[far_i%st_win].Tb);
	phat_sanity_count = 0;
	verbose(VERB_CONTROL, "Initializing full phat algo, pkt_j=%u, perr= %10.3lg", pkt_j,perr);
}


/* Initializations for normal plocal algo
 * [may not be enough history even in warmup, poll_period will only change timescale]
 */
if (using_plocal) {
if (i == Warmup_win-1) {
 	/* index of stamp we require to be available before proceeding (different usage to shift_end etc!) */
	plocal_end = i - plocal_win + 1-wwidth-wwidth/2;
	if ( plocal_end >= MAX(lastpoll_i, MAX(st_end,RTT_end)) ) {
		/* if fully past poll transition and have history read
		 * resets wwidth as well as finding near and far pkts
		 */
		init_plocal(plocal_win, plocal_winratio, RTT_hist, RTT_win, i, &wwidth, &far_i, &near_i);
		plocal_restartscheduled = 0;
	} 
	else {
		/* record a problem, will have to restart when it resolves */
		plocal_restartscheduled = 1;
		verbose(VERB_CONTROL, "i=%u:  plocal problem following parameter changes "
				"(desired window first stamp %u unavailable), defaulting to phat while windows fill", 
				i, plocal_end);
	}
	plocal_sanity_count = 0;
}
}


/* Initialisation for normal thetahat algo */
if ( i == Warmup_win-1 ) {
	/* fill entire RTThat history with current RTThat not a true history, but appropriate for offset */
	for ( j=0; j <= (long)RTThat_win-1; j++) {
		RTThat_hist[j] = RTThat;
		RTThat_end = i-RTThat_win+1;
	}
	minET_last = minET;
	offset_sanity_count = 0;
	offset_quality_count = 0;
	lastthetahat = i;
	copystamp(stamp, &lastthetastamp);
	verbose(VERB_CONTROL, "Switching to full thetahat algo, RTThat_hist set to RTThat=%llu, "
			"current est'd minimum error= %5.3lg [ms]", 
			RTThat, 1000*minET);

	verbose(VERB_CONTROL, "i=%u: Stamp read check: %llu %22.10Lf %22.10Lf %llu",
			i, stamp->Ta,stamp->Tb,stamp->Te,stamp->Tf);
	verbose(VERB_CONTROL, "End of Warmup Phase");

	/* Remove STARAD_WARMUP from the clock's status */
	DEL_STATUS(clock_handle, STARAD_WARMUP);
}




record_and_exit:

/* =============================================================================
 * RECORD LASTSTAMP AND PREPARE NEXT STAMP 
 * =============================================================================
 */
copystamp(stamp, &laststamp);
RTTlast = RTT;
i++;



/* =============================================================================
 * OUTPUT 
 * =============================================================================
 */


/* TODO: minET is not the correct thetahat error. Should provide a better estimate */

	/* We lock the global data to avoid sending partially updated to client 
	 * through the IPC socket. Also we lock the matlab output data at the same time
	 * to ensure consistency for live captures.
	 */
	pthread_mutex_lock(&clock_handle->globaldata_mutex);
	/* Update clock variable for returning.
	 * The valid_till field has to take into account the fact that ntpd sends
	 * packets with true period intervals [poll-1,poll+2] (see an histogram of 
	 * capture if you are not convinced). Also an extra half a second to be safe.
	 */ 
	GLOBAL_DATA(clock_handle)->phat				= phat;
	GLOBAL_DATA(clock_handle)->phat_err			= perr;
	GLOBAL_DATA(clock_handle)->phat_local		= plocal;
	GLOBAL_DATA(clock_handle)->phat_local_err	= plocalerr;
	GLOBAL_DATA(clock_handle)->ca				= C-(long double)thetahat;
	GLOBAL_DATA(clock_handle)->ca_err			= minET_last;
	GLOBAL_DATA(clock_handle)->last_changed		= stamp->Tf;
	GLOBAL_DATA(clock_handle)->valid_till		= stamp->Tf + ((poll_period -1.5) / phat);

	/* We don't want the leapsecond to create a jump in post processing of data,
	 * so we reverse the operation performed in get_bidir_stamp. With this implementation
	 * this will not have an impact on the matlab output file
	 */
	GLOBAL_DATA(clock_handle)->ca -= ((struct bidir_output*)clock_handle->algo_output)->leapsectotal;
	
	/* Note, retrospective recalcs not typically recorded!
	 * Note: errTa should be -ve, errTf should be +ve 
	 */
	errTa -= thetahat;
	errTf -= thetahat;

	/* Support uniform output format if plocal not used */
	if (!using_plocal)
		plocal = phat;

	/* Fill the output structure, used mainly to fill the matlab file
	 * TODO: there is a bit of redundancy in here
	 */
	OUTPUT(clock_handle, RTT) 			= RTT;
	OUTPUT(clock_handle, phat) 			= phat;
	OUTPUT(clock_handle, perr) 			= perr;
	OUTPUT(clock_handle, plocal) 		= plocal;
	OUTPUT(clock_handle, plocalerr) 	= plocalerr;
	OUTPUT(clock_handle, C) 			= C;
	OUTPUT(clock_handle, thetahat) 		= thetahat;
	OUTPUT(clock_handle, RTThat) 		= RTThat;
	OUTPUT(clock_handle, RTThat_new)	= RTThat_new;
	OUTPUT(clock_handle, RTThat_sh) 	= RTThat_sh;
	OUTPUT(clock_handle, th_naive) 		= th_naive;
	OUTPUT(clock_handle, minET) 		= minET;
	OUTPUT(clock_handle, minET_last)	= minET_last;
	OUTPUT(clock_handle, errTa) 		= errTa;
	OUTPUT(clock_handle, errTf) 		= errTf;
	OUTPUT(clock_handle, wsum) 			= wsum;
	OUTPUT(clock_handle, best_Tf) 		= st_hist[jbest%st_win].Tf;
	OUTPUT(clock_handle, status) 		= GLOBAL_DATA(clock_handle)->status;


	/* NTP server specific data */
	// TODO this is a bit dodgy to have this here ... 
	SERVER_DATA(clock_handle)->serverdelay = RTThat * phat;

	/* Unlock Global Data */
	pthread_mutex_unlock(&clock_handle->globaldata_mutex);


return 0;
}

#undef OUTPUT

