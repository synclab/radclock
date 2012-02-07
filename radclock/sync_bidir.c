/*
 * Copyright (C) 2006-2011 Julien Ridoux <julien@synclab.org>
 * Copyright (C) 2006 Darryl Veitch <dveitch@unimelb.edu.au> 
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


#include "../config.h"
#include "radclock.h"
/* The algo needs access to the global_data structure to update the user level clock */
#include "radclock-private.h"
#include "sync_algo.h"
#include "create_stamp.h"
#include "rawdata.h"
#include "verbose.h"
#include "config_mgr.h"
#include "proto_ntp.h"
#include "sync_history.h"
#include "jdebug.h"




/*
 *  Function to copy a stamp
 */
inline void copystamp(struct bidir_stamp *orig, struct bidir_stamp *copy)
{
	memcpy(copy, orig, sizeof(struct bidir_stamp));
}




/* =============================================================================
 * ALGO INITIALISATION ROUTINES
 * =============================================================================
 */


static void set_algo_windows(struct radclock_phyparam *phyparam, struct bidir_peer *p ) 
{
	index_t history_scale = 3600 * 24 * 7;		/* time-scale of top level window */

	/* top level window, must forget past */
	p->top_win = (index_t) ( history_scale / p->poll_period );

	/* shift detection. Ensure min of 100 samples (reference poll=16).
	 * TODO: right function? 
	 */
	p->shift_win = MAX( (index_t) ceil( (10*phyparam->TSLIMIT/1e-7)/p->poll_period ), 100 );

	/* offset estimation, based on SKM scale (don't allow too small) */
	p->offset_win = (index_t) MAX( (phyparam->SKM_SCALE/p->poll_period), 2 );

	/* local period, not the right function! should be # samples and time based */ 
	p->plocal_win = (index_t) MAX( ceil(p->offset_win*5), 4);
/*	p->plocal_win = (index_t) MAX( ceil(p->offset_win*4), 4);  // XXX Tuning purposes SIGCOMM */ 
}


/* Adjust window values to avoid window mismatches generating unnecessary complexity
 * This version initialises warmup_win on the first pkt, otherwise, after a parameter reload,
 * it takes the new algo windows and again increases the warmup period if necessary.
 * it will never decrease it in time to avoid problems, so there will always be more stamps to serve.
 * it will always recommend keeping existing packets so warmup history is not lost.
 * It also ensures that top_win is large enough.
 */ 
static void adjust_warmup_win(index_t i, struct bidir_peer *p, unsigned int plocal_winratio) 
{
	index_t win;
	double WU_dur;

	verbose(VERB_CONTROL,"Adjusting Warmup window");
	win = MAX(p->offset_win, MAX(p->shift_win, p->plocal_win + p->plocal_win/(plocal_winratio/2) ));

	if (i==0) {
		if ( win > p->warmup_win ) {
			/* simply full algo a little */
			verbose(VERB_CONTROL, "Warmup window smaller than algo windows, increasing "
					"from %lu to %lu stamps", p->warmup_win, win);
			p->warmup_win = win;
		} 
	} else {
		/* Simply adds on an entire new Warmup using new parameters: code can't fail
		 * WU_dur: [sec] of new warmup remaining to serve
		 */
		WU_dur = (double) (win * p->poll_period);
		p->warmup_win = (index_t) ceil(WU_dur / p->poll_period) + i;
		verbose(VERB_CONTROL, 
				"After adjustment, %4.1lf [sec] of warmup left to serve, or %lu stamps. "
				"Warmup window now %lu", 
				WU_dur, (index_t) ceil(WU_dur / p->poll_period), p->warmup_win);
	}

	/* Corollary of the following is that both warmup and shift windows are < top_win/2 , nice */
	if ( p->warmup_win + p->shift_win > p->top_win/2 ) {
		/* can neglect history window in warmup phase */
		verbose(VERB_CONTROL,
				"Warmup + shift window hits history half window, increasing history "
				"window from %lu to %lu", 
				p->top_win, (p->warmup_win + p->shift_win ) * 2 + 1);
		/* small history is bad, make is 3* the minimum possible */
		p->top_win = 3*( (p->warmup_win + p->shift_win) * 2 + 1 );
	}

	verbose(VERB_CONTROL,"Warmup Adjustment Complete");
}





/* Initialization function for normal plocal algo
 * 		Resets wwidth as well as finding near and far pkts 
 * 		poll_period dependence:  via plocal_win
 */
static void init_plocal(struct bidir_peer *peer, unsigned int plocal_winratio, index_t i)
{
	/* History lookup window boundaries */
	index_t lhs;
	index_t rhs;

	/* XXX Tuning ... Accept too few packets in the window makes plocal varies
	 * a lot. Let's accept more packets to increase quality.
	 * 		peer->wwidth = MAX(1,plocal_win/plocal_winratio);
	 */
	/* not used again for phat */
	peer->wwidth = MAX(4, peer->plocal_win/plocal_winratio);
	lhs = i - peer->plocal_win + 1 - peer->wwidth/2;
	rhs = i - peer->plocal_win + peer->wwidth - peer->wwidth/2;
	peer->far_i  = history_min(&peer->RTT_hist, lhs, rhs);

	lhs = i - peer->wwidth + 1;
	rhs = i;
	peer->near_i = history_min(&peer->RTT_hist, lhs, rhs);
	verbose(VERB_CONTROL, "i=%lu: Initializing full plocal algo, wwidth= %lu, "
			"(far_i,near_i) = (%lu,%lu)",
			peer->stamp_i, peer->wwidth, peer->far_i, peer->near_i);
}



/* Initialise the error threshold.
 * This procedure is a trick to modify static variables on 
 * reception of the first packet only.
 */
static void init_errthresholds( struct radclock_phyparam *phyparam, struct bidir_peer *peer) 
{
	/* XXX Tuning history:
	 * original: 10*TSLIMIT = 150 mus
	 * 		peer->Eshift			=  35*phyparam->TSLIMIT;  // 525 mus for Shouf Shouf?
	 */
	peer->Eshift				= 10*phyparam->TSLIMIT;
	peer->Ep					= 3*phyparam->TSLIMIT;
	peer->Ep_qual				= phyparam->RateErrBOUND/5;
	peer->Ep_sanity				= 3*phyparam->RateErrBOUND;
	/* XXX Tuning history:
	 * 		peer->Eplocal_qual	= 4*phyparam->BestSKMrate;  // Original
	 * 		peer->Eplocal_qual	= 4*2e-7; 		// Big Hack during TON paper
	 * 		peer->Eplocal_qual	= 40*1e-7;		// Tuning for Shouf Shouf tests ??
	 * but finally introduced a new parameter in the config file
	 */
	peer->Eplocal_qual			= phyparam->plocal_quality;
	peer->Eplocal_sanity		= 3*phyparam->RateErrBOUND;

	/* XXX Tuning history:
	 * 		*Eoffset		= 6*phyparam->TSLIMIT;  // Original
	 * but finally introduced a new parameter in the config file
	 */
	peer->Eoffset				= phyparam->offset_ratio * phyparam->TSLIMIT;

	/* XXX Tuning history: 
	 * We should decouple Eoffset and Eoffset_qual ... conclusion of shouf shouf analysis 
	 * Added the effect of poll period as a first try (~ line 740) 
	 * [UPDATE] - reverted ... see below
	 */
	peer->Eoffset_qual			= 3*(peer->Eoffset);
	peer->Eoffset_sanity_min	= 100*phyparam->TSLIMIT;
	peer->Eoffset_sanity_rate	= 20*phyparam->RateErrBOUND;
}




static void print_algo_parameters(struct radclock_phyparam *phyparam, struct bidir_peer *peer)
{
	verbose(VERB_CONTROL, "Machine Parameters:  TSLIMIT: %g, SKM_SCALE: %d, RateErrBOUND: %g, BestSKMrate: %g",
			phyparam->TSLIMIT, (int)phyparam->SKM_SCALE, phyparam->RateErrBOUND, phyparam->BestSKMrate);

	verbose(VERB_CONTROL, "Network Parameters:  poll_period: %u, h_win: %d ", peer->poll_period, peer->top_win);

	verbose(VERB_CONTROL, "Windows (in pkts):   warmup: %lu, history: %lu, shift: %lu "
			"(thres = %4.0lf [mus]), plocal: %lu, offset: %lu (SKM scale is %u)",
			peer->warmup_win, peer->top_win, peer->shift_win, peer->Eshift*1000000, peer->plocal_win, peer->offset_win,
			(int) (phyparam->SKM_SCALE/peer->poll_period) );

	verbose(VERB_CONTROL, "Error thresholds :   phat:  Ep %3.2lg [ms], Ep_qual %3.2lg [PPM], "
			"plocal:  Eplocal_qual %3.2lg [PPM]", 1000*peer->Ep, 1.e6*peer->Ep_qual, 1.e6*peer->Eplocal_qual);

	verbose(VERB_CONTROL, "                     offset:  Eoffset %3.1lg [ms], Eoffset_qual %3.1lg [ms]",
			1000*peer->Eoffset, 1000*peer->Eoffset_qual);

	verbose(VERB_CONTROL, "Sanity Levels:       phat  %5.3lg, plocal  %5.3lg, offset: "
			"absolute:  %5.3lg [ms], rate: %5.3lg [ms]/[sec] ( %5.3lg [ms]/[stamp])",
		   	peer->Ep_sanity, peer->Eplocal_sanity, 1000*peer->Eoffset_sanity_min, 
			1000*peer->Eoffset_sanity_rate, 1000*peer->Eoffset_sanity_rate*peer->poll_period);
}





/* Peer initialisation */
void init_peer( struct radclock *clock_handle, struct radclock_phyparam *phyparam,
				struct bidir_peer *peer, struct bidir_stamp *stamp, 
				unsigned int plocal_winratio, int poll_period)
{

	vcounter_t RTT;			// current RTT value
	double th_naive;		// thetahat naive estimate

	verbose(VERB_SYNC, "Initialising RADclock synchronization");

	peer->warmup_win = 100;

	/* Initialise the peer polling period to the configuration value
	* poll_transition_th: begin with no transition for thetahat
	* poll_changed_i: index of last change
	*/
	peer->poll_period = poll_period;
	peer->poll_transition_th = 0;
	peer->poll_ratio = 1;
	peer->poll_changed_i = 0;

	peer->next_RTThat = 0;
	peer->RTThat_shift = 0;

	peer->plocalerr = 0;
	peer->plocal_restartscheduled = 0;

	/* UPDATE The following was extracted from the block related to first packet
	 * and reaction to poll period and external environment parameters
	 */

	/* Initialize the error thresholds */
	init_errthresholds( phyparam, peer );

	/* Set pkt-index algo windows.
	 * These control the algo, independent of implementation.
	 */
	set_algo_windows( phyparam, peer);

	/* Ensure warmup_win consistent with algo windows for easy 
	 * initialisation of main algo after warmup 
	 */
	adjust_warmup_win(peer->stamp_i, peer, plocal_winratio);

	/* Create histories
	 * Set all history sizes to warmup window size
	 * note: currently stamps [_end,i-1] in history, i not yet processed
	 */
	history_init(&peer->stamp_hist, (unsigned int) peer->warmup_win, sizeof(struct bidir_stamp) );
	history_init(&peer->RTT_hist, (unsigned int) peer->warmup_win, sizeof(vcounter_t) );
	history_init(&peer->RTThat_hist, (unsigned int) peer->warmup_win, sizeof(vcounter_t) );
	history_init(&peer->thnaive_hist, (unsigned int) peer->warmup_win, sizeof(double) );

	/* Print out summary of parameters:
	 * physical, network, thresholds, and sanity 
	 */
	print_algo_parameters( phyparam, peer );

	/* Initialise peer stamp to default value */
	memset(&peer->stamp, 0, sizeof(struct bidir_stamp));

	/* Print the first timestamp tuple obtained */
	verbose(VERB_SYNC, "i=%lu: Beginning Warmup Phase. Stamp read check: %llu %22.10Lf %22.10Lf %llu",
			peer->stamp_i, stamp->Ta, stamp->Tb, stamp->Te, stamp->Tf);

	verbose(VERB_SYNC, "i=%lu: Assuming 1Ghz oscillator, 1st vcounter stamp is %5.3lf [days] "
			"(%5.1lf [min]) since reset, RTT is %5.3lf [ms], SD %5.3Lf [mus]",
			peer->stamp_i,
			(double) stamp->Ta * 1e-9/3600/24, (double) stamp->Ta * 1e-9/60, 
			(double) (stamp->Tf - stamp->Ta) * 1e-9*1000, (stamp->Te - stamp->Tb) * 1e6);


	/* MinET_old
	 * Initialise to 0 on first packet (static variable) 
	 */
	peer->minET = 0;

	/* Record stamp 0 */
	history_add(&peer->stamp_hist, peer->stamp_i, stamp);

	/* RTT */
	RTT = MAX(1,stamp->Tf - stamp->Ta);
	peer->RTThat = RTT;
	history_add(&peer->RTT_hist, peer->stamp_i, &RTT);
	peer->pstamp_i = 0;

	/* vcount period and clock definition.
	 * Once determined, C only altered to correct phat changes 
	 * note: phat unavailable after only 1 stamp, use config value, rough guess of 1Ghz beats zero!
	 * XXX: update comment, if reading first data from kernel timecounter /
	 * clocksource info. If the user put a default value in the config file,
	 * trust his choice. Otherwise, use kernel info from the first
	 * ffclock_getestimate.
	 */
	if (clock_handle->conf->phat_init == DEFAULT_PHAT_INIT)
		peer->phat = RAD_DATA(clock_handle)->phat;
	else
		peer->phat = clock_handle->conf->phat_init;
	peer->perr = 0;

	/* switch off pstamp_i search until initialised at top_win/2 */
	peer->jcount = 1;
	peer->jsearch_win = 0;

	/* Initializations for phat warmup algo 
	 * wwidth: initial width of end search windows. 
	 * near_i: index of stamp with minimal RTT in near window  (larger i)
	 * far_i: index of stamp with minimal RTT in  far window  (smaller i)
	 */
	peer->wwidth = 1;
	peer->near_i = 0;
	peer->far_i  = 0;

	/* C now determined.  For now C(t) = t_init */
	peer->C = stamp->Tb - (long double) (stamp->Ta * peer->phat);
	verbose(VERB_SYNC, "i=%lu: After initialisation: (far,near)=(%lu,%lu), "
			"phat = %.10lg, perr = %5.3lg, C = %7.4Lf",
			peer->stamp_i, 0, 0, peer->phat, peer->perr, peer->C);

	/* plocal algo 
	 * refinement pointless here, just copy. If not active, never used, no cleanup needed 
	 * TODO: we can probably clean that up and the management of UNIX signal
	 * regarding plocal at the same time. The logic there is cumbersome because
	 * of historical changes ... ways to make it much simpler and better.
	 */
	if (peer->using_plocal)
		peer->plocal = peer->phat;

	/* thetahat algo initialise on-line warmup algo */
	th_naive = 0;
	peer->thetahat = th_naive;
	history_add(&peer->thnaive_hist, peer->stamp_i, &th_naive);

	/* Peer error metrics */
	PEER_ERROR(peer)->Ebound_min_last	= 0;
	PEER_ERROR(peer)->nerror 			= 0;
	PEER_ERROR(peer)->cumsum 			= 0;
	PEER_ERROR(peer)->sq_cumsum 		= 0;
	PEER_ERROR(peer)->nerror_hwin 		= 0;
	PEER_ERROR(peer)->cumsum_hwin 		= 0;
	PEER_ERROR(peer)->sq_cumsum_hwin 	= 0;

	/* Peer statistics */
	peer->stats_sd[0] = 0;
	peer->stats_sd[1] = 0;
	peer->stats_sd[2] = 0;
}


void update_peer(struct bidir_peer *peer, struct radclock_phyparam *phyparam, int poll_period, 
					unsigned int plocal_winratio )
{
	index_t stamp_sz;			// Stamp max history size
	index_t RTT_sz;				// RTT max history size
	index_t RTThat_sz;			// RTThat max history size
	index_t thnaive_sz;			// thnaive max history size
	index_t st_end;				// index of last pkts in stamp history
	index_t RTT_end;			// index of last pkts in RTT history
	index_t RTThat_end;			// index of last pkts in RTThat history
	index_t thnaive_end;		// index of last pkts in thnaive history
	vcounter_t *RTThat_tmp;		// RTT hat value holder

	/* Initialize the error thresholds */
	init_errthresholds( phyparam, peer );

	/* Record change of poll period.
	 * Set poll_transition_th, poll_ratio and poll_changed_i for thetahat
	 * processing. poll_transition_th could be off by one depending on when NTP
	 * pkt rate changed, but not important.
	 */
	if ( poll_period != peer->poll_period )
	{
		peer->poll_transition_th = peer->offset_win;
		peer->poll_ratio = (double)poll_period / (double)peer->poll_period;
		peer->poll_period = poll_period;
		peer->poll_changed_i = peer->stamp_i;
	}

	/* Set pkt-index algo windows.
	 * With possibly new phyparam and/or polling period
	 * These control the algo, independent of implementation.
	 */
	set_algo_windows(phyparam, peer);

	/* Ensure warmup_win consistent with algo windows for easy 
	 * initialisation of main algo after warmup 
	 */
	if (peer->stamp_i < peer->warmup_win)
		adjust_warmup_win(peer->stamp_i, peer, plocal_winratio);
	else 
	{
		/* Re-init shift window from stamp i-1 back
		 * ensure don't go past 1st stamp, using history constraint (follows 
		 * that of RTThat already tracked). Window was reset, not 'slid'
	 	 * note: currently stamps [_end,i-1] in history, i not yet processed
		 *
		 */
		// Former code which requires to cast into signed variables. This macro
		// is dangerous because it does not check the sign of the variables (if
		// unsigned rolls over, it gives the wrong result
		//peer->shift_end = MAX(0, (peer->stamp_i-1) - peer->shift_win+1);
		if ( (peer->stamp_i-1) > (peer->shift_win-1) )
			peer->shift_end = (peer->stamp_i-1) - (peer->shift_win-1);
		else
			peer->shift_end = 0;

		RTT_end = history_end(&peer->RTT_hist);
		peer->shift_end = MAX(peer->shift_end, RTT_end);
		RTThat_tmp = history_find(&peer->RTT_hist, history_min(&peer->RTT_hist, peer->shift_end, peer->stamp_i-1) ); 
		peer->RTThat_shift = *RTThat_tmp;
	}

	/* Set history array sizes.
	 * If warmup is to be sacred, each must be larger than the current warmup_win 
	 * NOTE:  if set right, new histories will be big enough for future needs, 
	 * doesn't mean required data is in them after window resize!!
	 */
	if ( peer->stamp_i < peer->warmup_win ) {
		stamp_sz 	= peer->warmup_win;
		RTT_sz 	= peer->warmup_win;
		RTThat_sz 	= peer->warmup_win;
		thnaive_sz	= peer->warmup_win;
	}
	else {
		/* RTTHat_sz and thnaive_sz need >= offset_win */
		stamp_sz 	= MAX(peer->plocal_win + peer->plocal_win/(plocal_winratio/2), peer->offset_win);
		RTT_sz 		= MAX(peer->plocal_win + peer->plocal_win/(plocal_winratio/2), MAX(peer->offset_win, peer->shift_win));
		RTThat_sz 	= peer->offset_win;
		thnaive_sz 	= peer->offset_win;
	}

	/* Resize histories if needed.
	 * Note: currently stamps [_end,stamp_i-1] in history, stamp_i not yet processed, so all
	 * global index based on stamp_i-1.
	 */

	/* Resize Stamp History */
	if ( peer->stamp_hist.buffer_sz != stamp_sz )
	{
		st_end = history_end(&peer->stamp_hist);
		verbose(VERB_CONTROL, "Resizing st_win history from %lu to %lu. Current stamp range is [%lu %lu]",
			peer->stamp_hist.buffer_sz, stamp_sz, st_end, peer->stamp_i-1); 
		history_resize(&peer->stamp_hist, stamp_sz, peer->stamp_i-1);
		st_end = history_end(&peer->stamp_hist);
		verbose(VERB_CONTROL, "Range on exit: [%lu %lu]", st_end, peer->stamp_i-1);
	}

	/* Resize RTT History */
	if ( peer->RTT_hist.buffer_sz != RTT_sz )
	{
		RTT_end = history_end(&peer->RTT_hist);
		verbose(VERB_CONTROL, "Resizing RTT_win history from %lu to %lu. Current stamp range is [%lu %lu]", 
			peer->RTT_hist.buffer_sz, RTT_sz, RTT_end, peer->stamp_i-1);
		history_resize(&peer->RTT_hist, RTT_sz, peer->stamp_i-1);
		RTT_end = history_end(&peer->RTT_hist);
		verbose(VERB_CONTROL, "Range on exit: [%lu %lu]", RTT_end, peer->stamp_i-1);
	}

	/* Resize RTThat History */
	if ( peer->RTThat_hist.buffer_sz != RTThat_sz )
	{
		RTThat_end = history_end(&peer->RTThat_hist);
		verbose(VERB_CONTROL, "Resizing RTThat_win history from %lu to %lu. Current stamp range is [%lu %lu]", 
				peer->RTThat_hist.buffer_sz, RTThat_sz, RTThat_end, peer->stamp_i-1);
		history_resize(&peer->RTThat_hist, RTThat_sz, peer->stamp_i-1);
		RTThat_end = history_end(&peer->RTThat_hist);
		verbose(VERB_CONTROL, "Range on exit: [%lu %lu]", RTThat_end, peer->stamp_i-1);
	}

	/* Resize Thnaive History */
	if ( peer->thnaive_hist.buffer_sz != thnaive_sz ) {
		thnaive_end = history_end(&peer->thnaive_hist);
		verbose(VERB_CONTROL, "Resizing thnaive_win history from %lu to %lu.  Current stamp range is [%lu %lu]",
				peer->thnaive_hist.buffer_sz, thnaive_sz, thnaive_end, peer->stamp_i-1);
		history_resize(&peer->thnaive_hist, thnaive_sz, peer->stamp_i-1);
		thnaive_end = history_end(&peer->thnaive_hist);
		verbose(VERB_CONTROL, "Range on exit: [%lu %lu]", thnaive_end, peer->stamp_i-1);
	}

	/* Print out summary of parameters:
	 * physical, network, thresholds, and sanity 
	 */
	print_algo_parameters( phyparam, peer );


}




/* RTT Initializations for normal history and level_shift code */
void end_warmup_RTT( struct bidir_peer *peer, struct bidir_stamp *stamp)
{
	index_t RTT_end;			// index of last pkts in RTT history
	vcounter_t *RTT_tmp;		// RTT hat value holder

	/* Start tracking next_RTThat instead of in middle of 1st window, even if it
	 * is not used until then.
	 */
	peer->next_RTThat = peer->RTThat;

	/* Start tracking shift_end and first RTThat_shift estimate.
	 * shift_end = stamp_i-(shift_win-1) should work all the time, but some
	 * extra care does not harm. We also make sure shift_end corresponds to a
	 * stamp that is actually stored in history.
	 */
	if ( peer->stamp_i > peer->shift_win )
		peer->shift_end = peer->stamp_i - (peer->shift_win-1);
	else
		peer->shift_end = 0;
	RTT_end = history_end(&peer->RTT_hist);
	peer->shift_end = MAX(peer->shift_end, RTT_end);

	RTT_tmp = history_find(&peer->RTT_hist, history_min(&peer->RTT_hist, peer->shift_end, peer->stamp_i) );
	peer->RTThat_shift  = *RTT_tmp;
}



/* Initializations for normal phat algo
 * Need: reliable phat, estimate of its error, initial quality pstamp and associated data
 * Approximate error of current estimate from warmup algo, must be beaten before phat updated
 */
void end_warmup_phat(struct bidir_peer *peer, struct bidir_stamp *stamp)
{
	struct bidir_stamp *stamp_ptr;
	struct bidir_stamp *stamp_near;
	struct bidir_stamp *stamp_far;
	vcounter_t *RTT_far;
	vcounter_t *RTT_near;

	/* pstamp_i has been tracking RTThat during warmup, which is the stamp we
	 * choose to initialise pstamp to.
	 * This first pstamp is supposed to be 'perfect'. Error due to poor RTT 
	 * estimate will be picked in `global' error component baseerr.
	 * Note: the RTThat estimate associated to pstamp is the current RTThat and
	 * *not* the one in use at the time pstamp_i was last recorded. They should
	 * be the same, no?
	 */
	stamp_ptr = history_find(&peer->stamp_hist, peer->pstamp_i);
	copystamp(stamp_ptr, &peer->pstamp);
	peer->pstamp_perr 	= 0;
	peer->pstamp_RTThat = peer->RTThat;

	/* RTThat detection and last phat update may not correspond to the same
	 * stamp. Here we have reliable phat, but the corresponding point error may
	 * be outdated if RTThat is detected after last update. Reassess point 
	 * error with latest RTThat value.
	 */
	stamp_near	= history_find(&peer->stamp_hist, peer->near_i);
	stamp_far	= history_find(&peer->stamp_hist, peer->far_i);
	RTT_near	= history_find(&peer->RTT_hist, peer->near_i);
	RTT_far		= history_find(&peer->RTT_hist, peer->far_i);
	peer->perr	= (double) ((*RTT_far - peer->RTThat) + (*RTT_near - peer->RTThat)) 
						* peer->phat / (stamp_near->Tb - stamp_far->Tb);

	/* Reinitialise sanity count at the end of warmup */
	peer->phat_sanity_count = 0;
	verbose(VERB_CONTROL, "i=%lu: Initializing full phat algo, pstamp_i=%lu, perr= %10.3lg",
		   	peer->stamp_i, peer->pstamp_i, peer->perr);
}


/* Initializations for normal plocal algo
 * [may not be enough history even in warmup, poll_period will only change timescale]
 */
void end_warmup_plocal(struct bidir_peer *peer, struct bidir_stamp *stamp, unsigned int plocal_winratio)
{
	index_t st_end;				// indices of last pkts in stamp history
	index_t RTT_end;			// indices of last pkts in RTT history

	/* index of stamp we require to be available before proceeding (different usage to shift_end etc!) */
	peer->plocal_end = peer->stamp_i - peer->plocal_win + 1-peer->wwidth-peer->wwidth/2;
	st_end  = history_end(&peer->stamp_hist);
	RTT_end = history_end(&peer->RTT_hist);
	if ( peer->plocal_end >= MAX(peer->poll_changed_i, MAX(st_end,RTT_end)) ) {
		/* if fully past poll transition and have history read
		 * resets wwidth as well as finding near and far pkts
		 */
		init_plocal(peer, plocal_winratio, peer->stamp_i);
		peer->plocal_restartscheduled = 0;
	} 
	else {
		/* record a problem, will have to restart when it resolves */
		peer->plocal_restartscheduled = 1;
		verbose(VERB_CONTROL, "i=%lu:  plocal problem following parameter changes "
				"(desired window first stamp %lu unavailable), defaulting to phat while windows fill", 
				peer->stamp_i, peer->plocal_end);
	}
	peer->plocal_sanity_count = 0;
}


/* Initialisation for normal thetahat algo */
void end_warmup_thetahat(struct bidir_peer *peer, struct bidir_stamp *stamp)
{
	index_t RTThat_sz;		// RTThat max history size
	vcounter_t *RTThat_tmp;		// RTT hat value holder
	int j;

	/* fill entire RTThat history with current RTThat not a true history, but
	 * appropriate for offset
	 */
	RTThat_sz = peer->RTThat_hist.buffer_sz;
	for ( j=0; j<RTThat_sz; j++ )
	{
		RTThat_tmp = history_find(&peer->RTThat_hist, j);
		*RTThat_tmp = peer->RTThat;
	}
	peer->RTThat_hist.item_count = RTThat_sz;
	peer->RTThat_hist.curr_i = peer->stamp_i;

	peer->offset_sanity_count = 0;
	peer->offset_quality_count = 0;
// XXX TODO we should probably track the correct stamp in warmup instead of this
// bogus one ...
	copystamp(stamp, &peer->thetastamp);
	verbose(VERB_CONTROL, "i=%lu: Switching to full thetahat algo, RTThat_hist "
			"set to RTThat=%llu, current est'd minimum error= %5.3lg [ms]", 
			peer->stamp_i, peer->RTThat, 1000*peer->minET);
}



void parameters_calibration( struct bidir_peer *peer)
{
	/* Adjust parameters based on nearby/far away server.
	 * Nearby server is less than 3ms of RTT away
	 * TODO: this is a bit ugly since Eshift should be set directly to the
	 * correct value, but ... we will probably have other parameters to
	 * adjust at the end of warmup.
	 * Let's create a function for that when we have a list of them
	 */
	if ( peer->RTThat < (3e-3 / peer->phat) ) {
		verbose(VERB_CONTROL, "i=%lu: Detected close server based on minimum RTT",
				peer->stamp_i);
		/* make RTThat_shift_thres constant to avoid possible phat dynamics */
		peer->RTThat_shift_thres = (vcounter_t) ceil( peer->Eshift/peer->phat );
		/* Decoupling Eoffset and Eoffset_qual .. , for nearby servers, the
		 * looser quality has no (or very small?) effect
		 */
		peer->Eoffset_qual = 3 * peer->Eoffset;
	}
	else {
		verbose(VERB_CONTROL, "i=%lu: Detected far away server based on minimum RTT",
				peer->stamp_i);
		peer->RTThat_shift_thres = (vcounter_t) ceil( 3*peer->Eshift/peer->phat );

		/* Decoupling Eoffset and Eoffset_qual .. , for far away servers, increase the number
		 * of points accepted for processing. The bigger the pool period the looser we
		 * have to be. Provide here a rough estimate of the increase of the window based
		 * on data observed with sugr-glider and shouf shouf plots
		 * 		Eoffset_qual =  exp(log((double) poll_period)/2)/2 * 3 * Eoffset;
		 * [UPDATE]: actually doesn't work because the gaussian penalty function makes these 
		 * additional points be insignificant. Reverted back
		 */
		peer->Eoffset_qual = 6 * peer->Eoffset;
	}

	verbose(VERB_CONTROL, "i=%lu: Upward shift detection activated, "
			"threshold set at %llu [vcounter] (%4.0lf [mus])",
		   	peer->stamp_i, peer->RTThat_shift_thres, 
			peer->RTThat_shift_thres * peer->phat*1000000);

	verbose(VERB_CONTROL, "i=%lu: Adjusted Eoffset_qual %3.1lg [ms] (Eoffset %3.1lg [ms])", 
			peer->stamp_i, 1000*peer->Eoffset_qual, 1000*peer->Eoffset);
}


void collect_stats_peer(struct bidir_peer *peer, struct bidir_stamp *stamp)
{
	long double SD;	
	SD = stamp->Te - stamp->Tb;

	/*
	 * Fairly ad-hoc values based on observed servers. Good if less than 
	 * 100 us, avg if less than 300 us, bad otherwise.
	 */
	if (SD < 50e-6)
		peer->stats_sd[0]++;
	else if (SD < 200e-6)
		peer->stats_sd[1]++;
	else 
		peer->stats_sd[2]++;
}


void print_stats_peer(struct bidir_peer *peer)
{
	int total_sd;

	/* 
	 * Most of the variables needed for these stats are not used during warmup
	 */
	if (peer->stamp_i < peer->warmup_win) {
		peer->stats_sd[0] = 0;
		peer->stats_sd[1] = 0;
		peer->stats_sd[2] = 0;
		return;
	}

	if (peer->stamp_i % (int)(6 * 3600 / peer->poll_period))
		return;
	
	total_sd = peer->stats_sd[0] + peer->stats_sd[1] + peer->stats_sd[2];

	verbose(VERB_CONTROL, "i=%lu: Server recent statistics:", peer->stamp_i);
	verbose(VERB_CONTROL, "i=%lu:   Internal delay: %d%% < 50us, %d%% < 200us, %d%% > 200us",
		peer->stamp_i,
		100 * peer->stats_sd[0]/total_sd,
		100 * peer->stats_sd[1]/total_sd,
		100 * peer->stats_sd[2]/total_sd);

	verbose(VERB_CONTROL, "i=%lu:   Last stamp check: %llu %22.10Lf %22.10Lf %llu",
		peer->stamp_i,
		peer->stamp.Ta, peer->stamp.Tb, peer->stamp.Te, peer->stamp.Tf);

	verbose(VERB_SYNC, "i=%lu: Timekeeping summary:",
		peer->stamp_i); 
	verbose(VERB_SYNC, "i=%lu:   Period = %.10g, Period errorr = %.10g",
		peer->stamp_i, peer->phat, peer->perr); 
	verbose(VERB_SYNC, "i=%lu:   Tstamp pair = (%lu,%lu), base err = %.10g, "
		"DelTb = %.3Lg [hrs]",
		peer->stamp_i, 
		peer->phat * labs(peer->RTThat - peer->pstamp_RTThat),
		peer->stamp.Tb - peer->pstamp.Tb);

	verbose(VERB_SYNC, "i=%lu:   Thetahat = %5.3lf [ms], minET = %.3lf [ms], "
		"RTThat = %.3lf [ms]", 
		peer->stamp_i,
		1000 * peer->thetahat,
		1000 * peer->minET,
		1000 * peer->phat * peer->RTThat);

	/* Reset stats for this period */
	peer->stats_sd[0] = 0;
	peer->stats_sd[1] = 0;
	peer->stats_sd[2] = 0;
}


/* =============================================================================
 * RTT
 * =============================================================================
 */


void process_RTT_warmup (struct bidir_peer *peer, vcounter_t RTT)
{
	/* Record the minimum of RTT
	 * Record corresponding index for full phat processing */
	if ( RTT < peer->RTThat )
	{
		peer->RTThat = RTT;
		peer->pstamp_i = peer->stamp_i;
	}
}



/* Normal RTT updating.
 * This processes the new RTT=RTT_hist[i] of stamp i
 * Algos always simple: History transparently handled before stamp i
 * shifts below after normal i
 * - RTThat always below or equal RTThat_shift since top_win/2 > shift_win
 * - next_RTThat above or below RTThat_shift depending on position in history
 * - RTThat_end tracks last element stored
 */
void process_RTT_full (struct bidir_peer *peer, vcounter_t RTT)
{
	index_t lastshift = 0;	//  index of first stamp after last detected upward shift 
	index_t j;				// loop index, needs to be signed to avoid problem when j hits zero
	index_t jmin = 0;		// index that hits low end of loop
	vcounter_t* RTThat_ptr;	// points to a given RTThat in RTThat_hist
	vcounter_t next_RTT;		// points to a given RTThat in RTThat_hist

	peer->RTThat = MIN(peer->RTThat, RTT);
	history_add(&peer->RTThat_hist, peer->stamp_i, &peer->RTThat);
	peer->next_RTThat = MIN(peer->next_RTThat, RTT);

	/* if window (including processing of i) is not full,
	 * keep left hand side (ie shift_end) fixed and add pkt i on the right.
	 * Otherwise, window is full, and min inside it (thanks to reinit), can slide
	 */
	// MAX not safe with subtracting unsigned
//	if ( MAX(0, peer->stamp_i-peer->shift_win+1) < peer->shift_end ) {
	if ( peer->stamp_i < (peer->shift_win-1) + peer->shift_end )
	{
		verbose(VERB_CONTROL, "In shift_win transition following window change, "
				"[shift transition] windows are [%lu %lu] wide", 
				peer->shift_win, peer->stamp_i-peer->shift_end+1);
		peer->RTThat_shift =  MIN(peer->RTThat_shift,RTT);
	}
	else
	{
		 peer->RTThat_shift = history_min_slide_value(&peer->RTT_hist, peer->RTThat_shift, peer->shift_end, peer->stamp_i-1);
		 peer->shift_end++;
	}

	/* Upward Shifts.
	 * This checks for detection over window of width shift_win prior to stamp i 
	 * Detection about reaction to RTThat_shift. RTThat_shift itself is simple, always just a sliding window 
	 * lastshift is the index of first known stamp after shift
	 */
	if ( peer->RTThat_shift > (peer->RTThat + peer->RTThat_shift_thres) ) { 
		lastshift = peer->stamp_i - peer->shift_win + 1;
		verbose(VERB_SYNC, "Upward shift of %5.1lf [mus] triggered when i = %lu ! "
				"shift detected at stamp %lu",
				(peer->RTThat_shift-peer->RTThat)*peer->phat*1.e6,
				peer->stamp_i, lastshift);
		/* Recalc from [i-lastshift+1 i] 
		 * - note by design, won't run into last history change 
		 */
		peer->RTThat = peer->RTThat_shift;
		peer->next_RTThat = peer->RTThat;
		/* Recalc necessary for phat
		 * - note pstamp_i must be before lastshift by design
		 * - note that phat not the same as before, but that's ok
		 */
		if ( peer->next_pstamp_i >= lastshift) {
			next_RTT = peer->next_pstamp.Tf - peer->next_pstamp.Ta;
			verbose(VERB_SYNC, "Recalc necessary for next_pstamp_i = %lu", peer->next_pstamp_i);
			peer->next_pstamp_perr 	= peer->phat*(double)(next_RTT - peer->RTThat); 
			peer->next_pstamp_RTThat 	= peer->RTThat;
		}
		/* Recalc necessary for offset 
		 * typically shift_win >> offset_win, so lastshift won't bite
		 * correct RTThat history back as far as necessary or possible
		 */
		// MAX not safe with subtracting unsigned
		//for ( j=peer->stamp_i; j>=MAX(lastshift,peer->stamp_i-peer->offset_win+1); j--)
		if ( peer->stamp_i > (peer->offset_win-1) )
			jmin = peer->stamp_i - (peer->offset_win-1);
		else
			jmin = 0;
		jmin = MAX(lastshift, jmin);

		for ( j=peer->stamp_i; j>=jmin; j--)
		{
			RTThat_ptr = history_find(&peer->RTThat_hist, j);
			*RTThat_ptr = peer->RTThat;
		}
		verbose(VERB_SYNC, "i=%lu: Recalc necessary for RTThat for %lu stamps back to i=%lu",
				peer->stamp_i, peer->shift_win, lastshift);
	}
}







/* =============================================================================
 * PHAT ALGO 
 * =============================================================================
 */

double compute_phat (struct bidir_peer* peer,
		struct bidir_stamp* far, struct bidir_stamp* near)
{
	long double DelTb, DelTe;	// Server time intervals between stamps j and i
	vcounter_t DelTa, DelTf;	// Counter intervals between stamps j and i 
	double phat;			// Period estimate for current stamp
	double phat_b;			// Period estimate for current stamp (backward dir)
	double phat_f; 			// Period estimate for current stamp (forward dir)

	DelTa = near->Ta - far->Ta;
	DelTb = near->Tb - far->Tb;
	DelTe = near->Te - far->Te;
	DelTf = near->Tf - far->Tf;

	/* 
	 * Check for crazy values, and NaN cases induced by DelTa or DelTf equal
	 * zero Log a major error and hope someone will call us
	 */
	if ( ( DelTa <= 0 ) || ( DelTb <= 0 ) || (DelTe <= 0 ) || (DelTf <= 0) ) {
		verbose(LOG_ERR, "i=%lu we picked up the same i and j stamp. "
				"Contact developer.", peer->stamp_i);
		return 0;
	}

	/*
	 * Use naive estimates from chosen stamps {i,j}
	 * forward  (OUTGOING, sender)
	 * backward (INCOMING, receiver)
	 */
	phat_f	= (double) (DelTb / DelTa);
	phat_b	= (double) (DelTe / DelTf);
	phat	= (phat_f + phat_b) / 2;

	return phat;
}




int process_phat_warmup (struct bidir_peer* peer, vcounter_t RTT,
		unsigned int warmup_winratio)
{
	vcounter_t *RTT_tmp;		// RTT value holder
	vcounter_t *RTT_far;		// RTT value holder
	vcounter_t *RTT_near;		// RTT value holder
	struct bidir_stamp *stamp_near;
	struct bidir_stamp *stamp_far;
	long double DelTb; 		// Server time intervals between stamps j and i
	double phat;			// Period estimate for current stamp

	long near_i = 0;
	long far_i = 0;

	near_i = peer->near_i;
	far_i = peer->far_i;

	/*
	 * Select indices for new estimate. Indices taken from a far window 
	 * (stamps in [0 wwidth-1]) and a near window (stamps in [i-wwidth+1 i])
	 * Still works if poll_period changed, but rate increase of end windows can
	 * be different
	 * if stamp index not yet a multiple of warmup_winratio
	 * 		find near_i by sliding along one on RHS
	 * else
	 * 		increase near and far windows by 1, find index of new min RTT in 
	 * 		both, increase window width
	*/

	if ( peer->stamp_i%warmup_winratio ) {
		peer->near_i = history_min_slide(&peer->RTT_hist, peer->near_i, 
				peer->stamp_i-peer->wwidth, peer->stamp_i-1);
	}
	else {
		RTT_tmp = history_find(&peer->RTT_hist, peer->wwidth);
		RTT_near = history_find(&peer->RTT_hist, peer->near_i);
		RTT_far = history_find(&peer->RTT_hist, peer->far_i);
		if ( *RTT_tmp < *RTT_far )
			peer->far_i = peer->wwidth;
		if ( RTT < *RTT_near )
			peer->near_i = peer->stamp_i;
		peer->wwidth++;
	}

	/* Compute time intervals between NTP timestamps of selected stamps */
	stamp_near = history_find(&peer->stamp_hist, peer->near_i);
	stamp_far = history_find(&peer->stamp_hist, peer->far_i);

	phat = compute_phat(peer, stamp_far, stamp_near);
	if ( phat == 0 )
	{
		/* Something bad happen, most likely, we have a bug. The algo may
		 * recover from this, so do not update and keep going.
		 */
		return 1;
	}

	/* Clock correction
	 * correct C to keep C(t) continuous at time of last stamp
	 */
//	if ( peer->phat != phat ) {
	if ( (near_i != peer->near_i) || (far_i != peer->far_i) )
	{
		peer->C += peer->stamp.Ta * (long double) (peer->phat - phat);
		verbose(VERB_SYNC, "i=%lu: phat update (far,near)=(%lu,%lu), "
				"phat = %.10g, rel diff = %.10g, perr = %.10g, C = %7.4Lf",
				peer->stamp_i, peer->far_i, peer->near_i,
				phat, (phat - peer->phat)/phat, peer->perr, peer->C);
		peer->phat = phat;
		RTT_far = history_find(&peer->RTT_hist, peer->far_i);
		RTT_near = history_find(&peer->RTT_hist, peer->near_i);
		DelTb = stamp_near->Tb - stamp_far->Tb;
		peer->perr = peer->phat * (double)((*RTT_far - peer->RTThat) 
				+ (*RTT_near - peer->RTThat)) / DelTb;
	}
	return 0;
}


/* on-line calculation of new pstamp_i
 * If we are still in the jsearch window attached to start of current half
 * top_win then record this stamp if it is of better quality.
 * Record [index RTT RTThat point-error stamp ]
 * Only track and record the value that will be used in the next top_win/2
 * window it is NOT used for computing phat with the current stamp.
 */
void record_packet_j (struct bidir_peer* peer, vcounter_t RTT, 
		struct bidir_stamp* stamp)
{
	vcounter_t next_RTT;
	next_RTT = peer->next_pstamp.Tf - peer->next_pstamp.Ta;

	if ( peer->jcount <= peer->jsearch_win )
	{
		peer->jcount++;
		if ( RTT < next_RTT ) {
			peer->next_pstamp_i 	= peer->stamp_i;
			peer->next_pstamp_RTThat 	= peer->RTThat;
			peer->next_pstamp_perr 	= peer->phat * (double)(RTT - peer->RTThat);
			copystamp(stamp, &peer->next_pstamp);
		}
	}
}



int process_phat_full (struct bidir_peer* peer, struct radclock* clock_handle, 
						struct radclock_phyparam *phyparam, vcounter_t RTT, 
						struct bidir_stamp* stamp, int qual_warning)

{
	int ret;
	long double DelTb; 	// Server time interval between stamps j and i
	double phat;		// Period estimate for current stamp
	double perr_ij;		// Estimate of error of phat using given stamp pair [i,j]
	double perr_i;		// Estimate of error of phat at stamp i
	double baseerr;		// Holds difference in quality RTTmin values at
						// different stamps

	ret = 0;

	/* Compute new phat based on pstamp and current stamp */
	phat = compute_phat(peer, &peer->pstamp, stamp);
	if ( phat == 0 )
	{
		/* Something bad happen, most likely, we have a bug. The algo may
		 * recover from this, so do not update and keep going.
		 */
		return 1;
	}

	/*
	 * Determine if quality of i sufficient to bother, if so, if (j,i)
	 * sufficient to update phat
	 * if error smaller than Ep, quality pkt, proceed, else do nothing
	 */
	perr_i = peer->phat * (double)(RTT - peer->RTThat);

	if ( perr_i >= peer->Ep )
		return 0;

	/*
	 * Point errors (local)
	 * Level shifts (global)  (can also correct for error in RTThat assuming no
	 * true shifts)
	 * (total err)/Del(t) = (queueing/Delta(vcount))/p  ie. error relative to p
	 */
	DelTb = stamp->Tb - peer->pstamp.Tb;
	perr_ij = fabs(perr_i) + fabs(peer->pstamp_perr);
	// TODO: check values, but long and double casts seem unnecessary
	baseerr = peer->phat * (double)labs((long)(peer->RTThat-peer->pstamp_RTThat));
	perr_ij = (perr_ij + baseerr) / DelTb;

	if ( (perr_ij >= peer->perr) && (perr_ij >= peer->Ep_qual) ) 
	{
		/* Note: STARAD_PERIOD_QUAL is not set on every point that fails.
		 * Quality is a plocal issue only. Arguable?
		 */
		return 0;
	}

	/*
	 * We reach this point, so good candidate.
	 * If better, or extremely go`od, update with naive estimate using (j,i),
	 * else do nothing
	 * if extremely good, accept in order to gracefully track
	 * avoids possible lock-in (eg due to 'lucky' error on error estimate)
	 * phat_f: forward  (OUTGOING, sender)*
	 * phat_b: backward (INCOMING, receiver)
	 * perr: record improved quality
	 * pkt_i: record 2nd packet index
	 */
	peer->perr	= perr_ij;

	if ( fabs((phat - peer->phat)/phat) > phyparam->RateErrBOUND/3 ) {
		verbose(VERB_SYNC, "i=%lu: Jump in phat update, "
			"phat stats: (j,i)=(%lu,%lu), "
			"rel diff = %.10g, perr = %.3g, baseerr = %.10g, "
			"DelTb = %5.3Lg [hrs]",
			peer->pstamp_i,
		   	peer->stamp_i, (phat - peer->phat)/phat, 
			peer->perr, baseerr, DelTb/3600);
	}

	/* Clock correction and phat update.
	 * Sanity check applies here 
	 * correct C to keep C(t) continuous at time of last stamp
	 */
	if ((fabs(peer->phat - phat)/peer->phat > peer->Ep_sanity) || qual_warning) {
		if (qual_warning)
			verbose(VERB_QUALITY, "i=%lu: qual_warning received, following "
					"sanity check for phat", peer->stamp_i);

		verbose(VERB_SANITY, "i=%lu: phat update fails sanity check. "
			"phat stats: (j,i)=(%lu,%lu), "
			"rel diff = %.10g, perr = %.3g, baseerr = %.10g, "
			"DelTb = %5.3Lg [hrs]",
			peer->pstamp_i,
		   	peer->stamp_i, (phat - peer->phat)/phat, 
			peer->perr, baseerr, DelTb/3600);

		peer->phat_sanity_count++;
		ADD_STATUS(clock_handle, STARAD_PERIOD_SANITY);
		ret = STARAD_PERIOD_SANITY;
	}
	else {
		peer->C += peer->stamp.Ta * (long double) (peer->phat - phat);
		peer->phat = phat;
		DEL_STATUS(clock_handle, STARAD_PERIOD_SANITY);
	}

	return ret;
}




/* =============================================================================
 * PLOCAL ALGO
 * =============================================================================
 */


void process_plocal_warmup(struct bidir_peer* peer)
{
	/* refinement pointless here, just copy.
	 * If not active, never used, no cleanup needed
	 */
	peer->plocal = peer->phat;
}



int process_plocal_full(struct bidir_peer* peer, struct radclock* clock_handle,
		unsigned int plocal_winratio, int sig_plocal, struct bidir_stamp* stamp,
		int phat_sanity_raised, int qual_warning)
{

	index_t st_end;				// indices of last pkts in stamp history
	index_t RTT_end;			// indices of last pkts in RTT history

	/* History lookup window boundaries */
	index_t lhs;
	index_t rhs;
	long double DelTb; 	// Time between j and i based on each NTP timestamp
	struct bidir_stamp *stamp_near;
	struct bidir_stamp *stamp_far;
	double plocal;		// Local period estimate for current stamp
	double plocalerr;	// estimate of total error of plocal [unitless]
	vcounter_t *RTT_far;		// RTT value holder
	vcounter_t *RTT_near;		// RTT value holder


	/*
	 * Compute index of stamp we require to be available before proceeding
	 * (different usage to shift_end etc!)
	 * if not fully past poll transition and have not history ready then
	 * 		default to phat copy if problems with data or transitions
	 * 		record a problem, will have to restart when it resolves
	 * else proceed with plocal processing
	 */
	peer->plocal_end = peer->stamp_i - peer->plocal_win+1 - peer->wwidth 
		- peer->wwidth/2;
	st_end  = history_end(&peer->stamp_hist);
	RTT_end = history_end(&peer->RTT_hist);
	if ( peer->plocal_end < MAX(peer->poll_changed_i, MAX(st_end,RTT_end)) ) {
		peer->plocal = peer->phat;
		peer->plocal_restartscheduled = 1;
// TODO this is very chatty when it happens ... module the rate?		
		verbose(VERB_CONTROL, "plocal problem following parameter changes "
				"(desired window first stamp %lu unavailable), defaulting to "
				"phat while windows fill", peer->plocal_end);
		verbose(VERB_CONTROL, "[plocal_end, lastpoll_i, st_end, RTT_end] : "
				"%lu %lu %lu %lu ", peer->plocal_end, peer->poll_changed_i, 
				st_end, RTT_end);
		return 0;
	}

	/* if told to restart resets wwidth and finds near and far pkts
	 * else compute far_i, near_i  (min_slide takes old win as input)
	 */
	if ( sig_plocal == PLOCAL_RESTART || peer->plocal_restartscheduled ) {
		verbose(VERB_CONTROL, "Restart plocal");
		init_plocal(peer, plocal_winratio, peer->stamp_i);
		peer->plocal_restartscheduled = 0;
	}
	else {
		lhs = peer->stamp_i - peer->wwidth - peer->plocal_win - peer->wwidth/2;
		rhs = peer->stamp_i - 1 - peer->plocal_win - peer->wwidth/2;
		peer->far_i  = history_min_slide(&peer->RTT_hist, peer->far_i, lhs, rhs);
		peer->near_i = history_min_slide(&peer->RTT_hist, peer->near_i,
				peer->stamp_i-peer->wwidth, peer->stamp_i-1);
	}

	/* Compute time intervals between NTP timestamps of selected stamps */
	stamp_near = history_find(&peer->stamp_hist, peer->near_i);
	stamp_far = history_find(&peer->stamp_hist, peer->far_i);

	plocal = compute_phat(peer, stamp_far, stamp_near);
	/*
	 * Something bad happen, most likely, we have a bug. The algo may recover
	 * from this, so do not update and keep going.
	 */
	if ( plocal == 0 ) {
		return 1;
	}

	RTT_far = history_find(&peer->RTT_hist, peer->far_i);
	RTT_near = history_find(&peer->RTT_hist, peer->near_i);
	DelTb = stamp_near->Tb - stamp_far->Tb;
	plocalerr = peer->phat * (double)((*RTT_far - peer->RTThat)
			+ (*RTT_near - peer->RTThat)) / DelTb;

	/* if quality looks bad, retain previous value */
	if ( fabs(plocalerr) >= peer->Eplocal_qual ) {
		verbose(VERB_QUALITY, "i=%lu: plocal quality low,  (far_i,near_i) = "
				"(%lu,%lu), not updating plocalerr = %5.3lg, "
				"Eplocal_qual = %5.3lg ", peer->stamp_i, peer->far_i,
				peer->near_i, peer->plocalerr, peer->Eplocal_qual);
		ADD_STATUS(clock_handle, STARAD_PERIOD_QUALITY);
		return 0;
	}

	/* if quality looks good, continue but refuse to update if result looks
	 * insane. qual_warning may not apply to stamp_near or stamp_far, but we
	 * still follow the logic "there is something strange going on in here".
	 * Also, plocal searches in two windows for best stamps, which is a decent
	 * damage control.
	 */
	if ( (fabs(peer->plocal-plocal)/peer->plocal > peer->Eplocal_sanity) || qual_warning) {
		if (qual_warning)
			verbose(VERB_QUALITY, "qual_warning received, i=%lu, following "
					"sanity check for plocal", peer->stamp_i);
		verbose(VERB_SANITY, "i=%lu: plocal update fails sanity check: relative "
				"difference is: %5.3lg estimated error was %5.3lg",
				peer->stamp_i, fabs(peer->plocal-plocal)/peer->plocal, plocalerr);
		ADD_STATUS(clock_handle, STARAD_PERIOD_SANITY);
		peer->plocal_sanity_count++;
	}
	else {
		peer->plocal = plocal;
		// TODO, we should actually age this stored value if quality is
		// bad or sanity and we cannot update to the latest computed
		peer->plocalerr = plocalerr;
		DEL_STATUS(clock_handle, STARAD_PERIOD_QUALITY);
		if ( phat_sanity_raised != STARAD_PERIOD_SANITY )
			DEL_STATUS(clock_handle, STARAD_PERIOD_SANITY);
	}
	return 0;
}




/* =============================================================================
 * THETAHAT ALGO
 * =============================================================================
 */

void process_thetahat_warmup (struct bidir_peer* peer, struct radclock* clock_handle, struct radclock_phyparam *phyparam, vcounter_t RTT, struct bidir_stamp* stamp)
{	

	double thetahat;	// double ok since this corrects clock which is already almost right
	double errTa = 0;	// calculate causality errors for correction of thetahat
	double errTf = 0;	// calculate causality errors for correction of thetahat
	double wj;			// weight of pkt i
	double wsum = 0;	// sum of weights
	double th_naive = 0;// thetahat naive estimate
	double ET = 0;		// error thetahat ?
	double minET = 0;	// error thetahat ?

	double *thnaive_tmp;
	double gapsize;		// size in seconds between pkts, used to track widest gap in offset_win

	index_t adj_win;					// adjusted window
	index_t j;				// loop index, needs to be signed to avoid problem when j hits zero
	index_t jmin  = 0;		// index that hits low end of loop
	index_t jbest = 0;		// record best packet selected in window

	double Ebound;
	double Ebound_min = 0;
	index_t RTT_end;			// indices of last pkts in RTT history
	index_t thnaive_end;		// indices of last pkts in thnaive history
	struct bidir_stamp *stamp_tmp;
	vcounter_t *RTT_tmp;		// RTT value holder


	/* During warmup, no plocal refinement, no gap detection, no SD error
	 * correction, only simple sanity warning 
	 */
	if ( (stamp->Te - stamp->Tb) >= RTT*peer->phat*0.95 ) {
		verbose(VERB_SYNC, "i=%d: Apparent server timestamping error, RTT<SD: "
				"RTT = %6.4lg [ms], SD= %6.4lg [ms], SD/RTT= %6.4lg.",
				peer->stamp_i, 1000*RTT*peer->phat, 1000*(double)(stamp->Te-stamp->Tb), (double)(stamp->Te-stamp->Tb)/RTT/peer->phat );
	}
	/* Calculate naive estimate at stamp i
	 * Also track last element stored in thnaive_end
	 */
	th_naive = (peer->phat*((long double)stamp->Ta + (long double)stamp->Tf) + (2*peer->C - (stamp->Tb + stamp->Te)))/2.0;
	history_add(&peer->thnaive_hist, peer->stamp_i, &th_naive);


// TODO computing jmin code can be factored
	/* Calculate weighted sum */
	wsum = 0;
	thetahat = 0;
	/* Fix old end of thetahat window:  poll_period changes, offset_win changes, history limitations */
	if ( peer->poll_transition_th > 0 ) {
		/* linear interpolation over new offset_win */
		adj_win = (peer->offset_win - peer->poll_transition_th) + (ceil)(peer->poll_transition_th * peer->poll_ratio);
		verbose(VERB_CONTROL, "In offset_win transition following poll_period change, "
				"[offset transition] windows are [%lu %lu]", peer->offset_win,adj_win);

		// Former code which requires to cast into signed variables. This macro
		// is dangerous because it does not check the sign of the variables (if
		// unsigned rolls over, it gives the wrong result
		//jmin = MAX(1, peer->stamp_i-adj_win+1);
		if ( peer->stamp_i > (adj_win - 1) )
			jmin = peer->stamp_i - (adj_win - 1);
		else
			jmin = 0;
		jmin = MAX (1, jmin);
		peer->poll_transition_th--;
	}
	else {
		/* ensure don't go past 1st stamp, and don't use 1st, as thnaive set to
		 * zero there 
		 */
		// Former code which requires to cast into signed variables. This macro
		// is dangerous because it does not check the sign of the variables (if
		// unsigned rolls over, it gives the wrong result
		// jmin = MAX(1, peer->stamp_i-peer->offset_win+1);
		if ( peer->stamp_i > (peer->offset_win - 1 ))
			jmin = peer->stamp_i - (peer->offset_win - 1);
		else
			jmin = 0;
		jmin = MAX (1, jmin);
	}
	/* find history constraint */
	RTT_end = history_end(&peer->RTT_hist);
	thnaive_end = history_end(&peer->thnaive_hist);

	jmin = MAX(jmin, MAX(RTT_end, thnaive_end));

	for ( j = peer->stamp_i; j >= jmin; j-- ) {
		/* Reassess pt errors each time, as RTThat not stable in warmup.
		 * Errors due to phat errors are small
		 * then add aging with pessimistic rate (safer to trust recent)
		 */
		RTT_tmp = history_find(&peer->RTT_hist, j);
		stamp_tmp = history_find(&peer->stamp_hist, j);
		ET  = peer->phat * (double)( *RTT_tmp - peer->RTThat );
		ET += peer->phat * (double)( stamp->Tf - stamp_tmp->Tf ) * phyparam->BestSKMrate;

		/* Per point bound error is simply ET in here */
		Ebound  = ET;

		/* Record best in window, smaller the better. When i<offset_win, bound
		 * to be zero since arg minRTT also in win. Initialise minET to first
		 * one in window.
		 */
		if ( j == peer->stamp_i ) {
			minET = ET;
			jbest = j;
			Ebound_min = Ebound;
		}
		else {
			if ( ET < minET) {
				minET = ET;
				jbest = j;
				Ebound_min = Ebound;
			}
		}
		/* calculate weight, is <=1
		 * note: Eoffset initialised to non-0 value, safe to divide
		 */
		wj = exp(- ET * ET / peer->Eoffset / peer->Eoffset);
		wsum += wj;
		thnaive_tmp = history_find(&peer->thnaive_hist, j);
		thetahat = thetahat + wj * *thnaive_tmp;
	}

	/* Check Quality
	 * quality over window looks good, continue
	 * otherwise log out a quality warning
	 */
	gapsize = peer->phat * (double)(stamp->Tf - peer->stamp.Tf);
	if ( minET < peer->Eoffset_qual ) {
		/* if wsum==0 just copy thetahat to avoid crashing (can't divide by zero)
		 *   this problem must be addressed by operator
		 * else safe to normalise
		 */
		if ( wsum==0 ) {
			verbose(VERB_QUALITY, "i=%lu, quality looks good (minET = %lg) yet wsum=0! "
					"Eoffset_qual = %lg may be too large", peer->stamp_i, minET, peer->Eoffset_qual);
			thetahat = peer->thetahat;
		}
		else {
			thetahat /= wsum;
			/* store est'd quality of new estimate */
			peer->minET = minET;
			/* Record last good estimate of error bound.
			 * Also need to track last time we updated theta to do proper aging of
			 * clock error bound in warmup
			 */
			PEER_ERROR(peer)->Ebound_min_last = Ebound_min;
			copystamp(stamp, &peer->thetastamp);
		}
		/* if result looks insane, give warning */
		if ( fabs(peer->thetahat - thetahat) > (peer->Eoffset_sanity_min + peer->Eoffset_sanity_rate * gapsize) ) {
			verbose(VERB_SANITY, "i=%lu: thetahat update fails sanity check: "
					"difference is: %5.3lg [ms], estimated error was  %5.3lg [ms]",
					peer->stamp_i, 1000*(thetahat-peer->thetahat), 1000*minET);
			peer->offset_sanity_count++;
			ADD_STATUS(clock_handle, STARAD_OFFSET_SANITY);
		}
		else {
			DEL_STATUS(clock_handle, STARAD_OFFSET_QUALITY);
			DEL_STATUS(clock_handle, STARAD_OFFSET_SANITY);
		}

		/* update value of thetahat, even if sanity triggered */
		peer->thetahat = thetahat;

	}
	else {
		verbose(VERB_QUALITY, "i=%lu: thetahat quality over offset window very poor "
				"(%5.3lg [ms]), repeating current value", peer->stamp_i, 1000*minET);
		ADD_STATUS(clock_handle, STARAD_OFFSET_QUALITY);
	}

// TODO should we check causality if peer->thetahat has not been updated? Check with Darryl
// TODO also behaviour different in warmup and full algo

	/* errTa - thetahat should be -ve */
	errTa = (double)((long double)stamp->Ta * peer->phat + peer->C - (long double) stamp->Tb);
	if ( errTa > peer->thetahat ) {
		verbose(VERB_CAUSALITY, "i=%lu: causality error on C(Ta), errTa = %5.3lf [ms], "
				"thetahat = %5.3lf [ms], diff = %5.3lf [ms] ",
				peer->stamp_i, 1000*errTa, 1000*peer->thetahat, 1000*(errTa-peer->thetahat));
	}

	/* errTf - thetahat should be +ve */
	errTf = (double)((long double)stamp->Tf * peer->phat + peer->C - (long double) stamp->Te);
	if ( errTf < peer->thetahat ) {
		verbose(VERB_CAUSALITY, "i=%lu: causality error on C(Tf), errTf = %5.3lf [ms], "
				"thetahat = %5.3lf [ms], diff = %5.3lf [ms] ",
				peer->stamp_i, 1000*errTf, 1000*peer->thetahat, 1000*(errTf-peer->thetahat));
	}

	/* warmup to warmup is to pass offset_win */
	if ( (peer->stamp_i < peer->offset_win*2) || !(peer->stamp_i%50) )
	{
		verbose(VERB_SYNC, "i=%lu: th_naive = %5.3lf [ms], thetahat = %5.3lf [ms], "
				"wsum = %7.5lf, minET = %7.5lf [ms], RTThat/2 = %5.3lf [ms]", 
				peer->stamp_i, 1000*th_naive, 1000*thetahat, wsum,
				1000*minET, 1000*peer->phat*peer->RTThat/2.);
	}


	/* Fill output data structure to print internal local variables */
	errTa -= peer->thetahat;
	errTf -= peer->thetahat;
	OUTPUT(clock_handle, errTa) 		= errTa;
	OUTPUT(clock_handle, errTf) 		= errTf;
	OUTPUT(clock_handle, th_naive) 		= th_naive;
	OUTPUT(clock_handle, minET) 		= minET;
	OUTPUT(clock_handle, minET_last)	= peer->minET;
	OUTPUT(clock_handle, wsum) 			= wsum;
	stamp_tmp = history_find(&peer->stamp_hist, jbest);
	OUTPUT(clock_handle, best_Tf) 		= stamp_tmp->Tf;
}


void process_thetahat_full (struct bidir_peer* peer, struct radclock* clock_handle, 
							struct radclock_phyparam *phyparam, vcounter_t RTT, 
							struct bidir_stamp* stamp, int qual_warning)
{
	double thetahat;	// double ok since this corrects clock which is already almost right
	double errTa = 0;	// calculate causality errors for correction of thetahat
	double errTf = 0;	// calculate causality errors for correction of thetahat
	double wj;			// weight of pkt i
	double wsum = 0;	// sum of weights
	double th_naive = 0;// thetahat naive estimate
	double ET = 0;		// error thetahat ?
	double minET = 0;	// error thetahat ?

	double *thnaive_tmp;
	double gapsize;		// size in seconds between pkts, used to track widest gap in offset_win
	int gap = 0;		// logical: 1 = have found a large gap at THIS stamp

	index_t adj_win;					// adjusted window
	index_t j;				// loop index, needs to be signed to avoid problem when j hits zero
	index_t jmin  = 0;		// index that hits low end of loop
	index_t jbest = 0;		// record best packet selected in window

	double Ebound;
	double Ebound_min = 0;
	index_t st_end;				// indices of last pkts in stamp history
	index_t RTT_end;			// indices of last pkts in RTT history
	index_t RTThat_end;			// indices of last pkts in RTThat history
	index_t thnaive_end;		// indices of last pkts in thnaive history
	struct bidir_stamp *stamp_tmp;
	struct bidir_stamp *stamp_tmp2;
	vcounter_t *RTT_tmp;		// RTT value holder
	vcounter_t *RTThat_tmp;		// RTT hat value holder


	if ( (stamp->Te - stamp->Tb) >= RTT*peer->phat*0.95 ) {
		verbose(VERB_SYNC, "i=%lu: Apparent server timestamping error, RTT<SD: "
				"RTT = %6.4lg [ms], SD= %6.4lg [ms], SD/RTT= %6.4lg.",
				peer->stamp_i, 1000*RTT*peer->phat, 1000*(double)(stamp->Te-stamp->Tb), (double)(stamp->Te-stamp->Tb)/RTT/peer->phat );
	}

	/* Calculate naive estimate at stamp i
	 * Also track last element stored in thnaive_end
	 */
	th_naive = (peer->phat*((long double)stamp->Ta + (long double)stamp->Tf) + (2*peer->C - (stamp->Tb + stamp->Te)))/2.0;
	history_add(&peer->thnaive_hist, peer->stamp_i, &th_naive);

	/* Initialize gapsize
	 * Detect gaps and note large gaps (due to high loss)
	 * Default is no gap, if one, computed below
	 * gapsize is initialized here for this i, to localize big gaps
	 */
	gapsize = peer->phat * (double)(stamp->Tf - peer->stamp.Tf);

	/* gapsize is in [sec], but here looking for loss events */
	if ( gapsize > (double) peer->poll_period * 4.5 ) {
		verbose(VERB_SYNC, "i=%lu: Non-trivial gap found: gapsize = %5.1lf stamps or %5.3lg [sec]", 
				peer->stamp_i, gapsize/peer->poll_period, gapsize);
		if ( gapsize > (double) phyparam->SKM_SCALE ) {
			/* note that are in `big gap' mode, mistrust plocal and trust local th more */
			gap = 1;
			verbose(VERB_SYNC, "i=%lu: End of big gap found width = %5.3lg [day] or %5.2lg [hr]",
					peer->stamp_i, gapsize/(3600*24), gapsize/3600);
		}
	}

	/* Calculate weighted sum */
	wsum = 0;
	thetahat = 0;
	/* Fix old end of thetahat window:  poll_period changes, offset_win changes, history limitations */
	if ( peer->poll_transition_th > 0 ) {
		/* linear interpolation over new offset_win */
		adj_win = (peer->offset_win - peer->poll_transition_th) + (ceil)(peer->poll_transition_th * peer->poll_ratio);
		verbose(VERB_CONTROL, "In offset_win transition following poll_period change, "
				"[offset transition] windows are [%lu %lu]", peer->offset_win, adj_win);

		// Former code which requires to cast into signed variables. This macro
		// is dangerous because it does not check the sign of the variables (if
		// unsigned rolls over, it gives the wrong result
		//jmin = MAX(2, peer->stamp_i-adj_win+1);
		if ( peer->stamp_i > (adj_win - 1) )
			jmin = peer->stamp_i - (adj_win - 1);
		else
			jmin = 0;
		jmin = MAX(2, jmin);
		
		peer->poll_transition_th--;
	}
	else {
		/* ensure don't go past 1st stamp, and don't use 1st, as thnaive set to
		 * zero there 
		 */
		// Former code which requires to cast into signed variables. This macro
		// is dangerous because it does not check the sign of the variables (if
		// unsigned rolls over, it gives the wrong result
		// jmin = MAX(1, peer->stamp_i-peer->offset_win+1);
		if ( peer->stamp_i > (peer->offset_win-1) )
			jmin = peer->stamp_i - (peer->offset_win - 1);
		else
			jmin = 0;
		jmin = MAX (1, jmin);
	}
	/* find history constraint */
	st_end  	= history_end(&peer->stamp_hist);
	RTT_end 	= history_end(&peer->RTT_hist);
	RTThat_end 	= history_end(&peer->RTThat_hist);
	thnaive_end = history_end(&peer->thnaive_hist);

	jmin = MAX(jmin, MAX(st_end, MAX(RTT_end, MAX(RTThat_end, thnaive_end))));


	for ( j = peer->stamp_i; j >= jmin; j--) {
		/* first one done, and one fewer intervals than stamps
		 * find largest gap between stamps in window
		 */
		if ( j < peer->stamp_i-1 )
		{
			stamp_tmp = history_find(&peer->stamp_hist, j);
			stamp_tmp2 = history_find(&peer->stamp_hist, j+1);
			gapsize = MAX(gapsize, peer->phat * (double) (stamp_tmp2->Tf - stamp_tmp->Tf));
		}
		/* Don't reassess pt errors (shifts already accounted for)
		 * then add SD quality measure (large SD at small RTT=> delayed Te, distorting th_naive)
		 * then add aging with pessimistic rate (safer to trust recent)
		 */
		RTT_tmp = history_find(&peer->RTT_hist, j);
		RTThat_tmp = history_find(&peer->RTThat_hist, j);
		stamp_tmp = history_find(&peer->stamp_hist, j);
		ET  = peer->phat * (double) ( *RTT_tmp - *RTThat_tmp );
		ET += peer->phat * (double) ( stamp->Tf - stamp_tmp->Tf ) * phyparam->BestSKMrate;

		/* Per point bound error is ET without the SD penalty */
		Ebound  = ET;

		/* Add SD penalty to ET
		 * XXX: SD quality measure has been problematic in different cases:
		 * - kernel timestamping with hardware based servers(DAG, 1588), punish good packets
		 * - with bad NTP servers that have SD > Eoffset_qual all the time (cf CAIDA example).
		 * removed it definitively on 28/07/2011
		 */
		//ET += stamp_tmp->Te - stamp_tmp->Tb;


		/* Record best in window, smaller the better. When i<offset_win, bound
		 * to be zero since arg minRTT also in win. Initialise minET to first
		 * one in window.
		 */
		if ( j == peer->stamp_i ) {
			minET = ET;
			jbest = j;
			Ebound_min = Ebound;
		}
		else {
			if (ET < minET) {
				minET = ET;
				jbest = j;
			}
			/* Ebound and ET are different in here */
			if (Ebound < Ebound_min) {
				Ebound_min = Ebound;
			}
		}
		/* calculate weight, is <=1
		 * note: Eoffset initialised to non-0 value, safe to divide
		 */
		wj = exp(- ET * ET / peer->Eoffset / peer->Eoffset);
		wsum += wj;
		/* correct phat already used by difference with more locally accurate plocal */
		thnaive_tmp = history_find(&peer->thnaive_hist, j);
		if (peer->using_plocal)
			thetahat += wj 	* (*thnaive_tmp - (peer->plocal/peer->phat-1) 
								* peer->phat * (double) (stamp->Tf - stamp_tmp->Tf));
		else
			thetahat += wj * (*thnaive_tmp);
	}

	/* Check Quality and Calculate new candidate estimate
	 * quality over window looks good, use weights over window
	 */
	if ( minET < peer->Eoffset_qual ) {
		/* if wsum==0 just copy thetahat to avoid crashing (can't divide by zero)
		 *   this problem must be addressed by operator
		 * else safe to normalise
		 */
		if ( wsum==0 ) {
			verbose(VERB_QUALITY, "i=%lu: quality looks good (minET = %lg) yet wsum=0! "
					"Eoffset_qual = %lg may be too large", peer->stamp_i, minET,peer->Eoffset_qual);
			thetahat = peer->thetahat;
		}
		else {
			thetahat /= wsum;
			/* store est'd quality of new estimate */
			peer->minET = minET;
		}
	}
	/* quality bad, forget weights (and plocal refinement) and lean on last reliable estimate */
	else {
		/* if this executes, sanity can't be triggered! quality so bad, simply can't update */
		thetahat = peer->thetahat;
		verbose(VERB_QUALITY, "i=%lu: thetahat quality very poor. wsum = %5.3lg, "
				"curr err = %5.3lg, old = %5.3lg, this pt-err = [%5.3lg] [ms]", 
				peer->stamp_i, wsum, 1000*minET, 1000*peer->minET, 1000*ET);  
		peer->offset_quality_count++;
		ADD_STATUS(clock_handle, STARAD_OFFSET_QUALITY);
	}

// TODO behaviour different in warmup and full algo, should check causality on
// TODO thetahat or peer->thetahat?

	/* errTa - thetahat should be -ve */
	errTa = (double)((long double)stamp->Ta * peer->phat + peer->C - (long double) stamp->Tb);
	if ( errTa > peer->thetahat )
		verbose(VERB_CAUSALITY, "i=%lu: causality error uncorrected on C(Ta), errTa = %5.3lf [ms], "
				"thetahat = %5.3lf [ms], diff = %5.3lf [ms]",
				peer->stamp_i, 1000*errTa, 1000*thetahat, 1000*(errTa-thetahat));
	
	/* errTf - thetahat should be +ve */
	errTf = (double)((long double)stamp->Tf * peer->phat + peer->C - (long double) stamp->Te);
	if ( errTf < peer->thetahat )
		verbose(VERB_CAUSALITY, "i=%lu: causality error uncorrected on C(Tf), errTf = %5.3lf [ms], "
				"thetahat = %5.3lf [ms], diff = %5.3lf [ms]",
				peer->stamp_i, 1000*errTf, 1000*thetahat,1000*(errTf-thetahat));

	/* Apply Sanity Check 
	 * sanity also relative to duration of lockouts due to low quality
	 */
	gapsize = MAX(gapsize, peer->phat * (double)(stamp->Tf - peer->thetastamp.Tf) );
	/* if looks insane given gapsize, refuse update */
	if ( ( fabs(peer->thetahat-thetahat) > (peer->Eoffset_sanity_min + peer->Eoffset_sanity_rate * gapsize))
			|| qual_warning)
	{
		if (qual_warning)
			verbose(VERB_QUALITY, "i=%lu: qual_warning received, following sanity check for thetahat",
				   	peer->stamp_i);
		verbose(VERB_SANITY, "i=%lu: thetahat update fails sanity check. diff= %5.3lg [ms], "
				"est''d err= %5.3lg [ms], sanity level: %5.3lg [ms] with total gapsize = %.0lf [sec]",
				peer->stamp_i, 1000*(thetahat-peer->thetahat), 1000*minET, 
				1000*(peer->Eoffset_sanity_min+peer->Eoffset_sanity_rate*gapsize), gapsize);
		peer->offset_sanity_count++;
		ADD_STATUS(clock_handle, STARAD_OFFSET_SANITY);
	}
	else {
		/* it passes or the candidate has been overwritten to last good one
		 * TODO this is weird logic, prone to bugs and should be corrected,
		 *      and the reason why the status flag have to be tested first.
		 */
		if (peer->thetahat != thetahat)
			DEL_STATUS(clock_handle, STARAD_OFFSET_QUALITY);

		 /* update current value 
		 * both sane and quality, then a `true' update, record event for sanity test
		 */
		peer->thetahat = thetahat;
		if ( ( minET < peer->Eoffset_qual ) && ( wsum != 0 ) ) {
// TODO check the logic of this branch, why thetahat update not in here as well 			
			copystamp(stamp, &peer->thetastamp);
			/* Record last good estimate of error bound after sanity check */ 
			PEER_ERROR(peer)->Ebound_min_last = Ebound_min;
		}
//		DEL_STATUS(clock_handle, STARAD_OFFSET_QUALITY);
		DEL_STATUS(clock_handle, STARAD_OFFSET_SANITY);
	}

	if ( !(peer->stamp_i % (int)(6 * 3600 / peer->poll_period)) )
	{
		verbose(VERB_SYNC, "i=%lu: th_naive = %5.3lf [ms], thetahat = %5.3lf [ms], "
				"wsum = %7.5lf, minET = %7.5lf [ms], RTThat/2 = %5.3lf [ms]", 
				peer->stamp_i, 1000*th_naive, 1000*thetahat, wsum,
				1000*minET, 1000*peer->phat*peer->RTThat/2.);
	}

	/* Fill output data structure to print internal local variables */
	errTa -= peer->thetahat;
	errTf -= peer->thetahat;
	OUTPUT(clock_handle, errTa) 		= errTa;
	OUTPUT(clock_handle, errTf) 		= errTf;
	OUTPUT(clock_handle, th_naive) 		= th_naive;
	OUTPUT(clock_handle, minET) 		= minET;
	OUTPUT(clock_handle, minET_last)	= peer->minET;
	OUTPUT(clock_handle, wsum) 			= wsum;
	stamp_tmp = history_find(&peer->stamp_hist, jbest);
	OUTPUT(clock_handle, best_Tf) 		= stamp_tmp->Tf;

}


/* =============================================================================
 * CLOCK SYNCHRONISATION ALGORITHM
 * =============================================================================
 */


/* This routine takes in a new bi-directional stamp and uses it to update the
 * estimates of the clock calibration.   It implements the full `algorithm' and
 * is abstracted away from the lower and interface layers.  It should be
 * entirely portable.  It returns updated clock in the global clock format,
 * pre-corrected.
 *
 * Offset estimation C(t) = vcount(t)*phat + C 
 * theta(t) = C(t) - t
 */
int process_bidir_stamp(struct radclock *clock_handle, struct bidir_peer *peer, struct bidir_stamp *input_stamp, int qual_warning)
{
	JDEBUG

	/* Allocate some data structure needed below */
	struct bidir_stamp *stamp = input_stamp;
	struct radclock_phyparam *phyparam = &(clock_handle->conf->phyparam);
	struct radclock_config *conf = clock_handle->conf;
	int poll_period = conf->poll_period;
	int sig_plocal = conf->start_plocal;

	vcounter_t RTT;	// Current RTT (vcount units to avoid pb if phat bad */

	/* Warmup and plocal window, gives fraction of Delta(t) sacrificed to near
	 * and far search windows
	 */
	unsigned int warmup_winratio = 4;
	unsigned int plocal_winratio = 5;

	/* Error bound reporting. Error bound correspond to the last effective update of
	 * thetahat (i.e. it may not be the value computed with the current stamp).
	 * avg and std are tracked based on the size of the top window
	 * Only the ones needed to track top level window replacing values need to be
	 * static (until the window mechanism is rewritten to proper data structure to
	 * avoid statics).
	 * No need for a "_last", it is maintained outside the algo (as well as the
	 * current number)
	*/
	double error_bound;
	double cumsum;
	double sq_cumsum;
	long nerror;

	int phat_sanity_raised;

	/* First thing is to react to configuration updates passed to the process */

	/* Here is the tricky semantic part If sig_plocal is set to 0 and 1, we
	 * check first is the value just changed.  If sig_local is set to 2, we may
	 * be willing to restart consecutively several times without a change in the
	 * configuration file.  For this reason, the main program falls back to
	 * PLOCAL_START, then a reload of the conf file with plocal set to 2 but
	 * inchanged restart plocal. 
	 */
	if ( HAS_UPDATE(conf->mask, UPDMASK_PLOCAL) ) 
	{
		/* Adjust state of plocal according to signal */
		if (sig_plocal == PLOCAL_START || sig_plocal == PLOCAL_RESTART)
			peer->using_plocal = 1;
		/* PLOCAL_STOP or anything else
		 * (variable plocal not used in any way, no further action required)
		 */
		else
			peer->using_plocal = 0;
	}

	/* If the poll period or environment quality has changed, some key algorithm
	 * parameters have to be updated.
	 */
	if ( HAS_UPDATE(conf->mask, UPDMASK_POLLPERIOD) || HAS_UPDATE(conf->mask, UPDMASK_TEMPQUALITY))
	{
		update_peer(peer, phyparam, poll_period, plocal_winratio);
	}

	/* It is the first stamp, we initialise the peer structure, push the first
	 * stamp in history, initialize key algorithm variables: algo parameters,
	 * window sizes, history structures, states, poll period effects and return
	 */
	if ( peer->stamp_i == 0 )
	{
// TODO need to fix the logic with the plocal management
		/* Adjust state of plocal according to signal */
		if (sig_plocal == PLOCAL_START || sig_plocal == PLOCAL_RESTART)
			peer->using_plocal = 1;
		/* PLOCAL_STOP or anything else
		 * (variable plocal not used in any way, no further action required)
		 */
		else
			peer->using_plocal = 0;

		init_peer(clock_handle, phyparam, peer, stamp, plocal_winratio, poll_period);
		copystamp(stamp, &peer->stamp);
		peer->stamp_i++;
 	
// TODO fixme, just a side effect	
// Make sure we have a valid RTT for the output file
		RTT = MAX(1,stamp->Tf - stamp->Ta);

// TODO This may go one day, but will break regression test		
		OUTPUT(clock_handle, best_Tf) 	= stamp->Tf;

		/* Set the status of the clock to STARAD_WARMUP */
		ADD_STATUS(clock_handle, STARAD_WARMUP);
		ADD_STATUS(clock_handle, STARAD_UNSYNC);

		goto output_results;
	}



//	/* On second packet, i=1, let's get things started */
//	if ( peer->stamp_i == 1 )
//	{
//		/* Set the status of the clock to STARAD_WARMUP */
//		verbose(VERB_CONTROL, "Beginning Warmup Phase");
//		ADD_STATUS(clock_handle, STARAD_WARMUP);
//		ADD_STATUS(clock_handle, STARAD_UNSYNC);
//	}


	/* 
	 * Clear UNSYNC status once the burst of NTP packets is finished. This
	 * corresponds to the first update passed to the kernel. Cannot really do
	 * push an update before this, and not much after either. It should be
	 * driven by some quality metrick, but implementation is taking priority at
	 * this stage.
	 * This status should be put back on duing long gaps (outside the algo
	 * thread then), and cleared once recover from gaps or data starvation.
	 * Ideally, should not be right on recovery (i.e. the > test) but when
	 * quality gets good. 
	 */
	if ( peer->stamp_i == NTP_BURST )
	{
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
	// TODO: this should not happen since stamps would not be passed to the
	// algo ... remove the MAX operation
	RTT = MAX(1,stamp->Tf - stamp->Ta);

	/* Store history of basics
	 * [use circular buffer   a%b  performs  a - (a/b)*b ,  a,b integer]
	 * copy stamp i into history immediately, will be used in loops
	 */
	history_add(&peer->stamp_hist, peer->stamp_i, stamp);

	history_add(&peer->RTT_hist, peer->stamp_i, &RTT);




	/* =============================================================================
	 * HISTORY WINDOW MANAGEMENT
	 * This should only be kicked in when we are out of warmup,
	 * but since history window way bigger than warmup, this is safe
	 * This resets history prior to stamp i
	 * Shift window not affected 
	 * =============================================================================
	 */

	/* Initialize:  middle of very first window */
	if ( peer->stamp_i == peer->top_win/2 ) {
		/* reset half window estimate - previously  RTThat=next_RTThat */

		/* Make sure RTT is non zero in case we have corrupted stamps */
		// TODO: this should not happen since stamps would not be passed to the
		// algo ... remove the MAX operation
		peer->next_RTThat = MAX(1, peer->stamp.Tf - peer->stamp.Ta);

		/* initiate on-line algo for new pstamp_i calculation * [needs to be in surviving half of window!]
		* record next_pstamp_i (index), RTT, RTThat, point error and stamp
		* TODO: jsearch_win should be chosen < ??
		*/
		peer->jsearch_win = peer->warmup_win;
		peer->jcount = 1;
		peer->next_pstamp_i = peer->stamp_i;
		peer->next_pstamp_RTThat = peer->RTThat;
		peer->next_pstamp_perr = peer->phat*(double)(RTT - peer->RTThat);
		copystamp(stamp, &peer->next_pstamp);
		/* Now DelTb >= top_win/2,  become fussier */
		peer->Ep_qual /= 10;

		/* Background error bounds reinitialisation */
		PEER_ERROR(peer)->cumsum_hwin 	= 0;
		PEER_ERROR(peer)->sq_cumsum_hwin = 0;
		PEER_ERROR(peer)->nerror_hwin 	= 0;

		verbose(VERB_CONTROL, "Adjusting history window before normal processing of stamp %lu. "
				"FIRST 1/2 window reached", peer->stamp_i);
	}

	/* at end of history window */
	if ( peer->stamp_i == peer->top_win_half ) {
		/* move window ahead by top_win/2 so i is the first stamp in the 2nd half */
		peer->top_win_half   += peer->top_win/2;
		/* reset RTT estimate - next_RTThat must have been reset at prior upward * shifts */
		peer->RTThat = peer->next_RTThat;
		/* reset half window estimate - prior shifts irrelevant */
		/* Make sure RTT is non zero in case we have corrupted stamps */
		// TODO: this should not happen since stamps would not be passed to the
		// algo ... remove the MAX operation
		peer->next_RTThat = MAX(1, peer->stamp.Tf - peer->stamp.Ta);
		/* Take care of effects on phat algo
		* - begin using next_pstamp_i that has been precalculated in previous top_win/2
		* - reinitialise on-line algo for new next_pstamp_i calculation
		*   Record [index RTT RTThat stamp ]
		*/
		peer->pstamp_i 	= peer->next_pstamp_i;
		peer->pstamp_RTThat = peer->next_pstamp_RTThat;
		peer->pstamp_perr 	= peer->next_pstamp_perr;
		copystamp(&peer->next_pstamp, &peer->pstamp);
		peer->jcount = 1;
		peer->next_pstamp_i 	= peer->stamp_i;
		peer->next_pstamp_RTThat 	= peer->RTThat;
		peer->next_pstamp_perr 	= peer->phat*(double)(RTT - peer->RTThat);
		copystamp(stamp, &peer->next_pstamp);

		/* Background error bounds taking over and restart all over again */
		PEER_ERROR(peer)->cumsum 	= PEER_ERROR(peer)->cumsum_hwin;
		PEER_ERROR(peer)->sq_cumsum	= PEER_ERROR(peer)->sq_cumsum_hwin;
		PEER_ERROR(peer)->nerror 	= PEER_ERROR(peer)->nerror_hwin;
		PEER_ERROR(peer)->cumsum_hwin 		= 0;
		PEER_ERROR(peer)->sq_cumsum_hwin	= 0;
		PEER_ERROR(peer)->nerror_hwin 		= 0;


		verbose(VERB_CONTROL, "Total number of sanity events:  phat: %u, plocal: %u, Offset: %u ",
				peer->phat_sanity_count, peer->plocal_sanity_count, peer->offset_sanity_count);
		verbose(VERB_CONTROL, "Total number of low quality events:  Offset: %u ", peer->offset_quality_count);
		verbose(VERB_CONTROL, "Adjusting history window before normal processing of stamp %lu. "
				"New pstamp_i = %lu ", peer->stamp_i, peer->pstamp_i);
	}




	/* =============================================================================
	* GENERIC DESCRIPTION
	*
	* WARMUP MODDE
	* 0<i<warmup_win
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
	* Main body, i >= warmup_win
	* Start using full algos [still some initialisations left]
	* Start wrapping history vectors   
	* =============================================================================
	*/

	collect_stats_peer(peer, stamp);
	if (peer->stamp_i < peer->warmup_win )
	{
		process_RTT_warmup(peer, RTT);
		process_phat_warmup(peer, RTT, warmup_winratio);
		
		if (peer->using_plocal)
			process_plocal_warmup(peer);
			process_thetahat_warmup(peer, clock_handle, phyparam, RTT, stamp);
	}
	else
	{
		process_RTT_full(peer, RTT);
		record_packet_j (peer, RTT, stamp);
		phat_sanity_raised = process_phat_full(peer, clock_handle, phyparam, RTT, stamp, qual_warning);

		if (peer->using_plocal)
			// XXX TODO stamp is passed only for quality warning, but plocal
			// windows exclude the current stamp!! should take into account the
			// quality warnings of the stamps actually picked up, no?
			// Check with Darryl
			process_plocal_full(peer, clock_handle, plocal_winratio, sig_plocal, stamp, phat_sanity_raised, qual_warning);

		process_thetahat_full(peer, clock_handle, phyparam, RTT, stamp, qual_warning);
	}



/* =============================================================================
 * END OF WARMUP INITIALISATION 
 * =============================================================================
 */

	if (peer->stamp_i == peer->warmup_win-1)
	{
		end_warmup_RTT(peer, stamp);
		end_warmup_phat( peer, stamp );
		if (peer->using_plocal)
			end_warmup_plocal( peer, stamp, plocal_winratio);
		end_warmup_thetahat( peer, stamp );

		parameters_calibration(peer);

		/* Set bounds on top window */
// TODO why is it done in here ??
		peer->top_win_half = peer->top_win - 1;

		verbose(VERB_CONTROL, "i=%lu: End of Warmup Phase. Stamp read check: "
				"%llu %22.10Lf %22.10Lf %llu",
				peer->stamp_i, stamp->Ta,stamp->Tb,stamp->Te,stamp->Tf);

		/* Remove STARAD_WARMUP from the clock's status */
		DEL_STATUS(clock_handle, STARAD_WARMUP);
	}



/* =============================================================================
 * RECORD LASTSTAMP
 * =============================================================================
 */
	copystamp(stamp, &peer->stamp);

	print_stats_peer(peer);

	/* 
	 * Prepare for next stamp.
	 * XXX Not great for printing things out of the algo (need to
	 * subtract 1)
	 */
	peer->stamp_i++;



/* =============================================================================
 * OUTPUT 
 * =============================================================================
 */

output_results:


/* TODO: minET is not the correct thetahat error. Should provide a better estimate */

	/* We lock the global data to to ensure data consistency. Do not want shared
	 * memory segment be half updated and 3rd party processes get bad data.
	 * // TODO comment below is as clear as mud
	 * Also we lock the matlab output data at the same time
	 * to ensure consistency for live captures.
	 */
	pthread_mutex_lock(&clock_handle->globaldata_mutex);
	/* Update clock variable for returning.
	 */ 
	RAD_DATA(clock_handle)->phat			= peer->phat;
	RAD_DATA(clock_handle)->phat_err		= peer->perr;
	RAD_DATA(clock_handle)->phat_local		= peer->plocal;
	RAD_DATA(clock_handle)->phat_local_err	= peer->plocalerr;
	RAD_DATA(clock_handle)->ca				= peer->C-(long double)peer->thetahat;
	RAD_DATA(clock_handle)->ca_err			= peer->minET;
	RAD_DATA(clock_handle)->last_changed	= stamp->Tf;
	
	/* The valid_till field has to take into account the fact that ntpd sends
	 * packets with true period intervals [poll-1,poll+2] (see an histogram of 
	 * capture if you are not convinced). Also an extra half a second to be safe.
	 * Also, for very slow counters (e.g. ACPI), the first phat estimate can 
	 * send this value far in the future. Wait for i > 1
	 */
	if ( peer->stamp_i > 1 ) 
		/* TODO: XXX Previously valid till was offset by 1.5s to allow for NTP's
		 * varying poll period when in piggy back mode
		 * RAD_DATA(clock_handle)->valid_till	= stamp->Tf + ((peer->poll_period -1.5) / peer->phat); */
		RAD_DATA(clock_handle)->valid_till	= stamp->Tf + ((peer->poll_period) / peer->phat);


	/* Clock error estimates.
	 * Aging similar to fast recovery after gap
	 * The first point is badly wrong due to our very first estimate of phat. So
	 * let's not introduce this distortion that can be as large as 3 orders of magnitude
	 * only drawback, we have no estimate on the first point ... big deal!
	 * Also (nerror-1) need to be > 0!
	 * TODO put that in a function ...
	 */
	if (peer->stamp_i > 1) {
		error_bound = PEER_ERROR(peer)->Ebound_min_last +
			peer->phat * (double)(stamp->Tf - peer->thetastamp.Tf) *
			phyparam->RateErrBOUND;

		PEER_ERROR(peer)->cumsum_hwin = PEER_ERROR(peer)->cumsum_hwin + error_bound;
		PEER_ERROR(peer)->sq_cumsum_hwin = PEER_ERROR(peer)->sq_cumsum_hwin +
			(error_bound * error_bound) ;
		PEER_ERROR(peer)->nerror_hwin = PEER_ERROR(peer)->nerror_hwin + 1;

		cumsum		= PEER_ERROR(peer)->cumsum + error_bound;
		sq_cumsum	= PEER_ERROR(peer)->sq_cumsum + (error_bound * error_bound);
		nerror		= PEER_ERROR(peer)->nerror + 1;

		RAD_ERROR(clock_handle)->error_bound 		= error_bound;
		if ( nerror > 2 )
		{
			RAD_ERROR(clock_handle)->error_bound_avg = cumsum / nerror;
			RAD_ERROR(clock_handle)->error_bound_std = sqrt((sq_cumsum -
						(cumsum * cumsum / nerror)) / (nerror - 1));
		}
		PEER_ERROR(peer)->cumsum	= cumsum;
		PEER_ERROR(peer)->sq_cumsum	= sq_cumsum;
		PEER_ERROR(peer)->nerror	= nerror;
		RAD_ERROR(clock_handle)->min_RTT = peer->RTThat * peer->phat;
	}

	/* We don't want the leapsecond to create a jump in post processing of data,
	 * so we reverse the operation performed in get_bidir_stamp. With this
	 * implementation this will not have an impact on the matlab output file
	 */
	RAD_DATA(clock_handle)->ca -= ((struct
	bidir_output*)clock_handle->algo_output)->leapsectotal;
	
//	errTa -= peer->thetahat;
//	errTf -= peer->thetahat;

	/* Support uniform output format if plocal not used */
	if (!peer->using_plocal)
		peer->plocal = peer->phat;

	/* Fill the output structure, used mainly to fill the matlab file
	 * TODO: there is a bit of redundancy in here
	 */
	OUTPUT(clock_handle, RTT) 			= RTT;
	OUTPUT(clock_handle, phat) 			= peer->phat;
	OUTPUT(clock_handle, perr) 			= peer->perr;
	OUTPUT(clock_handle, plocal) 		= peer->plocal;
	OUTPUT(clock_handle, plocalerr) 	= peer->plocalerr;
	OUTPUT(clock_handle, C) 			= peer->C;
	OUTPUT(clock_handle, thetahat) 		= peer->thetahat;
	OUTPUT(clock_handle, RTThat) 		= peer->RTThat;
	OUTPUT(clock_handle, RTThat_new)	= peer->next_RTThat;
	OUTPUT(clock_handle, RTThat_shift) 	= peer->RTThat_shift;
//	OUTPUT(clock_handle, th_naive) 		= th_naive;
//	OUTPUT(clock_handle, minET) 		= minET;
	OUTPUT(clock_handle, minET_last)	= peer->minET;
//	OUTPUT(clock_handle, errTa) 		= errTa;
//	OUTPUT(clock_handle, errTf) 		= errTf;
//	OUTPUT(clock_handle, wsum) 			= wsum;
//	stamp_tmp = history_find(&peer->stamp_hist, jbest);
//	OUTPUT(clock_handle, best_Tf) 		= stamp_tmp->Tf;
	OUTPUT(clock_handle, status) 		= RAD_DATA(clock_handle)->status;


	/* NTP server specific data */
	// TODO this is a bit dodgy to have this here ... 
	SERVER_DATA(clock_handle)->serverdelay = peer->RTThat * peer->phat;

	/* Unlock Global Data */
	pthread_mutex_unlock(&clock_handle->globaldata_mutex);




	return 0;

}


