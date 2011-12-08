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




/*
 * Synchronisation Algorithm and supporting functions
 */
#ifndef _SYNC_ALGO_H
#define _SYNC_ALGO_H


/************************************************************/
/**************** Reference Timestamp level *****************/ 

/**************** NTP case *****************/ 
/*   Standard client-server NTP packet exchange.
                 
                              Tb     Te            real times:  ta < tb < te < tf
                              |      |          available TS's: Ta < Tf  [vcount units]
               Server  ------tb------te--------                 Tb < Te  [sec]
                            /          \
                           /            \
               Client  ---ta-------------tf-----  
                         |                 |
                         Ta                Tf
*/


#include <sys/types.h>

#include "radclock.h"
#include "sync_history.h"


/* 
 * These don't exist in the standard math library 
 */
#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))


#define OUTPUT(clock, x) ((struct bidir_output*)clock->algo_output)->x
				 
/* 
 * Internal algo parameters and default values
 */



/* Machine characteristics (interrupt latency and CPU oscillator stability) */
// [sec] natural TSing limitation: `maximum' interrupt latency
#define TS_LIMIT_EXCEL			0.000015  
#define TS_LIMIT_GOOD			0.000015  
#define TS_LIMIT_POOR			0.000015  
// [sec] maximum timescale of validity of the Simple Skew Model (SKM)
#define SKM_SCALE_EXCEL			1024.0  
#define SKM_SCALE_GOOD			1024.0  
#define SKM_SCALE_POOR			 512.0  
// bound on rate error regardless of time scale
#define RATE_ERR_BOUND_EXCEL	0.0000001   
#define RATE_ERR_BOUND_GOOD		0.0000005   
#define RATE_ERR_BOUND_POOR		0.000001   
// limit of meaningful accuracy of SKM rate
#define BEST_SKM_RATE_EXCEL		0.00000005  
#define BEST_SKM_RATE_GOOD		0.0000002  
#define BEST_SKM_RATE_POOR		0.000001  
// Ratio defining offset based on TSLIMIT 
#define OFFSET_RATIO_EXCEL		6  
#define OFFSET_RATIO_GOOD		6
#define OFFSET_RATIO_POOR		6
// plocal quality 
#define PLOCAL_QUALITY_EXCEL	0.0000008 
#define PLOCAL_QUALITY_GOOD		0.0000008 
#define PLOCAL_QUALITY_POOR		0.0000008 


/*
 * Data structure storing physical parameters
 */
struct radclock_phyparam {
		double TSLIMIT;
		double SKM_SCALE;
		double RateErrBOUND;
		double BestSKMrate;
		int offset_ratio; 
		double plocal_quality;
};






/* 
 * Dealing with communication between algo and main
 * - plocal
 */
#define PLOCAL_STOP 		0		// this means stop now, but if already off, 'carry on'
#define PLOCAL_START 		1		// this means start now, but if on already, 'carry on'
#define PLOCAL_RESTART 		2		// this means restart Now





/*
 * Stamps structures, could be uni- or bi- directional. The generic stamp
 * structure also holds side info regarding network or the like.
 */
typedef enum { 
	STAMP_UNKNOWN,
	STAMP_SPY,
	STAMP_NTP,		/* Handed by libpcap */
	STAMP_PPS,
} stamp_type_t;


struct unidir_stamp {
	vcounter_t stamp;
};


struct bidir_stamp {
	vcounter_t  Ta;     // vcount timestamp [counter value] of pkt leaving client
	long double Tb;     // timestamp [sec] of arrival at server
	long double Te;     // timestamp [sec] of departure from server
	vcounter_t  Tf;     // vcount timestamp [counter value] of pkt returning to client
};


struct stamp_t {
	stamp_type_t type;
	union stamp_u {
		struct unidir_stamp ustamp;
		struct bidir_stamp  bstamp;
	} st;
		
	int qual_warning;	/* warning: route or server changes, server problem */
};

#define UST(x) (&((x)->st.ustamp))
#define BST(x) (&((x)->st.bstamp))


struct bidir_output 
{
	/* Long term tracking variables */
	int leapsectotal;
	long int n_stamps;

	/* Per-stamp output */
	vcounter_t 	RTT;
	double		phat;
	double		perr;
	double 		plocal;
	double 		plocalerr;
	long double C;
	double 		thetahat;
	vcounter_t 	RTThat;
	vcounter_t 	RTThat_new;
	vcounter_t 	RTThat_shift;
	double 		th_naive;
	double 		minET;
	double 		minET_last;
	double 		errTa;
	double 		errTf;
	double 		wsum;
	vcounter_t 	best_Tf;
	unsigned int status;
};


// TODO
// Should have a generic peer structure with data common to all and union for
// specific params
struct bidir_peer
{
	/* Main index
	 * unique stamp index (C notation [ 0 1 2 ...])
	 * 136 yrs @ 1 stamp/[sec] if 32bit
	 */
	index_t stamp_i;

	struct bidir_stamp stamp;	// record previous stamp

	/* Histories */
	history stamp_hist;
	history RTT_hist;
	history RTThat_hist;
	history thnaive_hist;

	/* Window sizes, measured in [pkt index] These control algorithm, independent of implementation */
	index_t warmup_win;			// warmup window, RTT estimation (indep of time and CPU, need samples)
	index_t top_win;			// top level window, must forget past
	index_t top_win_half;		// future stamp when top level window half is updated 
	index_t shift_win;			// shift detection window size
	index_t shift_end;			// shift detection record of oldest pkt in shift window
	index_t plocal_win;			// local period estimation window based on SKM scale
	index_t plocal_end;			// oldest pkt in local period estimation window
	index_t offset_win;			// offset estimation, based on SKM scale (don't allow too small)
	index_t jsearch_win;		// window width for choosing pkt j for phat estimation

	int poll_period;			// Current polling period for the peer
	index_t poll_transition_th;	// Number of future stamps remaining to complete new polling period transition (thetahat business)
	double poll_ratio;			// Ratio between new and old polling period after it changed
	index_t poll_changed_i;		// First stamp after change in polling period

	/* Error thresholds, measured in [sec], or unitless */
	double Eshift;				// threshold for detection of upward level shifts (should adapt to variability)
	double Ep;					// point error threshold for phat
	double Ep_qual;				// [unitless] quality threshold for phat (value after 1st window) 
	double Ep_sanity;			// [unitless] sanity check threshold for phat
	double Eplocal_qual;		// [unitless] quality      threshold for plocal 
	double Eplocal_sanity;		// [unitless] sanity check threshold for plocal
	double Eoffset;				// quality band in weighted theta estimate
	double Eoffset_qual;		// weighted quality threshold for offset, choose with Gaussian decay in mind!! small multiple of Eoffset
	double Eoffset_sanity_min;	// was absolute sanity check threshold for offset (should adapt to data)
	double Eoffset_sanity_rate;	// [unitless] sanity check threshold per unit time [sec] for offset

	/* Warmup phase */
	index_t wwidth;			// warmup width of end windows in pkt units (also used for plocal)
	index_t near_i;			// index of minimal RTT within near windows
	index_t far_i;			// index of minimal RTT within far windows
 
	/* RTT (in vcounter units to avoid pb if phat bad)
	 * Records related to top window, and level shift
	 */
	vcounter_t RTThat;				// Estimate of minimal RTT 
 	vcounter_t next_RTThat;			// RTT estimate to be in the next half top window
	vcounter_t RTThat_shift;		// sliding window RTT estimate for upward level shift detection
	vcounter_t RTThat_shift_thres;	// threshold in [vcount] units for triggering upward shift detection

	/* Oscillator period estimation */
	double phat;					// period estimate
	double perr;					// estimate of total error of phat [unitless]
	index_t jcount;					// counter for pkt index in jsearch window
	int phat_sanity_count;			// counters of error conditions

	/* Record of past stamps for oscillator period estimation */
	struct bidir_stamp pstamp;		// left hand stamp used to compute phat in full algo (1st half win)
	struct bidir_stamp next_pstamp;	// the one to be in the next half top window
	index_t pstamp_i;				// index of phat stamp 
	index_t next_pstamp_i;			// index of next phat stamp to be used
	double pstamp_perr;				// point error of phat stamp
	double next_pstamp_perr;		// point error of next phat stamp 
	vcounter_t pstamp_RTThat;		// RTThat estimate recorded with phat stamp 
	vcounter_t next_pstamp_RTThat;	// RTThat estimate recorded for next phat stamp

	/* Plocal estimation */
	double plocal;					// local period estimate
	double plocalerr;				// estimate of total error of plocal [unitless]
	int plocal_sanity_count;		// plocal sanity count
	int using_plocal;				// state variable for plocal refinement of algo:  1 = ON, 0 = OFF 
	int plocal_restartscheduled; 	// if plocal reinit required

	/* Offset estimation */
	long double C;		// Uncorrected clock origin alignement constant
						// must hold [sec] since timescale origin, and at least 1mus precision
	double thetahat;	// Drift correction for uncorrected clock
	double minET;		// Estimate of thetahat error
	struct bidir_stamp thetastamp;	// Stamp corresponding to last update of thetahat
	int offset_quality_count;		// Offset quality events counter
	int offset_sanity_count;		// Offset sanity events counter

	/* Statistics */
	int stats_sd[3];			// Stats on server delay (good, avg, bad)
};


/* 
 * Functions declarations
 */

int process_bidir_stamp(struct radclock *clock_handle, struct bidir_peer *peer, struct bidir_stamp *input_stamp, int qual_warning);



#endif
