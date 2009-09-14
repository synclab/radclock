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
#include <radclock.h>



/* 
 * These don't exist in the standard math library 
 */
#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))


				 
/* 
 * Internal alog parameters and default values
 */

#define MIN_NTP_POLL_PERIOD 	1	// 1  NTP pkt every NTP_POLL_PERIOD [sec]



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





// TODO sPort is useful for packet mathing purpose (packet pairs and DAG data
// but it is a bit dirty 
/**
 * Bi-directionnal stamp used by the bidirectionnal synchronisation algorithm
 */
struct bidir_stamp {
	vcounter_t  Ta;     // vcount timestamp [counter value] of pkt leaving client
	long double Tb;     // timestamp [sec] of arrival at server
	long double Te;     // timestamp [sec] of departure from server
	vcounter_t  Tf;     // vcount timestamp [counter value] of pkt returning to client
	int 		qual_warning;    // warning level: route or server changes, server problem
	int 		sPort; // Source port of the client NTP request (useful if using ntpdate)
};




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
	vcounter_t 	RTThat_sh;
	double 		th_naive;
	double 		minET;
	double 		minET_last;
	double 		errTa;
	double 		errTf;
	double 		wsum;
	vcounter_t 	best_Tf;
	unsigned int status;
};





/* 
 * Functions declarations
 */

int process_bidir_stamp(struct radclock *clock_handle, struct bidir_stamp *input_stamp);



#endif
