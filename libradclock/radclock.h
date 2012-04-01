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

#ifndef _RADCLOCK_H
#define _RADCLOCK_H

#include <sys/time.h>
#include <stdint.h>
#include <pcap.h>

/*
 * This header defines the RADclock API to create a RADclock, access time and
 * get internal clock parameters.
 */

/* RADclock status word */
#define STARAD_UNSYNC			0x0001	/* RADclock not sync'ed (just started,
										 * server not reachable)
										 */
#define STARAD_WARMUP			0x0002	/* RADclock in warmup phase, error
										 * estimates unreliable
										 */
#define STARAD_KCLOCK			0x0004	/* RADclock kernel time is reliable */
#define STARAD_SYSCLOCK			0x0008	/* The system clock is fairly accurate
										 *  (if adjusted by the RADclock)
										 */
#define STARAD_STARVING			0x0010	/* RADclock is lacking quality input */
#define STARAD_PERIOD_QUALITY	0x0020	/* The quality of the RADclock period
										 * estimate is poor
										 */
#define STARAD_PERIOD_SANITY	0x0040	/* Consecutive period sanity checks have
										 * been triggered
										 */
#define STARAD_OFFSET_QUALITY	0x0080	/* The quality of the RADclock offset
										 * estimate is poor
										 */
#define STARAD_OFFSET_SANITY	0x0100	/* Consecutive offset sanity checks
										 * have been triggered
										 */


typedef uint64_t vcounter_t;

typedef enum { RADCLOCK_LOCAL_PERIOD_ON, RADCLOCK_LOCAL_PERIOD_OFF }
		radclock_local_period_t;

struct radclock;


/**
 * Read the tsc value from the cpu register. 
 * @return the current value of the TSC register
 */
vcounter_t radclock_readtsc(void);

/**
 * Read the vcounter value based on the current clocksource/timecounter selected. 
 * @return the current value of the vcounter
 */
int radclock_get_vcounter(struct radclock *clock, vcounter_t *vcount);


/**
 * Create a new radclock.
 * Each application needs to create its own copy of the radclock
 * @return a radclock clock or NULL on a failure
 */
struct radclock *radclock_create(void);


/**
 * Destroy the radclock clock.
 * @param The private clock for accessing global data
 */
void radclock_destroy(struct radclock *clock);


/**
 * Initialise a RADclock.
 * @param The private clock for accessing global data
 * @return 0 on success, -1 on failure
 */
int radclock_init(struct radclock *clock);


/**
 * Set the mode when composing time based on raw vcount values and RADclock parameters.
 * If set to RADCLOCK_LOCAL_PERIOD_ON a local estimate of the CPU
 * period is used instead of the long term estimate. The default behavior is to
 * have the local period estimate used, assuming the RADclock daemon is running
 * with plocal ON. If not this falls back to using the long term period
 * estimate.
 * @param clock The radclock clock
 * @param local_period_mode A reference to the mode used for creating timestamps 
 */
int radclock_set_local_period_mode(struct radclock *clock, radclock_local_period_t *local_period_mode);


/**
 * Retrieve the mode of composing time when reading the RADclock.
 * @param clock The radclock clock
 * @param local_period_mode A reference to the mode used for creating timestamps 
 */
int radclock_get_local_period_mode(struct radclock *clock, radclock_local_period_t *local_period_mode);


/**
 * Get the time from the radclock in a timeval format (micro second resolution).
 * @param  clock The private clock for accessing global data
 * @param  abstime_tv A reference to the timeval structure to be filled 
 * @return 0 on success
 * @return 1 on error
 * @return 2 on possibly poor quality timestamp (clock could not be reached, but
 * last data is recent)
 * @return 3 on very poor quality timestamp (clock could not be reached, and
 * last dat is really old)
 */
int radclock_gettime(struct radclock *clock, long double *abstime);


/**
 * Convert a vcounter value to a timeval struct representation of absolute time,
 * based on the current radclock parameters.
 * Obtain a micro second resolution. 
 * @param  clock The private clock for accessing global data
 * @param  vcount A reference to the vcounter_t vcounter value to convert 
 * @param  abstime_tv A reference to the timeval structure to be filled 
 * @return 0 on success
 * @return 1 on error
 * @return 2 on possibly poor quality timestamp (clock could not be reached, but
 * last data is recent)
 * @return 3 on very poor quality timestamp (clock could not be reached, and
 * last dat is really old)
 */
int radclock_vcount_to_abstime(struct radclock *clock, const vcounter_t *vcount,
		long double *abstime);


/** 
 * Get the time elapsed since a vcount event in a timeval format based on the current radclock parameters.
 * Obtain a micro second resolution. 
 * @param  clock The private clock for accessing global data 
 * @param  past_vcount A reference to the vcount value corresponding to the past event
 * @param  duration_tv A reference to the long double time value to be filled 
 * @return 0 on success
 * @return 1 on error
 * @return 2 on possibly poor quality timestamp (clock could not be reached, but
 * last data is recent)
 * @return 3 on very poor quality timestamp (clock could not be reached, and
 * last dat is really old)
 */
int radclock_elapsed(struct radclock *clock, const vcounter_t *past_vcount,
		long double *duration);


/** 
 * Get a duration between two vcount events in a timeval format based on the current radclock parameters.
 * Obtain a micro second resolution. 
 * @param  clock The private clock for accessing global data 
 * @param  start_vcount A reference to the vcount value corresponding to the starting event
 * @param  end_vcount A reference to the vcount value corresponding to the ending event
 * @param  duration_tv A reference to the timeval structure to be filled 
 * @return 0 on success
 * @return 1 on error
 * @return 2 on possibly poor quality timestamp (clock could not be reached, but
 * last data is recent)
 * @return 3 on very poor quality timestamp (clock could not be reached, and
 * last dat is really old)
 */
int radclock_duration(struct radclock *clock, const vcounter_t *start_vcount,
		const vcounter_t *end_vcount, long double *duration);


/** 
 * Get instantaneous estimate of the clock error bound in seconds
 * @param  clock The private clock for accessing global data 
 * @param  duration_fp A reference to the long double time value to be filled 
 * @return 0 on success
 * @return 1 on error
 * @return 2 on possibly outdated data (clock could not be reached, but
 * last data is recent)
 * @return 3 on very old data (clock could not be reached)
 */
int radclock_get_clockerror_bound(struct radclock *clock, double *error_bound);


/** 
 * Get averaged estimate of the clock error bound in seconds
 * @param  clock The private clock for accessing global data 
 * @param  duration_fp A reference to the long double time value to be filled 
 * @return 0 on success
 * @return 1 on error
 * @return 2 on possibly outdated data (clock could not be reached, but
 * last data is recent)
 * @return 3 on very old data (clock could not be reached)
 */
int radclock_get_clockerror_bound_avg(struct radclock *clock, double *error_bound_avg);


/** 
 * Get standard deviation estimate of the clock error bound in seconds
 * @param  clock The private clock for accessing global data 
 * @param  duration_fp A reference to the long double time value to be filled 
 * @return 0 on success
 * @return 1 on error
 * @return 2 on possibly outdated data (clock could not be reached, but
 * last data is recent)
 * @return 3 on very old data (clock could not be reached)
 */
int radclock_get_clockerror_bound_std(struct radclock *clock, double *error_bound_std);


/** 
 * Get estimate of the minimum RTT to reference clock in seconds
 * @param  clock The private clock for accessing global data 
 * @param  duration_fp A reference to the long double time value to be filled 
 * @return 0 on success
 * @return 1 on error
 * @return 2 on possibly outdated data (clock could not be reached, but
 * last data is recent)
 * @return 3 on very old data (clock could not be reached)
 */
int radclock_get_min_RTT(struct radclock *clock, double *min_RTT);


/**
 * Get the vcount value corresponding to the last time the clock
 * parameters have been updated.
 * @param  clock The private clock for accessing global data
 * @param  last_stamp A reference to the vcounter value to be filled
 * @return 0 on success
 * @return 1 on error
 * @return 2 on possibly outdated data (clock could not be reached, but
 * last data is recent)
 * @return 3 on very old data (clock could not be reached)
 */
int radclock_get_last_stamp(struct radclock *clock, vcounter_t *last_stamp);


/**
 * Get the vcount value corresponding to the next time the clock
 * should be updated.
 * @param  clock The private clock for accessing global data
 * @param  till_stamp A reference to the vcounter value to be filled
 * @return 0 on success
 * @return 1 on error
 * @return 2 on possibly outdated data (clock could not be reached, but
 * last data is recent)
 * @return 3 on very old data (clock could not be reached)
 */
int radclock_get_till_stamp(struct radclock *clock, vcounter_t *till_stamp);


/**
 * Get the period of the CPU oscillator.
 * @param  clock The private clock for accessing global data
 * @param  period A reference to the double period to be filled
 * @return 0 on success
 * @return 1 on error
 * @return 2 on possibly outdated data (clock could not be reached, but
 * last data is recent)
 * @return 3 on very old data (clock could not be reached)
 */
int radclock_get_period(struct radclock *clock, double *period);


/**
 * Get the radclock offset.
 * @param  clock The private clock for accessing global data
 * @param  offset A reference to the long double offset to be filled
 * @return 0 on success
 * @return 1 on error
 * @return 2 on possibly outdated data (clock could not be reached, but
 * last data is recent)
 * @return 3 on very old data (clock could not be reached)
 */
int radclock_get_offset(struct radclock *clock, long double *offset);


/**
 * Get the error estimate of period of the CPU oscillator.
 * @param  clock The private clock for accessing global data
 * @param  err_period A reference to the double err_period to be filled
 * @return 0 on success
 * @return 1 on error
 * @return 2 on possibly outdated data (clock could not be reached, but
 * last data is recent)
 * @return 3 on very old data (clock could not be reached)
 */
int radclock_get_period_error(struct radclock *clock, double *err_period);


/**
 * Get the error estimate of the radclock offset.
 * @param  clock The private clock for accessing global data
 * @param  err_offset A reference to the long double err_offset to be filled
 * @return 0 on success
 * @return 1 on error
 * @return 2 on possibly outdated data (clock could not be reached, but
 * last data is recent)
 * @return 3 on very old data (clock could not be reached)
 */
int radclock_get_offset_error(struct radclock *clock, double *err_offset);


/**
 * Get the status of the radclock.
 * @param  clock The private clock for accessing global data
 * @param  status A reference to the unsigned int status to be filled
 * @return 0 on success
 * @return 1 on error
 * @return 2 on possibly outdated data (clock could not be reached, but
 * last data is recent)
 * @return 3 on very old data (clock could not be reached)
 */
int radclock_get_status(struct radclock *clock, unsigned int *status);



/* Modes accepted by a kernel with RADclock support
 * The different modes allow returning different types of timestamps
 */
enum radclock_tsmode {
	/* Kernel modes are number from 1 to 3 */
	RADCLOCK_TSMODE_NOMODE = 0,	
	/* Return normal system clock time stamp and corresponding vcount value */
	RADCLOCK_TSMODE_SYSCLOCK = 1, 
	/* Return vcount value and timeval timestamp both using the RADclock */
	RADCLOCK_TSMODE_RADCLOCK = 2,
	/* Return vcount value and system clock timestamp taken at the same improved
	 * location in the kernel */
	RADCLOCK_TSMODE_FAIRCOMPARE = 3
};

typedef enum radclock_tsmode radclock_tsmode_t ;


/**
 * Register pcap clock into radclock structure
 */
int radclock_register_pcap(struct radclock *clock, pcap_t *pcap_handle);


/**
 * Set the mode of timestamping on the pcap handle
 * This will only work on a live socket.
 * @return 0 on success, non-zero on failure
 */
int radclock_set_tsmode(struct radclock *clock, pcap_t *p_handle, radclock_tsmode_t mode);


/**
 * Get the mode of timestamping on the pcap handle into the refence
 * This will only work on a live socket.
 * @return 0 on success, non-zero on failure
 */
int radclock_get_tsmode(struct radclock *clock, pcap_t *p_handle, radclock_tsmode_t *mode);


/**
 * Get a packet all associated information.
 * This is a shorcut function to read a single packet and get all the
 * associated timestamps.
 * @return error code 
 */
int radclock_get_packet(struct radclock *clock, pcap_t *p_handle,
		struct pcap_pkthdr *header, unsigned char **packet, vcounter_t *vcount, struct timeval *ts);


#endif
