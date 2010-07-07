/*
 * Copyright (C) 2006-2010 Julien Ridoux <julien@synclab.org>
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
 * This program illustrate the use of functions related to time access and
 * defined in the RADclock API. These functions:
 * - retrieve the RADclock internal parameters
 * - access the RAW vcounter
 * - give access to absolute time based on the RADclock
 * - give access to difference time baed on the RADclock.
 *
 * The RADclock daemon should be running for this example to work correctly.
 */ 

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>

/* Needed for accessing the RADclock API */
#include <radclock.h>





int main (int argc, char *argv[])
{
	/* RADclock */
	struct radclock *clock_handle;

	/* Clock parameters */
	unsigned int status;
	double period;
	double period_error;
	long double offset;
	double offset_error;

	/* Time data structure */
	struct timeval tv;
	long double currtime;
	time_t currtime_t;

	/* Raw vcounter stamps */
	vcounter_t vcount1, vcount2;

	int j;
	int err = 0;


	/* Initialize the clock handle */
	clock_handle = radclock_create();
	if (!clock_handle) {
		fprintf(stderr, "Could not create clock handle");
		return -1;
	}
	radclock_init(clock_handle);


	/* radclock_get_*
	 *
	 * Functions to get some information regarding the radclock itself
	 */
	err += radclock_get_status(clock_handle, &status);
	err += radclock_get_last_stamp(clock_handle, &vcount1);
	err += radclock_get_period(clock_handle, &period);
	err += radclock_get_offset(clock_handle, &offset);
	err += radclock_get_period_error(clock_handle, &period_error);
	err += radclock_get_offset_error(clock_handle, &offset_error);

	if ( err != 0 ) {
	   printf ("At least one of the calls to the radclock failed. Giving up.\n");	
	   return -1;
	}

	printf("Get some information about the clock parameters: \n");
	printf(" - Clock status: %u\n", status);
	printf(" - Clock last update (vcount value): %"VC_FMT" \n", vcount1);
	printf(" - Clock ocsillator period: %15.9lg \n", period);
	printf(" - Clock ocsillator period error: %15.9lg \n", period_error);
	printf(" - Clock offset: %22.9Lf\n", offset);
	printf(" - Clock offset error: %15.9lf\n", offset_error);


	/* radclock_get_vcounter
	 *
	 * Quick test to check the routinte to access the RAW vcounter 
	 */
	err = radclock_get_vcounter(clock_handle, &vcount1);
	printf(" Initial vcounter reading is %"VC_FMT" error=%d\n", vcount1, err);
	for ( j=0; j<5; j++ ) {

		err = radclock_get_vcounter(clock_handle, &vcount2);
		radclock_duration_fp(clock_handle, &vcount1, &vcount2, &currtime);
		printf(" Delta(vcount) from previous vcount = %"VC_FMT"  (%9.4Lg [ms]) error=%d\n", vcount2-vcount1, currtime*1e3, err);
		vcount1 = vcount2;
	}
	printf("\n");


	/* radclock_gettimeofday 
	 *
	 * This uses the absolute RADclock, and passes back a tval, 
	 * on the UNIX timescale. It is based on a vcounter reading made 
	 * in user space
	 */
	printf("Calling the RADclock equivalent to gettimeofday\n");
	err = radclock_gettimeofday(clock_handle, &tv);
	if ( err ) {
		printf("ERROR: could not get time from the vcount clock\n");
		exit (1);
	}
	printf(" - radclock_gettimeofday now: %s (UNIX time: %ld.%6d)\n", ctime((time_t *)&(tv.tv_sec)), tv.tv_sec, (int)tv.tv_usec);


	/* radclock_gettimeofday_fp
	 * 
	 * This uses the absolute RADclock, and passes back a long double,
	 * the resolution depends on the selected oscillator frequency and 
	 * the definition of a long double on your architecture
	 */
	printf("Calling the RADclock equivalent to gettimeofday with possibly higher resolution'\n");
	err = radclock_gettimeofday_fp(clock_handle, &currtime);
	currtime_t = (time_t) currtime;
	printf(" - radclock_gettimeofday now: %s (UNIX time: %12.20Lf)\n", ctime(&currtime_t), currtime);


	/* radclock_vcount_to_abstime and radclock_vcount_to_abstime_fp
	 *
	 * This allows to quickly read the counter, store the value and
	 * convert it to time information later on.
	 * Since the RADclock is updated every poll_period seconds, the conversion
	 * should be done within that interval.
	 */
	err = radclock_get_vcounter(clock_handle, &vcount1);
	printf("Reading a vcount value now: %"VC_FMT" \n", vcount1);

	err = radclock_vcount_to_abstime(clock_handle, &vcount1, &tv);
	printf(" - converted to timeval: %s (UNIX time: %ld.%6d)\n", ctime((time_t *)&(tv.tv_sec)), tv.tv_sec, (int)tv.tv_usec);

	err = radclock_vcount_to_abstime_fp(clock_handle, &vcount1, &currtime);
	currtime_t = (time_t) currtime;
	printf(" - converted to long double: %s (UNIX time: %12.20Lf)\n", ctime(&currtime_t), currtime);


	/* radclock_elapsed and radclock_elapsed_fp
	 *
	 * These take advantage of the stability of the difference RADclock. These
	 * are the function to use to measure time intervals over a short time scale
	 * between a past event and now.
	 */
	err = radclock_get_vcounter(clock_handle, &vcount1);
	printf("Reading a vcount value now: %"VC_FMT" \n", vcount1);
	
	printf(" - We have a little rest and sleep for 2 seconds...\n");
	sleep(2);

	err = radclock_elapsed(clock_handle, &vcount1, &tv);
	err = radclock_elapsed_fp(clock_handle, &vcount1, &currtime);

	printf(" - radclock_elapsed says we have been sleeping for [sec] %ld.%6d\n", tv.tv_sec, (int)tv.tv_usec);
	printf(" - radclock_elapsed_fp says we have been sleeping for [sec] %12.20Lf\n", currtime);


	/* radclock_duration and radclock_duration_fp 
	 *
	 * These take advantage of the stability of the difference RADclock. These
	 * are the function to use to measure time intervals over a short time scale
	 * between two events.
	 */
	err = radclock_get_vcounter(clock_handle, &vcount1);
	printf("Reading a vcount value now: %"VC_FMT" \n", vcount1);
	
	printf(" - We have a little rest and sleep for 2 seconds...\n");
	sleep(2);
	
	err = radclock_get_vcounter(clock_handle, &vcount2);
	printf("Reading a second vcount value now: %"VC_FMT" \n", vcount2);

	err = radclock_duration(clock_handle, &vcount1, &vcount2, &tv);
	err = radclock_duration_fp(clock_handle, &vcount1, &vcount2, &currtime);
	
	printf(" - radclock_duration says we have been sleeping for [sec] %ld.%6d\n", tv.tv_sec, (int)tv.tv_usec);
	printf(" - radclock_duration_fp says we have been sleeping for [sec] %12.20Lf\n", currtime);

	return 0;
}

