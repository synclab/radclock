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


#include <sys/types.h>
#include <sys/timepps.h>

#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>


inline void
ts_sub(struct timespec *ts1, struct timespec *ts2)
{
	ts1->tv_sec -= ts2->tv_sec;
	ts1->tv_nsec -= ts2->tv_nsec;
	if (ts1->tv_nsec < 0) {
		ts1->tv_sec--;
		ts1->tv_nsec += 1000000000;
	}
}


void
print_pulse(pps_info_ffc_t *pi)
{
	ffcounter delta_ffc;
	struct timespec delta_ts;
	struct timespec *assert_ts, *clear_ts;

	assert_ts = (struct timespec *) &(pi->assert_tu);
	clear_ts = (struct timespec *) &(pi->clear_tu);
	delta_ts = *clear_ts;
	ts_sub(&delta_ts, assert_ts);
	delta_ffc = pi->clear_ffcount - pi->assert_ffcount;

	fprintf(stdout, "ASSERT: %llu %ld.%09lu %8d | "
		"CLEAR: %llu %ld.%09lu %8d | "
		"DELTA: %8llu %2ld.%09lu | "
		"MODE: %d\n",
		(long long unsigned)pi->assert_ffcount,
		assert_ts->tv_sec, assert_ts->tv_nsec,
		pi->assert_sequence,
		(long long unsigned) pi->clear_ffcount,
		clear_ts->tv_sec, clear_ts->tv_nsec, pi->clear_sequence,
		(long long unsigned)delta_ffc, delta_ts.tv_sec, delta_ts.tv_nsec,
		pi->current_mode);
	fflush(stdout);
}


int
report_pps_capability(pps_handle_t ph, int *capability)
{
	int err;

	err = time_pps_getcap(ph, capability);
	if (err < 0) {
		fprintf(stderr, "time_pps_getcap failed");
		return err;
	}

	fprintf(stdout, "%% PPS-API Capability report:\n");

	if (*capability & PPS_CAPTUREASSERT)
		fprintf(stdout, "%%  PPS_CAPTUREASSERT:\tyes\n");
	else
		fprintf(stdout, "%%  PPS_CAPTUREASSERT:\tno\n");

	if (*capability & PPS_CAPTURECLEAR)
		fprintf(stdout, "%%  PPS_CAPTURECLEAR:\tyes\n");
	else
		fprintf(stdout, "%%  PPS_CAPTURECLEAR:\tno\n");

	if (*capability & PPS_OFFSETASSERT)
		fprintf(stdout, "%%  PPS_OFFSETASSERT:\tyes\n");
	else
		fprintf(stdout, "%%  PPS_OFFSETASSERT:\tno\n");

	if (*capability & PPS_OFFSETCLEAR)
		fprintf(stdout, "%%  PPS_OFFSETCLEAR:\tyes\n");
	else
		fprintf(stdout, "%%  PPS_OFFSETCLEAR:\tno\n");

	if (*capability & PPS_ECHOASSERT)
		fprintf(stdout, "%%  PPS_ECHOASSERT:\tyes\n");
	else
		fprintf(stdout, "%%  PPS_ECHOASSERT:\tno\n");

	if (*capability & PPS_ECHOCLEAR)
		fprintf(stdout, "%%  PPS_ECHOCLEAR:\tyes\n");
	else
		fprintf(stdout, "%%  PPS_ECHOCLEAR:\tno\n");

	if (*capability & PPS_CANWAIT)
		fprintf(stdout, "%%  PPS_CANWAIT:\t\tyes\n");
	else
		fprintf(stdout, "%%  PPS_CANWAIT:\t\tno\n");

	if (*capability & PPS_CANPOLL)
		fprintf(stdout, "%%  PPS_CANPOLL:\t\tyes\n");
	else
		fprintf(stdout, "%%  PPS_CANPOLL:\t\tno\n");

	if (*capability & PPS_TSFMT_TSPEC)
		fprintf(stdout, "%%  PPS_TSFMT_TSPEC:\tyes\n");
	else
		fprintf(stdout, "%%  PPS_TSFMT_TSPEC:\tno\n");

	if (*capability & PPS_TSFMT_NTPFP)
		fprintf(stdout, "%%  PPS_TSFMT_NTPFP:\tyes\n");
	else
		fprintf(stdout, "%%  PPS_TSFMT_NTPFP:\tno\n");

	if (*capability & PPS_TSCLK_FBCK)
		fprintf(stdout, "%%  PPS_TSCLK_FBCK:\tyes\n");
	else
		fprintf(stdout, "%%  PPS_TSCLK_FBCK:\tno\n");

	if (*capability & PPS_TSCLK_FFWD)
		fprintf(stdout, "%%  PPS_TSCLK_FFWD:\tyes\n");
	else
		fprintf(stdout, "%%  PPS_TSCLK_FFWD:\tno\n");

	return 0;
}



int
set_pps_parameters(pps_handle_t ph, int capability, int tsclock, pps_params_t *ppsparams)
{
	int mode;
	int err;

	mode = 0;

	if (capability & PPS_CAPTUREASSERT)
		mode |= PPS_CAPTUREASSERT;

	if (capability & PPS_CAPTURECLEAR)
		mode |= PPS_CAPTURECLEAR;

	if (capability & tsclock)
		mode |= tsclock;
	else {
		fprintf(stdout, "Warning: PPS-API does not support this tsclock: %d\n", tsclock);
		return (-1);
	}

	ppsparams->mode = mode;

	err = time_pps_setparams(ph, ppsparams);
	if (err < 0) {
		fprintf(stderr, "time_pps_setparams\n");
		return (err);
	}

	err = time_pps_getparams(ph, ppsparams);
	if (err < 0) {
		fprintf(stderr, "time_pps_getparams\n");
		return (err);
	}
	
	if (mode != ppsparams->mode) {
		fprintf(stderr, "Inconsistent parameters: mode = %d, pps = %d\n", mode, ppsparams->mode);
		return (-1);
	}

	return (0);
}

int
capture_pulses(pps_handle_t ph, int ppscount)
{
	pps_info_ffc_t pi_ffc;
	struct timespec to;
	unsigned int old_assert, old_clear;
	int count;
	int err;

	count = 0;
	to.tv_nsec = 0;
	to.tv_sec = 0;
	old_assert = 0;
	old_clear = 0;

	while (1) {
		err = time_pps_fetch_ffc(ph, PPS_TSFMT_TSPEC, &pi_ffc, &to);
		if (err < 0) {
			fprintf(stderr, "time_pps_fetch");
			time_pps_destroy(ph);
			return (err);
		}

		if (old_assert == pi_ffc.assert_sequence &&
		    old_clear == pi_ffc.clear_sequence) {
			//usleep(10000);
			usleep(500000);
			continue;
		}

		// TODO: should do a bit of housecleaning if we fetch in between CLEAR
		// and ASSERT, otherwise, get mismatch pulses. Note, possible on of the
		// edges is missed by kernel, so seq numbers may drift away

		print_pulse(&pi_ffc);

		old_assert = pi_ffc.assert_sequence;
		old_clear = pi_ffc.clear_sequence;

		count++;
		if ( ppscount && (count >= ppscount))
			break;
	}

	fprintf(stdout, "Captured %d pulses\n", count);

	return (0);
}


int
main(int argc, char **argv)
{
	int fd;
	pps_handle_t ph;
	pps_params_t ppsparams;
	int capability;
	int err;

	if (argc < 2)
		argv[1] = "/dev/cuaa1";

	setbuf(stdout, 0);

	fd = open(argv[1], O_RDONLY);
	if (fd < 0)
		fprintf(stderr, "Cannot open device: %s\n", argv[1]);

	err = time_pps_create(fd, &ph);
	if (err < 0)
		fprintf(stderr, "time_pps_create\n");

	err = report_pps_capability(ph, &capability);
	if (err < 0) {
		time_pps_destroy(ph);
		return (1);
	}

	err = set_pps_parameters(ph, capability, PPS_TSCLK_FBCK, &ppsparams);
	if (err < 0) {
		time_pps_destroy(ph);
		return (1);
	}

	err = capture_pulses(ph, 3);
	if (err < 0) {
		time_pps_destroy(ph);
		return (1);
	}

	err = set_pps_parameters(ph, capability, PPS_TSCLK_FFWD, &ppsparams);
	if (err < 0) {
		time_pps_destroy(ph);
		return (1);
	}

	err = capture_pulses(ph, 0);
	if (err < 0) {
		time_pps_destroy(ph);
		return (1);
	}

	time_pps_destroy(ph);

	return(0);
}
