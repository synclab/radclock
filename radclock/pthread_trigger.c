/*
 * Copyright (C) 2006-2012, Julien Ridoux <julien@synclab.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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

#include "../config.h"

#ifdef HAVE_POSIX_TIMER
#include <sys/time.h>
#endif
//#include <sys/types.h>
//#include <sys/socket.h>

//#include <arpa/inet.h>
//#include <netinet/in.h>

//#include <errno.h>
//#include <netdb.h>
#include <pthread.h>
//#include <signal.h>
//#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>

#include "radclock.h"
#include "radclock-private.h"
#include "radclock_daemon.h"
#include "misc.h"
#include "verbose.h"
#include "sync_history.h"
#include "sync_algo.h"
#include "config_mgr.h"
//#include "proto_ntp.h"
#include "pthread_mgr.h"
#include "jdebug.h"



// TODO check if these two have to stay here or should be moved elsewhere.
// have been extern'ed in client_ntp.c
pthread_mutex_t alarm_mutex;
pthread_cond_t alarm_cwait;


/*
 * NTP client declarations.
 */
int ntp_client_init(struct radclock_handle *handle);
int ntp_client(struct radclock_handle *handle);


/*
 * This one does nothing except sleep and wake up the processing thread every
 * second.
 */
int
dummy_client() { JDEBUG

	/* 500 ms */
	usleep(500000);
	return (0);
}

/*
 * Timer handler
 */
void catch_alarm(int sig)
{
	JDEBUG

	pthread_mutex_lock(&alarm_mutex);
	pthread_cond_signal(&alarm_cwait);
	pthread_mutex_unlock(&alarm_mutex);
}


/* (re)set and arm the POSIX timer */
#ifdef HAVE_POSIX_TIMER
int
set_ptimer(timer_t timer, float next, float period)
{
	struct itimerspec itimer_ts;

	itimer_ts.it_value.tv_sec = (int) next;
	itimer_ts.it_value.tv_nsec = 1e9 * (next - (int) next);
	itimer_ts.it_interval.tv_sec = (int) period;
	itimer_ts.it_interval.tv_nsec = 1e9 * (period - (int) period);

	return (timer_settime(timer, 0 /*!TIMER_ABSTIME*/, &itimer_ts, NULL));
}

/* Is there a need for change? */
int
assess_ptimer(timer_t timer, float period)
{
	struct itimerspec its;
	float ptnext;
	float ptperiod;
	int err;

	JDEBUG

	err = timer_gettime(timer, &its);
	if (err < 0)
		return (err);

	ptnext   = its.it_value.tv_sec + (float)its.it_value.tv_nsec / 1e9;
	ptperiod = its.it_interval.tv_sec + (float)its.it_interval.tv_nsec / 1e9;

	if (ptperiod != period)
		err = set_ptimer(timer, ptnext, period);

	return (err);
}
#else /* ! HAVE_POSIX_TIMER */
int
set_itimer(float next, float period)
{
	struct itimerval itv;

	itv.it_value.tv_sec = (int) next;
	itv.it_value.tv_usec = 1e6 * (next - (int) next);
	itv.it_interval.tv_sec = (int) period;
	itv.it_interval.tv_usec = 1e6 * (period - (int) period);
	return (setitimer(ITIMER_REAL, &itv, NULL));
}

int
assess_itimer(float period)
{
	struct itimerval itv;
	float itperiod;
	float itnext;
	int err;

	JDEBUG

	err = getitimer(ITIMER_REAL, &itv);
	if (err < 0)
		return (err);

	itnext   = itv.it_value.tv_sec + (float)itv.it_value.tv_usec / 1e6;
	itperiod = itv.it_interval.tv_sec + (float)itv.it_interval.tv_usec / 1e6;

	if (itperiod != period)
		return (set_itimer(itnext, itperiod));

	return (0);
}
#endif /* HAVE_POSIX_TIMER */


int
trigger_work(struct radclock_handle *handle)
{
	vcounter_t vcount;
	int err;

	JDEBUG

	switch (handle->conf->synchro_type) {
	case SYNCTYPE_SPY:
	case SYNCTYPE_PIGGY:
	case SYNCTYPE_PPS:
	case SYNCTYPE_1588:
		dummy_client();
		break;

	case SYNCTYPE_NTP:
		ntp_client(handle);
		break;

	default:
		verbose(LOG_ERR, "Trigger for this sync type is not implemented");
		break;
	}

	/*
	 * Here we have a notion of time elapsed that is not driven by packet input,
	 * so we can act upon starvation periods and set correct clock status if
	 * needed.
	 * TODO Need to move from STARVING to UNSYNC and clear that either
	 * here or in the sync algo
	 */
	err = radclock_get_vcounter(handle->clock, &vcount);
	if (err < 0)
		return (err);

	if ((vcount - RAD_DATA(handle)->last_changed) * RAD_DATA(handle)->phat >
			handle->conf->phyparam.SKM_SCALE / 2) {
		/* Data is quite old */
		if (!HAS_STATUS(handle, STARAD_STARVING)) {
			verbose(LOG_WARNING, "Clock is starving. No valid input for a long "
					"time!!");
			ADD_STATUS(handle, STARAD_STARVING);
		}
	} else
		/* We are happy with the data */
		DEL_STATUS(handle, STARAD_STARVING);

	return (0);
}



int
trigger_init(struct radclock_handle *handle)
{
	int err;

	JDEBUG

	err = 0;
	if (!VM_SLAVE(handle)) {
		switch (handle->conf->synchro_type) {
		case SYNCTYPE_SPY:
		case SYNCTYPE_PIGGY:
			/* Nothing to do */
			break;

		case SYNCTYPE_NTP:
			err = ntp_client_init(handle);
			break;

		case SYNCTYPE_1588:
		case SYNCTYPE_PPS:
		default:
			verbose(LOG_ERR, "Init Trigger type not implemented");
			break;
		}
	}
	return (err);
}


