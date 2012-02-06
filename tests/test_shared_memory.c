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

#include "../config.h"


#include <sys/shm.h>

#include <errno.h>		// manage failed shmget calls 
#include <fcntl.h>		// open()
#include <stdlib.h>
#include <stdio.h>
#include <string.h>		// manage failed shmget calls 
#include <unistd.h>		// for sleep()


#include "radclock.h"
#include "radclock-private.h"


int
read_raddata(struct radclock_data *data)
{
	
	if (!data) {
		fprintf(stdout, "ERROR: NULL data pointer\n");
		return (1);
	}

	fprintf(stdout, "  phat: %.10g\n", data->phat);
	fprintf(stdout, "  phat_err: %.6g\n", data->phat_err);
	fprintf(stdout, "  phat_local: %.10g\n", data->phat_local);
	fprintf(stdout, "  phat_local_err: %.6g\n", data->phat_local_err);
	fprintf(stdout, "  ca: %.9Lf\n", data->ca);
	fprintf(stdout, "  ca_err: %.6g\n", data->ca_err);
	fprintf(stdout, "  status: %u\n", data->status);
	fprintf(stdout, "  last_changed: %llu\n", (long long unsigned)data->last_changed);
	fprintf(stdout, "  valid_till: %llu\n", (long long unsigned)data->valid_till);

	return (0);
}

int 
read_shm(struct radclock *clock)
{
	struct radclock_data *data;
	struct radclock_shm *shm;

	shm = (struct radclock_shm *)clock->ipc_shm;

	fprintf(stdout, "Reading SHM:\n");
	fprintf(stdout, "version: %d\n", shm->version);
	fprintf(stdout, "status: %d\n", shm->status);
	fprintf(stdout, "clockid: %d\n", shm->clockid);
	fprintf(stdout, "gen: %u\n", shm->gen);

	fprintf(stdout, "Current data:\n");
	data = clock->ipc_shm + shm->data_off;
	read_raddata(data);

	fprintf(stdout, "Old data:\n");
	data = clock->ipc_shm + shm->data_off_old;
	read_raddata(data);

	return (0);
}


int
main(int argc, char *argv[])
{
	struct radclock *clock;

	clock = radclock_create();
	radclock_init(clock);
	read_shm(clock);
	radclock_destroy(clock);

	return (0);
}

