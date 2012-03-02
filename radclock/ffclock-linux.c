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
#ifdef WITH_RADKERNEL_LINUX


#include <errno.h>
#include <syslog.h>

#include <netinet/in.h>

#ifdef HAVE_LINUX_GENETLINK_H
# include <linux/genetlink.h>
#elif defined(WITH_LOCAL_GENETLINK_H)
# include "local-genetlink.h"
#else
# error Need a linux/genetlink.h
#endif

#include <linux/rtnetlink.h>
#include <linux/netlink.h>

#include <netlink/netlink.h>
#include <netlink/attr.h>
#include <netlink/utils.h>
#include <netlink/msg.h>

#include <linux/types.h>

#include "radclock.h"
#include "radclock-private.h"
#include "ffclock.h"
#include "fixedpoint.h"
#include "verbose.h"
#include "jdebug.h"



enum {
	RADCLOCK_ATTR_DUMMY,
	RADCLOCK_ATTR_DATA,
	RADCLOCK_ATTR_FIXEDPOINT,
	__RADCLOCK_ATTR_MAX,
};

#define RADCLOCK_ATTR_MAX (__RADCLOCK_ATTR_MAX - 1)

static struct nla_policy radclock_attr_policy[RADCLOCK_ATTR_MAX+1] = {
	[RADCLOCK_ATTR_DUMMY] = { .type = NLA_U16 },
	[RADCLOCK_ATTR_DATA] = { .minlen = sizeof(struct radclock_data) },
	[RADCLOCK_ATTR_FIXEDPOINT] = { .minlen = sizeof(struct radclock_fixedpoint) },
};


enum {
	RADCLOCK_CMD_UNSPEC,
	RADCLOCK_CMD_GETATTR,
	RADCLOCK_CMD_SETATTR,
	__RADCLOCK_CMD_MAX,
};


#define RADCLOCK_CMD_MAX (__RADCLOCK_CMD_MAX - 1)

#define RADCLOCK_NAME "radclock"


/* Redefinition from netlink-kernel.h but has moved into
 * into netlink.h stable version of the library 
 */
#ifndef NETLINK_GENERIC
#define NETLINK_GENERIC 16
#endif


/**
 * Resolve a generic netlink id from a family name
 *
 * Return 0 or less than 0 on failure
 *	or the id on success
 *
 *
 * TODO: SVN versions of libnl seem to finally include this functionality -
 * use their version later if possible - TY Jun/2007
 */
static int resolve_family(const char *family_name)
{
	struct nl_handle *nlhandle;
	struct nlattr * attrs[CTRL_ATTR_MAX +1];
	struct sockaddr_nl peer;
	unsigned char *buf;
	struct nlmsghdr *reply_hdr;

	int ret = 0;
	int recv_len;

	struct nl_msg *msg = nlmsg_build_simple(GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK);
	if (!msg) {
		verbose(LOG_ERR, "Error allocating message");
		goto errout;
	}

	struct genlmsghdr generic_header = {
		.cmd = CTRL_CMD_GETFAMILY,
		.version = 0,
		.reserved =0,
	};

	nlhandle = nl_handle_alloc();

	if (!nlhandle) {
		verbose(LOG_ERR, "Cannot allocate handle\n");
		goto msg_errout;
	}

	//nl_disable_sequence_check(nlhandle);

	if (nl_connect(nlhandle, NETLINK_GENERIC) < 0) {
		verbose(LOG_ERR, "Cannot open generic netlink socket\n");
		goto destroy_errout;
	}

	nlmsg_append(msg, &generic_header, sizeof(generic_header), 1);

	nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, family_name);

	if (nl_send_auto_complete(nlhandle, msg)< 0) {
		verbose(LOG_ERR, "Error sending netlink message to kernel");
		goto close_errout;
	}

	recv_len = nl_recv(nlhandle,
			&peer,
			&buf
#ifdef WITH_NL_RECV_FOUR_PARM
			//evil kludge to handle the changes between libnl1-pre5 and libnl1-pre6
			//api changes are the root of that's evil in the world
			, NULL
#endif
			);
	if (recv_len <=0) {
		verbose(LOG_ERR, "Error receiving from kernel: %s", strerror(-recv_len));
		goto close_errout;
	}

	reply_hdr = (struct nlmsghdr *) buf;
	while (nlmsg_ok(reply_hdr, recv_len)) {
		ret = nlmsg_parse(reply_hdr,GENL_HDRLEN,attrs,CTRL_ATTR_MAX,NULL);
		if (ret <0) {
			verbose(LOG_ERR, "Error parsing message");
			goto close_errout;
		}

		if (attrs[CTRL_ATTR_FAMILY_ID] != NULL) {
			ret = nla_get_u16(attrs[CTRL_ATTR_FAMILY_ID]);
			reply_hdr = nlmsg_next(reply_hdr, &recv_len);
		}
	}

	free(buf);

close_errout:
	nl_close(nlhandle);
destroy_errout:
	nl_handle_destroy(nlhandle);
msg_errout:
	nlmsg_free(msg);
errout:
	return ret;
}




static int radclock_gnl_receive(int radclock_gnl_id, const struct sockaddr_nl *who, struct nlmsghdr *n, void *into)
{
	int ret;
	struct nlattr * attrs[RADCLOCK_ATTR_MAX +1];
	struct genlmsghdr *ghdr = NLMSG_DATA(n);
	int len = n->nlmsg_len;

	if (n->nlmsg_type != radclock_gnl_id) {
		verbose(LOG_WARNING, "message id was not from global data");
		return 0;
	}
	if (ghdr->cmd != RADCLOCK_CMD_GETATTR) {
		verbose(LOG_WARNING, "message cmd was not a set attr");
		return 0;
	}
	len -=NLMSG_LENGTH(GENL_HDRLEN);
	if (len < 0) {
		verbose(LOG_WARNING, "Message was not long enough to be a generic netlink");
		return -1;
	}

	ret = nlmsg_parse(n,GENL_HDRLEN,attrs,RADCLOCK_ATTR_MAX,radclock_attr_policy);

	if (attrs[RADCLOCK_ATTR_DATA]) {
		struct nl_data* data_attr = nla_get_data(attrs[RADCLOCK_ATTR_DATA]);
		if (data_attr) {
			struct radclock_data *data =  (struct radclock_data *) nl_data_get(data_attr);
			memcpy(into, data, sizeof(struct radclock_data));
			nl_data_free(data_attr);
			return 0;
		}else {
			verbose(LOG_ERR, "Could not allocate data attribute");
		}
	}
	return -1;
}


// XXX this one is not used anymore ... remove?
static int radclock_gnl_get_attr(int radclock_gnl_id, void *into)
{
	struct nl_handle *nlhandle;
	unsigned char *buf;
	struct nlmsghdr *hdr;
	struct sockaddr_nl peer;
	int ret = -1;
	int recv_len;

	struct genlmsghdr generic_header = {
		.cmd = RADCLOCK_CMD_GETATTR,
		.version = 0,
		.reserved =0,
	};

	struct nl_msg *msg = nlmsg_build_simple(radclock_gnl_id, NLM_F_REQUEST | NLM_F_ACK);

	if (!msg) {
		verbose(LOG_ERR, "Error allocating message");
		goto errout;
	}

	nlmsg_append(msg, &generic_header, sizeof(generic_header),0);


	nlhandle = nl_handle_alloc();
//	nl_disable_sequence_check(nlhandle);
	if (!nlhandle) {
		verbose(LOG_ERR, "Error allocating handle");
		goto msg_errout;
	}

	if (nl_connect(nlhandle, NETLINK_GENERIC) < 0) {
		verbose(LOG_ERR, "Error connecting to generic netlink socket");
		goto destroy_errout;
	}
	if (nl_send_auto_complete(nlhandle, msg) < 0)
	{
		verbose(LOG_ERR, "Error sending to generic netlink socket");
		goto close_errout;
	}

	recv_len = nl_recv(nlhandle,
			&peer,
			&buf
#ifdef WITH_NL_RECV_FOUR_PARM
			//evil kludge to handle the changes between libnl1-pre5 and libnl1-pre6
			//api changes are the root of that's evil in the world
			, NULL
#endif
			);

	if (recv_len >=0) {
		hdr = (struct nlmsghdr *) buf;
		while (nlmsg_ok(hdr, recv_len)) {
			if (radclock_gnl_receive(radclock_gnl_id, NULL, hdr, into) < 0) {
				verbose(LOG_ERR, "Error receiving from generic netlink socket");
				//Free buff allocated by nl_recv
				free(buf);
				goto close_errout;
			}
			hdr = nlmsg_next(hdr, &recv_len);
		}
	}
	else {
		verbose(LOG_ERR, "Error receiving from generic netlink socket");
		goto close_errout;
	}
	//Free buff allocated by nl_recv
	free(buf);

	ret =0;
close_errout:
	nl_close(nlhandle);

destroy_errout:
	nl_handle_destroy(nlhandle);
msg_errout:
	nlmsg_free(msg);
errout:
	return ret;
}



static int radclock_gnl_set_attr(int radclock_gnl_id, int id, void *from)
{
	struct nl_handle *nlhandle;
	int ret = -1;

	struct genlmsghdr generic_header = {
		.cmd = RADCLOCK_CMD_SETATTR,
		.version = 0,
		.reserved =0,
	};

	struct nl_msg *msg = nlmsg_build_simple(radclock_gnl_id, NLM_F_REQUEST | NLM_F_ACK);
	if (!msg) {
		verbose(LOG_ERR, "Error allocating message");
		goto errout;
	}

	nlmsg_append(msg, &generic_header, GENL_HDRLEN,0);

	nlhandle = nl_handle_alloc();
	if (!nlhandle) {
		verbose(LOG_ERR, "Error allocating handle");
		goto msg_errout;
	}

	if (nl_connect(nlhandle, NETLINK_GENERIC) < 0) {
		verbose(LOG_ERR, "Error connecting to generic netlink socket");
		goto destroy_errout;
	}

	if (id == RADCLOCK_ATTR_DATA)
	{
		if (nla_put(msg, RADCLOCK_ATTR_DATA, sizeof(struct radclock_data), from))
		{
			verbose(LOG_ERR, "Couldn't set attr");
			goto close_errout;
		}
	}
	else if (id == RADCLOCK_ATTR_FIXEDPOINT)
	{
		if (nla_put(msg, RADCLOCK_ATTR_FIXEDPOINT, sizeof(struct radclock_fixedpoint), from))
		{
			verbose(LOG_ERR, "Couldn't set attr");
			goto close_errout;
		}
	}
	if (nl_send_auto_complete(nlhandle, msg) < 0)
	{
		verbose(LOG_ERR, "Error sending to generic netlink socket");
		goto close_errout;
	}
	nl_wait_for_ack(nlhandle);

	ret =0;
close_errout:
	nl_close(nlhandle);

destroy_errout:
	nl_handle_destroy(nlhandle);
msg_errout:
	nlmsg_free(msg);
errout:
	return ret;
}



int init_kernel_support(struct radclock *handle)
{
	PRIV_DATA(handle)->radclock_gnl_id = resolve_family(RADCLOCK_NAME);
	if (PRIV_DATA(handle)->radclock_gnl_id  == 0)
	{
		//PANIC
		verbose(LOG_ERR, "Cannot lookup linux global data netlink ID");
		return -ENOENT;
	}
	else 
	{
		verbose(LOG_NOTICE, "Global data generic netlink id is %d", PRIV_DATA(handle)->radclock_gnl_id);
	}
	verbose(LOG_NOTICE, "Feed-Forward Kernel initialised");

	return 0;
}




/* Need to check that the passthrough mode is enabled and that the counter can
 * do the job. The latter is a bit "hard coded"
 */
int has_vm_vcounter(struct radclock *handle)
{
	int passthrough_counter = 0;
	char clocksource[32];
	FILE *fd = NULL;

	fd = fopen ("/sys/devices/system/clocksource/clocksource0/passthrough_clocksource", "r");
	if (!fd)
	{
		verbose(LOG_ERR, "Cannot open passthrough_clocksource from sysfs");
		return 0;
	}
	fscanf(fd, "%d", &passthrough_counter);
	fclose(fd);

	if ( passthrough_counter == 0)
	{
		verbose(LOG_ERR, "Clocksource not in pass-through mode. Cannot init virtual machine mode");
		return 0;
	}
	verbose(LOG_NOTICE, "Found clocksource in pass-through mode");


	fd = fopen ("/sys/devices/system/clocksource/clocksource0/current_clocksource", "r");
	if (!fd)
	{
		verbose(LOG_WARNING, "Cannot open current_clocksource from sysfs");
		return 1;
	}
	fscanf(fd, "%s", &clocksource[0]);
	fclose(fd);

	if ( (strcmp(clocksource, "tsc") != 0) && (strcmp(clocksource, "xen") != 0) )
		verbose(LOG_WARNING, "Clocksource is neither tsc nor xen. "
				"There must be something wrong!!");
	else
		verbose(LOG_WARNING, "Clocksource is %s", clocksource);

	return 1;
}





/*
 * XXX Deprecated
 * Old way of pushing clock updates to the kernel.
 * TODO: remove when backward compatibility for kernel versions < 2 is dropped.
 */
inline int set_kernel_fixedpoint(struct radclock *handle, struct radclock_fixedpoint *fpdata)
{
	JDEBUG
	int err;

	switch (handle->kernel_version)
	{
	case 0:
	case 1:
		err = radclock_gnl_set_attr(PRIV_DATA(handle)->radclock_gnl_id, RADCLOCK_ATTR_FIXEDPOINT, fpdata);
		break;

	case 2:	
		verbose(LOG_ERR, "set_kernel_fixedpoint but kernel version 2!!");
		return -1;

	default:
		verbose(LOG_ERR, "Unknown kernel version");
		return -1;
	}

	return err;
}



int
set_kernel_ffclock(struct radclock *clock)
{
//	JDEBUG
//	int err;
//	struct ffclock_data fdata;
//	vcounter_t vcount;
//	long double time;
//	uint64_t period;
//	uint64_t period_shortterm;
//	uint64_t frac;
//
	verbose(LOG_ERR, "Not yet setting ffclock data in the kernel");
	if (clock->kernel_version < 2) {
		verbose(LOG_ERR, "set_kernel_ffclock with unfit kernel!");
		return (-1);
	}

//
//	/*
//	 * Build the data structure to pass to the kernel
//	 */
//	vcount = RAD_DATA(clock)->last_changed;
//
//	/* Convert vcount to long double time and to bintime */
//	if (radclock_vcount_to_abstime_fp(clock, &vcount, &time))
//		verbose(LOG_ERR, "Error calculating time");
//
//	/* What I would like to do is: 
//	 * fdata->time.frac = (time - (time_t) time) * (1LLU << 64);
//	 * but cannot push '1' by 64 bits, does not fit in LLU. So push 63 bits,
//	 * multiply for best resolution and loose resolution of 1/2^64.
//	 * Same for phat.
//	 */
//	fdata.time.sec = (time_t) time;
//	frac = (time - (time_t) time) * (1LLU << 63);
//	fdata.time.frac = frac << 1;
//
//	period = ((long double) RAD_DATA(clock)->phat) * (1LLU << 63);
//	fdata.period = period << 1;
//
//	period_shortterm = ((long double) RAD_DATA(clock)->phat_local) * (1LLU << 63);
//	fdata.period_shortterm = period_shortterm << 1;
//
//	fdata.last_update = vcount;
//	fdata.status = RAD_DATA(clock)->status;
//	fdata.error_bound_avg = (uint32_t) RAD_ERROR(clock)->error_bound_avg * 1e9;
//
//	
//	/* Push */
//	err = radclock_gnl_set_attr(PRIV_DATA(clock)->radclock_gnl_id, RADCLOCK_ATTR_DATA,  &fdata);
//	if ( err < 0 ) {
//		verbose(LOG_ERR, "error on syscall set_ffclock: %s", strerror(errno));
//		return -1;
//	}
//
	return (0);
}



#endif	/* WITH_RADKERNEL_LINUX */
