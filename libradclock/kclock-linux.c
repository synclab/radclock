/*
 * Copyright (C) 2006-2012, Julien Ridoux <julien@synclab.org>
 * Copyright (C) 2006-2007, Thomas Young <tfyoung@gmail.com>
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
#ifdef WITH_FFKERNEL_LINUX

#include <asm/types.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/socket.h>

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

#include <errno.h>
#include <err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Check for kernel memory mapped capability */
#include <linux/if_packet.h>

#include "radclock.h"
#include "radclock-private.h"
#include "kclock.h"
#include "logger.h"


#define RADCLOCK_NAME "radclock"

/* Redefinition from netlink-kernel.h but has moved into
 * into netlink.h stable version of the library
 */
#ifndef NETLINK_GENERIC
#define NETLINK_GENERIC 16
#endif


static int resolve_family(const char *family_name);


int
init_kernel_clock(struct radclock *handle)
{
	PRIV_DATA(handle)->radclock_gnl_id = resolve_family(RADCLOCK_NAME);

	if (PRIV_DATA(handle)->radclock_gnl_id  == 0) {
		//PANIC
		logger(RADLOG_ERR, "Cannot lookup linux global data netlink ID");
		return (1);
	}
	else {
		logger(RADLOG_NOTICE, "Global data generic netlink id is %d",
				PRIV_DATA(handle)->radclock_gnl_id);
	}
	logger(RADLOG_NOTICE, "Feed-Forward Kernel initialised");

	return (0);
}


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


/**
 * Resolve a generic netlink id from a family name
 * Return 0 or less than 0 on failure or the id on success
 *
 * TODO: SVN versions of libnl seem to finally include this functionality -
 * use their version later if possible - TY Jun/2007
 */
static int
resolve_family(const char *family_name)
{
	struct nl_handle *nlhandle;
	struct nlattr * attrs[CTRL_ATTR_MAX +1];
	struct sockaddr_nl peer;
	unsigned char *buf;
	struct nlmsghdr *reply_hdr;

	int ret = 0;
	int recv_len;

	struct nl_msg *msg = nlmsg_build_simple(GENL_ID_CTRL,
			NLM_F_REQUEST | NLM_F_ACK);
	if (!msg) {
		logger(RADLOG_ERR, "Error allocating message");
		goto errout;
	}

	struct genlmsghdr generic_header = {
		.cmd = CTRL_CMD_GETFAMILY,
		.version = 0,
		.reserved =0,
	};

	nlhandle = nl_handle_alloc();

	if (!nlhandle) {
		logger(RADLOG_ERR, "Cannot allocate handle\n");
		goto msg_errout;
	}

	//nl_disable_sequence_check(nlhandle);

	if (nl_connect(nlhandle, NETLINK_GENERIC) < 0) {
		logger(RADLOG_ERR, "Cannot open generic netlink socket\n");
		goto destroy_errout;
	}

	nlmsg_append(msg, &generic_header, sizeof(generic_header), 1);

	nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, family_name);

	if (nl_send_auto_complete(nlhandle, msg)< 0) {
		logger(RADLOG_ERR, "Error sending netlink message to kernel");
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
		logger(RADLOG_ERR, "Error receiving from kernel: %s", strerror(-recv_len));
		goto close_errout;
	}

	reply_hdr = (struct nlmsghdr *) buf;
	while (nlmsg_ok(reply_hdr, recv_len)) {
		ret = nlmsg_parse(reply_hdr,GENL_HDRLEN,attrs,CTRL_ATTR_MAX,NULL);
		if (ret <0) {
			logger(RADLOG_ERR, "Error parsing message");
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
	return (ret);
}


static int
radclock_gnl_receive(int radclock_gnl_id, const struct sockaddr_nl *who,
		struct nlmsghdr *n, void *into)
{
	int ret;
	struct nlattr * attrs[RADCLOCK_ATTR_MAX +1];
	struct genlmsghdr *ghdr = NLMSG_DATA(n);
	int len = n->nlmsg_len;

	if (n->nlmsg_type != radclock_gnl_id) {
		logger(RADLOG_WARNING, "message id was not from global data");
		return (0);
	}
	if (ghdr->cmd != RADCLOCK_CMD_GETATTR) {
		logger(RADLOG_WARNING, "message cmd was not a set attr");
		return (0);
	}
	len -=NLMSG_LENGTH(GENL_HDRLEN);
	if (len < 0) {
		logger(RADLOG_WARNING, "Message was not long enough to be a generic netlink");
		return (-1);
	}

	ret = nlmsg_parse(n,GENL_HDRLEN,attrs,RADCLOCK_ATTR_MAX,radclock_attr_policy);

	if (attrs[RADCLOCK_ATTR_DATA]) {
		struct nl_data* data_attr = nla_get_data(attrs[RADCLOCK_ATTR_DATA]);
		if (data_attr) {
			struct radclock_data *data;
			data = (struct radclock_data *) nl_data_get(data_attr);
			memcpy(into, data, sizeof(struct radclock_data));
			nl_data_free(data_attr);
			return (0);
		}else {
			logger(RADLOG_ERR, "Could not allocate data attribute");
		}
	}
	return (-1);
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

	struct nl_msg *msg;
	msg = nlmsg_build_simple(radclock_gnl_id, NLM_F_REQUEST | NLM_F_ACK);

	if (!msg) {
		logger(RADLOG_ERR, "Error allocating message");
		goto errout;
	}

	nlmsg_append(msg, &generic_header, sizeof(generic_header),0);


	nlhandle = nl_handle_alloc();
//	nl_disable_sequence_check(nlhandle);
	if (!nlhandle) {
		logger(RADLOG_ERR, "Error allocating handle");
		goto msg_errout;
	}

	if (nl_connect(nlhandle, NETLINK_GENERIC) < 0) {
		logger(RADLOG_ERR, "Error connecting to generic netlink socket");
		goto destroy_errout;
	}

	if (nl_send_auto_complete(nlhandle, msg) < 0) {
		logger(RADLOG_ERR, "Error sending to generic netlink socket");
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
				logger(RADLOG_ERR, "Error receiving from generic netlink socket");
				//Free buff allocated by nl_recv
				free(buf);
				goto close_errout;
			}
			hdr = nlmsg_next(hdr, &recv_len);
		}
	}
	else {
		logger(RADLOG_ERR, "Error receiving from generic netlink socket");
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
	return (ret);
}


static int
radclock_gnl_set_attr(int radclock_gnl_id, int id, void *from)
{
	struct nl_handle *nlhandle;
	int ret = -1;

	struct genlmsghdr generic_header = {
		.cmd = RADCLOCK_CMD_SETATTR,
		.version = 0,
		.reserved =0,
	};

	struct nl_msg *msg;
	msg = nlmsg_build_simple(radclock_gnl_id, NLM_F_REQUEST | NLM_F_ACK);

	if (!msg) {
		logger(RADLOG_ERR, "Error allocating message");
		goto errout;
	}

	nlmsg_append(msg, &generic_header, GENL_HDRLEN,0);

	nlhandle = nl_handle_alloc();
	if (!nlhandle) {
		logger(RADLOG_ERR, "Error allocating handle");
		goto msg_errout;
	}

	if (nl_connect(nlhandle, NETLINK_GENERIC) < 0) {
		logger(RADLOG_ERR, "Error connecting to generic netlink socket");
		goto destroy_errout;
	}

	if (id == RADCLOCK_ATTR_DATA) {
		if (nla_put(msg, RADCLOCK_ATTR_DATA, sizeof(struct radclock_data), from)) {
			logger(RADLOG_ERR, "Couldn't set attr");
			goto close_errout;
		}
	}
	else if (id == RADCLOCK_ATTR_FIXEDPOINT) {
		if (nla_put(msg, RADCLOCK_ATTR_FIXEDPOINT,
				sizeof(struct radclock_fixedpoint), from)) {
			logger(RADLOG_ERR, "Couldn't set attr");
			goto close_errout;
		}
	}
	if (nl_send_auto_complete(nlhandle, msg) < 0) {
		logger(RADLOG_ERR, "Error sending to generic netlink socket");
		goto close_errout;
	}
	nl_wait_for_ack(nlhandle);

	ret = 0;
close_errout:
	nl_close(nlhandle);

destroy_errout:
	nl_handle_destroy(nlhandle);
msg_errout:
	nlmsg_free(msg);
errout:
	return (ret);
}


// TODO the set_kernel_ffclock should be in the library too?
int
get_kernel_ffclock(struct radclock *clock, struct ffclock_estimate *cest)
{
	logger(RADLOG_ERR, "Not yet getting ffclock data in the kernel");
	if (clock->kernel_version < 2) {
		logger(RADLOG_ERR, "get_kernel_ffclock with unfit kernel!");
		return (1);
	}

	return (0);
}


int
set_kernel_ffclock(struct radclock *clock, struct ffclock_estimate *cest)
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
	logger(RADLOG_ERR, "Not yet setting ffclock data in the kernel");
	if (clock->kernel_version < 2) {
		logger(RADLOG_ERR, "set_kernel_ffclock with unfit kernel!");
		return (1);
	}

//
//	/*
//	 * Build the data structure to pass to the kernel
//	 */
//	vcount = RAD_DATA(clock)->last_changed;
//
//	/* Convert vcount to long double time and to bintime */
//	if (radclock_vcount_to_abstime_fp(clock, &vcount, &time))
//		logger(RADLOG_ERR, "Error calculating time");
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
//	err = radclock_gnl_set_attr(PRIV_DATA(clock)->radclock_gnl_id,
//			RADCLOCK_ATTR_DATA,  &fdata);
//	if ( err < 0 ) {
//		logger(RADLOG_ERR, "error on syscall set_ffclock: %s", strerror(errno));
//		return (1);
//	}
//
	return (0);
}


/*
 * XXX Deprecated
 * Old way of pushing clock updates to the kernel.
 * TODO: remove when backward compatibility for kernel versions < 2 is dropped.
 */
inline int
set_kernel_fixedpoint(struct radclock *handle, struct radclock_fixedpoint *fpdata)
{
	int err;

	switch (handle->kernel_version)
	{
	case 0:
	case 1:
		err = radclock_gnl_set_attr(PRIV_DATA(handle)->radclock_gnl_id,
				RADCLOCK_ATTR_FIXEDPOINT, fpdata);
		break;

	case 2:	
		logger(RADLOG_ERR, "set_kernel_fixedpoint but kernel version 2!!");
		return (1);

	default:
		logger(RADLOG_ERR, "Unknown kernel version");
		return (1);
	}

	if (err < 0) 
		return (1);
	return (0);
}

#endif
