/*
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


#include "../config.h"
#ifdef WITH_RADKERNEL_LINUX
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <errno.h>
#include <err.h>
#include <string.h>

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

/* Check for kernel memory mapped capability */
#include <linux/if_packet.h>

#include <netlink/netlink.h>
#include <netlink/attr.h>
#include <netlink/utils.h>
#include <netlink/msg.h>

#include <radclock.h>
#include "radclock-private.h"
#include "linux-private.h"
#include "logger.h"

/* Redefinition from netlink-kernel.h but has moved into
 * into netlink.h stable version of the library 
 */
#ifndef NETLINK_GENERIC
#define NETLINK_GENERIC 16
#endif

/* Here you go, some dirty tricks */
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
/* TODO This  is broken since naming change, but kept for historical reasons
 * should go away soon-ish
 */
#define NET_CORE_RADCLOCK_DEFAULT_TSMODE 22
#define SIOCSRADCLOCKTSMODE 	0x8907
#define SIOCGRADCLOCKTSMODE 	0x8908
#define SIOCGRADCLOCKSTAMP 		0x894B

#else
/* New SYSCTL on the net.core side and also new
 * IOCTL for timespec timestamps on the socket */
#define NET_CORE_RADCLOCK_DEFAULT_TSMODE 23
#define SIOCSRADCLOCKTSMODE 	0x8908
#define SIOCGRADCLOCKTSMODE 	0x8909
#define SIOCGRADCLOCKSTAMP 		0x894B
#endif


/**
 * TODO LINUX:
 *  Consider moving the vcount stamp to ancilary data
 *  - Would mean moving away from standard pcap (maybe to libtrace, which
 *  already supports ancilary data for the sw stamp, or patching pcap to use
 *  it
 *  - This would avoid 2 syscalls (one of sw stamp, one for vcount stamp)
 *  - UPDATE: new packet MMAP support should solve all of this
 *  
 *  Concider moving the mode to a sockopt
 *  - This would just be cleaner and the right thing to do, no performance benifet
 */


static int resolve_family(const char *family_name);



radclock_runmode_t radclock_detect_support(void) 
{
	FILE *fd = NULL;
	int ret = 0;

/* 
 * It seems the sysctl inteface is quite broken in Linux
 * Let's do it this way.
 * TODO: improve/ correct the use of the proc filesystem in the future
 */
	fd = fopen ("/proc/sys/net/core/radclock_default_tsmode", "r");
	if (!fd)
		ret = -1;
	else 
		fclose(fd);	
	
	if (ret == -1) {
		logger(RADLOG_NOTICE, "Kernel support NOT detected");
		return RADCLOCK_RUN_NOTSET;
	}
	else {
		logger(RADLOG_NOTICE, "Kernel support detected");
		return RADCLOCK_RUN_KERNEL;
	}
}

int radclock_init_vcounter_syscall(struct radclock *handle)
{
	/* From config.h */
	handle->syscall_get_vcounter = LINUX_SYSCALL_GET_VCOUNTER;
	logger(RADLOG_NOTICE, "registered get_vcounter syscall at %d", handle->syscall_get_vcounter);

	handle->syscall_get_vcounter_latency = LINUX_SYSCALL_GET_VCOUNTER_LATENCY;
	logger(RADLOG_NOTICE, "registered get_vcounter_latency syscall at %d", handle->syscall_get_vcounter_latency);
	return 0;
}


int radclock_init_kernelclock(struct radclock *handle)
{
	radclock_autoupdate_t automode;
	PRIV_DATA(handle)->radclock_gnl_id = resolve_family(RADCLOCK_NAME);
	if (PRIV_DATA(handle)->radclock_gnl_id  == 0)
	{
		//PANIC
		logger(RADLOG_ERR, "Cannot lookup linux global data netlink ID");
		return -ENOENT;
	}
	else 
	{
		logger(RADLOG_NOTICE, "Global data generic netlink id is %d", PRIV_DATA(handle)->radclock_gnl_id);
	}

	// Init mode for clock autoupdate
	automode = RADCLOCK_UPDATE_AUTO;
	radclock_set_autoupdate(handle, &automode);
		
	return 0;
}



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
	return ret;
}




static int radclock_gnl_receive(int radclock_gnl_id, const struct sockaddr_nl *who, struct nlmsghdr *n, void *into)
{
	int ret;
	struct nlattr * attrs[RADCLOCK_ATTR_MAX +1];
	struct genlmsghdr *ghdr = NLMSG_DATA(n);
	int len = n->nlmsg_len;

	if (n->nlmsg_type != radclock_gnl_id) {
		logger(RADLOG_WARNING, "message id was not from global data");
		return 0;
	}
	if (ghdr->cmd != RADCLOCK_CMD_GETATTR) {
		logger(RADLOG_WARNING, "message cmd was not a set attr");
		return 0;
	}
	len -=NLMSG_LENGTH(GENL_HDRLEN);
	if (len < 0) {
		logger(RADLOG_WARNING, "Message was not long enough to be a generic netlink");
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
			logger(RADLOG_ERR, "Could not allocate data attribute");
		}
	}
	return -1;
}

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
	if (nl_send_auto_complete(nlhandle, msg) < 0)
	{
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

	if (id == RADCLOCK_ATTR_DATA)
	{
		if (nla_put(msg, RADCLOCK_ATTR_DATA, sizeof(struct radclock_data), from))
		{
			logger(RADLOG_ERR, "Couldn't set attr");
			goto close_errout;
		}
	}
	else if (id == RADCLOCK_ATTR_FIXEDPOINT)
	{
		if (nla_put(msg, RADCLOCK_ATTR_FIXEDPOINT, sizeof(struct radclock_fixedpoint), from))
		{
			logger(RADLOG_ERR, "Couldn't set attr");
			goto close_errout;
		}
	}
	if (nl_send_auto_complete(nlhandle, msg) < 0)
	{
		logger(RADLOG_ERR, "Error sending to generic netlink socket");
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



/* ** Clock Data Routines ** */
/* Set global radclock data. */
int radclock_set_kernelclock(struct radclock *handle) 
{  
	int err =-1;
	struct radclock_data currclock;

	memset(&currclock, 0, sizeof(currclock));
	currclock.phat 				= GLOBAL_DATA(handle)->phat;
	currclock.phat_err 			= GLOBAL_DATA(handle)->phat_err;
	currclock.phat_local 		= GLOBAL_DATA(handle)->phat_local;
	currclock.phat_local_err 	= GLOBAL_DATA(handle)->phat_local_err;
	currclock.ca 				= GLOBAL_DATA(handle)->ca;
	currclock.ca_err 			= GLOBAL_DATA(handle)->ca_err;
	currclock.status 			= GLOBAL_DATA(handle)->status;
	currclock.last_changed 		= GLOBAL_DATA(handle)->last_changed;
	currclock.valid_till 		= GLOBAL_DATA(handle)->valid_till;
	//TODO any more data
	if (!PRIV_DATA(handle)->radclock_gnl_id) {
		err = -EINVAL;
		goto errout;
	}
	err = radclock_gnl_set_attr(PRIV_DATA(handle)->radclock_gnl_id, RADCLOCK_ATTR_DATA,  &currclock);
	if (err)
	{
		/* Set the status of the clock to error since can't set kernel radclock_data */
		DEL_STATUS(handle, STARAD_KCLOCK);
		goto errout;
	}
	/* We manage to set the global data */
	ADD_STATUS(handle, STARAD_KCLOCK);

	return 0;
errout:
	return err;
}



/* Read global clock data from the kernel. The structure actually used by the
 * sync algorithm should NEVER be passed to this function. The kernel data may
 * be completely outdated !
 */
int radclock_read_kernelclock(struct radclock *handle) 
{     
	int err =-1;
	struct radclock_data currclock;
	if (!PRIV_DATA(handle)->radclock_gnl_id) {
		err = -EINVAL;
		goto errout;
	}
	err = radclock_gnl_get_attr(PRIV_DATA(handle)->radclock_gnl_id, &currclock);
	if (err)
	{
		logger(RADLOG_ERR, "netlink read kclock failed - %s !!!");
		goto errout;
	}
	
	GLOBAL_DATA(handle)->phat 			= currclock.phat;
	GLOBAL_DATA(handle)->phat_err 		= currclock.phat_err;
	GLOBAL_DATA(handle)->phat_local 	= currclock.phat_local;
	GLOBAL_DATA(handle)->phat_local_err	= currclock.phat_local_err;
	GLOBAL_DATA(handle)->ca 			= currclock.ca;
	GLOBAL_DATA(handle)->ca_err 		= currclock.ca_err;
	GLOBAL_DATA(handle)->status			= currclock.status;
	GLOBAL_DATA(handle)->last_changed	= currclock.last_changed;
	GLOBAL_DATA(handle)->valid_till		= currclock.valid_till;

	return 0;
errout:
	return err;
}



int descriptor_set_tsmode(pcap_t *p_handle, int kmode)
{
	/* int and long imay have different size on 32bit and 64bit architectures.
	 * the kernel expects a long based on IOCTL definition
	 */
	long kmode_long = 0;
	kmode_long += kmode;
	if (ioctl(pcap_fileno(p_handle), SIOCSRADCLOCKTSMODE, (caddr_t)&kmode_long) == -1) 
	{
		logger(RADLOG_ERR, "Setting capture mode failed: %s", strerror(errno));
		return -1;
	}
	return 0;
}


int descriptor_get_tsmode(pcap_t *p_handle, int *kmode)
{
	/* int and long imay have different size on 32bit and 64bit architectures.
	 * the kernel expects a long based on IOCTL definition
	 */
	long kmode_long;
	if (ioctl(pcap_fileno(p_handle), SIOCGRADCLOCKTSMODE, (caddr_t)(&kmode_long)) == -1)
	{
		logger(RADLOG_ERR, "Getting capture mode failed: %s", strerror(errno));
		return -1;
	}
	*kmode = 0;
	*kmode += kmode_long;
	return 0;
}

/* We need to be sure that both the kernel AND libpcap support PACKET_MMAP
 * Otherwise, use 'old' ioctl call to retrieve vcount.
 * Try to make this as quick as possible
 */
#if defined(TPACKET_HDRLEN) && defined (HAVE_PCAP_ACTIVATE) 

inline int extract_vcount_stamp(
			pcap_t *p_handle, 
			const struct pcap_pkthdr *header, 
			const unsigned char *packet,
			vcounter_t *vcount)
{
	char * bp;
	bp = (char*)packet - sizeof(vcounter_t);
	memcpy(vcount, bp, sizeof(vcounter_t)); 
	return 0;
}

#else

inline int extract_vcount_stamp(
			pcap_t *p_handle, 
			const struct pcap_pkthdr *header, 
			const unsigned char *packet,
			vcounter_t *vcount)
{
	if (ioctl(pcap_fileno(p_handle), SIOCGRADCLOCKSTAMP, vcount))
	{
		perror("ioctl");
		logger(RADLOG_ERR, "IOCTL failed to get vcount");
		return -1;
	}
	return 0;
}

#endif


inline int set_kernel_fixedpoint(struct radclock *handle, struct radclock_fixedpoint *fpdata)
{
	return radclock_gnl_set_attr(PRIV_DATA(handle)->radclock_gnl_id, RADCLOCK_ATTR_FIXEDPOINT, fpdata);
}

#endif
