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

#ifndef _CONFIG_MGR_H
#define _CONFIG_MGR_H

#include "radclock-private.h"


#define DAEMON_CONFIG_FILE		"/etc/radclock.conf"
#define BIN_CONFIG_FILE			"radclock.conf"


#define	RAD_MINPOLL	1		/* min poll interval (s) */
#define	RAD_MAXPOLL	1024	/* max poll interval (s) */


/* 
 * Define max size for command line and configuration file parameters 
 */
#define MAXLINE			250	


/*
 * Trigger / Sync Protocol configuration
 */
#define SYNCTYPE_SPY 	0
#define SYNCTYPE_PIGGY 	1
#define SYNCTYPE_NTP	2
#define SYNCTYPE_1588	3
#define SYNCTYPE_PPS	4
#define SYNCTYPE_VM_UDP 5
#define SYNCTYPE_XEN	6
#define SYNCTYPE_VMWARE	7

/*
 * Server Protocol configuration
 */
#define BOOL_OFF 	0
#define BOOL_ON 	1


/*
 * Virtual Machine environmnent
 */
#define VM_SLAVE(val) ((val->conf->synchro_type == SYNCTYPE_VM_UDP) || \
		(val->conf->synchro_type == SYNCTYPE_XEN) || \
		(val->conf->synchro_type == SYNCTYPE_VMWARE))

#define VM_MASTER(val) ((val->conf->server_vm_udp == BOOL_ON) || \
		(val->conf->server_xen == BOOL_ON) || \
		(val->conf->server_vmware == BOOL_ON))

/* 
 * Default configuration values 
 */
#define DEFAULT_VERBOSE				1
#define DEFAULT_SYNCHRO_TYPE		SYNCTYPE_NTP	// Protocol used 
#define DEFAULT_SERVER_IPC			BOOL_ON			// Update the clock 
#define DEFAULT_SERVER_NTP			BOOL_ON			// Default we start a NTP server 
#define DEFAULT_SERVER_VM_UDP		BOOL_OFF		// Don't Start VM servers
#define DEFAULT_SERVER_XEN			BOOL_OFF
#define DEFAULT_SERVER_VMWARE		BOOL_OFF
#define DEFAULT_ADJUST_SYSCLOCK		BOOL_ON			// Default we adjust the system clock 
#define DEFAULT_NTP_POLL_PERIOD 	16				// 16 NTP pkts every [sec]
#define DEFAULT_PHAT_INIT			1.e-9
#define DEFAULT_ASYM_HOST			0.0				// 0 micro-sconds
#define DEFAULT_ASYM_NET			0.0				// 0 micro-seconds 
#define DEFAULT_HOSTNAME			"numbat.cubinlab.ee.unimelb.edu.au"
#define DEFAULT_TIME_SERVER			"ntp.cubinlab.ee.unimelb.edu.au"
#define DEFAULT_NETWORKDEV			"xl0"
#define DEFAULT_SYNC_IN_PCAP		"sync_input.pcap"
#define DEFAULT_SYNC_IN_ASCII		"sync_input.ascii"
#define DEFAULT_SYNC_OUT_PCAP		"sync_output.pcap"
#define DEFAULT_SYNC_OUT_ASCII		"sync_output.ascii"
#define DEFAULT_CLOCK_OUT_ASCII		"clock_output.ascii"

#define DEFAULT_VM_UDP_LIST			"vm_udp_list"


/*
 *  Definition of keys for configuration file keywords
 */
#define CONFIG_UNKNOWN			0
#define CONFIG_RADCLOCK_VERSION 1
/* Generic stuff */
#define CONFIG_VERBOSE			10
#define CONFIG_SERVER_IPC		11
//#define CONFIG_				13
#define CONFIG_SYNCHRO_TYPE		13
#define CONFIG_SERVER_NTP		14
#define CONFIG_ADJUST_SYSCLOCK	15
/* Clock parameters */
#define CONFIG_POLLPERIOD		20
//#define CONFIG_				21
#define CONFIG_PHAT_INIT		22
#define CONFIG_ASYM_HOST		23
#define CONFIG_ASYM_NET			24
/* Environment */
#define CONFIG_TEMPQUALITY		30
#define CONFIG_TSLIMIT			31
#define CONFIG_SKM_SCALE		32
#define CONFIG_RATE_ERR_BOUND	33
#define CONFIG_BEST_SKM_RATE	34
#define CONFIG_OFFSET_RATIO		35
#define CONFIG_PLOCAL_QUALITY	36
/* Network Level */
#define CONFIG_HOSTNAME			40
#define CONFIG_TIME_SERVER		41
/* I/O defintions */
#define CONFIG_NETWORKDEV		50
#define CONFIG_SYNC_IN_PCAP		51
#define CONFIG_SYNC_IN_ASCII	52
#define CONFIG_SYNC_OUT_PCAP	53
#define CONFIG_SYNC_OUT_ASCII	54
#define CONFIG_CLOCK_OUT_ASCII	55
/* Virtual Machine stuff */
#define CONFIG_SERVER_VM_UDP	60
#define CONFIG_SERVER_XEN		61
#define CONFIG_SERVER_VMWARE	62
#define CONFIG_VM_UDP_LIST		63



/*
 * Pre-defined description of temperature environment quality
 * CONFIG_QUALITY_UNKWN has to be defined with the highest values to parse
 * the config file correctly
 */
#define CONFIG_QUALITY_POOR		0
#define CONFIG_QUALITY_GOOD		1
#define CONFIG_QUALITY_EXCEL	2
#define CONFIG_QUALITY_UNKWN	3


/*
 * Masks to reload the configuration parameters
 */
#define UPDMASK_NOUPD			0x0000000
#define UPDMASK_POLLPERIOD		0x0000001
//#define UPDMASK_				0x0000002
#define UPDMASK_TEMPQUALITY		0x0000004
#define UPDMASK_ASYM_HOST		0x0000008
#define UPDMASK_ASYM_NET		0x0000010
#define UPDMASK_SERVER_IPC		0x0000020
//#define UPDMASK_				0x0000040
#define UPDMASK_SYNCHRO_TYPE	0x0000080
#define UPDMASK_SERVER_NTP		0x0000100
#define UPDMASK_ADJUST_SYSCLOCK	0x0000200
#define UPDMASK_HOSTNAME		0x0000400
#define UPDMASK_TIME_SERVER		0x0000800
#define UPDMASK_VERBOSE			0x0001000
#define UPDMASK_NETWORKDEV		0x0002000
#define UPDMASK_SYNC_IN_PCAP	0x0004000
#define UPDMASK_SYNC_IN_ASCII	0x0008000
#define UPDMASK_SYNC_OUT_PCAP	0x0010000
#define UPDMASK_SYNC_OUT_ASCII	0x0020000
#define UPDMASK_CLOCK_OUT_ASCII	0x0040000
#define UPDMASK_SERVER_VM_UDP	0x0080000
#define UPDMASK_SERVER_XEN		0x0100000
#define UPDMASK_SERVER_VMWARE	0x0200000
#define UPDMASK_VM_UDP_LIST		0x0400000
#define UPDMASK_PID_FILE		0x0800000
#define UPD_NTP_UPSTREAM_PORT	0x1000000
#define UPD_NTP_DOWNSTREAM_PORT	0x2000000


#define HAS_UPDATE(val,mask)	((val & mask) == mask)	
#define SET_UPDATE(val,mask)	(val |= mask) 
#define CLEAR_UPDATE(val,mask)	(val &= ~mask)



/* This is a global structure used to keep track of the config parameters Mostly
 * used by signal handlers The fields present here correspond to the parameters
 * of the get_config function.
 */ 
struct radclock_config {
	u_int32_t mask;						/* Update param mask */
	char 	conffile[MAXLINE]; 			/* Configuration file path */
	char 	logfile[MAXLINE]; 			/* Log file path */
	char 	radclock_version[MAXLINE]; 	/* Package version id */
	int 	verbose_level; 				/* debug output level */
	int 	poll_period; 				/* period of NTP pkt sending [sec] */
	struct 	radclock_phyparam phyparam; /* Physical and temperature characteristics */ 
	int 	synchro_type; 				/* multi-choice depending on client-side protocol */
	int 	server_ipc; 				/* Boolean */
	int 	server_ntp;					/* Boolean */
	int 	server_vm_udp;				/* Boolean */
	int 	server_xen;					/* Boolean */
	int 	server_vmware;				/* Boolean */
	int 	adjust_sysclock;			/* Boolean */
	double 	phat_init;					/* Initial value for phat */
	double 	asym_host;					/* Host asymmetry estimate [sec] */
	double	asym_net;					/* Network asymmetry estimate [sec] */ 
        int     ntp_upstream_port;                      /* NTP Upstream port */
        int     ntp_downstream_port;                    /* NTP Downstream port */
	char 	hostname[MAXLINE]; 			/* Client hostname */
	char 	time_server[MAXLINE]; 		/* Server name */
	char 	network_device[MAXLINE];	/* physical device string, eg xl0, eth0 */ 
	char 	sync_in_pcap[MAXLINE];	 	/* read from stored instead of live input */
	char 	sync_in_ascii[MAXLINE]; 		/* input is a preprocessed stamp file */
	char 	sync_out_pcap[MAXLINE]; 		/* raw packet Output file name */
	char 	sync_out_ascii[MAXLINE]; 	/* output processed stamp file */
	char 	clock_out_ascii[MAXLINE];  		/* output matlab requirements */
	char 	vm_udp_list[MAXLINE];  		/* File containing list of udp vm's */
};





/**
 * Initialise the configuration of the radclock daemon
 */
void config_init(struct radclock_config *conf);

/**
 * Parse a configuration file
 */
int config_parse(struct radclock_config *conf, u_int32_t *mask, int is_daemon);

/**
 * Output the config in config to verbose using level
 */
void config_print(int level, struct radclock_config *conf);


#endif
