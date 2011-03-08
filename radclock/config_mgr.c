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



#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <syslog.h>
#include <sys/stat.h>

#include "../config.h"
#include "verbose.h"
#include "sync_algo.h"
#include "config_mgr.h"
#include "jdebug.h"



/* The configuration file lines follow the template : 
 * key = value
 */


/** Basic structure definition containing label and corresponding index */
struct _key {
	const char *label;
	int keytype;
};



/* Definition of the keys used in the conf file */
static struct _key keys[] = {
	{ "radclock_version",		CONFIG_RADCLOCK_VERSION},
	{ "verbose_level",			CONFIG_VERBOSE},
	{ "synchronisation_type",	CONFIG_SYNCHRO_TYPE},
	{ "ipc_server",				CONFIG_SERVER_IPC},
	{ "ntp_server",				CONFIG_SERVER_NTP},
	{ "adjust_system_clock",	CONFIG_ADJUST_SYSCLOCK},
	{ "virtual_machine_mode",	CONFIG_VIRTUAL_MACHINE},
	{ "polling_period", 		CONFIG_POLLPERIOD},
	{ "temperature_quality", 	CONFIG_TEMPQUALITY},
	{ "ts_limit",				CONFIG_TSLIMIT},
	{ "skm_scale",				CONFIG_SKM_SCALE},
	{ "rate_error_bound",		CONFIG_RATE_ERR_BOUND},
	{ "best_skm_rate",			CONFIG_BEST_SKM_RATE},
	{ "offset_ratio",			CONFIG_OFFSET_RATIO},
	{ "plocal_quality",			CONFIG_PLOCAL_QUALITY},
	{ "start_local_phat",		CONFIG_PLOCAL},
	{ "init_period_estimate",	CONFIG_PHAT_INIT},
	{ "host_asymmetry",			CONFIG_ASYM_HOST},
	{ "network_asymmetry",		CONFIG_ASYM_NET},
	{ "hostname",				CONFIG_HOSTNAME},
	{ "time_server",			CONFIG_TIME_SERVER},
	{ "network_device",			CONFIG_NETWORKDEV},
	{ "sync_input_pcap",		CONFIG_SYNC_IN_PCAP},
	{ "sync_input_ascii",		CONFIG_SYNC_IN_ASCII},
	{ "sync_output_pcap",		CONFIG_SYNC_OUT_PCAP},
	{ "sync_output_ascii",		CONFIG_SYNC_OUT_ASCII},
	{ "clock_output_ascii",		CONFIG_CLOCK_OUT_ASCII},
	{ "",			 			CONFIG_UNKNOWN} // Must be the last one
};

/* Definition of the options labels
 * Order matters !
 * TODO make this a bit more robust to bugs with enums already partly defined
 */
static char* labels_bool[] 		= { "off", "on" };
static char* labels_verb[] 		= { "quiet", "normal", "high" };
static char* labels_plocal[] 	= { "off", "on", "restart" };
static char* labels_sync[] 		= { "spy", "piggy", "ntp", "ieee1588", "pps" };
static char* labels_vm[] 		= { "none", "xen-slave", "xen-master", "vbox-slave", "vbox-master" };



/** Modes for the quality of the temperature environment 
 * Must be defined in the same sequence order as the CONFIG_QUALITY_* 
 * values 
 */
static struct _key temp_quality[] = {
	{ "poor", 				CONFIG_QUALITY_POOR},
	{ "good",				CONFIG_QUALITY_GOOD},
	{ "excellent",			CONFIG_QUALITY_EXCEL},
	{ "",			 		CONFIG_QUALITY_UNKWN} // Must be the last one
};



/** Initialise the structure of global data to default values.
 *  Avoid weird configuration and a basis to generate a conf file
 *   if it does not exist 
 */
void config_init(struct radclock_config *conf) 
{
	JDEBUG

	/* Init the mask for parameters */ 
	conf->mask = UPDMASK_NOUPD;

	/* Runnning defaults */
	strcpy(conf->conffile, "");
	strcpy(conf->logfile, "");
	strcpy(conf->radclock_version, PACKAGE_VERSION);
	conf->server_ipc			= DEFAULT_SERVER_IPC;
	conf->synchro_type 			= DEFAULT_SYNCHRO_TYPE;
	conf->server_ntp 			= DEFAULT_SERVER_NTP;
	conf->adjust_sysclock 		= DEFAULT_ADJUST_SYSCLOCK;
	
	/* Virtual Machine */
	conf->virtual_machine		= DEFAULT_VIRTUAL_MACHINE;

	/* Clock parameters */ 
	conf->poll_period			= DEFAULT_NTP_POLL_PERIOD;
	conf->start_plocal			= DEFAULT_START_PLOCAL;
	conf->phyparam.TSLIMIT 		= TS_LIMIT_GOOD;
	conf->phyparam.SKM_SCALE		= SKM_SCALE_GOOD;
	conf->phyparam.RateErrBOUND 	= RATE_ERR_BOUND_GOOD;
	conf->phyparam.BestSKMrate 	= BEST_SKM_RATE_GOOD;
	conf->phyparam.offset_ratio 	= OFFSET_RATIO_GOOD;
	conf->phyparam.plocal_quality	= PLOCAL_QUALITY_GOOD;
	conf->phat_init 			= DEFAULT_PHAT_INIT;
	conf->asym_host 			= DEFAULT_ASYM_HOST;
	conf->asym_net				= DEFAULT_ASYM_NET;

	/* Network level  */
	strcpy(conf->hostname, "");
	strcpy(conf->time_server, "");
	
	/* Input/Output files and devices */ 
	// Must be put to empty string not to confuse anything. Only one input must
	// be specified at a time (either from the conf file or the command line
	strcpy(conf->network_device, "");
	strcpy(conf->sync_in_pcap, "");
	strcpy(conf->sync_in_ascii, "");
	strcpy(conf->sync_out_pcap, "");
	strcpy(conf->sync_out_ascii, "");
	strcpy(conf->clock_out_ascii, "");
}



/** For a given key index, lookup for the corresponding label */
const char* find_key_label(struct _key *keys, int codekey) 
{
	for (;;) {	
		if (keys->keytype == CONFIG_UNKNOWN) {
			verbose(LOG_ERR, "Did not find a key while creating the configuration file.");
			return NULL;
		}
		if (keys->keytype == codekey) {
			return keys->label;
		}
		keys++;	
	}
	return NULL;
}


int get_temperature_config(struct radclock_config *conf)
{
	if ( (conf->phyparam.TSLIMIT == TS_LIMIT_POOR)
	  && (conf->phyparam.RateErrBOUND == RATE_ERR_BOUND_POOR)
	  && (conf->phyparam.SKM_SCALE == SKM_SCALE_POOR)
	  && (conf->phyparam.BestSKMrate == BEST_SKM_RATE_POOR)
	  && (conf->phyparam.offset_ratio == OFFSET_RATIO_POOR)
	  && (conf->phyparam.plocal_quality == PLOCAL_QUALITY_POOR))
			return CONFIG_QUALITY_POOR;

	else if ( (conf->phyparam.TSLIMIT == TS_LIMIT_GOOD)
	  && (conf->phyparam.RateErrBOUND == RATE_ERR_BOUND_GOOD)
	  && (conf->phyparam.SKM_SCALE == SKM_SCALE_GOOD)
	  && (conf->phyparam.BestSKMrate == BEST_SKM_RATE_GOOD)
	  && (conf->phyparam.offset_ratio == OFFSET_RATIO_GOOD)
	  && (conf->phyparam.plocal_quality == PLOCAL_QUALITY_GOOD))
			return CONFIG_QUALITY_GOOD;

	else if ( (conf->phyparam.TSLIMIT == TS_LIMIT_EXCEL)
	  && (conf->phyparam.RateErrBOUND == RATE_ERR_BOUND_EXCEL)
	  && (conf->phyparam.SKM_SCALE == SKM_SCALE_EXCEL)
	  && (conf->phyparam.BestSKMrate == BEST_SKM_RATE_EXCEL)
	  && (conf->phyparam.offset_ratio == OFFSET_RATIO_EXCEL)
	  && (conf->phyparam.plocal_quality == PLOCAL_QUALITY_EXCEL))
			return CONFIG_QUALITY_EXCEL;

	else	
			return CONFIG_QUALITY_UNKWN;
}


/** Write a default configuration file */
void write_config_file(FILE *fd, struct _key *keys, struct radclock_config *conf) {

	fprintf(fd, "##\n");
	fprintf(fd, "## This is the default configuration file for the RADclock\n");
	fprintf(fd, "##\n\n");

	/* PACKAGE_VERSION defined with autoconf tools */
	fprintf(fd, "#----------------------------------------------------------------------------#\n");
	fprintf(fd, "# Package version. Do not modify this line.\n");
	fprintf(fd, "%s = %s\n", find_key_label(keys, CONFIG_RADCLOCK_VERSION), PACKAGE_VERSION);
	fprintf(fd, "#----------------------------------------------------------------------------#\n");
	fprintf(fd, "\n\n");

	/* Verbose */
	fprintf(fd, "# Verbosity level of the radclock daemon.\n");
	fprintf(fd, "#\tquiet : only errors and warnings are logged\n");
	fprintf(fd, "#\tnormal: adaptive logging of events\n");
	fprintf(fd, "#\thigh  : include debug messages\n");
	if (conf == NULL)
		fprintf(fd, "%s = %s\n\n", find_key_label(keys, CONFIG_VERBOSE), labels_verb[DEFAULT_VERBOSE]);
	else
		fprintf(fd, "%s = %s\n\n", find_key_label(keys, CONFIG_VERBOSE), labels_verb[conf->verbose_level]);


	fprintf(fd, "\n\n\n");
	fprintf(fd, "#----------------------------------------------------------------------------#\n");
	fprintf(fd, "# Synchronisation Client parameters\n");
	fprintf(fd, "#----------------------------------------------------------------------------#\n");
	fprintf(fd, "\n");


	/* Specify the type of synchronisation to use*/
	fprintf(fd, "# Specify the type of underlying synchronisation used.\n"
				"# Note that piggybacking requires an ntp daemon running and is then\n"
				"# incompatible with the RADclock serving clients over the network or \n"
				"# adjusting the system clock. Piggybacking disables these functions.\n");
	fprintf(fd, "#\tpiggy   : piggybacking on running ntp daemon\n");
	fprintf(fd, "#\tntp     : RADclock uses NTP protocol\n");
	fprintf(fd, "#\tieee1588: RADclock uses IEEE 1588 protocol - NOT IMPLEMENTED YET\n");
	fprintf(fd, "#\tpps     : RADclock listens to PPS - NOT IMPLEMENTED YET\n");
	if (conf == NULL)
		fprintf(fd, "%s = %s\n\n", find_key_label(keys, CONFIG_SYNCHRO_TYPE), labels_sync[DEFAULT_SYNCHRO_TYPE]);
	else
		fprintf(fd, "%s = %s\n\n", find_key_label(keys, CONFIG_SYNCHRO_TYPE), labels_sync[conf->synchro_type]);


	/* Poll Period */
	fprintf(fd, "# The polling period specifies the time interval at which\n");
	fprintf(fd, "# the requests for time are sent to the server (value in seconds)\n");
	if (conf == NULL)
		fprintf(fd, "%s = %d\n\n", find_key_label(keys, CONFIG_POLLPERIOD), DEFAULT_NTP_POLL_PERIOD);
	else
		fprintf(fd, "%s = %d\n\n", find_key_label(keys, CONFIG_POLLPERIOD), conf->poll_period);


	/* Hostname */
   	fprintf(fd, "# Hostname or IP address (uses lookup name resolution).\n");
   	fprintf(fd, "# Automatic detection will be attempted if not specified.\n");
	if ( (conf) && (strlen(conf->hostname) > 0) )
		fprintf(fd, "%s = %s\n\n", find_key_label(keys, CONFIG_HOSTNAME), conf->hostname);
	else
		fprintf(fd, "#%s = %s\n\n", find_key_label(keys, CONFIG_HOSTNAME), DEFAULT_HOSTNAME);


	/* NTP server */
	fprintf(fd, "# Time server answering the requests from this client.\n");
   	fprintf(fd, "# Can be a host name or an IP address (uses lookup name resolution).\n");
	if ( (conf) && (strlen(conf->time_server) > 0) )
		fprintf(fd, "%s = %s\n\n", find_key_label(keys, CONFIG_TIME_SERVER), conf->time_server);
	else
		fprintf(fd, "#%s = %s\n\n", find_key_label(keys, CONFIG_TIME_SERVER), DEFAULT_TIME_SERVER);


	fprintf(fd, "\n\n\n");
	fprintf(fd, "#----------------------------------------------------------------------------#\n");
	fprintf(fd, "# Synchronisation Server parameters\n");
	fprintf(fd, "#----------------------------------------------------------------------------#\n");
	fprintf(fd, "\n");


	/* Serve other processes and kernel update */
	fprintf(fd, "# IPC server.\n");
	fprintf(fd, "# Serves time to the kernel and other processes.\n");
	fprintf(fd, "#\ton : Start service - makes the RADclock available to other programs\n");
	fprintf(fd, "#\toff: Stop service  - useful when replaying traces\n");
	if (conf == NULL)
		fprintf(fd, "%s = %s\n\n", find_key_label(keys, CONFIG_SERVER_IPC), labels_bool[DEFAULT_SERVER_IPC]);
	else
		fprintf(fd, "%s = %s\n\n", find_key_label(keys, CONFIG_SERVER_IPC), labels_bool[conf->server_ipc]);


	/* Specify the type of synchronisation server we run */
	fprintf(fd, "# NTP server.\n");
	fprintf(fd, "# Serves time to radclock clients over the network.\n");
	fprintf(fd, "#\ton : runs a NTP server for remote clients\n");
	fprintf(fd, "#\toff: no server running\n");
	if (conf == NULL)
		fprintf(fd, "%s = %s\n\n", find_key_label(keys, CONFIG_SERVER_NTP), labels_bool[DEFAULT_SERVER_NTP]);
	else
		fprintf(fd, "%s = %s\n\n", find_key_label(keys, CONFIG_SERVER_NTP), labels_bool[conf->server_ntp]);


	/* Adjust the system clock */
	fprintf(fd, "# System clock.\n"
				"# Let the RADclock adjust the system clock, make sure no other synchronisation\n"
				"# daemon is running, especially the ntp daemon.\n"
				"# Note that this feature relies on standard kernel calls to adjust the time and\n"
				"# is completely different from the IPC server provided. This feature is essentially\n"
				"# provided to maintain system time for non critical operations. If you care about\n"
				"# synchronisation, turn the IPC server on and use the libradclock API\n"
				"# Also note that system clock time causality may break since the system clock will\n"
				"# be set on RADclock restart. The system clock will tick monotically afterwards.\n"
				"#\ton : adjust the system clock\n"
				"#\toff: does not adjust the system clock (to use with NTP piggybacking)\n");
	if (conf == NULL)
		fprintf(fd, "%s = %s\n\n", find_key_label(keys, CONFIG_ADJUST_SYSCLOCK), labels_bool[DEFAULT_ADJUST_SYSCLOCK]);
	else
		fprintf(fd, "%s = %s\n\n", find_key_label(keys, CONFIG_ADJUST_SYSCLOCK), labels_bool[conf->adjust_sysclock]);

	
	
	fprintf(fd, "\n\n\n");
	fprintf(fd, "#----------------------------------------------------------------------------#\n");
	fprintf(fd, "# Virtual Machine Environment parameters\n");
	fprintf(fd, "#----------------------------------------------------------------------------#\n");
	fprintf(fd, "\n");


	/* Specify the vm mode radclock runs in */
	fprintf(fd, "# The role of the radclock in a virtual machine environment (if any).\n"
				"# It is usually better to give the master role to the radclock instance \n"
				"# running in the host system, and the slave roles to the radclock running \n"
				"# in the guest system.\n");
	fprintf(fd, "# Possible values are:\n");
	fprintf(fd, "#\tnone        : no virtual machine environment\n");
	fprintf(fd, "#\txen-master  : radclock creates time for all Xen systems\n");
	fprintf(fd, "#\txen-slave   : radclock gets its time from a Xen master\n");
	fprintf(fd, "#\tvbox-master : radclock creates time for all Virtual Box systems\n");
	fprintf(fd, "#\tvbox-slave  : radclock gets its time from a Virtual Box master\n");
	if (conf == NULL)
		fprintf(fd, "%s = %s\n\n", find_key_label(keys, CONFIG_VIRTUAL_MACHINE), labels_vm[DEFAULT_VIRTUAL_MACHINE]);
	else
		fprintf(fd, "%s = %s\n\n", find_key_label(keys, CONFIG_VIRTUAL_MACHINE), labels_vm[conf->virtual_machine]);
	

	fprintf(fd, "\n\n\n");
	fprintf(fd, "#----------------------------------------------------------------------------#\n");
	fprintf(fd, "# Environment and Tuning parameters\n");
	fprintf(fd, "#----------------------------------------------------------------------------#\n");
	fprintf(fd, "\n");
	

	/* Temperature */	
	fprintf(fd, "# Temperature environment and hardware quality.\n");
	fprintf(fd, "# Keywods accepted are: poor, good, excellent.\n"	);
	fprintf(fd, "# This setting overrides temperature and hardware expert mode (default behavior). \n"	);
	if (conf == NULL)
		fprintf(fd, "%s = %s\n\n", find_key_label(keys, CONFIG_TEMPQUALITY ), temp_quality[CONFIG_QUALITY_GOOD].label);
	else {
		/* There is an existing configuration file */
		switch (get_temperature_config(conf)) { 
		case CONFIG_QUALITY_POOR:
			fprintf(fd, "%s = %s\n\n", find_key_label(keys, CONFIG_TEMPQUALITY ), 
					temp_quality[CONFIG_QUALITY_POOR].label);
			break;
		case CONFIG_QUALITY_GOOD:
			fprintf(fd, "%s = %s\n\n", find_key_label(keys, CONFIG_TEMPQUALITY ), 
					temp_quality[CONFIG_QUALITY_GOOD].label);
			break;
		case CONFIG_QUALITY_EXCEL:
			fprintf(fd, "%s = %s\n\n", find_key_label(keys, CONFIG_TEMPQUALITY ), 
					temp_quality[CONFIG_QUALITY_EXCEL].label);
			break;
		/* We have an existing expert config */
		case CONFIG_QUALITY_UNKWN:
		default:
		fprintf(fd, "#%s = %s\n\n", find_key_label(keys, CONFIG_TEMPQUALITY ), 
				temp_quality[CONFIG_QUALITY_GOOD].label);
		}
	}

	/* Temperature expert mode */	
	fprintf(fd, "# EXPERIMENTAL.\n");
	fprintf(fd, "# Temperature environment and hardware quality - EXPERT.\n");
	fprintf(fd, "# This settings are over-written by the %s keyword.\n", find_key_label(keys,CONFIG_TEMPQUALITY));
	if (conf == NULL) {
		fprintf(fd, "#%s = %.9lf\n", find_key_label(keys, CONFIG_TSLIMIT), TS_LIMIT_GOOD);
		fprintf(fd, "#%s = %.9lf\n", find_key_label(keys, CONFIG_SKM_SCALE), SKM_SCALE_GOOD);
		fprintf(fd, "#%s = %.9lf\n", find_key_label(keys, CONFIG_RATE_ERR_BOUND), RATE_ERR_BOUND_GOOD);
		fprintf(fd, "#%s = %.9lf\n", find_key_label(keys, CONFIG_BEST_SKM_RATE), BEST_SKM_RATE_GOOD);
		fprintf(fd, "#%s = %d\n", find_key_label(keys, CONFIG_OFFSET_RATIO), OFFSET_RATIO_GOOD);
		fprintf(fd, "#%s = %.9lf\n", find_key_label(keys, CONFIG_PLOCAL_QUALITY), PLOCAL_QUALITY_GOOD);
		fprintf(fd, "\n"); 
	} else {
		switch (get_temperature_config(conf)) { 
		case CONFIG_QUALITY_POOR:
		case CONFIG_QUALITY_GOOD:
		case CONFIG_QUALITY_EXCEL:
			fprintf(fd, "#%s = %.9lf\n", find_key_label(keys, CONFIG_TSLIMIT), TS_LIMIT_GOOD);
			fprintf(fd, "#%s = %.9lf\n", find_key_label(keys, CONFIG_SKM_SCALE), SKM_SCALE_GOOD);
			fprintf(fd, "#%s = %.9lf\n", find_key_label(keys, CONFIG_RATE_ERR_BOUND), RATE_ERR_BOUND_GOOD);
			fprintf(fd, "#%s = %.9lf\n", find_key_label(keys, CONFIG_BEST_SKM_RATE), BEST_SKM_RATE_GOOD);
			fprintf(fd, "#%s = %d\n", find_key_label(keys, CONFIG_OFFSET_RATIO), OFFSET_RATIO_GOOD);
			fprintf(fd, "#%s = %.9lf\n", find_key_label(keys, CONFIG_PLOCAL_QUALITY), PLOCAL_QUALITY_GOOD);
			fprintf(fd, "\n"); 
			break;
		/* We have an existing expert config */
		case CONFIG_QUALITY_UNKWN:
		default:
			fprintf(fd, "%s = %.9lf\n", find_key_label(keys, CONFIG_TSLIMIT), conf->phyparam.TSLIMIT);
			fprintf(fd, "%s = %.9lf\n", find_key_label(keys, CONFIG_SKM_SCALE), conf->phyparam.SKM_SCALE);
			fprintf(fd, "%s = %.9lf\n", find_key_label(keys, CONFIG_RATE_ERR_BOUND), conf->phyparam.RateErrBOUND);
			fprintf(fd, "%s = %.9lf\n", find_key_label(keys, CONFIG_BEST_SKM_RATE), conf->phyparam.BestSKMrate);
			fprintf(fd, "%s = %d\n", find_key_label(keys, CONFIG_OFFSET_RATIO), conf->phyparam.offset_ratio);
			fprintf(fd, "%s = %.9lf\n", find_key_label(keys, CONFIG_PLOCAL_QUALITY), conf->phyparam.plocal_quality);
			fprintf(fd, "\n"); 
		}
	}


	
	/* P Local */
	fprintf(fd, "# Specify if p_local should be started.\n");
	fprintf(fd, "# Possible values are:\n");
	fprintf(fd, "#\ton\n");
	fprintf(fd, "#\toff\n");
	fprintf(fd, "#\trestart\n");
	if (conf == NULL)
		fprintf(fd, "%s = %s\n\n", find_key_label(keys, CONFIG_PLOCAL), labels_plocal[DEFAULT_START_PLOCAL]);
	else
		fprintf(fd, "%s = %s\n\n", find_key_label(keys, CONFIG_PLOCAL), labels_plocal[conf->start_plocal]);


	/* Phat init */
	fprintf(fd, "# For a quick start, the initial value of the period of the counter (in seconds). \n");
	if (conf == NULL)
		fprintf(fd, "%s = %lg\n\n", find_key_label(keys, CONFIG_PHAT_INIT), DEFAULT_PHAT_INIT);
	else
		fprintf(fd, "%s = %lg\n\n", find_key_label(keys, CONFIG_PHAT_INIT), conf->phat_init);


	/* Delta Host */
	fprintf(fd, "# Estimation of the asym within the host (in seconds). \n");
	if (conf == NULL)
		fprintf(fd, "%s = %lf\n\n", find_key_label(keys, CONFIG_ASYM_HOST), DEFAULT_ASYM_HOST);
	else
		fprintf(fd, "%s = %lf\n\n", find_key_label(keys, CONFIG_ASYM_HOST), conf->asym_host);

	/* Delta Network */
	fprintf(fd, "# Estimation of the network asym (in seconds). \n"	);
	if (conf == NULL)
		fprintf(fd, "%s = %lf\n\n", find_key_label(keys, CONFIG_ASYM_NET), DEFAULT_ASYM_NET);
	else
		fprintf(fd, "%s = %lf\n\n", find_key_label(keys, CONFIG_ASYM_NET), conf->asym_net);

	
		
	fprintf(fd, "\n\n\n");
	fprintf(fd, "#----------------------------------------------------------------------------#\n");
	fprintf(fd, "# Input / Output parameters\n");
	fprintf(fd, "#----------------------------------------------------------------------------#\n");
	fprintf(fd, "\n");
	
	/* Network device */
	fprintf(fd, "# Network interface.\n");
	fprintf(fd, "# Specify a different interface (xl0, eth0, ...)\n");
	fprintf(fd, "# If none, the RADclock will lookup for a default one.\n");
	if ( (conf) && (strlen(conf->network_device) > 0) )
		fprintf(fd, "%s = %s\n\n", find_key_label(keys, CONFIG_NETWORKDEV), conf->network_device);
	else
		fprintf(fd, "#%s = %s\n\n", find_key_label(keys, CONFIG_NETWORKDEV), DEFAULT_NETWORKDEV);


	/* RAW Input */
	fprintf(fd, "# Synchronisation data input file (modified pcap format).\n");
	fprintf(fd, "# Replay mode requires a file produced by the RADclock.\n");
	if ( (conf) && (strlen(conf->sync_in_pcap) > 0) )
		fprintf(fd, "%s = %s\n\n", find_key_label(keys, CONFIG_SYNC_IN_PCAP), conf->sync_in_pcap);
	else
		fprintf(fd, "#%s = %s\n\n", find_key_label(keys, CONFIG_SYNC_IN_PCAP), DEFAULT_SYNC_IN_PCAP);

	/* Stamp Input */
	fprintf(fd, "# Synchronisation data input file (ascii format).\n");
	fprintf(fd, "# Replay mode requires a file produced by the RADclock.\n");
	if ( (conf) && (strlen(conf->sync_in_ascii) > 0) )
		fprintf(fd, "%s = %s\n\n", find_key_label(keys, CONFIG_SYNC_IN_ASCII), conf->sync_in_ascii);
	else
		fprintf(fd, "#%s = %s\n\n", find_key_label(keys, CONFIG_SYNC_IN_ASCII), DEFAULT_SYNC_IN_ASCII);

	/* RAW Output */
	fprintf(fd, "# Synchronisation data output file (modified pcap format).\n");
	if ( (conf) && (strlen(conf->sync_out_pcap) > 0) )
		fprintf(fd, "%s = %s\n\n", find_key_label(keys, CONFIG_SYNC_OUT_PCAP), conf->sync_out_pcap);
	else
		fprintf(fd, "#%s = %s\n\n", find_key_label(keys, CONFIG_SYNC_OUT_PCAP), DEFAULT_SYNC_OUT_PCAP);

	/* Stamp output */
	fprintf(fd, "# Synchronisation data output file (ascii format).\n");
	if ( (conf) && (strlen(conf->sync_out_ascii) > 0) )
		fprintf(fd, "%s = %s\n\n", find_key_label(keys, CONFIG_SYNC_OUT_ASCII), conf->sync_out_ascii);
	else
		fprintf(fd, "#%s = %s\n\n", find_key_label(keys, CONFIG_SYNC_OUT_ASCII), DEFAULT_SYNC_OUT_ASCII);

	/* Matlab */
	fprintf(fd, "# Internal clock data output file (ascii format).\n");
	if ( (conf) && (strlen(conf->clock_out_ascii) > 0) )
		fprintf(fd, "%s = %s\n\n", find_key_label(keys, CONFIG_CLOCK_OUT_ASCII), conf->clock_out_ascii);
	else
		fprintf(fd, "#%s = %s\n\n", find_key_label(keys, CONFIG_CLOCK_OUT_ASCII), DEFAULT_CLOCK_OUT_ASCII);

}


/** Extract the key label and the corresponding value from a line of the parsed
 * configuration file. 
 */
int extract_key_value (char* c, char* key, char* value) {

	char *ch;
	
	// Look for first character in line
	while ((*c==' ') || (*c=='\t')) { c++; }

	// Check if character for a config parameter
	if ((*c=='#') || (*c=='\n') || (*c=='\0')) { return 0; }
	
	// Identify the separator, copy key and clean end white spaces 
	strncpy(key, c, strchr(c,'=')-c);
	ch = key;
	while ((*ch!=' ') && (*ch!='\n') && (*ch != '\t')) { ch++; }
	*ch = '\0';

	// Identify first character of the value
	c = strchr(c,'=');
	ch = c;
	while ((*ch=='=') || (*ch==' ') || (*ch=='\t')) { ch++; }
	c = ch;
	
	// Remove possible comments in line after the value '#' 
	while ((*ch!='\0') && (*ch!='#')) {ch++;}
		*ch = '\0';
	
	// Remove extra space at the end of the line if any
	ch = c + strlen(c) - 1 ;
	while ((*ch==' ') || (*ch=='\t') || (*ch=='\n')) { ch--; }
	*(ch+1) = '\0';

	// Copy final string
	strncpy(value, c, strlen(c)+1);

	return 1;
}




/** Match the key index from the key label */
int match_key(struct _key *keys, char* keylabel) {
	for (;;) {	
		if (keys->keytype == CONFIG_UNKNOWN) {
			verbose(LOG_WARNING, "Unknown key in config file: %s", keylabel);
			return 0;
		}
		if (strcmp(keys->label, keylabel) == 0) 
			return keys->keytype;
		keys++;	
	}
	return 1;
}


int check_valid_option(char* value, char* labels[], int label_sz) 
{
	int i;
	for ( i=0; i<label_sz; i++ )
	{
		if ( strcmp(value, labels[i]) == 0 )
			return i;
	}
	return -1;
}

	



// Global data, but also really ugly to make it a parameter.
int have_all_tmpqual = 0; /* To know if we run expert mode */

/** Update global data with values retrieved from the configuration file */
int update_data (struct radclock_config *conf, u_int32_t *mask, int codekey, char *value) { 

	// The mask parameter should always be positioned to UPDMASK_NOUPD except
	// for the first call to config_parse() after parsing the command line
	// arguments

	int ival 		= 0;
	double dval 	= 0.0;
	int iqual 		= 0;
	struct _key *quality = temp_quality;
	
	// Additionnal input checks: codekey and value
	if ( codekey < 0) {
		verbose(LOG_ERR, "Negative key value from the config file");
		return 0;
	}

	if (value == NULL || strlen(value)==0) {
		verbose(LOG_ERR, "Empty value from the config file");
		return 0;
	}



switch (codekey) {
	
	case CONFIG_RADCLOCK_VERSION:
		strcpy(conf->radclock_version, value);
		break;


	case CONFIG_VERBOSE:
		// If value specified on the command line
		if ( HAS_UPDATE(*mask, UPDMASK_VERBOSE) ) 
			break;
		ival = check_valid_option(value, labels_verb, 3);
		// Indicate changed value
		if ( conf->verbose_level != ival )
			SET_UPDATE(*mask, UPDMASK_VERBOSE);
		if ( (ival<0) || (ival>2)) {
			verbose(LOG_WARNING, "verbose_level value incorrect. Fall back to default.");
			conf->verbose_level = DEFAULT_VERBOSE;
		}
		else {
			conf->verbose_level = ival;
		}
		break;


	case CONFIG_SERVER_IPC:
		// If value specified on the command line
		if ( HAS_UPDATE(*mask, UPDMASK_SERVER_IPC) ) 
			break;
		ival = check_valid_option(value, labels_bool, 2);
		// Indicate changed value
		if ( conf->server_ipc != ival )
			SET_UPDATE(*mask, UPDMASK_SERVER_IPC);
		if ( ival < 0)
		{
			verbose(LOG_WARNING, "ipc_server value incorrect. Fall back to default.");
			conf->server_ipc = DEFAULT_SERVER_IPC;
		}
		else
			conf->server_ipc = ival;
		break;


	case CONFIG_SYNCHRO_TYPE:
		// If value specified on the command line
		if ( HAS_UPDATE(*mask, UPDMASK_SYNCHRO_TYPE) ) 
			break;
		ival = check_valid_option(value, labels_sync, 5);
		// Indicate changed value
		if ( conf->synchro_type != ival )
			SET_UPDATE(*mask, UPDMASK_SYNCHRO_TYPE);
		if ( ival < 0) {
			verbose(LOG_WARNING, "synchro_type value incorrect. Fall back to default.");
			conf->synchro_type = DEFAULT_SYNCHRO_TYPE;
		}
		else
			conf->synchro_type = ival;
		break;


	case CONFIG_SERVER_NTP:
		// If value specified on the command line
		if ( HAS_UPDATE(*mask, UPDMASK_SERVER_NTP) ) 
			break;
		ival = check_valid_option(value, labels_bool, 2);
		// Indicate changed value
		if ( conf->server_ntp != ival )
			SET_UPDATE(*mask, UPDMASK_SERVER_NTP);
		if ( ival < 0 ) {
			verbose(LOG_WARNING, "ntp_server parameter incorrect. Fall back to default.");
			conf->server_ntp = DEFAULT_SERVER_NTP;
		}
		else
			conf->server_ntp = ival;
		break;


	case CONFIG_ADJUST_SYSCLOCK:
		// If value specified on the command line
		if ( HAS_UPDATE(*mask, UPDMASK_ADJUST_SYSCLOCK) ) 
			break;
		ival = check_valid_option(value, labels_bool, 2);
		// Indicate changed value
		if ( conf->adjust_sysclock != ival )
			SET_UPDATE(*mask, UPDMASK_ADJUST_SYSCLOCK);
		if ( ival < 0 ) {
			verbose(LOG_WARNING, "adjust_system_clock parameter incorrect. Fall back to default.");
			conf->adjust_sysclock = DEFAULT_ADJUST_SYSCLOCK;
		}
		else
			conf->adjust_sysclock = ival;
		break;


	case CONFIG_VIRTUAL_MACHINE:
		// If value specified on the command line
		if ( HAS_UPDATE(*mask, UPDMASK_VIRTUAL_MACHINE) ) 
			break;
		ival = check_valid_option(value, labels_vm, 5);
		// Indicate changed value
		if ( conf->virtual_machine != ival )
			SET_UPDATE(*mask, UPDMASK_VIRTUAL_MACHINE);
		if ( ival < 0 ) {
			verbose(LOG_WARNING, "virtual_machine_mode parameter incorrect. Fall back to default.");
			conf->virtual_machine = DEFAULT_VIRTUAL_MACHINE;
		}
		else
			conf->virtual_machine = ival;
		break;


	case CONFIG_POLLPERIOD:
		// If value specified on the command line
		if ( HAS_UPDATE(*mask, UPDMASK_POLLPERIOD) )
			break;
		ival = atoi(value);
		// Indicate changed value
		if ( conf->poll_period != ival )
			SET_UPDATE(*mask, UPDMASK_POLLPERIOD);
		if ((ival<RAD_MINPOLL) || (ival>RAD_MAXPOLL)) {	
			verbose(LOG_WARNING, "Poll period value out of [%d,%d] range (%d). Fall back to default.",
				   	ival, RAD_MINPOLL, RAD_MAXPOLL);
			conf->poll_period = DEFAULT_NTP_POLL_PERIOD;
		}
		else {
			conf->poll_period = ival;
		}
		break;


	case CONFIG_TSLIMIT:
		/* Be sure we don't override an overall temperature setting */
		if (have_all_tmpqual == 0) { 
			dval = strtod(value, NULL);
			// Indicate changed value
			if ( conf->phyparam.TSLIMIT != dval )
				SET_UPDATE(*mask, UPDMASK_TEMPQUALITY);
			if (dval<0)  {
				verbose(LOG_WARNING, "Using ts_limit value out of range (%f). Fall back to default.", dval);
				conf->phyparam.TSLIMIT = TS_LIMIT_GOOD;
			}
			else {
				conf->phyparam.TSLIMIT = dval;
			}
		}
		break;
		
	case CONFIG_SKM_SCALE:
		/* Be sure we don't override an overall temperature setting */
		if (have_all_tmpqual == 0) { 
			dval = strtod(value, NULL);
			// Indicate changed value
			if ( conf->phyparam.SKM_SCALE != dval )
				SET_UPDATE(*mask, UPDMASK_TEMPQUALITY);
			if (dval<0)  {
				verbose(LOG_WARNING, "Using skm_scale value out of range (%f). Fall back to default.", dval);
				conf->phyparam.SKM_SCALE = SKM_SCALE_GOOD;
			}
			else {
				conf->phyparam.SKM_SCALE = dval;
			}
		}
		break;
		
	case CONFIG_RATE_ERR_BOUND:
		/* Be sure we don't override an overall temperature setting */
		if (have_all_tmpqual == 0) { 
			dval = strtod(value, NULL);
			// Indicate changed value
			if ( conf->phyparam.RateErrBOUND != dval )
				SET_UPDATE(*mask, UPDMASK_TEMPQUALITY);
			if (dval<0)  {
				verbose(LOG_WARNING, "Using rate_error_bound value out of range (%f). Fall back to default.", dval);
				conf->phyparam.RateErrBOUND = RATE_ERR_BOUND_GOOD;
			}
			else {
				conf->phyparam.RateErrBOUND = dval;
			}
		}
		break;
	
	case CONFIG_BEST_SKM_RATE:
		/* Be sure we don't override an overall temperature setting */
		if (have_all_tmpqual == 0) { 
			dval = strtod(value, NULL);
			// Indicate changed value
			if ( conf->phyparam.BestSKMrate != dval )
				SET_UPDATE(*mask, UPDMASK_TEMPQUALITY);
			if (dval<0)  {
				verbose(LOG_WARNING, "Using best_skm_rate value out of range (%f). Fall back to default.", dval);
				conf->phyparam.BestSKMrate = BEST_SKM_RATE_GOOD;
			}
			else {
				conf->phyparam.BestSKMrate = dval;
			}
		}
		break;

	case CONFIG_OFFSET_RATIO:
		/* Be sure we don't override an overall temperature setting */
		if (have_all_tmpqual == 0) { 
			ival = atoi(value);
			// Indicate changed value
			if ( conf->phyparam.offset_ratio != ival )
				SET_UPDATE(*mask, UPDMASK_TEMPQUALITY);
			if (ival<=0)  {
				verbose(LOG_WARNING, "Using offset_ratio value out of range (%f). Fall back to default.", ival);
				conf->phyparam.offset_ratio = OFFSET_RATIO_GOOD;
			}
			else {
				conf->phyparam.offset_ratio = ival;
			}
		}
		break;

	case CONFIG_PLOCAL_QUALITY:
		/* Be sure we don't override an overall temperature setting */
		if (have_all_tmpqual == 0) { 
			dval = strtod(value, NULL);
			// Indicate changed value
			if ( conf->phyparam.plocal_quality != dval )
				SET_UPDATE(*mask, UPDMASK_TEMPQUALITY);
			if (dval<0)  {
				verbose(LOG_WARNING, "Using plocal_quality value out of range (%f). Fall back to default.", dval);
				conf->phyparam.plocal_quality = PLOCAL_QUALITY_GOOD;
			}
			else {
				conf->phyparam.plocal_quality = dval;
			}
		}
		break;

	
	case CONFIG_TEMPQUALITY:
		/* We have an overall environment quality key word */
		have_all_tmpqual = 1;
		for (;;) {
			if (quality->keytype == CONFIG_QUALITY_UNKWN) {
				verbose(LOG_ERR, "The quality parameter given is unknown");
				return 0;	
			}
			if (strcmp(quality->label, value) == 0) {
				iqual = quality->keytype;
				break;
			}
			quality++;
		}
		switch (iqual) {
			case CONFIG_QUALITY_POOR:
				// Indicate changed value
				if ( (conf->phyparam.TSLIMIT - TS_LIMIT_POOR) != 0)
					SET_UPDATE(*mask, UPDMASK_TEMPQUALITY);
				conf->phyparam.TSLIMIT 		= TS_LIMIT_POOR;
				conf->phyparam.SKM_SCALE 		= SKM_SCALE_POOR;
				conf->phyparam.RateErrBOUND 	= RATE_ERR_BOUND_POOR;
				conf->phyparam.BestSKMrate 	= BEST_SKM_RATE_POOR;
				conf->phyparam.offset_ratio 	= OFFSET_RATIO_POOR;
				conf->phyparam.plocal_quality	= PLOCAL_QUALITY_POOR;
				break;
			case CONFIG_QUALITY_GOOD:
				// Indicate changed value
				if ( (conf->phyparam.TSLIMIT - TS_LIMIT_GOOD) != 0 )
					SET_UPDATE(*mask, UPDMASK_TEMPQUALITY);
				conf->phyparam.TSLIMIT 		= TS_LIMIT_GOOD;
				conf->phyparam.SKM_SCALE		= SKM_SCALE_GOOD;
				conf->phyparam.RateErrBOUND 	= RATE_ERR_BOUND_GOOD;
				conf->phyparam.BestSKMrate 	= BEST_SKM_RATE_GOOD;
				conf->phyparam.offset_ratio 	= OFFSET_RATIO_GOOD;
				conf->phyparam.plocal_quality	= PLOCAL_QUALITY_GOOD;
				break;
			case CONFIG_QUALITY_EXCEL:
				// Indicate changed value
				if ( (conf->phyparam.TSLIMIT - TS_LIMIT_EXCEL) != 0 )
					SET_UPDATE(*mask, UPDMASK_TEMPQUALITY);
				conf->phyparam.TSLIMIT 		= TS_LIMIT_EXCEL;
				conf->phyparam.SKM_SCALE 		= SKM_SCALE_EXCEL;
				conf->phyparam.RateErrBOUND 	= RATE_ERR_BOUND_EXCEL;
				conf->phyparam.BestSKMrate 	= BEST_SKM_RATE_EXCEL;
				conf->phyparam.offset_ratio 	= OFFSET_RATIO_EXCEL;
				conf->phyparam.plocal_quality	= PLOCAL_QUALITY_EXCEL;
				break;
			default:
				verbose(LOG_ERR, "Quality parameter given is unknown");
				break;
		}	
		break;
	

	case CONFIG_PLOCAL:
		// If value specified on the command line
		if ( HAS_UPDATE(*mask, UPDMASK_PLOCAL) ) 
			break;
		ival = check_valid_option(value, labels_plocal, 3);
		// Indicate changed value
		if ( conf->start_plocal != ival )
			SET_UPDATE(*mask, UPDMASK_PLOCAL);
		if ( (ival<0) || (ival>2)) {
			verbose(LOG_WARNING, "start_local_phat parameter incorrect. Fall back to default.");
			conf->start_plocal = DEFAULT_START_PLOCAL;
		}
		else {
			conf->start_plocal = ival;
		}
		break;


	case CONFIG_PHAT_INIT:
		dval = strtod(value, NULL);
		if ( (dval<0) || (dval==0) || (dval>1)) {
			verbose(LOG_WARNING, "Using phat_init value out of range (%f). Falling back to default.", dval);
			conf->phat_init = DEFAULT_PHAT_INIT;
		}
		else {
			conf->phat_init = dval;
		}
		break;


	case CONFIG_ASYM_HOST:
		// If value specified on the command line
		if ( HAS_UPDATE(*mask, UPDMASK_ASYM_HOST) ) 
			break;
		dval = strtod(value, NULL);
		// Indicate changed value
		if ( conf->asym_host != dval )
			SET_UPDATE(*mask, UPDMASK_ASYM_HOST);
		if ( (dval<0) || (dval>1)) {
			verbose(LOG_WARNING, "Using host_asymmetry value out of range (%f). Falling back to default.", dval);
			conf->asym_host = DEFAULT_ASYM_HOST;
		}
		else {
			conf->asym_host = dval;
		}
		break;


	case CONFIG_ASYM_NET:
		// If value specified on the command line
		if ( HAS_UPDATE(*mask, UPDMASK_ASYM_NET) ) 
			break;
		dval = strtod(value, NULL);
		// Indicate changed value
		if ( conf->asym_net != dval )
			SET_UPDATE(*mask, UPDMASK_ASYM_NET);
		if ( (dval<0) || (dval>1)) {
			verbose(LOG_WARNING, "Using network_asymmetry value out of range (%f). Falling back to default.", dval);
			conf->asym_net = DEFAULT_ASYM_NET;
		}
		else {
			conf->asym_net = dval;
		}
		break;


	case CONFIG_HOSTNAME:
		// If value specified on the command line
		if ( HAS_UPDATE(*mask, UPDMASK_HOSTNAME) ) 
			break;
		if ( strcmp(conf->hostname, value) != 0 )
			SET_UPDATE(*mask, UPDMASK_HOSTNAME);
		strcpy(conf->hostname, value);
		break;


	case CONFIG_TIME_SERVER:
		// If value specified on the command line
		if ( HAS_UPDATE(*mask, UPDMASK_TIME_SERVER) ) 
			break;
		if ( strcmp(conf->time_server, value) != 0 )
			SET_UPDATE(*mask, UPDMASK_TIME_SERVER);
		strcpy(conf->time_server, value);
		break;


	case CONFIG_NETWORKDEV:
		// If value specified on the command line
		if ( HAS_UPDATE(*mask, UPDMASK_NETWORKDEV) ) 
			break;
		if ( strcmp(conf->network_device, value) != 0 )
			SET_UPDATE(*mask, UPDMASK_NETWORKDEV);
		strcpy(conf->network_device, value);
		break;


	case CONFIG_SYNC_IN_PCAP:
		// If value specified on the command line
		if ( HAS_UPDATE(*mask, UPDMASK_SYNC_IN_PCAP) ) 
			break;
		if ( strcmp(conf->sync_in_pcap, value) != 0 )
			SET_UPDATE(*mask, UPDMASK_SYNC_IN_PCAP);
		strcpy(conf->sync_in_pcap, value);
		break;


	case CONFIG_SYNC_IN_ASCII:
		// If value specified on the command line
		if ( HAS_UPDATE(*mask, UPDMASK_SYNC_IN_ASCII) ) 
			break;
		if ( strcmp(conf->sync_in_ascii, value) != 0 )
			SET_UPDATE(*mask, UPDMASK_SYNC_IN_ASCII);
		strcpy(conf->sync_in_ascii, value);
		break;


	case CONFIG_SYNC_OUT_PCAP:
		// If value specified on the command line
		if ( HAS_UPDATE(*mask, UPDMASK_SYNC_OUT_PCAP) ) 
			break;
		if ( strcmp(conf->sync_out_pcap, value) != 0 )
			SET_UPDATE(*mask, UPDMASK_SYNC_OUT_PCAP);
		strcpy(conf->sync_out_pcap, value);
		break;


	case CONFIG_SYNC_OUT_ASCII:
		// If value specified on the command line
		if ( HAS_UPDATE(*mask, UPDMASK_SYNC_OUT_ASCII) ) 
			break;
		if ( strcmp(conf->sync_out_ascii, value) != 0 )
			SET_UPDATE(*mask, UPDMASK_SYNC_OUT_ASCII);
		strcpy(conf->sync_out_ascii, value);
		break;


	case CONFIG_CLOCK_OUT_ASCII:
		// If value specified on the command line
		if ( HAS_UPDATE(*mask, UPDMASK_CLOCK_OUT_ASCII) ) 
			break;
		if ( strcmp(conf->clock_out_ascii, value) != 0 )
			SET_UPDATE(*mask, UPDMASK_CLOCK_OUT_ASCII);
		strcpy(conf->clock_out_ascii, value);
		break;


	default:
		verbose(LOG_WARNING, "Unknown CONFIG_* symbol.");
		break;
}
return 1;
}


/*
 * Reads config file line by line, retrieve (key,value) and update global data
 */
int config_parse(struct radclock_config *conf, u_int32_t *mask, int is_daemon) 
{
	struct _key *pkey = keys;
	int codekey=0;	
	char *c;
	char line[MAXLINE];
	char key[MAXLINE];
	char value[MAXLINE];
	FILE* fd = NULL;

	/* Check input */
	if (conf == NULL) {
		verbose(LOG_ERR, "Configuration structure is NULL.");
		return 0;
	}
	
	/* Config and log files */
	if (strlen(conf->conffile) == 0)
	{
		if ( is_daemon )
			strcpy(conf->conffile, DAEMON_CONFIG_FILE);
		else
			strcpy(conf->conffile, BIN_CONFIG_FILE);
	}

	if (strlen(conf->logfile) == 0)
	{
		if ( is_daemon )
			strcpy(conf->conffile, DAEMON_CONFIG_FILE);
		else
			strcpy(conf->conffile, BIN_CONFIG_FILE);
	}



	// The file can't be opened. Ether it doesn't exist yet or I/O error.
	fd = fopen(conf->conffile, "r");
	if (!fd) {

		// Modify umask so that the file can be read by all after being written
		umask(022);
		verbose(LOG_NOTICE, "Did not find configuration file: %s.", conf->conffile);
		fd = fopen(conf->conffile, "w+");
		if (!fd) {
			verbose(LOG_ERR, "Cannot write configuration file: %s. ", conf->conffile);
                        umask(027);
			return 0;
		}

		write_config_file(fd, keys, NULL);
		fclose(fd);
                verbose(LOG_NOTICE, "Writing configuration file.");
		
		// Reposition umask
		umask(027);
		return 1;
	}
	// The configuration file exist, parse it and update default values
	have_all_tmpqual = 0; //ugly 
	while ((c=fgets(line, MAXLINE, fd))!=NULL) {

		// Start with a reset of the value to avoid mistakes
		strcpy(value, "");

		// Extract key and values from the conf file
		if ( !(extract_key_value(c, key, value) ))
			continue;
	
		// Identify the key and update config values
		codekey = match_key(pkey, key);

		// This line is not a configuration line
		if (codekey < 0)
			continue;

		// update in case we actually retrieved a value
		// This is our basic output check 
		if ( strlen(value) > 0 )
			update_data(conf, mask, codekey, value);
	}
	fclose(fd);
	

	/* Ok, the file has been parsed, but may the version may be outdated. Since
	 * we just parsed the configuration, we can produce an up-to-date version
	 */
	if ( strcmp(conf->radclock_version, PACKAGE_VERSION) != 0 ) {

		// Modify umask so that the file can be read by all after being written
		umask(022);
		fd = fopen(conf->conffile, "w");
		if ( !fd )
                {
			verbose(LOG_ERR, "Cannot update configuration file: %s.", conf->conffile);
                        umask(027);
                        return 0;
                }

                write_config_file(fd, keys, conf);
                fclose(fd);
                umask(027);

                // Adjust version
                strcpy(conf->radclock_version, PACKAGE_VERSION);
                verbose(LOG_NOTICE, "Updated the configuration file "
                                    "to the current package version");
	}

	/* Check command line arguments and config file for exclusion. 
	 * - If running as a daemon, refuse to read input raw or ascii file
	 */
	if ( is_daemon ) {
		if ( (strlen(conf->sync_in_ascii) > 0) || ( strlen(conf->sync_in_pcap) > 0) )
			verbose(LOG_WARNING, "Running as a daemon. Live capture only.");
		// Force the input to be a live device
		strcpy(conf->sync_in_ascii,"");
		strcpy(conf->sync_in_pcap,"");
	}
	
	return 1;
}





void config_print(int level, struct radclock_config *conf)
{
	verbose(level, "RADclock - configuration summary");
	verbose(level, "radclock version     : %s", conf->radclock_version);
	verbose(level, "Configuration file   : %s", conf->conffile);
	verbose(level, "Log file             : %s", conf->logfile);
	verbose(level, "Verbose level        : %s", labels_verb[conf->verbose_level]);
	verbose(level, "Client sync          : %s", labels_sync[conf->synchro_type]);
	verbose(level, "Server IPC           : %s", labels_bool[conf->server_ipc]);
	verbose(level, "Server NTP           : %s", labels_bool[conf->server_ntp]);
	verbose(level, "Adjust system clock  : %s", labels_bool[conf->adjust_sysclock]);
	verbose(level, "Virtual Machine mode : %s", labels_vm[conf->virtual_machine]);
	verbose(level, "Polling period       : %d", conf->poll_period);
	verbose(level, "TSLIMIT              : %.9lf", conf->phyparam.TSLIMIT);
	verbose(level, "SKM_SCALE            : %.9lf", conf->phyparam.SKM_SCALE);
	verbose(level, "RateErrBound         : %.9lf", conf->phyparam.RateErrBOUND);
	verbose(level, "BestSKMrate          : %.9lf", conf->phyparam.BestSKMrate);
	verbose(level, "offset_ratio         : %d", conf->phyparam.offset_ratio);
	verbose(level, "plocal_quality       : %.9lf", conf->phyparam.plocal_quality);
	verbose(level, "Using plocal         : %s", labels_plocal[conf->start_plocal]);
	verbose(level, "Initial phat         : %lg", conf->phat_init);
	verbose(level, "Host asymmetry       : %lf", conf->asym_host);
	verbose(level, "Network asymmetry    : %lf", conf->asym_net);
	verbose(level, "Host name            : %s", conf->hostname);
	verbose(level, "Time server          : %s", conf->time_server);
	verbose(level, "Interface            : %s", conf->network_device);
	verbose(level, "pcap sync input      : %s", conf->sync_in_pcap);
	verbose(level, "ascii sync input     : %s", conf->sync_in_ascii);
	verbose(level, "pcap sync output     : %s", conf->sync_out_pcap);
	verbose(level, "ascii sync output    : %s", conf->sync_out_ascii);
	verbose(level, "ascii clock output   : %s", conf->clock_out_ascii);
}
