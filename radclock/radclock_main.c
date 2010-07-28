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



// TODO we probably don't need all these includes anymore

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <signal.h>
#include <sched.h>

#include <syslog.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include <string.h>
#include <math.h> 
#include <time.h> 

#include "../config.h"
#include "radclock.h"
#include "radclock-private.h"
#include "logger.h"
#include "verbose.h"
#include "sync_algo.h"
#include "create_stamp.h"
#include "config_mgr.h"
#include "pthread_mgr.h"
#include "rawdata.h"
#include "stampinput.h"
#include "stampoutput.h"
#include "proto_ntp.h"
#include "jdebug.h"


/* Defines specific to the main program */
#define DAEMON_LOCK_FILE ( RADCLOCK_RUN_DIRECTORY "/radclock.pid" )



/* Globals */

/* RADclock handler */ 
struct radclock *clock_handle;

/* Verbose data contains pthread_mutex */
extern struct verbose_data_t verbose_data;

/* Debug */
#ifdef WITH_JDEBUG
long int jdbg_memuse = 0;
struct rusage jdbg_rusage;
#endif






/*************************** Helper Routines ******************************/

/*** Guide to input parameters of radclock ***/
void usage(char *argv) {
	fprintf(stderr, "%s \n"
		"\t\t-x do not serve radclock time/data (IOCTL / Netlink socket to kernel, IPC to processes)\n"
		"\t\t-d run as a daemon\n"
		"\t\t-i <interface>\n"
		"\t\t-n <hostname> we, the host sending queries\n"
		"\t\t-t <hostname> the timeserver replying to queries\n"
		"\t\t-p <poll_period> [sec] default is DEFAULT_NTP_POLL_PERIOD=16\n" 
		"\t\t-l do not use local rate refinement\n"
		"\t\t-r <filename> read sync input from pcap file (\"-\" for stdin)\n"
		"\t\t-s <filename> read sync input from ascii file (header comments and extra columns skipped)\n"
		"\t\t-w <filename> write sync output to file (modified pcap format)\n"
		"\t\t-a <filename> write sync output to file (ascii)\n"
		"\t\t-o <filename> write clock data output to file (ascii)\n"
		"\t\t-v -vv verbose\n"
		"\t\t-h this help mesage\n"
		, argv);
	exit(EXIT_SUCCESS);
}









/*-------------------------------------------------------------------------*/
/************************ Daemon(-like) Routines ***************************/
/*-------------------------------------------------------------------------*/

/** 
 * Reparse the configuration file when receiving SIGHUP 
 * Reason for most of the global variables
 */
int rehash_daemon(struct radclock *clock_handle, 
				  u_int32_t param_mask) 
{
	/* The update of the following parameters either requires no action, 
	 * or it has to be handled by the algo only: 
	 * UPDMASK_DELTA_HOST 
	 * UPDMASK_DELTA_NET 
	 * UPDMASK_POLLPERIOD 
	 * UPDMASK_PLOCAL 
	 * UPDMASK_TEMPQUALITY 
	 * UPDMASK_VERBOSE
	 * UPDMASK_ADJUST_SYSCLOCK
	*/

// TODO : Reload of individual physical parameters is not handled


	struct radclock_config *conf;
	conf = clock_handle->conf;

	verbose(LOG_NOTICE, "Update of configuration parameters");
	/* Parse the configuration file */
	if ( !(config_parse(conf, &param_mask, clock_handle->is_daemon)) ) {
		verbose(LOG_ERR, "Error: Rehash of configuration file failed");
		return 1;
	}
	
	if ( HAS_UPDATE(param_mask, UPDMASK_SYNCHRO_TYPE) )
	{
		verbose(LOG_WARNING, "It is not possible to change the type of client synchronisation on the fly!");
	}
	
	// TODO XXX TODO 	
	if ( HAS_UPDATE(param_mask, UPDMASK_VIRTUAL_MACHINE) )
	{
		verbose(LOG_WARNING, "It is not possible to change the virtual machine environment on the fly!");
	}
	 
	//XXX Should check we have only one input selected 	
	if ( HAS_UPDATE(param_mask, UPDMASK_NETWORKDEV)
	  || HAS_UPDATE(param_mask, UPDMASK_SYNC_IN_PCAP)
	  || HAS_UPDATE(param_mask, UPDMASK_SYNC_IN_ASCII) 
	  )
	{
		verbose(LOG_WARNING, "It is not possible to change the type of input on the fly!");
		verbose(LOG_WARNING, "Parameter is parsed and saved but not taken into account");
		CLEAR_UPDATE(param_mask, UPDMASK_NETWORKDEV);
		CLEAR_UPDATE(param_mask, UPDMASK_SYNC_IN_PCAP);
		CLEAR_UPDATE(param_mask, UPDMASK_SYNC_IN_ASCII);
	}

	if ( HAS_UPDATE(param_mask, UPDMASK_SERVER_IPC) ) {
		switch ( conf->server_ipc ) {
			case BOOL_ON:
				/* We start serving global data */
				clock_handle->ipc_mode = RADCLOCK_IPC_SERVER;
				start_thread_IPC_SERV(clock_handle);
				break;
			case BOOL_OFF:
				/* We stop serving global data */
				clock_handle->ipc_mode = RADCLOCK_IPC_NONE;
				clock_handle->pthread_flag_stop |= PTH_IPC_SERV_STOP; 
	//TODO should we join the thread in here ... requires testing
		//	pthread_join(clock_handle->threads[PTH_IPC_SERV], &thread_status);
				close(clock_handle->ipc_socket);
				break;
		}
	}
	
	if ( HAS_UPDATE(param_mask, UPDMASK_SERVER_NTP) ) {
		switch( conf->server_ntp) {
			case BOOL_ON:	
				/* We start NTP server */
				start_thread_NTP_SERV(clock_handle);
				break;
			case BOOL_OFF:
				/* We stop the NTP server */
				clock_handle->pthread_flag_stop |= PTH_NTP_SERV_STOP; 
	//TODO should we join the thread in here ... requires testing
	//			pthread_join(clock_handle->threads[PTH_NTP_SERV], &thread_status);
				break;
		}
	}


	/* Management of output files */
	if ( HAS_UPDATE(param_mask, UPDMASK_SYNC_OUT_ASCII) )
	{
		close_output_stamp(clock_handle);
		open_output_stamp(clock_handle);
		CLEAR_UPDATE(param_mask, UPDMASK_SYNC_OUT_ASCII);
	}	
	if ( HAS_UPDATE(param_mask, UPDMASK_CLOCK_OUT_ASCII) )
	{
		close_output_matlab(clock_handle);
		open_output_matlab(clock_handle);
		CLEAR_UPDATE(param_mask, UPDMASK_CLOCK_OUT_ASCII);
	}
	if ( HAS_UPDATE(param_mask, UPDMASK_SYNC_OUT_PCAP) )
	{
		if ( update_dumpout_source(clock_handle, (struct stampsource *)clock_handle->stamp_source) != 0) {
			verbose(LOG_ERR, "Things are probably out of control. Bye !");
			exit (1);
		}
		CLEAR_UPDATE(param_mask, UPDMASK_SYNC_OUT_PCAP);
	}


	/* Change the filter on the open BPF device */ 
	if ( HAS_UPDATE(param_mask, UPDMASK_SYNCHRO_TYPE)
	  || HAS_UPDATE(param_mask, UPDMASK_SERVER_NTP)
	  || HAS_UPDATE(param_mask, UPDMASK_TIME_SERVER)
	  || HAS_UPDATE(param_mask, UPDMASK_HOSTNAME) )
	{
		if ( update_filter_source(clock_handle, (struct stampsource *)clock_handle->stamp_source) != 0 )  {
			verbose(LOG_ERR, "Things are probably out of control. Bye !");
			exit (1);
		}
		CLEAR_UPDATE(param_mask, UPDMASK_TIME_SERVER);
		CLEAR_UPDATE(param_mask, UPDMASK_HOSTNAME);
	}

	/*  Print configuration actually used */
	config_print(LOG_NOTICE, conf);

	/* Reinit rehash flag */
//	clock_handle->unix_signal = 0;

	/* Push param_mask into the config so that the algo sees it, 
	 * since only algo related thing should be remaining
	 */
	conf->mask = param_mask;

	return 0;
}




void logger_verbose_bridge(int level, char *msg)
{
	switch (level)
	{
	case RADLOG_ERR:
		verbose(LOG_ERR, msg);
		break;
	case RADLOG_WARNING:
		verbose(LOG_WARNING, msg);
		break;
	case RADLOG_NOTICE:
		verbose(LOG_NOTICE, msg);
		break;
	}
}


/** 
 * Signal handler function 
 */
void signal_handler(int sig) 
{
	switch(sig){
		case SIGHUP:
			// TODO fix this commment
			/* We caught a SIGHUP, if the algo is processing data, we delay the
			 * configuration update to keep data consistent. 
			 * Other possiblity is that we are blocked on pcap capture function. We then 
			 * force leaving the blocking state and the capture exit with a specific error
			 * code to goto rehash call.
			 * Warning: this is valid as long as the pcap capture and pcap_breakloop calls
			 * are made from the same thread. If we fork the capture loop from the main(),
			 * this will not work anymore. See man pcap_breakloop
			 */ 
			clock_handle->unix_signal = SIGHUP;
			source_breakloop(clock_handle, (struct stampsource *)clock_handle->stamp_source);
			verbose(LOG_NOTICE, "SIGHUP scheduled after packet processing.");
			break;

		case SIGTERM:
			/* First of all raise our exit flag and break loop (blocking
			 * function for live input
			 */
			clock_handle->unix_signal = SIGTERM;
			source_breakloop(clock_handle, (struct stampsource *)clock_handle->stamp_source);
			break;		

		case SIGUSR1:
			/* user signal 1 */
			verbose(LOG_NOTICE, "SIGUSR1 received, closing log file.");
			if ( verbose_data.logfile != NULL)
			{
				pthread_mutex_lock( &(verbose_data.vmutex) );
				fclose(verbose_data.logfile);
				verbose_data.logfile = NULL;
				pthread_mutex_unlock( &(verbose_data.vmutex) );
			}
			break;		

		case SIGUSR2:
			/* user signal 2 */
			break;		
	}	
}





/** Function that fork the process and creates the running daemon */
int daemonize(char* lockfile, int *daemon_pid_fd) 
{
	/* Scheduler */
	struct sched_param sched;

	/* Process ID, Session ID, Lock file */ 
	pid_t pid, sid;
	char* str = (char*) malloc(20 * sizeof(char));
	JDEBUG_MEMORY(JDBG_MALLOC, str);

	/* If already a daemon */ 
	if( getppid() == 1 ) {
		verbose(LOG_NOTICE, "Already a daemon");	
		return 0; 
	}

	/* Fork off the parent process */
	pid = fork();
	if (pid < 0) {
		exit(EXIT_FAILURE);
	}

	/* If we got a good PID, then we can exit the parent process. */
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	/* Change the file mode mask to the complement of mode 750 */
	umask(027);
			
	/* Open any logs here. Allow all levels */
	setlogmask (LOG_UPTO (LOG_DEBUG));
	openlog ("radclock ", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_DAEMON);

	/* Create a new SID for the child process */
	sid = setsid();
	if (sid < 0) {
		syslog (LOG_ERR, "sid error");
		exit(EXIT_FAILURE);
	}
	
	/* Change the current working directory */
	if ((chdir("/")) < 0) {
		/* Log the failure */
		syslog (LOG_ERR, "chdir error");
		exit(EXIT_FAILURE);
	}
	
	/* Mutual exclusion of concurrent daemons */
	*daemon_pid_fd = open(lockfile, O_RDWR|O_CREAT, 0640);

	if (*daemon_pid_fd < 0) {
		verbose(LOG_ERR, "Cannot open lock file");
		exit(EXIT_FAILURE);
	}

	/* The first instance locks the pid file */
	if ( lockf(*daemon_pid_fd, F_TLOCK,0) < 0) {
		verbose(LOG_ERR, "Cannot lock. Another instance of the daemon should be running");
	   	exit(EXIT_FAILURE);
	}

   	/* Record pid to lockfile (write is a no buffering function) */
	sprintf(str, "%d\n", getpid());
	write(*daemon_pid_fd, str, strlen(str));

	/* Close out the standard file descriptors */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);


	/* Boost our scheduler priority. Here I assume we have access to the 
	 * Posix scheduling API ... and if not?
	 */
	sched.sched_priority = sched_get_priority_max(SCHED_FIFO);
	if ( sched_setscheduler(0, SCHED_FIFO, &sched) == -1 )
		verbose(LOG_ERR, "Could not set scheduler priority");

	JDEBUG_MEMORY(JDBG_FREE, str);
	free(str);
	return 1;
}




/*
 * radclock process specific init of the clock_handle
 */
// TODO should extract the similar ones from the library to clean up the mess
int radclock_init_specific (struct radclock *clock_handle) 
{
	int err;

	JDEBUG

	err = init_virtual_machine_mode(clock_handle);
	if (err < 0)
		return -1;

	return 0;
}




/*-------------------------------------------------------------------------*/
/********************************* main ************************************/
/*-------------------------------------------------------------------------*/

int main (int argc, char *argv[]) 
{
	/* File and command line reading */
	int ch;
	
	/* Mask variable used to know which parameter to update */
	u_int32_t param_mask	= 0;

	/* PID lock file for daemon */
	int daemon_pid_fd 		= 0;

	/* Run mode for the algo. Default is kernel mode */
	radclock_runmode_t run_mode = RADCLOCK_RUN_KERNEL;

	/* Threads */
	void* thread_status;

	/* Input source */
	struct stampsource *stamp_source;

	/* Misc */
	int err;


	/* turn off buffering to allow results to be seen immediately if JDEBUG*/
	#ifdef WITH_JDEBUG
	setvbuf(stdout, (char *)NULL, _IONBF, 0);
	setvbuf(stderr, (char *)NULL, _IONBF, 0);
	#endif

	/* Register Signal handlers 
	 * We use sigaction() instead of signal() to catch signals. The main reason 
	 * concerns the SIGHUP signal. In Linux, the syscalls are restarted as soon
	 * as the signal handler returns. This prevent pcap_breakloop() to do its job 
	 * (see pcap man page). Using sigaction() we can overwrite the default flag to
	 * prevent this behavior
	 */
	sigset_t block_mask;
	sigfillset (&block_mask);
	struct sigaction sig_struct;
	sig_struct.sa_handler 	= signal_handler;
	sig_struct.sa_mask 		= block_mask;
	sig_struct.sa_flags 	= 0;
	
	sigaction(SIGHUP,  &sig_struct, NULL); /* hangup signal (1) */
	sigaction(SIGTERM, &sig_struct, NULL); /* software termination signal (15) */
	sigaction(SIGUSR1, &sig_struct, NULL); /* user signal 1 (30) */
	sigaction(SIGUSR2, &sig_struct, NULL); /* user signal 2 (31) */


	/* Initialise verbose data to defaults */
 	verbose_data.clock = NULL;
 	verbose_data.is_daemon = 0;
 	verbose_data.verbose_level = 0;
 	verbose_data.logfile = NULL;
	pthread_mutex_init(&(verbose_data.vmutex), NULL);


	/* Create the global data handle */
	clock_handle = radclock_create();
	if (!clock_handle) {
		verbose(LOG_ERR, "Could not create clock handle");
		return -1;
	}

	/* Quite a few structure of the clock handler are not used by the clients of
	 * the radclock daemon and are then not initialised before.
	 * Here we allocate memory for them. Maybe all of this should be put in a
	 * daemon specific function.
	 */
	clock_handle->conf = (struct radclock_config *) malloc(sizeof(struct radclock_config));
	JDEBUG_MEMORY(JDBG_MALLOC, clock_handle->conf);

	clock_handle->client_data = (struct radclock_client_data*) malloc(sizeof(struct radclock_client_data));
	JDEBUG_MEMORY(JDBG_MALLOC, clock_handle->client_data);

	clock_handle->server_data = (struct radclock_ntpserver_data*) malloc(sizeof(struct radclock_ntpserver_data));
	JDEBUG_MEMORY(JDBG_MALLOC, clock_handle->server_data);

	clock_handle->algo_output = (void*) malloc(sizeof(struct bidir_output));
	JDEBUG_MEMORY(JDBG_MALLOC, clock_handle->algo_output);

	memset(clock_handle->conf, 0, sizeof(struct radclock_config));
	memset(clock_handle->client_data, 0, sizeof(struct radclock_client_data));
	memset(clock_handle->server_data, 0, sizeof(struct radclock_ntpserver_data));
	memset(clock_handle->algo_output, 0, sizeof(struct bidir_output));

	/* Set 8 burst packets at startup for the NTP client (just like ntpd) */
	clock_handle->server_data->burst = NTP_BURST;

	/* Initialise with unspect stratum */
	SERVER_DATA(clock_handle)->stratum = STRATUM_UNSPEC;
  
	/*** Management of configuration options *****/
	// The command line arguments are given the priority and override possible
	// values of the configuration file
	// But the configuration file is parsed after the command line because we need
	// to know if we are running a daemon or not (configuration file is different if
	// we run a daemon or not). Use the param_mask variable to indicate which values
	// have to be updated from the config file


	/* Initialize the physical parameters, and other config parameters. */
	config_init(clock_handle->conf);

	/* Init the mask we use to signal configuration updates */
	param_mask = UPDMASK_NOUPD;

	/* Reading the command line arguments */     
	while ((ch = getopt(argc, argv, "dxvhli:n:t:r:w:s:a:o:p:")) != -1)
		switch (ch) {
			case 'x':
				SET_UPDATE(param_mask, UPDMASK_SERVER_IPC);
				clock_handle->conf->server_ipc = 0;
				break;
			case 'd':
				clock_handle->is_daemon = 1;
				break;
			case 'p':
				SET_UPDATE(param_mask, UPDMASK_POLLPERIOD);
				if ( atoi(optarg) < RAD_MINPOLL )
				{
					clock_handle->conf->poll_period = RAD_MINPOLL;
					fprintf(stdout, "Warning: Poll period too small, set to %d\n",
						   	clock_handle->conf->poll_period);
				}
				else
					clock_handle->conf->poll_period = atoi(optarg);
				if ( clock_handle->conf->poll_period > RAD_MAXPOLL )
				{
					clock_handle->conf->poll_period = RAD_MAXPOLL;
					fprintf(stdout, "Warning: Poll period too big, set to %d\n",
						   	clock_handle->conf->poll_period);
				}
				break;
			case 'l':
				SET_UPDATE(param_mask, UPDMASK_PLOCAL);
				clock_handle->conf->start_plocal = 0;
				break;
			case 'n':
				if (strlen(optarg) > MAXLINE) {
					fprintf(stdout, "ERROR: parameter too long\n");
					exit (1);
				}
				SET_UPDATE(param_mask, UPDMASK_HOSTNAME);
				strcpy(clock_handle->conf->hostname, optarg);
				break;
			case 't':
				if (strlen(optarg) > MAXLINE) {
					fprintf(stdout, "ERROR: parameter too long\n");
					exit (1);
				}
				SET_UPDATE(param_mask, UPDMASK_TIME_SERVER);
				strcpy(clock_handle->conf->time_server, optarg);
				break;
			case 'i':
				if (strlen(optarg) > MAXLINE) {
					fprintf(stdout, "ERROR: parameter too long\n");
					exit (1);
				}
				SET_UPDATE(param_mask, UPDMASK_NETWORKDEV);
				strcpy(clock_handle->conf->network_device, optarg);
				break;
			case 'r':
				if (strlen(optarg) > MAXLINE) {
					fprintf(stdout, "ERROR: parameter too long\n");
					exit (1);
				}
				SET_UPDATE(param_mask, UPDMASK_SYNC_IN_PCAP);
				strcpy(clock_handle->conf->sync_in_pcap, optarg);
				break;
			case 'w':
				if (strlen(optarg) > MAXLINE) {
					fprintf(stdout, "ERROR: parameter too long\n");
					exit (1);
				}
				SET_UPDATE(param_mask, UPDMASK_SYNC_OUT_PCAP);
				strcpy(clock_handle->conf->sync_out_pcap, optarg);
				break;
			case 's':
				if (strlen(optarg) > MAXLINE) {
					fprintf(stdout, "ERROR: parameter too long\n");
					exit (1);
				}
				SET_UPDATE(param_mask, UPDMASK_SYNC_IN_ASCII);
				strcpy(clock_handle->conf->sync_in_ascii, optarg);
				break;             
			case 'a':
				if (strlen(optarg) > MAXLINE) {
					fprintf(stdout, "ERROR: parameter too long\n");
					exit (1);
				}
				SET_UPDATE(param_mask, UPDMASK_SYNC_OUT_ASCII);
				strcpy(clock_handle->conf->sync_out_ascii, optarg);
				break;
			case 'o':
				if (strlen(optarg) > MAXLINE) {
					fprintf(stdout, "ERROR: parameter too long\n");
					exit (1);
				}
				SET_UPDATE(param_mask, UPDMASK_CLOCK_OUT_ASCII);
				strcpy(clock_handle->conf->clock_out_ascii, optarg);
				break;
			case 'v':
				SET_UPDATE(param_mask, UPDMASK_VERBOSE);
				clock_handle->conf->verbose_level++;
				break;
			case 'h':
			case '?':
			default:
				usage(argv[0]);
		}

	argc -= optind;
	argv += optind;

	/* Little hack to deal with the parsing of long options in the command line */
	if (clock_handle->conf->verbose_level > 0)
		SET_UPDATE(param_mask, UPDMASK_VERBOSE);
	
	/* Have not parsed the config file yet, so will have to do it again since it
	 * may not be the right settings. Handles config parse messages in the right
	 * log file though. So far clock has not been sent to init, no syscall
	 * registered, pass a NULL pointer to verbose.
	 */
	set_verbose(NULL, clock_handle->is_daemon, clock_handle->conf->verbose_level);
	set_logger(logger_verbose_bridge);
	
	/* Daemonize now, so that we can open the log files and close connection to
	 * stdin since we parsed the command line
	 */
	if (clock_handle->is_daemon) {
		struct stat sb;
		if (stat(RADCLOCK_RUN_DIRECTORY, &sb) < 0) {
			if (mkdir(RADCLOCK_RUN_DIRECTORY, 0755) < 0) { 
				verbose(LOG_ERR, "Cannot create %s directory. Run as root or (!daemon && !server)", RADCLOCK_RUN_DIRECTORY);
				return 1;
			}
		}
		/* Check this everytime in case something happened */
		chmod(RADCLOCK_RUN_DIRECTORY, 00755);

		if ( !(daemonize(DAEMON_LOCK_FILE, &daemon_pid_fd)) ) {
			fprintf(stderr, "Error: did not manage to create the daemon\n");
			exit(EXIT_FAILURE);
		}
	}

	/* Retrieve configuration from the config file (write it down if it does not exist) 
	 * That should be the only occasion when get_config() is called and the param_mask
	 * is not positioned to UPDMASK_NOUPD !!!  Only the parameters not specified on 
	 * the command line are updated 
	 */
	if ( !config_parse(clock_handle->conf, &param_mask, clock_handle->is_daemon) )
		return 0; 


	/* Now that we have the configuration to use (verbose level),  let's initialise the 
	 * verbose level to correct value
	 */
	set_verbose(NULL, clock_handle->is_daemon, clock_handle->conf->verbose_level);
	set_logger(logger_verbose_bridge);

	/* Check for incompatible configurations and correct them */
	if ( clock_handle->conf->synchro_type == TRIGGER_PIGGY )
	{
		if ( clock_handle->conf->server_ntp == BOOL_ON )
		{
			verbose(LOG_ERR, "Configuration error. Disabling NTP server (incompatible with piggybacking mode).");
			clock_handle->conf->server_ntp = BOOL_OFF;
		}
		if ( clock_handle->conf->adjust_sysclock == BOOL_ON )
		{
			verbose(LOG_ERR, "Configuration error. Disabling adjust system clock (incompatible with piggybacking mode).");
			clock_handle->conf->adjust_sysclock = BOOL_OFF;
		}
	}

	/* Diagnosis output for the configuration used */
	config_print(LOG_NOTICE, clock_handle->conf);
	
	/* Reinit the mask that counts updated values */
	param_mask = UPDMASK_NOUPD;

	/* Need to know if we are replaying data or not. If not, no need to create
	 * shared global data on the system or open a BPF. This define input to the
	 * init of the radclock handle
	 */
	if (!is_live_source(clock_handle)) {
		run_mode = RADCLOCK_RUN_DEAD;
	}
	clock_handle->run_mode = run_mode;

	/* Manually signal we are the radclock algo and that we have to serve global data to the
	 * kernel and other processes throught the IPC socket.
	 */
	if ( clock_handle->conf->server_ipc && is_live_source(clock_handle))
		clock_handle->ipc_mode = RADCLOCK_IPC_SERVER;
	else
		clock_handle->ipc_mode = RADCLOCK_IPC_NONE;

	/* Init clock handle and private data */
	if (radclock_init(clock_handle))
	{
		verbose(LOG_ERR, "Could not initialise the RADclock");
		return 1;
	}


// XXX TODO XXX work in progress in here, should extract radclock only init from
// the library ... 
	if (radclock_init_specific(clock_handle))
	{
		verbose(LOG_ERR, "Radclock process specific init failed.");
		return 1;
	}




	/* Initial status words */
	// TODO there should be more set in here
	ADD_STATUS(clock_handle, STARAD_STARVING);
	
	
	/* Clock has been init', set the pointer to the clock */
	set_verbose(clock_handle, clock_handle->is_daemon, clock_handle->conf->verbose_level);
	set_logger(logger_verbose_bridge);

	/* Create directory to store pid lock file and ipc socket */
	if (  (clock_handle->ipc_mode == RADCLOCK_IPC_SERVER) 
				|| (clock_handle->is_daemon) ) 
		{
		struct stat sb;
		if (stat(RADCLOCK_RUN_DIRECTORY, &sb) < 0) {
			if (mkdir(RADCLOCK_RUN_DIRECTORY, 0755) < 0) { 
				verbose(LOG_ERR, "Cannot create %s directory. Run as root or (!daemon && !server)",
					   	RADCLOCK_RUN_DIRECTORY);
				return 1;
			}
		}
	}

	/* Open input file from which to read TS data */   
	stamp_source = create_source(clock_handle);
	if (!stamp_source)
	{
		verbose(LOG_ERR, "Error creating stamp source, exiting");
		exit(EXIT_FAILURE);
	}
	/* Hang stamp source on the handler */
	clock_handle->stamp_source = (void *) stamp_source;
	

	/* Open output files */ 
	open_output_stamp(clock_handle);
	open_output_matlab(clock_handle);


	/* Now 2 cases. Either we are running live or we are replaying some data.
	 * If we run live, we will spawn some threads and do some smart things.
	 * If we replay data, no need to do all of that, we access data and process
	 * it in the same thread.
	 */

	if (clock_handle->run_mode == RADCLOCK_RUN_DEAD)
	{
		struct bidir_peer peer;
		// TODO XXX Need to manage peers better !!
		/* Register active peer */
		clock_handle->active_peer = (void*) &peer;
		
		peer.stamp_i = 0;
		while (1)
		{
			err = process_rawdata(clock_handle, &peer);
			if (err)
				break;
		}
	}
	else
	{
		/* We loop in here in case we are rehashed. Threads are (re-)created
		 * every time we loop in
		*/
		while (1)
		{

			/* Handle first time run. If no time_server specified while we
			 * produce packets, we would be a nasty CPU hog. Better avoid
			 * creating problems and exit with an error message
			 */
			if (	(clock_handle->conf->synchro_type == TRIGGER_NTP)
				||	(clock_handle->conf->synchro_type == TRIGGER_1588) ) 
			{
				if ( strlen(clock_handle->conf->time_server) == 0)
				{
					verbose(LOG_ERR, "No time server specified on command line or configuration file, attempting suicide.");
					break;
				}
			}

			/* This thread triggers the processing of data. It could be a dummy
			 * sleeping loop, an NTP client, a 1588 slave  ...
			 */
			err = start_thread_TRIGGER(clock_handle);
			if (err < 0)
				return 1;
			
			/* This thread is in charge of processing the raw data collected,
			 * magically transform the data into stamps and give them to the
			 * sync algo for processing.
			 */
			if ( clock_handle->unix_signal == SIGHUP )
			{
				/* This is not start, but HUP, the algo thread is still running
				 * Simply clear the flag and bypass
				 */
				clock_handle->unix_signal = 0;
			}
			else
			{
				err = start_thread_DATA_PROC(clock_handle);
				if (err < 0)
					return 1;
			}
			
			/* Are we serving some data to other processes and update the
			 * clock globaldata in the kernel?
			 */
			if (clock_handle->ipc_mode == RADCLOCK_IPC_SERVER) 
			{
				err = start_thread_IPC_SERV(clock_handle);
				if (err < 0) 	return 1;
			}
			
			/* Are we running an NTP server for network clients ? */
			switch (clock_handle->conf->server_ntp) {
				case BOOL_ON:
					err = start_thread_NTP_SERV(clock_handle);
					if (err < 0) 	return 1;
					break;
				case BOOL_OFF:
				default:
					/* do nothing */
					break;
			}

	
			/* To be able to provide the RADCLOCK timestamping
			 * mode, we need to refresh the fixed point data in the kernel.
			 * That's this guy's job.
			 */
			if ( (clock_handle->run_mode != RADCLOCK_RUN_DEAD) && (clock_handle->ipc_mode == RADCLOCK_IPC_SERVER) ) {
				err = start_thread_FIXEDPOINT(clock_handle);
				if (err < 0) 	return 1;
			}

			/* That's our main capture loop, it does not return until the end of
			 * input of we explicitely break it
			 */
			err = capture_raw_data(clock_handle);

			if (err ==  -1) {
				/* Yes, we abuse this a bit ... */
				clock_handle->unix_signal = SIGTERM;
				verbose(LOG_NOTICE, "Reached end of input");
			}
			if (err == -2) {
				verbose(LOG_NOTICE, "Breaking current capture loop for rehash");
			}


			/* pcap_break_loop() has been called or end of input. In both cases kill
			 * the threads. If we rehash, they will be restarted anyway.
			 */
			verbose(LOG_NOTICE, "Send killing signal to threads. Wait for stop message.");

			clock_handle->pthread_flag_stop = PTH_STOP_ALL;
			
			/* Do not stop sync algo thread if we HUP */
			if (clock_handle->unix_signal == SIGHUP)
				clock_handle->pthread_flag_stop &= ~PTH_DATA_PROC_STOP;

			if (clock_handle->conf->server_ntp == BOOL_ON) {
				pthread_join(clock_handle->threads[PTH_NTP_SERV], &thread_status);
				verbose(LOG_NOTICE, "NTP server thread is dead.");
			}
			if (clock_handle->conf->server_ipc == BOOL_ON) {
				pthread_join(clock_handle->threads[PTH_IPC_SERV], &thread_status);
				verbose(LOG_NOTICE, "IPC thread is dead.");
			}
			pthread_join(clock_handle->threads[PTH_TRIGGER], &thread_status);
			verbose(LOG_NOTICE, "Trigger thread is dead.");
			pthread_join(clock_handle->threads[PTH_FIXEDPOINT], &thread_status);
			verbose(LOG_NOTICE, "Kernel fixedpoint thread is dead.");
			
			/* Join on TERM since algo has been told to die */
			if (clock_handle->unix_signal != SIGHUP) 
			{
				pthread_join(clock_handle->threads[PTH_DATA_PROC], &thread_status);
				verbose(LOG_NOTICE, "Data processing thread is dead.");
				/* Reinitialise flags */
				clock_handle->pthread_flag_stop = 0;
				verbose(LOG_NOTICE, "Threads are dead.");
				/* We received a SIGTERM, we exit the loop. */
				break;
			}
			else
			{
				clock_handle->pthread_flag_stop = 0;
				if ( rehash_daemon(clock_handle, param_mask) )
					verbose(LOG_ERR, "SIGHUP - Failed to rehash daemon !!.");
			}

		}
		/* End of thread while loop */
	} /* End of run live case */

	long int n_stamp;    
	n_stamp = ((struct bidir_output *)clock_handle->algo_output)->n_stamps;
	verbose(LOG_NOTICE, "%u NTP packets captured", stampsource_get_stats(clock_handle, stamp_source)->ref_count);
	verbose(LOG_NOTICE,"%ld missed NTP packets",
			stampsource_get_stats(clock_handle, stamp_source)->ref_count-2*n_stamp);
	verbose(LOG_NOTICE, "%ld valid timestamp tuples extracted", n_stamp);

	/* Close output files */
	close_output_stamp(clock_handle);

	/* Print out last good phat value */
	verbose(LOG_NOTICE, "Last estimate of the clock source period: %12.10lg", GLOBAL_DATA(clock_handle)->phat);
	

	// TODO:  all the destructors have to be re-written
	destroy_source(clock_handle, stamp_source);
	radclock_destroy(clock_handle);
	
	/* Say bye and close syslog */
	verbose(LOG_NOTICE, "RADclock stopped");
	if ( clock_handle->is_daemon ) {
		closelog ();
	}
	unset_verbose();

	/* Free the lock file */
	if ( clock_handle->is_daemon ) {
		write(daemon_pid_fd, "", 0);
		lockf(daemon_pid_fd, F_ULOCK, 0);
	}
	
	exit(EXIT_SUCCESS);
}

