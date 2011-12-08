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


/**
 * A stamp source that reads from An ASCII file
 */

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>

#include "../config.h" 
#include "sync_algo.h"
#include "config_mgr.h"
#include "verbose.h"
#include "create_stamp.h"
#include "stampinput.h"
#include "stampinput_int.h"
#include "jdebug.h"



#define NTPtoUTC_OFFSET  2272060800lu  // [sec] since NTP base epoch [current UNIX + 730 days = 2 years]
#define NTPtoUNIX_OFFSET 2208988800lu  // [sec] since NTP base epoch, currently!

#define ASCII_DATA(x) ((struct ascii_data *)(x->priv_data))



struct ascii_data
{
	FILE *fd;
};



/* Function to skip contiguous comment lines (comment char selectable)
 * Used to skip comment block heading ascii input files
 */
int skip_commentblock(FILE *fd, const char commentchar)
{ 
	int c;
	// see if first char of line is a comment
	while ((c=fgetc(fd))!=EOF && c==commentchar ){
		// skip to start of next line
		while ((fgetc(fd))!= '\n'){}
		//fprintf(stdout,"c line: \n");
	}
	if (c!=EOF) {
		// oops, first char wasn't a comment, push it back, it is the first data element
		c= ungetc(c,fd);   
	}
	return c;   // returns EOF if no data 
}



/** 
 * Open a timestamp file 
 */
static FILE* open_timestamp(char* sync_in_ascii) 
{
	FILE* stamp_fd = NULL;
	int ch;
	if ((stamp_fd = fopen(sync_in_ascii,"r")) == NULL) {
		verbose(LOG_ERR, "Open failed on preprocessed stamp input file- %s",sync_in_ascii);
		return NULL;
	} 

	if ((ch=skip_commentblock(stamp_fd,'%'))==EOF)        
		verbose(LOG_WARNING,"Stored ascii stamp file %s seems to be data free", sync_in_ascii);
	else
		verbose(LOG_NOTICE, "Reading from stored ascii stamp file %s", sync_in_ascii);
	return stamp_fd;
}

static int asciistamp_init(struct radclock *handle, struct stampsource *source)
{
	source->priv_data = (struct ascii_data *) malloc(sizeof(struct ascii_data));
	JDEBUG_MEMORY(JDBG_MALLOC, source->priv_data);
	if (!ASCII_DATA(source))
	{
		verbose(LOG_ERR, "Couldn't allocate memory");
		return -1;
	}
	// Timestamp file input
	if (strlen(handle->conf->sync_in_ascii) > 0) {
		// preprocessed ascii TS input available, assumed 4 column
		ASCII_DATA(source)->fd = open_timestamp(handle->conf->sync_in_ascii); 
		if (!ASCII_DATA(source)->fd)
		{
			return -1;
		}
	}
	return 0;
}

static int
asciistamp_get_next(struct radclock *handle, struct stampsource *source, struct stamp_t *stamp, uint64_t *stamp_id)
{
	FILE *stamp_fd = ASCII_DATA(source)->fd;

	if ( fscanf(stamp_fd,"%"VC_FMT" %Lf %Lf %"VC_FMT,
			 &(BST(stamp)->Ta), &(BST(stamp)->Tb), &(BST(stamp)->Te), &(BST(stamp)->Tf) ) == EOF ) {
		verbose(LOG_NOTICE, "Got EOF on ascii input file.");
		return -1;
	} 
	else {
		// skip to start of next line (robust to 5 or more column input)
		while((fgetc(stamp_fd))!= '\n'){} 

		// TODO: Do we still need to keep this ??
		// hack to convert old ascii files with NTP TSs to UNIX 
		if ( BST(stamp)->Te > NTPtoUNIX_OFFSET ) 
		{
			BST(stamp)->Tb -= NTPtoUNIX_OFFSET;
			BST(stamp)->Te -= NTPtoUNIX_OFFSET;
		}
		// TODO: need to detect stamp type, ie, get a better input format
		stamp->type = STAMP_NTP;
		stamp->qual_warning = 0;
		source->ntp_stats.ref_count+=2; 
	}
	*stamp_id = 0;
	return 0;
} 


static void asciistamp_breakloop(struct radclock *handle, struct stampsource *source)
{
	verbose(LOG_WARNING, "Call to breakloop in ascii replay has no effect");
	return;
}


static void asciistamp_finish(struct radclock *handle, struct stampsource *source)
{
	fclose(ASCII_DATA(source)->fd);
	JDEBUG_MEMORY(JDBG_FREE, ASCII_DATA(source));
	free(ASCII_DATA(source));
}

static int asciistamp_update_filter(struct radclock *handle, struct stampsource *source)
{
	/* So far this does nothing ...  */
	return 0;
}

static int asciistamp_update_dumpout(struct radclock *handle, struct stampsource *source)
{
	/* So far this does nothing ...  */
	return 0;
}

//This is externed elsehere
struct stampsource_def ascii_source =
{
	.init 				= asciistamp_init,
	.get_next_stamp 	= asciistamp_get_next,
	.source_breakloop 	= asciistamp_breakloop,
	.destroy 			= asciistamp_finish,
	.update_filter 		= asciistamp_update_filter,
	.update_dumpout 	= asciistamp_update_dumpout,
};
