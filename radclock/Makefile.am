
# Copyright (C) 2006-2011 Julien Ridoux <julien@synclab.org>
#
# This file is part of the radclock program.
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.


INCLUDES = -I$(top_srcdir)/libradclock/ -I$(ADD_INCLS)

noinst_HEADERS = ntohll.h \
		 create_stamp.h \
		 proto_ntp.h \
		 sync_algo.h \
		 config_mgr.h \
		 pthread_mgr.h \
		 verbose.h \
		 rawdata.h \
		 fixedpoint.h \
		 ffclock.h \
		 sync_history.h \
		 jdebug.h


bin_PROGRAMS = radclock


radclock_SOURCES = sync_bidir.c \
		   sync_history.c \
		   fixedpoint.c \
		   ffclock-fbsd.c \
		   ffclock-linux.c \
		   ffclock-none.c \
		   create_stamp.c \
		   verbose.c \
		   config_mgr.c \
		   rawdata.c \
		   pthread_mgr.c \
		   pthread_ipcserver.c \
		   pthread_ntpserver.c \
		   pthread_rawdata.c \
		   pthread_trigger.c \
		   radclock_main.c \
		   stampinput.c \
		   stampinput.h \
		   stampinput_int.h \
		   stampinput-ascii.c \
		   stampinput-livepcap.c \
		   stampinput-tracefile.c \
		   stampinput-spy.c \
		   stampoutput.h \
		   stampoutput.c \
		   virtual_machine.c


# Make sure the radclock binary is linked statically
# Handy for not-installed runs
radclock_LDFLAGS = -static -pthread

# We want librt for an accurate NTP packet sender
radclock_LDADD = -lrt -lpcap -lm @LIBRADCLOCK_LIBS@ 

if HAVE_XEN_API 
radclock_LDADD += -lxenstore
else
radclock_LDADD +=
endif
