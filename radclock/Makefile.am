#
# Copyright (C) 2006-2012, Julien Ridoux <julien@synclab.org>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


INCLUDES = -I$(top_srcdir)/libradclock/ -I$(ADD_INCLS)

noinst_HEADERS = \
		config_mgr.h \
		create_stamp.h \
		fixedpoint.h \
		misc.h \
		ntohll.h \
		pthread_mgr.h \
		proto_ntp.h \
		rawdata.h \
		stampinput.h \
		sync_algo.h \
		sync_history.h \
		verbose.h \
		jdebug.h

bin_PROGRAMS = radclock


radclock_SOURCES = \
		client_ntp.c \
		create_stamp.c \
		fixedpoint.c \
		config_mgr.c \
		rawdata.c \
		pthread_mgr.c \
		pthread_ntpserver.c \
		pthread_rawdata.c \
		pthread_trigger.c \
		radclock_main.c \
		stampinput.c \
		stampinput_int.h \
		stampinput-ascii.c \
		stampinput-livepcap.c \
		stampinput-tracefile.c \
		stampinput-spy.c \
		stampoutput.h \
		stampoutput.c \
		sync_bidir.c \
		sync_history.c \
		verbose.c \
		virtual_machine.c


# Make sure the radclock binary is linked statically
# Handy for not-installed runs
radclock_LDFLAGS = -static -pthread

# We want librt for an accurate NTP packet sender
radclock_LDADD = -lpcap -lm @LIBRADCLOCK_LIBS@

if MK_LIBRT
radclock_LDADD += -lrt
endif

if MK_XEN
radclock_LDADD += -lxenstore
endif
