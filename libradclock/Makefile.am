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

lib_LTLIBRARIES = libradclock.la
include_HEADERS = radclock.h
noinst_HEADERS = local-genetlink.h logger.h radclock-private.h kclock.h

libradclock_la_SOURCES = \
		radapi-base.c \
		radapi-getset.c \
		radapi-time.c \
		radapi-pcap.c \
		radclock-read.c \
		logger.c \
		local-genetlink.h

if MK_FFKERNEL_FBSD
libradclock_la_SOURCES += \
		ffkernel-fbsd.c \
		kclock-fbsd.c \
		pcap-fbsd.c
else
if MK_FFKERNEL_LINUX
libradclock_la_SOURCES += \
		ffkernel-linux.c \
		kclock-linux.c \
		pcap-linux.c
else
if MK_FFKERNEL_NONE
libradclock_la_SOURCES += \
		ffkernel-none.c \
		kclock-none.c \
		pcap-none.c
endif
endif
endif

libradclock_la_LIBADD = -lm
libradclock_la_LDFLAGS = -release $(PACKAGE_VERSION)
