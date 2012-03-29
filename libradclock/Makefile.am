
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

if MAKE_RADKERNEL_FBSD
libradclock_la_SOURCES += \
		radkernel-fbsd.c \
		kclock-fbsd.c \
		pcap-fbsd.c
else
if MAKE_RADKERNEL_LINUX
libradclock_la_SOURCES += \
		radkernel-linux.c \
		kclock-linux.c \
		pcap-linux.c
else
if MAKE_RADKERNEL_NONE
libradclock_la_SOURCES += \
		radkernel-none.c \
		kclock-none.c \
		pcap-none.c
endif
endif
endif

libradclock_la_LIBADD = -lm
libradclock_la_LDFLAGS = -release $(PACKAGE_VERSION)

