
# Copyright (C) 2006-2010 Julien Ridoux <julien@synclab.org>
#
# This file is part of the radclock program.
# 
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <http://www.gnu.org/licenses/>.


lib_LTLIBRARIES = libradclock.la
include_HEADERS = radclock.h
noinst_HEADERS = local-genetlink.h logger.h radclock-private.h

libradclock_la_SOURCES = radapi-base.c radapi-getset.c radapi-time.c radapi-pcap.c logger.c radclock-read.c radkernel-linux.c radkernel-fbsd.c radkernel-none.c local-genetlink.h

libradclock_la_LIBADD = -lm
libradclock_la_LDFLAGS = -release $(PACKAGE_VERSION)

