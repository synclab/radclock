
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

noinst_PROGRAMS = radclock_get_time radclock_capture_packet 

INCLUDES = -I$(top_srcdir)/radclock -I$(top_srcdir)/libradclock

radclock_get_time_SOURCES = radclock_get_time.c
radclock_get_time_LDADD = -lm @LIBRADCLOCK_LIBS@

radclock_capture_packet_SOURCES = radclock_capture_packet.c
radclock_capture_packet_LDADD = -lpcap -lm  @LIBRADCLOCK_LIBS@

