#
# Copyright (C) 2006-2012 Julien Ridoux <julien@synclab.org>
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

INCLUDES = -I$(top_srcdir)/libradclock/ -I$(top_srcdir)/radclock/

check_PROGRAMS = test_timestamping test_shared_memory

test_timestamping_SOURCES = test_timestamping.c
test_timestamping_LDADD = @LIBRADCLOCK_LIBS@
test_timestamping_LDFLAGS = -static

test_shared_memory_SOURCES = test_shared_memory.c
test_shared_memory_LDADD = @LIBRADCLOCK_LIBS@
test_shared_memory_LDFLAGS = -static

