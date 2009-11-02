#!/usr/bin/env python

# Copyright (C) 2006-2009 Julien Ridoux <julien@synclab.org>
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



import time

import radclock

clock = radclock.radclock()
print 'Created a radclock instance'

vcount = clock.get_vcounter()
print 'Read vcount = %d' %(vcount)


rad_time = clock.gettimeofday_fp()
sys_time = time.time()
print 'rad_time = %.9f - sys_time = %.9f' %(rad_time, sys_time)

time.sleep(1)

rad_time = clock.gettimeofday_fp()
sys_time = time.time()
print 'rad_time = %.9f - sys_time = %.9f' %(rad_time, sys_time)


period 			= clock.get_period()
offset 			= clock.get_offset()
period_error 	= clock.get_period_error()
offset_error 	= clock.get_offset_error()
clockerror 		= clock.get_clockerror()
last_stamp 		= clock.get_last_stamp()
till_stamp 		= clock.get_till_stamp()
status 			= clock.get_status()

print 'period \t\t= %.9g (error = %.9g)' %(period, period_error)
print 'offset \t\t= %.9g (error = %.9g)' %(offset, offset_error)
print 'clockerror \t= %.9g ' %(clockerror)
print 'last_stamp \t= %d - till_stamp = %d' %(last_stamp, till_stamp)
print 'status \t\t= %x' %status



