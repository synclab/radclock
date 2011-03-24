
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

from distutils.core import setup, Extension
import os, re


OS_LINUX 	= 'Linux'
OS_FREEBSD 	= 'FreeBSD'

os_uname = os.uname()
OS = os_uname[0] 



module_radclock_linux = Extension('radclock', 
		include_dirs = ['../libradclock'],
		libraries = ['radclock', 'nl'],
		library_dirs = ['/usr/local/lib'],
		sources = [ 'radclockmodule.c' ]
		)

module_radclock_freebsd = Extension('radclock', 
		include_dirs = ['../libradclock'],
		libraries = ['radclock'],
		library_dirs = ['/usr/local/lib'],
		sources = [ 'radclockmodule.c' ]
		)


if OS == OS_LINUX:
	module_radclock = module_radclock_linux
 
if OS == OS_FREEBSD:
	module_radclock = module_radclock_freebsd
 


setup ( name = 'python-radclock',
		version = '0.2.2',
		description = 'This package provides python bindings to the libradclock C library.',
		author = 'Julien Ridoux',
		author_email = 'julien@synclab.org',
		url = 'http://www.synclab.org/tscclock/',
		long_description = '''
This package provides python bindings to the libradclock C library.
It provides ways of creating a radclock instance and get the time as
created by the radclock.
It provides all basic functions of the libradclock library: absolute
clock, difference clock, clock status and system data.
''',
		ext_modules = [module_radclock]
		)

