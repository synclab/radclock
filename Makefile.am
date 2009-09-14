
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

SUBDIRS = libradclock radclock examples man

if HAVE_TESTBED_DIR
SUBDIRS += testbed 
else
SUBDIRS +=
endif

if HAVE_TOOLS_DIR
SUBDIRS += tools 
else
SUBDIRS +=
endif

DIST_SUBDIRS = libradclock radclock examples man

EXTRA_DIST = python-module

if HAVE_TESTBED_DIR
dist-hook:
	@echo "Cleaning the sync algo from its comments (radclock/sync_bidir.c)"
	head -n 20 $(distdir)/radclock/sync_bidir.c > $(distdir)/radclock/sync_bidir.c.header
	sed -f $(srcdir)/tools/remove_comments.sed $(distdir)/radclock/sync_bidir.c > $(distdir)/radclock/sync_bidir.c.clean
	cat $(distdir)/radclock/sync_bidir.c.header > $(distdir)/radclock/sync_bidir.c
	cat $(distdir)/radclock/sync_bidir.c.clean >> $(distdir)/radclock/sync_bidir.c
	rm $(distdir)/radclock/sync_bidir.c.clean $(distdir)/radclock/sync_bidir.c.header
	@echo "Copying the python module and wall clock into the tarball"
	cp $(srcdir)/python-gui/tscclock_wallclock.py $(distdir)/python-module/
	cp -R $(srcdir)/python-gui/img $(distdir)/python-module/
	@echo "Copying kernel patches into the tarball"
	mkdir $(distdir)/kernel-patches
	mkdir $(distdir)/kernel-patches/freebsd
	mkdir $(distdir)/kernel-patches/linux
	cp -p `find ./kernel/freebsd/ -name *\.patch -print` $(distdir)/kernel-patches/freebsd/
	cp -Rp $(srcdir)/kernel/linux/* $(distdir)/kernel-patches/linux/
	find $(distdir)/kernel-patches/linux/ -name ".svn" | xargs rm -rf
	@echo ""
	@echo "------------------------------------------------------"
	@echo "*         You made a release distribution"
	@echo "------------------------------------------------------"
	@echo "* Things you should check:"
	@echo "*   Package name : $(PACKAGE_NAME)"
	@echo "*   Package version : $(PACKAGE_VERSION)"
	@echo "*   Did you tag the SVN repository?"
	@echo "*   Did you run make distcheck?"
	@echo "*   Are the kernel patches up-to-date?"
	@echo "------------------------------------------------------"
	@echo ""
endif
