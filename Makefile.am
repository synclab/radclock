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


DIST_SUBDIRS = libradclock radclock examples man

EXTRA_DIST = python-module debian redhat


SUBDIRS = $(DIST_SUBDIRS)
SUBDIRS += tests

# Extra cscope target
CSCOPE_DIRS = libradclock radclock

cscope: cscope-clean cscope.out

cscope.out: $(srcdir)/cscope.files
	cd $(srcdir); cscope -buq -p4

$(srcdir)/cscope.files:
	cd $(srcdir); \
	find $(CSCOPE_DIRS) -name "*.[ch]" -a -type f > $(srcdir)/cscope.files

cscope-clean:
	cd $(srcdir)
	rm -f cscope.files cscope.out cscope.in.out cscope.po.out



if MK_UPSTREAM
dist-hook:
	@echo "Copying kernel patches into the tarball"
	mkdir $(distdir)/kernel-patches
	mkdir $(distdir)/kernel-patches/freebsd
	for d in `ls $(srcdir)/kernel/freebsd`; do \
		mkdir $(distdir)/kernel-patches/freebsd/$$d; \
		cp $(srcdir)/kernel/freebsd/$$d/* $(distdir)/kernel-patches/freebsd/$$d/ ; \
	done
	mkdir $(distdir)/kernel-patches/linux
	for d in `ls $(srcdir)/kernel/linux`; do \
		mkdir $(distdir)/kernel-patches/linux/$$d; \
		cp $(srcdir)/kernel/linux/$$d/* $(distdir)/kernel-patches/linux/$$d/ ; \
	done
	@echo "Pushing version number in packaging scripts" 
	sed -i -e 's/_RADCLOCK_VERSION_/$(PACKAGE_VERSION)/' $(distdir)/debian/changelog
	sed -i -e 's/_RADCLOCK_VERSION_/$(PACKAGE_VERSION)/' $(distdir)/redhat/radclock.spec
	@echo "Move debian copyright file in $(distdir) for Debian packaging"
	mv $(distdir)/debian/copyright $(distdir)/
	@echo ""
	@echo "------------------------------------------------------"
	@echo "*         You made a release distribution"
	@echo "------------------------------------------------------"
	@echo "* Things you should check:"
	@echo "*   Package name : $(PACKAGE_NAME)"
	@echo "*   Package version : $(PACKAGE_VERSION)"
	@echo "*   Did you tag the git repository?"
	@echo "*   Did you run make distcheck?"
	@echo "*   Are the kernel patches up-to-date?"
	@echo "*   Are the kernel patches set to the right version?"
	@echo "------------------------------------------------------"
	@echo ""
endif
