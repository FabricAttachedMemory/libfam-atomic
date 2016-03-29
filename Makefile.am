#
#  Copyright © 2015, Hewlett Packard Enterprise Development LP
#
#  Author: Keith Packard <packard@hpe.com>
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public License
#  as published by the Free Software Foundation, either version 3 of
#  the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#

SUBDIRS= rcu-rbtree . tests doc

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = \
        fam_atomic.pc.in

DISTCLEANFILES = config.cache

MAINTAINERCLEANFILES = \
	$(srcdir)/aclocal.m4 \
	$(srcdir)/autoscan.log \
	$(srcdir)/compile \
	$(srcdir)/config.guess \
	$(srcdir)/config.h.in \
	$(srcdir)/config.sub \
	$(srcdir)/configure.scan \
	$(srcdir)/depcomp \
	$(srcdir)/install-sh \
	$(srcdir)/ltmain.sh \
	$(srcdir)/missing \
	$(srcdir)/mkinstalldirs \
	$(srcdir)/test-driver \
	`find "$(srcdir)" -type f -name Makefile.in -print`

pkgconfig_DATA = fam_atomic.pc

# Creating ChangeLog from git log:

MAINTAINERCLEANFILES += $(srcdir)/ChangeLog
EXTRA_DIST += ChangeLog
ChangeLog: $(srcdir)/ChangeLog
$(srcdir)/ChangeLog:
	if test -d "$(srcdir)/.git"; then \
	  (GIT_DIR=$(top_srcdir)/.git $(GIT) log --stat) | fmt --split-only > $@.tmp \
	  && mv -f $@.tmp $@ \
	  || ($(RM) $@.tmp; \
	      echo Failed to generate ChangeLog, your ChangeLog may be outdated >&2; \
	      (test -f $@ || echo git-log is required to generate this file >> $@)); \
	else \
	  test -f $@ || \
	  (echo A git checkout and git-log is required to generate ChangeLog >&2 && \
	  echo A git checkout and git-log is required to generate this file >> $@); \
	fi

.PHONY: ChangeLog

debuild debuild-signed: debuild-dirs
	(cd $(distdir)/debian && debuild)

debuild-unsigned: debuild-dirs
	(cd $(distdir)/debian && debuild -us -uc)

debuild-dirs: distdir
	$(RM) $(PACKAGE)_$(VERSION).orig.tar.gz
	$(RM) -r $(distdir).orig
	cp -a $(distdir) $(distdir).orig
	$(RM) -r $(distdir).orig/debian

DISTCHECK_CONFIGURE_FLAGS =

-include $(top_srcdir)/git.mk

libfam_atomic_la_SOURCES = \
	fam_atomic.c \
	fam_atomic.h

lib_LTLIBRARIES = libfam_atomic.la

include_HEADERS = fam_atomic.h

libfam_atomic_la_LDFLAGS =			\
	-version-info @LIBT_VERSION_INFO@ -no-undefined $(export_symbols)

libfam_atomic_la_LIBADD = $(ICONV_LIBS) $(FREETYPE_LIBS) $(LIBXML2_LIBS) $(EXPAT_LIBS) rcu-rbtree/librcu_rbtree.la
