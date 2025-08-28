# Makefile.am - GNU Automake configuration for libgpg-stream
#
# Copyright (C) 2025 William Theesfeld <william@theesfeld.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

ACLOCAL_AMFLAGS = -I m4

# Subdirectories to build
SUBDIRS = src

if EXAMPLES
SUBDIRS += examples
endif

if DOCS
SUBDIRS += doc
endif

# Extra files to distribute
EXTRA_DIST = README.md COPYING autogen.sh libgpg-stream.pc.in

# pkg-config file
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libgpg-stream.pc

# Library built in src/ subdirectory
# Headers installed from src/ as well

# Test targets
check_PROGRAMS = 
TESTS = 

# Custom targets for development
.PHONY: format analyze demo

format:
	indent -gnu -i2 -l79 *.c *.h 2>/dev/null || true

analyze:
	@echo "=== Static Analysis ==="
	@cppcheck --enable=all --std=c99 *.c *.h 2>/dev/null || echo "cppcheck not available"
	@splint +posixlib *.c 2>/dev/null || echo "splint not available"

demo: all
	@echo "libgpg-stream demonstration - run 'make check' for tests"

# Documentation
if DOCS
man_MANS = doc/libgpg-stream.3
endif

# Clean additional files
CLEANFILES = libgpg-stream.pc
DISTCLEANFILES = 
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 configure config.h.in

distclean-local:
	-rm -rf autom4te.cache

maintainer-clean-local:
	-rm -f $(MAINTAINERCLEANFILES)