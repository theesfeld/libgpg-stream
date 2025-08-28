# examples/Makefile.am - GNU Automake configuration for libgpg-stream examples
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

# Example programs
noinst_PROGRAMS = example-sender example-receiver

# Common settings
AM_CPPFLAGS = $(GPGME_CFLAGS) -I$(top_srcdir)/src -D_GNU_SOURCE
AM_CFLAGS = -Wall -Wextra -std=c99
AM_LDFLAGS = 

# Link against our library
LDADD = $(top_builddir)/src/libgpg-stream.la $(GPGME_LIBS) -lpthread -lm

# Example sender
example_sender_SOURCES = example-sender.c

# Example receiver  
example_receiver_SOURCES = example-receiver.c

# Extra files
EXTRA_DIST = README