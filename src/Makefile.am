# src/Makefile.am - GNU Automake configuration for libgpg-stream source
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

# Main library
lib_LIBRARIES = libgpg-stream.a
include_HEADERS = libgpg-stream.h

# Source files
libgpg_stream_a_SOURCES = libgpg-stream.c libgpg-stream.h
libgpg_stream_a_CPPFLAGS = $(GPGME_CFLAGS) -D_GNU_SOURCE
libgpg_stream_a_CFLAGS = -Wall -Wextra -std=c99

# Shared library using libtool
lib_LTLIBRARIES = libgpg-stream.la
libgpg_stream_la_SOURCES = $(libgpg_stream_a_SOURCES)
libgpg_stream_la_CPPFLAGS = $(libgpg_stream_a_CPPFLAGS)
libgpg_stream_la_CFLAGS = $(libgpg_stream_a_CFLAGS)
libgpg_stream_la_LIBADD = $(GPGME_LIBS) -lpthread -lm
libgpg_stream_la_LDFLAGS = -version-info 1:0:0