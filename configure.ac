# configure.ac - GNU Autoconf configuration for libgpg-stream
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

AC_INIT([libgpg-stream], [1.0.0], [william@theesfeld.net])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
LT_INIT
AC_PROG_RANLIB
AM_PROG_AR

# Check for required header files
AC_CHECK_HEADERS([stdio.h stdlib.h string.h unistd.h])
AC_CHECK_HEADERS([sys/socket.h netinet/in.h arpa/inet.h netdb.h])
AC_CHECK_HEADERS([pthread.h time.h stdarg.h fcntl.h errno.h])

# Check for required libraries
AC_CHECK_LIB([pthread], [pthread_create], [], [
    AC_MSG_ERROR([pthread library is required])
])

AC_CHECK_LIB([m], [pow], [], [
    AC_MSG_ERROR([math library is required])
])

# Check for GPGME using pkg-config
PKG_CHECK_MODULES([GPGME], [gpgme >= 1.0.0], [], [
    AC_MSG_ERROR([GPGME library is required (libgpgme-dev)])
])

# Check for specific functions
AC_CHECK_FUNCS([socket bind listen accept connect])
AC_CHECK_FUNCS([pthread_mutex_init pthread_mutex_lock pthread_mutex_unlock])

# Define preprocessor macros
AC_DEFINE([_GNU_SOURCE], [1], [Enable GNU extensions])

# Set compiler flags with LFS support
CFLAGS="$CFLAGS -Wall -Wextra -std=c99 -D_FILE_OFFSET_BITS=64"
CPPFLAGS="$CPPFLAGS -D_FILE_OFFSET_BITS=64"

# Debug support
AC_ARG_ENABLE([debug],
    AS_HELP_STRING([--enable-debug], [Enable debug build]),
    [debug=yes], [debug=no])

AM_CONDITIONAL([DEBUG], [test "x$debug" = "xyes"])

if test "x$debug" = "xyes"; then
    CFLAGS="$CFLAGS -g -O0 -DDEBUG"
    AC_DEFINE([DEBUG], [1], [Enable debug output])
else
    CFLAGS="$CFLAGS -O2 -DNDEBUG"
fi

# Example programs support
AC_ARG_ENABLE([examples],
    AS_HELP_STRING([--enable-examples], [Build example programs]),
    [examples=yes], [examples=no])

AM_CONDITIONAL([EXAMPLES], [test "x$examples" = "xyes"])

# Documentation support
AC_ARG_ENABLE([docs],
    AS_HELP_STRING([--enable-docs], [Generate documentation]),
    [docs=yes], [docs=no])

AM_CONDITIONAL([DOCS], [test "x$docs" = "xyes"])

# Output files
AC_CONFIG_FILES([
    Makefile
    src/Makefile
    examples/Makefile
    doc/Makefile
    libgpg-stream.pc
])

AC_OUTPUT

echo "
Configuration:
  Package:          $PACKAGE_NAME $VERSION
  C Compiler:       $CC
  CFLAGS:           $CFLAGS
  GPGME CFLAGS:     $GPGME_CFLAGS
  GPGME LIBS:       $GPGME_LIBS
  Debug:            $debug
  Examples:         $examples
  Documentation:    $docs
  Installation:     $prefix
"