#!/bin/bash
# autogen.sh - GNU autotools bootstrap script for libgpg-stream
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

set -e

echo "Bootstrapping GNU autotools for libgpg-stream..."

# Check for required tools
check_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Error: $1 not found. Please install $2"
        exit 1
    fi
}

check_tool "autoreconf" "autotools (autoconf, automake, libtool)"
check_tool "pkg-config" "pkg-config"

# Clean previous autotools files
echo "Cleaning previous autotools files..."
rm -rf autom4te.cache
rm -f aclocal.m4 config.h.in configure
find . -name "Makefile.in" -delete

# Create m4 directory if it doesn't exist
mkdir -p m4

# Generate the build system
echo "Running autoreconf..."
autoreconf --install --verbose --force

echo ""
echo "Autotools bootstrap completed successfully!"
echo ""
echo "To build libgpg-stream:"
echo "  ./configure [options]"
echo "  make"
echo "  make check    # run tests"
echo "  make install  # install to system"
echo ""
echo "Common configure options:"
echo "  --enable-debug     Enable debug build"
echo "  --enable-examples  Build example programs"
echo "  --enable-docs      Generate documentation"
echo "  --prefix=DIR       Install to DIR (default: /usr/local)"
echo ""