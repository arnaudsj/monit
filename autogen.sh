#! /usr/bin/env bash
# autogen.sh (borrowed from Gnet autogen.sh)
#
# This script is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

srcdir=$(dirname $0)
test -z "$srcdir" && srcdir=.

(test -f $srcdir/configure.ac) ||
{
	echo -n "Error: directory '$srcdir' does not look like the"
	echo " top level directory"
	echo
	exit 1
}

DIE=0

(autoconf --version) < /dev/null > /dev/null 2>&1 ||
{
	echo "Error: 'autoconf' must be installed"
	echo
	DIE=1
}

if test "$DIE" -eq 1; then
	exit 1
fi

if test -z "$*"; then
	echo "Warning: I am going to run \`configure' with no arguments."
	echo "If you wish to pass any to it, please specify them on the"
	echo \`$0\'" command line."
	echo
fi

echo "Running aclocal"
aclocal -I m4
echo "Running autoheader"
autoheader
echo "Running autoconf"
autoconf	

conf_flags="--enable-compile-warnings"
if test x$NOCONFIGURE = x; then
	echo Running $srcdir/configure $conf_flags "$@" ...
	[ ! -x $srcdir/configure ] && chmod 755 $srcdir/configure
	$srcdir/configure $conf_flags "$@" || exit 1
  echo -n "Now type '"
    if ! ( uname -s | grep -i bsd >/dev/null 2>&1 ); then
      echo -n "make"
    else
      echo -n "gmake"
    fi
  echo "' to compile"
else
	echo Skipping configure process
fi
