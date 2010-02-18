#!/bin/sh
# 
# This script generates a solaris package of of monit
#
# Author: Christian Hopp <chopp@iei.tu-clausthal.de>
#
# Beware: You have to run it from the contrib/packages/solaris dir!!!
#

place=`pwd | sed 's%^.*/\([a-zA-z0-9]*/[a-zA-z0-9]*/[a-zA-z0-9]*\)$%\1%'`

if [ $place != "contrib/packages/solaris" ]; then
    echo "This script has to be started from [contrib/packages/solaris]!"
    exit 1
fi

# 0) Configuration
# ----------------

cd ../../..

# set path to strip
PATH=$PATH:/usr/ccs/bin
export PATH

name=monit
pkgname=GNUmonit
make=/usr/local/bin/make
prefix=/usr/local
vendor="http://www.tildeslash.com/monit/"

version=`cat configure.ac | sed -n -e '/AC_INIT/s%.*\[.*\].*\[\(.*\)\].*\[.*\].*%\1%p'`
pstamp=monit`hostname | cut -d "." -f 1`-`date +%Y%m%d%H%M`
platform=`uname -p`
release=`uname -r | sed 's/5\./sol/'`
filename=${name}-${version}-${release}-${platform}-local.pkg
tmpdir=/tmp/${name}-install
docs="monitrc CHANGES.txt COPYING LICENSE \
      PLATFORMS README README.SSL STATUS UPGRADE.txt \
      doc/* contrib/packages/solaris/init.monit \
      contrib/packages/solaris/README.solaris"

# 1) Compilation phase
# --------------------

if [ -f Makefile ]; then
    $make clean
fi

./configure --prefix=$prefix $*
$make

# 2) Data gathering
# -----------------

if [ -x ${tmpdir} ]; then
    /bin/rm -Rf ${tmpdir}
fi

mkdir ${tmpdir}
mkdir ${tmpdir}/doc
mkdir ${tmpdir}/doc/${name}

$make exec_prefix=${tmpdir} prefix=${tmpdir} install

cp -r $docs ${tmpdir}/doc/${name}/

chown bin:bin ${tmpdir}/*
chown bin:bin ${tmpdir}/man/*

# 3) Package generation
# ---------------------

cd contrib/packages/solaris

cat > pkginfo <<EOF
CLASSES=none
BASEDIR=$prefix
LC_CTYPE=iso_8859_1
LANG=C
TZ=MET
PATH=/sbin:/usr/sbin:/usr/bin:/usr/sadm/install/bin
OAMBASE=/usr/sadm/sysadm
PKG=$pkgname
NAME=$name
ARCH=$platform
VERSION=$version
CATEGORY=application
VENDOR=$vendor
PSTAMP=$pstamp
EOF

(echo 'i pkginfo'; pkgproto ${tmpdir}= ) > prototype
pkgmk -o
pkgtrans -s /var/spool/pkg `pwd`/${filename} $pkgname
gzip ./${filename}
openssl dgst -md5 ${filename}.gz > ${filename}.gz.md5

# 4) Cleaning up
# --------------

/bin/rm -Rf ${tmpdir}
/bin/rm -Rf /var/spool/pkg/$pkgname
/bin/rm prototype
/bin/rm pkginfo
