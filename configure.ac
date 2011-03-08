# Process this file with autoconf to produce a configure script.
# Mark Ferlatte, <ferlatte@cryptio.net>
#

# autoconf requirement
AC_PREREQ([2.53])

# Init autoconf and automake

# Note: in  case of beta subversion, use underscore "_" rather then dash "-"
# since RPM doesn't allow dash in Version
# Example: 5.0_beta2
AC_INIT([monit], [5.2.5], [monit-general@nongnu.org])

# Package info
AC_REVISION([$Revision: 1.194 $])
AC_CONFIG_SRCDIR([monitor.c])

# ------------------------------------------------------------------------
# Programs 
# ------------------------------------------------------------------------

AC_PROG_CC
AC_PROG_GCC_TRADITIONAL
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_LEX
	if test "$LEX" != flex; then
		AC_MSG_ERROR([monit requires flex, not lex])
	fi
AC_CHECK_PROGS(YACC, 'bison -y' byacc yacc)
if test "x$YACC" = "x"; then
		AC_MSG_ERROR([monit requires bison, byacc or yacc])
fi

# ------------------------------------------------------------------------
# Libraries 
# ------------------------------------------------------------------------

# Check for libraries
AC_CHECK_LIB([socket], [socket])
AC_CHECK_LIB([inet],   [socket])
AC_CHECK_LIB([nsl],    [inet_addr])
AC_CHECK_LIB([resolv], [inet_aton])
AC_CHECK_LIB([crypt],  [crypt])

# Wacky pthread madness
pthread_libs=""
AC_CHECK_LIB([pthread], 
	     [pthread_create],
	     [pthread_libs="-lpthread"])
AC_CHECK_LIB([c_r],
	     [pthread_create],
	     [pthread_libs="-pthread"])
if test `uname` = "FreeBSD" -a `uname -r | cut -c1` = "6"
then
	pthread_libs="-lthr"
fi
if test "$pthread_libs"
then
	LIBS="$pthread_libs $LIBS"
fi

# ------------------------------------------------------------------------
# Header files 
# ------------------------------------------------------------------------

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_HEADER_STAT
AC_HEADER_TIME

AC_CHECK_HEADERS([ \
        alloca.h \
	arpa/inet.h \
	asm/page.h \
	asm/param.h \
	cf.h \
	crt_externs.h \
	ctype.h \
	crypt.h \
	dirent.h \
	errno.h \
	execinfo.h \
	fcntl.h \
	getopt.h \
	glob.h \
	grp.h \
	kvm.h \
	paths.h \
	kstat.h \
	libperfstat.h \
	limits.h \
	loadavg.h \
	locale.h \
        mach/host_info.h \
        mach/mach.h \
        mach/mach_host.h \
	memory.h \
	mntent.h \
	netdb.h \
        sys/socket.h \
	netinet/in.h \
        netinet/in_systm.h \
        pam/pam_appl.h \
	poll.h \
	procfs.h \
	sys/procfs.h \
	procinfo.h \
	pthread.h \
	pwd.h \
	regex.h \
        security/pam_appl.h \
	setjmp.h \
	signal.h \
	stdarg.h \
        stddef.h \
	stdio.h \
	string.h \
	strings.h \
	stropts.h \
	sys/cfgodm.h \
	sys/cfgdb.h \
	sys/dk.h \
	sys/dkstat.h \
	sys/filio.h \
	sys/ioctl.h \
	sys/loadavg.h \
	sys/lock.h \
	sys/mnttab.h \
	sys/mutex.h \
	sys/nlist.h \
	sys/param.h \
	sys/pstat.h \
	sys/queue.h \
	sys/resource.h \
	sys/statfs.h \
	sys/statvfs.h \
	sys/systemcfg.h \
	sys/time.h \
	sys/tree.h \
	sys/types.h \
	sys/un.h \
	sys/utsname.h \
        sys/vmmeter.h \
	sys/vfs.h \
	syslog.h \
	unistd.h \
        uvm/uvm.h \
        uvm/uvm_extern.h \
        vm/vm.h \
	])

AC_CHECK_HEADERS([ \
	netinet/ip.h \
        ],
        [],
        [],
        [
         #ifdef HAVE_SYS_TYPES_H
         #include <sys/types.h>
         #endif
         #if HAVE_NETINET_IN_SYSTM_H
         #include <netinet/in_systm.h>
         #endif
         #if HAVE_NETINET_IN_SYSTM_H
         #include <netinet/in.h>
         #endif
        ])

AC_CHECK_HEADERS([ \
	net/if.h \
	netinet/ip_icmp.h \
        ],
        [],
        [],
        [
         #ifdef HAVE_SYS_TYPES_H
         #include <sys/types.h>
         #endif
         #if HAVE_SYS_SOCKET_H
         #include <sys/socket.h>
         #endif
         #if HAVE_NETINET_IN_SYSTM_H
         #include <netinet/in.h>
         #endif
         #if HAVE_NETINET_IN_SYSTM_H
         #include <netinet/in_systm.h>
         #endif
         #if HAVE_NETINET_IP_H
         #include <netinet/ip.h>
         #endif
        ])

AC_CHECK_HEADERS([ \
        sys/sysctl.h \
        sys/mount.h \
        sys/proc.h \
        sys/swap.h \
	sys/ucred.h \
        sys/user.h \
        ],
        [],
        [],
        [
         #ifdef HAVE_SYS_PARAM_H
         #include <sys/param.h>
         #endif
        ])

AC_CHECK_HEADERS([ \
	machine/vmparam.h \
        vm/pmap.h \
        machine/pmap.h \
        vm/vm_map.h \
	vm/vm_object.h \
        ],
        [],
        [],
        [
         #ifdef HAVE_SYS_PARAM_H
         #include <sys/param.h>
         #endif
         #ifdef HAVE_SYS_QUEUE_H
         #include <sys/queue.h>
         #endif
         #ifdef HAVE_SYS_LOCK_H
         #include <sys/lock.h>
         #endif
         #ifdef HAVE_SYS_MUTEX_H
         #include <sys/mutex.h>
         #endif
         #ifdef HAVE_VM_VM_H
         #include <vm/vm.h>
         #endif
         #ifdef HAVE_VM_PMAP_H
         #include <vm/pmap.h>
         #endif
        ])

AC_CHECK_HEADERS([ \
        sys/resourcevar.h \
        ],
        [],
        [],
        [
         #ifdef HAVE_SYS_TIME_H
         #include <sys/time.h>
         #endif
         #ifdef HAVE_SYS_RESOURCE_H
         #include <sys/resource.h>
         #endif
        ])

AC_CHECK_HEADERS([ \
	uvm/uvm_map.h \
	uvm/uvm_pmap.h \
	uvm/uvm_object.h \
        ],
        [],
        [],
        [
         #ifdef HAVE_SYS_TIME_H
         #include <sys/time.h>
         #endif
         #ifdef HAVE_SYS_LOCK_H
         #include <sys/lock.h>
         #endif
         #ifdef HAVE_SYS_TREE_H
         #include <sys/tree.h>
         #endif
         #ifdef HAVE_UVM_UVM_EXTERN_H
         #include <uvm/uvm_extern.h>
         #endif
        ])

# Check for types.
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_PID_T
AC_TYPE_SIGNAL

# Check for structures.
AC_STRUCT_TM
AC_CHECK_MEMBERS([struct tm.tm_gmtoff])

# ------------------------------------------------------------------------
# Compiler 
# ------------------------------------------------------------------------

# Compiler characteristics
AC_C_CONST
AC_C_BIGENDIAN

# If the compiler is gcc, turn on warnings
if test "x$GCC" = "xyes"; then
	case " $CFLAGS " in
		*[\ \	]-Wall[\ \	]*)
			;;
		*)
			CFLAGS="$CFLAGS -Wall"
			;;
	esac
fi

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_STAT
AC_FUNC_STRFTIME
AC_CHECK_FUNCS(statfs)
AC_CHECK_FUNCS(statvfs)
AC_CHECK_FUNCS(setlocale)
AC_CHECK_FUNCS(getaddrinfo)
AC_CHECK_FUNCS(syslog)
AC_CHECK_FUNCS(vsyslog)
AC_CHECK_FUNCS(backtrace)

jm_FUNC_GNU_STRFTIME

EXTERNALS=""
if test "$jm_cv_func_working_gnu_strftime" = "no"; then
	# We do not have have a working strftime supporting %z
	EXTERNALS="$EXTERNALS external/strftime.c"
fi

AC_SUBST(EXTERNALS)

# Check for SOL_IP
AC_MSG_CHECKING(for SOL_IP)
AC_TRY_COMPILE([
	#include <netdb.h>
	#include <sys/socket.h>
], [
	int level = SOL_IP;
], [
	AC_MSG_RESULT(yes)
	AC_DEFINE([HAVE_SOL_IP], [1], [Define to 1 if SOL_IP is defined.])
], [
	AC_MSG_RESULT(no)
])

AC_MSG_CHECKING(for va_copy)
AC_TRY_LINK([
	#include <stdarg.h>
], [
	va_list ap;
	va_list ap_copy;
	va_copy(ap, ap_copy);
], [
	AC_MSG_RESULT(yes)
	AC_DEFINE([HAVE_VA_COPY], [1], [Define to 1 if VA_COPY is defined.])
], [
	AC_MSG_RESULT(no)
])

# ------------------------------------------------------------------------
# Paths 
# ------------------------------------------------------------------------

# Find the right directory to put the root-mode PID file in
AC_MSG_CHECKING([pid file location])
if test -d "/var/run"
then
	piddir="/var/run"
elif test -d "/etc"
then
	piddir="/etc"
fi

AC_DEFINE_UNQUOTED([PIDDIR], "$piddir",
	  [Define to the pid storage directory.])
AC_MSG_RESULT([$piddir])

# Test mounted filesystem description file
if test -f "/etc/mtab"
then
  AC_DEFINE([HAVE_MTAB], 1, [Define to 1 if you have /etc/mtab])
elif test -f "/etc/mnttab"; then
  AC_DEFINE([HAVE_MNTTAB], 1, [Define to 1 if you have /etc/mnttab])
fi

# ------------------------------------------------------------------------
# Architecture/OS detection
# ------------------------------------------------------------------------

# Backward compatibility until we get ride of arch settings
if test `uname` = "SunOS" 
then
   ARCH="SOLARIS"
   CFLAGS="$CFLAGS -D _REENTRANT -D_POSIX_PTHREAD_SEMANTICS"
   test_kstat="true"
   AC_DEFINE([HAVE_CPU_WAIT], [1], [Define to 1 if CPU wait information is available.])
elif test `uname` = "Linux" 
then
   ARCH="LINUX"
   CFLAGS="$CFLAGS -D _REENTRANT"
   LDFLAGS="$LDFLAGS -rdynamic"
   if test `uname -r | awk -F '.' '{print$1$2}'` -ge "26"
   then
   	AC_DEFINE([HAVE_CPU_WAIT], [1], [Define to 1 if CPU wait information is available.])
   fi
elif test `uname` = "HP-UX"
then
   ARCH="HPUX"
   CFLAGS="$CFLAGS -D _REENTRANT"
   AC_DEFINE([HAVE_CPU_WAIT], [1], [Define to 1 if CPU wait information is available.])
elif test `uname` = "OpenBSD"
then
   ARCH="OPENBSD"
   CFLAGS="$CFLAGS -D _REENTRANT"
   test_kvm="true"
elif test `uname` = "FreeBSD"
then
   ARCH="FREEBSD"
   CFLAGS="$CFLAGS -D _REENTRANT"
   test_kvm="true"
elif test `uname` = "NetBSD"
then
   ARCH="NETBSD"
   CFLAGS="$CFLAGS -D _REENTRANT"
   test_kvm="true"
elif test `uname` = "Darwin"
then
   ARCH="DARWIN"
   CFLAGS="$CFLAGS -DREENTRANT -no-cpp-precomp -DNEED_SOCKLEN_T_DEFINED"
   test_kvm="true"
   LIBS="$LIBS -framework System -multiply_defined suppress"
elif test `uname` = "AIX"
then
   ARCH="AIX"
   CFLAGS="$CFLAGS -D_THREAD_SAFE -D_REENTRANT"
   LIBS="$LIBS -lodm"	
   # AIX v. 5.2
   LIBS="$LIBS -lcfg"	
   # AIX v. 5.3
   LIBS="$LIBS -lperfstat"	
   AC_DEFINE([HAVE_CPU_WAIT], [1], [Define to 1 if CPU wait information is available.])
else
   AC_MSG_WARN([Architecture not supported: `uname`.])
   CFLAGS="$CFLAGS -D _REENTRANT"
   ARCH="UNKNOWN"
fi
AC_SUBST(ARCH)

# ------------------------------------------------------------------------
# Resource code
# ------------------------------------------------------------------------

# Test for kvm libs
kvm_libs=""
if test "$test_kvm"; then
       	AC_CHECK_LIB([kvm],
        	     [kvm_open],
        	     [kvm_libs="-lkvm"])
       	if test "$kvm_libs"
       	then
       	        LIBS="$LIBS $kvm_libs"
       	fi
fi
kstat_libs=""
if test "$test_kstat"; then
       	AC_CHECK_LIB([kstat],
        	     [kstat_open],
        	     [kstat_libs="-lkstat"])
       	if test "$kstat_libs"
       	then
       	        LIBS="$LIBS $kstat_libs"
       	fi
fi


# ------------------------------------------------------------------------
# Large files code
# ------------------------------------------------------------------------

# Check if we want to have large files support
AC_MSG_CHECKING([for large files support])
AC_ARG_WITH(largefiles,
    [  --without-largefiles    disable large files support (default: enabled)],
    [
        dnl Check the withvalue                
        if test "x$withval" = "xno" ; then
            use_largefiles=0
            AC_MSG_RESULT([disabled])
        fi
        if test "x$withval" = "xyes" ; then
            use_largefiles=1
            AC_MSG_RESULT([enabled])
        fi
    ],
    [
	if test `uname` = "AIX"
	then
	    use_largefiles=0
	    AC_MSG_RESULT([disabled])
	else
	    use_largefiles=1
	    AC_MSG_RESULT([enabled])
	fi
    ]
)

# Settings for largefiles support
if test "$use_largefiles" = 1; then
        if test "$ARCH" = "SOLARIS"; then
            if ! ( echo $CFLAGS | egrep '(64|v9)' >/dev/null 2>&1); then
                echo "###############################################################################"
                echo "### Solaris requires 64-bit support for large files and resource monitoring ###"
                echo "### enabled.                                                                ###"
                echo "###                                                                         ###"
                echo "### Compile monit with 64-bit support (see PLATFORMS file for details)      ###"
                echo "###############################################################################"
		AC_MSG_ERROR([Solaris requires 64-bit support for large files and resource monitoring enabled])
            fi
        fi
        AC_SYS_LARGEFILE
fi


# ------------------------------------------------------------------------
# PAM Code
# ------------------------------------------------------------------------

AC_MSG_CHECKING([for PAM support])
AC_ARG_WITH(pam,
    [  --without-pam           disable the use of pam (default: enabled)],
    [
        dnl Check the withvalue                
        if test "x$withval" = "xno" ; then
            use_pam=0
            AC_MSG_RESULT([disabled])
        fi
        if test "x$withval" = "xyes" ; then
            use_pam=1
            AC_MSG_RESULT([enabled])
        fi
    ],
    [
        use_pam=1
        AC_MSG_RESULT([enabled])
    ]
)

if test "$use_pam" = "1"; then
        AC_CHECK_LIB([pam],    [pam_start])
fi


# ------------------------------------------------------------------------
# SSL Code
# ------------------------------------------------------------------------

# Check for ssl includes (taken from the stunnel project)
checksslincldir() { :
    if test -f "$1/openssl/ssl.h"; then
        sslincldir="$1"
        return 0
    fi
    return 1
}

# Check for ssl libraries 
checkssllibdirdynamic() { :
    if test "(" -f "$1/libcrypto.so" -o -f "$1/libcrypto.dylib" ")"  -a \
            "(" -f "$1/libssl.so"    -o -f "$1/libssl.dylib" ")" ; then
        ssllibdir="$1"
        return 0
    fi
    return 1
}

checkssllibdirstatic() { :
    if test "(" -f "$1/libcrypto.a" ")"  -a \
            "(" -f "$1/libssl.a" ")" ; then
        ssllibdir="$1"
        return 0
    fi
    return 1
}

# Check if we want to have SSL

AC_MSG_CHECKING([for static SSL support])

AC_ARG_WITH(ssl-static,
    [  --with-ssl-static=DIR       location of SSL installation],
    [
        dnl Check the specified location only
        for dir in "$withval" "$withval/include"; do
            checksslincldir "$dir"
        done
        for dir in "$withval" "$withval/lib"; do
            checkssllibdirstatic "$dir" && break 2
        done
        use_sslstatic=1
        LDFLAGS="`echo $LDFLAGS | sed -e 's/-rdynamic/-ldl/g'`"
        AC_MSG_RESULT([enabled])
        AC_DEFINE([HAVE_OPENSSL], 1, [Define to 1 if you have openssl.])
        AC_SUBST(sslincldir)
        AC_SUBST(ssllibdir)
        CFLAGS="$CFLAGS -I$sslincldir"
        LIBS="$LIBS $ssllibdir/libssl.a $ssllibdir/libcrypto.a"
    ],
    [
	use_sslstatic=0
        AC_MSG_RESULT([disabled])
    ]
)

if test "$use_sslstatic" = "0"
then
    AC_MSG_CHECKING([for SSL support])

    AC_ARG_WITH(ssl,
        [  --without-ssl           disable the use of ssl (default: enabled)],
        [
            dnl Check the withvalue                
            if test "x$withval" = "xno" ; then
                use_ssl=0
                AC_MSG_RESULT([disabled])
            fi
            if test "x$withval" = "xyes" ; then
                use_ssl=1
                AC_MSG_RESULT([enabled])
            fi
        ],
        [
            use_ssl=1
            AC_MSG_RESULT([enabled])
        ]
    )


    # Check for SSL directory (taken from the stunnel project)
    if test "$use_ssl" = "1"; then

        AC_ARG_WITH(ssl-dir,
            [  --with-ssl-dir=DIR       location of SSL installation],
            [
                dnl Check the specified location only
                for dir in "$withval" "$withval/include"; do
                	checksslincldir "$dir"
                done
                for dir in "$withval" "$withval/lib"; do
                    checkssllibdirdynamic "$dir" && break 2
                done
            ]
        )

        AC_MSG_CHECKING([for SSL include directory])
        AC_ARG_WITH(ssl-incl-dir,
            [  --with-ssl-incl-dir=DIR  location of installed SSL include files],
            [
                dnl Check the specified location only
                checksslincldir "$withval"
            ],
            [
                if test -z "$sslincldir"; then	
                    dnl Search default locations of SSL includes
                    for maindir in /usr /usr/local /usr/lib /usr/pkg /var /opt /usr/sfw; do
                        for dir in "$maindir/include"\
                                   "$maindir/include/openssl"\ 
                                   "$maindir/include/ssl"\
                                   "$maindir/ssl/include"; do
                            checksslincldir $dir && break 2
                        done
                    done
                fi
            ]
        )
        if test -z "$sslincldir"; then
            AC_MSG_RESULT([Not found])
            echo
            echo "Couldn't find your SSL header files."
            echo "Use --with-ssl-incl-dir option to fix this problem or disable"
            echo "the SSL support with --without-ssl"
            echo
            exit 1
        fi
        AC_MSG_RESULT([$sslincldir])

        AC_MSG_CHECKING([for SSL library directory])
        AC_ARG_WITH(ssl-lib-dir,
            [  --with-ssl-lib-dir=DIR   location of installed SSL library files],
            [
                dnl Check the specified location only
                checkssllibdirdynamic "$withval"
            ],
            [
                if test -z "$ssllibdir"; then	
                    dnl Search default locations of SSL libraries
                    for maindir in /usr \
                                   /usr/local \
                                   /usr/pkg \
                                   /var /opt \
                                   /usr/sfw; do
                        for dir in $maindir \
                                   $maindir/openssl \
                                   $maindir/ssl \
                                   $maindir/lib \
                                   $maindir/lib/openssl \
                                   $maindir/lib/ssl \
                                   $maindir/ssl/lib \
                                   $maindir/lib/64 \
                                   $maindir/lib/64/openssl \
                                   $maindir/lib/64/ssl \
                                   $maindir/ssl/lib/64 \
                                   $maindir/lib64 \
                                   $maindir/lib64/openssl \
                                   $maindir/lib64/ssl \
                                   $maindir/ssl/lib64; do
                            checkssllibdirdynamic $dir && break 2
                        done
                    done
                fi
            ]
        )
        if test -z "$ssllibdir"; then
            AC_MSG_RESULT([Not found])
            echo
            echo "Couldn't find your SSL library files."
            echo "Use --with-ssl-lib-dir option to fix this problem or disable the"
            echo "SSL support with --without-ssl"
            echo
            exit 1
        fi
        AC_MSG_RESULT([$ssllibdir])

        AC_DEFINE([HAVE_OPENSSL], 1, [Define to 1 if you have openssl.])
        AC_SUBST(sslincldir)
        AC_SUBST(ssllibdir)
    fi

    # Add SSL includes and libraries
    if test "$sslincldir" -a "$ssllibdir"
    then
        if test "x$ARCH" = "xDARWIN"; then
         # Darwin already knows about ssldirs
         LIBS="$LIBS -lssl -lcrypto"
        elif test -f "/usr/kerberos/include/krb5.h"; then
         # Redhat 9 compilation fix:
         CFLAGS="$CFLAGS -I$sslincldir -I/usr/kerberos/include"
         LIBS="$LIBS -L$ssllibdir -lssl -lcrypto"
        else
         CFLAGS="$CFLAGS -I$sslincldir"
         LIBS="$LIBS -L$ssllibdir -lssl -lcrypto"
        fi
    fi
fi

# ------------------------------------------------------------------------
# Outputs
# ------------------------------------------------------------------------

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo ""
echo "monit has been configured with the following options:"

echo "                Architecture: ${ARCH}"
if test "$use_pam" = "1"; then
    echo "                 PAM support: enabled"
else
    echo "                 PAM support: disabled"
fi
if test "$use_sslstatic" = "1" -o "$use_ssl" = "1"; then
    echo "                 SSL support: enabled"
    echo "       SSL include directory: ${sslincldir}"
    echo "       SSL library directory: ${ssllibdir}"
else
    echo "                 SSL support: disabled"
fi
if test "$use_largefiles" = "1"; then
    echo "         large files support: enabled"  
else
    echo "         large files support: disabled"
fi
echo "              Compiler flags: ${CFLAGS}"
echo "                Linker flags: ${LIBS}"
echo "           pid file location: ${piddir}"
echo
