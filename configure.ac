dnl
dnl  Copyright © 2015, Hewlett Packard Enterprise Development LP
dnl
dnl  Author: Keith Packard <packard@hpe.com>
dnl
dnl  This program is free software; you can redistribute it and/or
dnl  modify it under the terms of the GNU Lesser General Public License
dnl  as published by the Free Software Foundation, either version 3 of
dnl  the License, or (at your option) any later version.
dnl
dnl  This program is distributed in the hope that it will be useful, but
dnl  WITHOUT ANY WARRANTY; without even the implied warranty of
dnl  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
dnl  Lesser General Public License for more details.
dnl
dnl
dnl
dnl Process this file with autoconf to create configure.

AC_PREREQ(2.61)

dnl ==========================================================================
dnl                               Versioning
dnl ==========================================================================

dnl This is the package version number, not the shared library
dnl version.
AC_INIT([fam_atomic], [1.5], [http://hlinux-home.us.rdlabs.hpecorp.net/bugzilla/enter_bug.cgi?product=Userspace])
AM_INIT_AUTOMAKE([1.11 parallel-tests])
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

dnl ==========================================================================

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
PKG_PROG_PKG_CONFIG
m4_ifdef([PKG_INSTALLDIR], [PKG_INSTALLDIR], AC_SUBST([pkgconfigdir], ${libdir}/pkgconfig))

AC_MSG_CHECKING([for RM macro])
_predefined_rm=`make -p -f /dev/null 2>/dev/null|grep '^RM ='|sed -e 's/^RM = //'`
if test "x$_predefined_rm" = "x"; then
	AC_MSG_RESULT([no predefined RM])
	AC_CHECK_PROG(RM, rm, [rm -f])
else
	AC_MSG_RESULT($_predefined_rm)
fi

dnl Initialize libtool
LT_PREREQ([2.2])
LT_INIT([disable-static win32-dll])

dnl libtool versioning

dnl bump revision when fixing bugs
dnl bump current and age, reset revision to zero when adding APIs
dnl bump current, leave age, reset revision to zero when changing/removing APIS
LIBT_CURRENT=1
LIBT_REVISION=0
AC_SUBST(LIBT_CURRENT)
AC_SUBST(LIBT_REVISION)
LIBT_AGE=0

LIBT_VERSION_INFO="$LIBT_CURRENT:$LIBT_REVISION:$LIBT_AGE"
AC_SUBST(LIBT_VERSION_INFO)

LIBT_CURRENT_MINUS_AGE=`expr $LIBT_CURRENT - $LIBT_AGE`
AC_SUBST(LIBT_CURRENT_MINUS_AGE)

PKGCONFIG_REQUIRES=
PKGCONFIG_REQUIRES_PRIVATELY=

dnl ==========================================================================

case "$host" in
  *-*-mingw*)
    os_win32=yes
    ;;
  *)
    os_win32=no
esac
AM_CONDITIONAL(OS_WIN32, test "$os_win32" = "yes")

if test "$os_win32" = "yes"; then
  AC_CHECK_PROG(ms_librarian, lib.exe, yes, no)
fi
AM_CONDITIONAL(MS_LIB_AVAILABLE, test x$ms_librarian = xyes)

WARN_CFLAGS=""
if test "x$GCC" = "xyes"; then
	WARN_CFLAGS="-Wall -Wpointer-arith -Wstrict-prototypes \
	-Wmissing-prototypes -Wmissing-declarations \
	-Wnested-externs -fno-strict-aliasing"
	AC_DEFINE_UNQUOTED(HAVE_WARNING_CPP_DIRECTIVE,1,
	[Can use #warning in C files])
fi
AC_SUBST(WARN_CFLAGS)


dnl ==========================================================================

AX_CC_FOR_BUILD()
AC_ARG_VAR(CC_FOR_BUILD, [build system C compiler])
AM_CONDITIONAL(CROSS_COMPILING, test $cross_compiling = yes)
AM_CONDITIONAL(ENABLE_SHARED, test "$enable_shared" = "yes")

dnl ==========================================================================

AC_ARG_WITH(arch,
	[AC_HELP_STRING([--with-arch=ARCH],
			[Force architecture to ARCH])],
	arch="$withval", arch=auto)

if test "x$arch" != xauto; then
	AC_DEFINE_UNQUOTED([FC_ARCHITECTURE], "$arch", [Architecture prefix to use for cache file names])
fi


dnl ==========================================================================

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS([stdint.h stdbool.h sys/ioctl.h sys/types.h stdlib.h stdio.h assert.h signal.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_C_FLEXIBLE_ARRAY_MEMBER

# Checks for library functions.
AC_FUNC_VPRINTF
AC_FUNC_MMAP
AC_CHECK_FUNCS([mmap])

have_pthread=false
AX_PTHREAD([have_pthread=true])
if $have_pthread; then
	LIBS="$PTHREAD_LIBS $LIBS"
	CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
	CC="$PTHREAD_CC"
	AC_DEFINE(HAVE_PTHREAD, 1, [Have POSIX threads])
fi
AM_CONDITIONAL(HAVE_PTHREAD, $have_pthread)

dnl ===========================================================================

AC_SUBST(PKGCONFIG_REQUIRES)
AC_SUBST(PKGCONFIG_REQUIRES_PRIVATELY)

dnl
AC_CONFIG_FILES([
Makefile
tests/Makefile
doc/Makefile
fam_atomic.pc
])
AC_OUTPUT
