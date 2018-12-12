dnl Process this file with autoconf to produce a configure script.
AC_PREREQ(2.59)
AC_INIT(fuse_xattr, 0.0.0.1,felipe@felipebarriga.cl)
AC_CONFIG_SRCDIR([src/fuse_xattrs.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])

dnl AC_CANONICAL_SYSTEM

dnl Initialize automake
dnl AM_INIT_AUTOMAKE([dist-bzip2 subdir-objects]) 
dnl https://stackoverflow.com/questions/21609580/autotools-build-fails-due-to-subdir-objects-option-in-am-init-automake
AM_INIT_AUTOMAKE([dist-bzip2])

dnl Initialize Libtool
LT_INIT

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AM_PROG_CC_C_O
AC_PROG_RANLIB

# Checks for header files.
AC_CHECK_HEADERS([stddef.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_UID_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_CHECK_FUNCS([lchown setxattr memset mkdir mkfifo rmdir strdup])

# Checks for pkg config and needed parameters files
PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES(libfuse, [fuse],,
    AC_MSG_ERROR([You need the FUSE library]
    [])
)

dnl debug
AC_ARG_ENABLE(debug,
        [  --enable-debug enable debug mode ],
        [case "${enableval}" in
         yes) enable_debug="yes";;
          no) enable_debug="no" ;;
           *) AC_MSG_ERROR(bad value ${enableval} for --enable-debug) ;;
         esac],
        [enable_debug="no"]
)
if test "$enable_debug" = "yes"; then
        AC_DEFINE(_DEBUG_, 1, [Defined if debug mode is enabled (it's easier to check).])        
fi

if test "$enable_debug" = "no"; then
        AC_DEFINE(NDEBUG, 1, [Defined if debug mode is disabled.])
fi

#if test "${enable_retail}" = "yes"; then
#        AC_DEFINE(_RETAIL_,1,[Defined is retail mode is enabled.])
#fi

AC_ARG_ENABLE(debug-console,
        [  --enable-debug-console enable debug messages on console ],
        [case "${enableval}" in
         yes) enable_debug_console="yes";;
          no) enable_debug_console="no" ;;
           *) AC_MSG_ERROR(bad value ${enableval} for --enable-debug-console) ;;
         esac],
        [enable_debug="no"]
)
if test "$enable_debug_console" = "yes"; then
        AC_DEFINE(_CONSOLE_, 1, [Defined if debug console mode is enabled.])        
fi
             
# Qualimetry
AC_ARG_WITH([counttool-dir],
  [AS_HELP_STRING([--with-counttool-dir],[location of the comptage tool directory (optional, default is $HOME/comptage)])],
  [COMPTAGE_ROOT="$withval"],
  [COMPTAGE_ROOT="$HOME/comptage"])
AC_SUBST(COMPTAGE_ROOT)
	
AC_CONFIG_FILES(Makefile 
	src/Makefile	
	)
AC_OUTPUT

