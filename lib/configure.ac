AC_INIT([uspe-client], [1.0], [arni@uplink-spe.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AM_PROG_AR
LT_PREREQ([2.4.0])
LT_INIT([dlopen])
AC_CONFIG_LIBOBJ_DIR([.])
AC_CONFIG_MACRO_DIR([m4])

AC_SEARCH_LIBS([dlopen], [dl], [], [
  AC_MSG_ERROR([unable to find the dlopen function])
])
XXFLAGS=-Wall

AC_CONFIG_FILES([
	Makefile
])
AC_OUTPUT

