AC_INIT([d0_blind_id], [0.1], [divVerent@alientrap.org])
AM_INIT_AUTOMAKE([-Wall foreign])
AC_PROG_CC
AM_PROG_LIBTOOL

AC_SEARCH_LIBS(clock_gettime, rt, , [AC_MSG_ERROR([GNU MP not found, see http://gmplib.org/])])
AC_SEARCH_LIBS(__gmpz_init, gmp, , [AC_MSG_ERROR([GNU MP not found, see http://gmplib.org/])])

dnl AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile d0_blind_id.pc])
AC_OUTPUT
