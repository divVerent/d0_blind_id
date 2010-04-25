AC_INIT([d0_blind_id], [0.1], [divVerent@alientrap.org])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall foreign])
AC_PROG_CC
AC_PROG_LIBTOOL

AC_SEARCH_LIBS(__gmpz_init, gmp, , [AC_MSG_ERROR([GNU MP not found, see http://gmplib.org/])])

dnl AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile d0_blind_id.pc])
AC_OUTPUT
