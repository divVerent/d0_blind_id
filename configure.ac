AC_INIT([d0_blind_id], [0.1], [divVerent@alientrap.org])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall foreign])
AC_PROG_CC
AC_PROG_LIBTOOL

AC_SEARCH_LIBS(__gmpz_init, gmp, , [AC_MSG_ERROR([GNU MP not found, see http://gmplib.org/])])

AC_ARG_ENABLE(rijndael, AS_HELP_STRING([--disable-rijndael], [Disable build of the d0_rijndael library]), [enable_aes=$enableval], [enable_aes=yes])
AM_CONDITIONAL(ENABLE_RIJNDAEL, [test x$enable_aes = xyes])

dnl AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile d0_blind_id.pc])
AC_OUTPUT
