AC_INIT([d0_blind_id], [0.2], [divVerent@xonotic.org])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall foreign])
AC_PROG_CC
AC_PROG_LIBTOOL

AC_ARG_WITH(openssl, AS_HELP_STRING([--with-openssl], [Use OpenSSL instead of GMP (beware of the OpenSSL license)]), [with_openssl=$withval], [with_openssl=no])
AM_CONDITIONAL(WITH_OPENSSL, [test x"$with_openssl" != xno])

AS_IF([test x"$with_openssl" != xno],
	[AC_SEARCH_LIBS(BN_init, crypto, ,
		[AC_MSG_ERROR([OpenSSL not found, see http://www.openssl.org/, or try --without-openssl])])],
	[AC_SEARCH_LIBS(__gmpz_init, gmp, ,
		[AC_MSG_ERROR([GNU MP not found, see http://gmplib.org/, or try --with-openssl])])])

AC_ARG_ENABLE(rijndael, AS_HELP_STRING([--disable-rijndael], [Disable build of the d0_rijndael library]), [enable_aes=$enableval], [enable_aes=yes])

AS_IF([test -f d0_rijndael.c], [], [AS_IF([test x"$enable_aes" != x"no"], [AC_MSG_ERROR([d0_rijndael.c is missing, try --disable-rijndael or download the full version of this library, but beware of crypto import laws then])])])
AM_CONDITIONAL(ENABLE_RIJNDAEL, [test x$enable_aes = xyes])

AC_CONFIG_FILES([Makefile d0_blind_id.pc d0_rijndael.pc])

AC_OUTPUT
