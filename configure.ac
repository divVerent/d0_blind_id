AC_INIT([d0_blind_id],[0.5],[divVerent@xonotic.org])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall foreign])
AC_PROG_CC
AM_PROG_AR
LT_INIT

AC_ARG_WITH(openssl, AS_HELP_STRING([--with-openssl], [Use OpenSSL instead of GMP (beware of the OpenSSL license)]), [with_openssl=$withval], [with_openssl=no])
AC_ARG_WITH(tommath, AS_HELP_STRING([--with-tommath], [Use libtommath instead of GMP (slow, but WTFPL)]), [with_tommath=$withval], [with_tommath=no])
AC_ARG_WITH(tfm, AS_HELP_STRING([--with-tfm], [Use tfm (TomsFastMath) instead of GMP (PD)]), [with_tfm=$withval], [with_tfm=no])
AM_CONDITIONAL(WITH_OPENSSL, [test x"$with_openssl" != xno])
AM_CONDITIONAL(WITH_TOMMATH, [test x"$with_tommath" != xno])
AM_CONDITIONAL(WITH_TOMSFASTMATH, [test x"$with_tfm" != xno])

AS_IF([test x"$with_tommath" != xno],
	[AC_SEARCH_LIBS(mp_init, tommath, ,
		[AC_MSG_ERROR([libtommath not found, see http://www.libtom.org/, or try --without-tommath])])],
	[AS_IF([test x"$with_tfm" != xno],
		[AC_SEARCH_LIBS(fp_ident, tfm, ,
			[AC_MSG_ERROR([libtfm not found, see http://www.libtom.org/, or try --without-tfm])])],
		[AS_IF([test x"$with_openssl" != xno],
			[AC_SEARCH_LIBS(BN_init, crypto, ,
				[AC_MSG_ERROR([OpenSSL not found, see http://www.openssl.org/, or try --without-openssl])])],
			[AC_SEARCH_LIBS(__gmpz_init, gmp, ,
				[AC_MSG_ERROR([GNU MP not found, see http://gmplib.org/, or try --with-openssl])])])])])

AC_ARG_ENABLE(rijndael, AS_HELP_STRING([--disable-rijndael], [Disable build of the d0_rijndael library]), [enable_aes=$enableval], [enable_aes=yes])

AS_IF([test -f "$srcdir/d0_rijndael.c"], [], [AS_IF([test x"$enable_aes" != xno], [AC_MSG_ERROR([d0_rijndael.c is missing, try --disable-rijndael or download the full version of this library, but beware of crypto import laws then])])])
AM_CONDITIONAL(ENABLE_RIJNDAEL, [test x$enable_aes = xyes])

AC_CONFIG_FILES([Makefile d0_blind_id.pc d0_rijndael.pc])

AC_OUTPUT
