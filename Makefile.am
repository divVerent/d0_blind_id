ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = blind_id
blind_id_SOURCES = main.c
blind_id_LDADD = libd0_blind_id.la

lib_LTLIBRARIES = libd0_blind_id.la
# versioninfo:
#   - compatible interface change: c:r:a -> c+1:0:a+1
#   - incompatible interface change: c:r:a -> c+1:0:0
#   - internal change: c:r:a -> c:r+1:a

libd0_blind_id_la_SOURCES = d0_blind_id.c d0.c d0_iobuf.c sha2.c \
                            d0_blind_id.h d0.h d0_iobuf.h sha2.h \
			    d0_bignum.h

if WITH_TOMMATH
libd0_blind_id_la_SOURCES += d0_bignum-tommath.c
else
if WITH_OPENSSL
libd0_blind_id_la_SOURCES += d0_bignum-openssl.c
else
libd0_blind_id_la_SOURCES += d0_bignum-gmp.c
endif
endif
libd0_blind_id_la_LDFLAGS = -versioninfo 6:0:6
libd0_blind_id_la_CFLAGS = -fvisibility=hidden -Wold-style-definition -Wstrict-prototypes -Wsign-compare -Wdeclaration-after-statement
library_includedir = $(includedir)/d0_blind_id
library_include_HEADERS = d0_blind_id.h d0.h
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_HEADERS = d0_blind_id.pc

if ENABLE_RIJNDAEL
lib_LTLIBRARIES += libd0_rijndael.la
libd0_rijndael_la_SOURCES = d0_rijndael.c \
                            d0_rijndael.h
libd0_rijndael_la_LDFLAGS = -versioninfo 0:0:0
libd0_rijndael_la_CFLAGS = -fvisibility=hidden -Wold-style-definition -Wstrict-prototypes -Wsign-compare -Wdeclaration-after-statement
library_include_HEADERS += d0_rijndael.h
pkgconfig_HEADERS += d0_rijndael.pc
endif

EXTRA_DIST = d0_blind_id.txt autogen.sh
