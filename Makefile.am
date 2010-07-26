ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = blind_id
blind_id_SOURCES = main.c
blind_id_LDADD = libd0_blind_id.la

lib_LTLIBRARIES = libd0_blind_id.la libd0_rijndael.la
# versioninfo:
#   - compatible interface change: c:r:a -> c+1:0:a+1
#   - incompatible interface change: c:r:a -> c+1:0:0
#   - internal change: c:r:a -> c:r+1:a

libd0_blind_id_la_SOURCES = d0_bignum-gmp.c d0_blind_id.c d0.c d0_iobuf.c sha2.c
libd0_blind_id_la_LDFLAGS = -versioninfo 2:0:2
libd0_blind_id_la_CFLAGS = -fvisibility=hidden -Wold-style-definition -Wstrict-prototypes -Wsign-compare -Wdeclaration-after-statement

libd0_rijndael_la_SOURCES = d0_rijndael.c
libd0_rijndael_la_LDFLAGS = -versioninfo 0:0:0
libd0_rijndael_la_CFLAGS = -fvisibility=hidden -Wold-style-definition -Wstrict-prototypes -Wsign-compare -Wdeclaration-after-statement

library_includedir = $(includedir)/d0_blind_id
library_include_HEADERS = d0_blind_id.h d0.h d0_rijndael.h
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_HEADERS = d0_blind_id.pc
