bin_PROGRAMS = blind_id
blind_id_SOURCES = main.c
blind_id_LDADD = libblind_id.la

lib_LTLIBRARIES = libblind_id.la
libblind_id_la_SOURCES = d0_bignum-gmp.c d0_blind_id.c d0.c d0_iobuf.c sha1.c
libblind_id_la_LDFLAGS = -versioninfo 0:0:0
# versioninfo:
#   - compatible interface change: c:r:a -> c+1:0:a+1
#   - incompatible interface change: c:r:a -> c+1:0:0
#   - internal change: c:r:a -> c:r+1:a

library_includedir = $(includedir)/d0_blind_id
library_include_HEADERS = d0_blind_id.h d0.h
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_HEADERS = d0_blind_id.pc
