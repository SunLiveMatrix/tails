## Process this file with automake to produce Makefile.in

## Created by Anjuta

AM_CPPFLAGS = \
	-DPACKAGE_LOCALE_DIR=\""$(localedir)"\" \
	-DPACKAGE_SRC_DIR=\""$(srcdir)"\" \
	-DPACKAGE_DATA_DIR=\""$(pkgdatadir)"\" \
	$(TAILS_CFLAGS)

AM_CFLAGS =\
	 -Wall\
	 -g

lib_LTLIBRARIES = libtails.la


libtails_la_SOURCES = \
	lib.c

libtails_la_LDFLAGS = 

libtails_la_LIBADD = $(TAILS_LIBS)


if PLATFORM_WIN32
libtails_la_LDFLAGS += -no-undefined
endif

if NATIVE_WIN32
libtails_la_LDFLAGS += -export-dynamic
endif

include_HEADERS = \
	tails.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = tails-0.1.pc

EXTRA_DIST = \
	tails-0.1.pc.in
