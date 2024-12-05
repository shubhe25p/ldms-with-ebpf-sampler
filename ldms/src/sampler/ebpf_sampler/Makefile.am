pkglib_LTLIBRARIES =
lib_LTLIBRARIES =
dist_man7_MANS =
dist_man1_MANS =

AM_CPPFLAGS = @OVIS_INCLUDE_ABS@
AM_LDFLAGS = @OVIS_LIB_ABS@
COMMON_LIBADD = ../libsampler_base.la \
		$(top_builddir)/ldms/src/core/libldms.la \
		@LDFLAGS_GETTIME@ \
		$(top_builddir)/lib/src/ovis_util/libovis_util.la \
		$(top_builddir)/lib/src/coll/libcoll.la
if HAVE_LIBBPF
libebpfsampler_la_SOURCES = ebpf_sampler.c
libebpfsampler_la_CFLAGS = -I$(LIB_BPF)/src
libebpfsampler_la_LIBADD = $(COMMON_LIBADD) -L$(LIB_BPF)/src -lbpf
pkglib_LTLIBRARIES += libebpfsampler.la
dist_man7_MANS += 
endif


