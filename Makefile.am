ACLOCAL_AMFLAGS=-I m4
SUBDIRS = inc
bin_SCRIPTS = scripts/bin/*

pyutilsdir=$(libdir)/opx
pyutils_SCRIPTS = scripts/lib/python/*.py

lib_LTLIBRARIES=libopx_hal_routing.la

libopx_hal_routing_la_SOURCES=src/hal_rt_arp.c src/hal_rt_host.c  src/hal_rt_mpath.c src/hal_rt_nh.c \
                              src/nas_rt_api.c src/nas_rt_nht.c src/hal_rt_debug.c  src/hal_rt_main.c \
                              src/hal_rt_mpath_grp.c src/hal_rt_route.c src/nas_rt_cps.c src/hal_rt_dr.c \
                              src/hal_rt_mem.c src/hal_rt_mpath_util.c src/hal_rt_util.cpp \
                              src/nas_rt_mac.cpp

libopx_hal_routing_la_CPPFLAGS= -D_FILE_OFFSET_BITS=64 -I$(top_srcdir)/inc/opx -I$(includedir)/opx

libopx_hal_routing_la_CXXFLAGS=-std=c++11

libopx_hal_routing_la_LDFLAGS=-shared -version-info 1:1:0

libopx_hal_routing_la_LIBADD=-lopx_nas_linux -lopx_nas_common -lopx_common -lopx_nas_ndi -lopx_cps_api_common -lopx_logging -lcrypto
