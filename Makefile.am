#
# Copyright (c) 2018 Dell Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
# LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
# FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
#
# See the Apache Version 2.0 License for specific language governing
# permissions and limitations under the License.
#

ACLOCAL_AMFLAGS=-I m4
SUBDIRS = inc
bin_SCRIPTS = scripts/bin/*

pyutilsdir=$(libdir)/opx
pyutils_SCRIPTS = scripts/lib/python/*.py

lib_LTLIBRARIES=libopx_hal_routing.la

COMMON_HARDEN_FLAGS=-fexceptions -fstack-protector-strong -fstack-protector-all -D_FORTIFY_SOURCE=2 -Wall -Wformat -Wformat-security -Werror
C_HARDEN_FLAGS=-Wimplicit-function-declaration
LD_HARDEN_FLAGS=-Wl,-z,defs -Wl,-z,now -Wl,-z,relo


libopx_hal_routing_la_SOURCES=src/hal_rt_arp.c src/hal_rt_host.c  src/hal_rt_mpath.c src/hal_rt_nh.c \
                              src/nas_rt_api.c src/nas_rt_nht.c src/hal_rt_debug.c  src/hal_rt_main.c \
                              src/hal_rt_mpath_grp.c src/hal_rt_route.c src/nas_rt_cps.c src/hal_rt_dr.c \
                              src/hal_rt_mem.c src/hal_rt_mpath_util.c src/hal_rt_util.cpp \
                              src/nas_rt_mac.cpp src/hal_rt_intf_util.c src/hal_rt_offload.cpp \
                              src/nas_rt_virt_routing.cpp src/hal_rt_leak.c

libopx_hal_routing_la_CPPFLAGS= -D_FILE_OFFSET_BITS=64 -I$(top_srcdir)/inc/opx -I$(includedir)/opx $(COMMON_HARDEN_FLAGS) -fPIC

libopx_hal_routing_la_CXXFLAGS=-std=c++11

libopx_hal_routing_la_CFLAGS=$(C_HARDEN_FLAGS)

libopx_hal_routing_la_LDFLAGS=-shared -version-info 1:1:0 $(LD_HARDEN_FLAGS)

libopx_hal_routing_la_LIBADD=-lopx_nas_linux -lopx_nas_common -lopx_common -lopx_nas_ndi -lopx_cps_api_common -lopx_logging -lcrypto -lpthread

bin_PROGRAMS=base_nbr_mgr_svc

base_nbr_mgr_svc_CXXFLAGS=-std=c++11

base_nbr_mgr_svc_SOURCES=nbr-mgr/src/nbr_mgr_main.cpp nbr-mgr/src/nbr_mgr_utils.cpp
base_nbr_mgr_svc_SOURCES+=nbr-mgr/src/nbr_mgr_cps.cpp nbr-mgr/src/nbr_mgr_msgq.cpp
base_nbr_mgr_svc_SOURCES+=nbr-mgr/src/nbr_mgr_proc.cpp nbr-mgr/src/nbr_mgr_timer.cpp nbr-mgr/src/nbr_mgr_debug.cpp
base_nbr_mgr_svc_SOURCES+=nbr-mgr/src/nbr_mgr_nl_evt.cpp nbr-mgr/src/nbr_mgr_rslv.cpp

base_nbr_mgr_svc_LDADD=-lopx_nas_linux -lopx_common -lopx_logging -lopx_cps_api_common -lsystemd

base_nbr_mgr_svc_CPPFLAGS=-I$(top_srcdir)/inc/opx -I$(top_srcdir)/inc/opx/nbr-mgr -I$(includedir)/opx $(COMMON_HARDEN_FLAGS)
base_nbr_mgr_svc_CFLAGS=$(C_HARDEN_FLAGS)
base_nbr_mgr_svc_LDFLAGS=$(LD_HARDEN_FLAGS)

systemdconfdir=/lib/systemd/system
systemdconf_DATA = scripts/init/*.service

