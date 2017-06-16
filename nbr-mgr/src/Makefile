PROGRAMS=base_nbr_mgr_svc

CXXFLAGS+=-std=c++11

base_nbr_mgr_svc_SRCS=nbr_mgr_main.cpp
base_nbr_mgr_svc_SRCS+=nbr_mgr_utils.cpp
base_nbr_mgr_svc_SRCS+=nbr_mgr_cps.cpp
base_nbr_mgr_svc_SRCS+=nbr_mgr_msgq.cpp
base_nbr_mgr_svc_SRCS+=nbr_mgr_proc.cpp
base_nbr_mgr_svc_SRCS+=nbr_mgr_timer.cpp
base_nbr_mgr_svc_SRCS+=nbr_mgr_nl_evt.cpp
base_nbr_mgr_svc_SRCS+=nbr_mgr_rslv.cpp


base_nbr_mgr_svc_CPPFLAGS=-I${BUILD_CURDIR} -I../inc
base_nbr_mgr_svc_LDFLAGS=-ldb-api -ldn_common -levent_log -lcps-api-common -lsystemd

include ${MAKE_INC}/workspace.mak

