/*
 * Copyright (c) 2018 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 * LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 * FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
 *
 * See the Apache Version 2.0 License for specific language governing
 * permissions and limitations under the License.
 */

/*!
 * \file   hal_rt_main.h
 * \brief  Hal Routing Core functionality
 * \date   05-2014
 * \author Prince Sunny & Satish Mynam
 */

#ifndef __HAL_RT_MAIN_H__
#define __HAL_RT_MAIN_H__

#include "std_radical.h"
#include "std_radix.h"
#include "ds_common_types.h"
#include "nas_ndi_route.h"
#include "nas_ndi_router_interface.h"
#include "std_llist.h"
#include "std_mutex_lock.h"
#include "cps_api_interface_types.h"
#include "nas_vrf_utils.h"

#include <stdbool.h>
#include <sys/socket.h>
#include "event_log.h"

#define HAL_RT_MAC_ADDR_LEN               HAL_MAC_ADDR_LEN
#define HAL_RT_V4_ADDR_LEN                HAL_INET4_LEN
#define HAL_RT_V6_ADDR_LEN                HAL_INET6_LEN
#define HAL_RT_V4_AFINDEX                 HAL_INET4_FAMILY
#define HAL_RT_V6_AFINDEX                 HAL_INET6_FAMILY
#define HAL_RT_MAX_VALID_AF_CNT           2
#define HAL_RT_MAX_INSTANCE               1
#define HAL_RT_V4_PREFIX_LEN              (8 * HAL_INET4_LEN)
#define HAL_RT_V6_PREFIX_LEN              (8 * HAL_INET6_LEN)
#define HAL_RT_MAX_ECMP_PATH              NDI_MAX_NH_ENTRIES_PER_GROUP   /* Maximum supported ECMP paths per Group */
#define FIB_MIN_AFINDEX                   HAL_RT_V4_AFINDEX
#define FIB_MAX_AFINDEX                   (HAL_RT_V6_AFINDEX + 1)
/* The current neighbor reachable time is 1 hour, if the below variable changes,
 * update the below macro accordingly.
 * /etc/sysctl.d/dn-ip.conf -
 * net.ipv4.neigh.default.base_reachable_time_ms=3600000
 * */
#define HAL_RT_NBR_TIMEOUT                (3600 *3)/2 /* Max. neighbor reachable time - 90mins */

#define FIB_IS_AFINDEX_VALID(af)         (((af >= FIB_MIN_AFINDEX) && (af < FIB_MAX_AFINDEX)) ? true : false)

#define FIB_RT_NH_FLAGS_ONLINK 1

enum _rt_proto {
    // Direct routes.
    RT_CONNECTED = 1,
    // Kernel routes
    RT_KERNEL,
    // Static mroutes.
    RT_MSTATIC,
    // Static routes.
    RT_STATIC,
    // OSPF routes.
    RT_OSPF,
    // IS-IS routes.
    RT_ISIS,
    // BGP routes.
    RT_MBGP,
    // BGP routes.
    RT_BGP,
    // RIP routes.
    RT_RIP,
    // MPLS routes.
    RT_MPLS,
    // MAX value for range check. MUST BE LAST.
    RT_PROTO_MAX,
};

typedef enum _rt_type {
    RT_UNSPEC = 0,
    RT_UNICAST,
    RT_LOCAL,
    RT_BROADCAST,
    RT_ANYCAST,
    RT_MULTICAST,
    RT_BLACKHOLE,
    RT_UNREACHABLE,
    RT_PROHIBIT,
    /* Add the standard rtm_type above this line */
    RT_CACHE, // Cache only, dont program it in the NPU
    // MAX value for range check. MUST BE LAST.
    RT_TYPE_MAX,
} t_rt_type;

enum {
    RT_INTF_ADMIN_STATUS_NONE,
    RT_INTF_ADMIN_STATUS_UP,
    RT_INTF_ADMIN_STATUS_DOWN
};

/* interface events for route/nh processing */
typedef enum _t_fib_intf_event_type {
    FIB_INTF_ADMIN_EVENT = 1,
    FIB_INTF_MODE_CHANGE_EVENT,
    FIB_INTF_FORCE_DEL
} t_fib_intf_event_type;

/* ARP/ND status */
#define RT_NUD_INCOMPLETE 0x01
#define RT_NUD_REACHABLE  0x02
#define RT_NUD_STALE      0x04
#define RT_NUD_DELAY      0x08
#define RT_NUD_PROBE      0x10
#define RT_NUD_FAILED     0x20
#define RT_NUD_NOARP      0x40
#define RT_NUD_PERMANENT  0x80
#define RT_NUD_NONE          0x00

typedef enum _t_fib_rt_msg_type {
    FIB_RT_MSG_ADD = 1,
    FIB_RT_MSG_DEL,
    FIB_RT_MSG_UPD
} t_fib_rt_msg_type;

typedef enum _rt_proto rt_proto;

typedef hal_ip_addr_t t_fib_ip_addr;

typedef struct _t_fib_audit_host_key {
    hal_vrf_id_t  vrf_id;
    t_fib_ip_addr ip_addr;
} t_fib_audit_host_key;

typedef struct _t_fib_audit_cfg {
    uint32_t interval;   /* Time interval in minutes */
} t_fib_audit_cfg;

typedef struct _t_fib_audit_route_key {
    hal_vrf_id_t      vrf_id;
    t_fib_ip_addr     prefix;
    uint8_t           prefix_len;
} t_fib_audit_route_key;

typedef struct _t_fib_route_summary {
    uint32_t         a_curr_count [HAL_RT_V6_PREFIX_LEN + 1];
} t_fib_route_summary;

typedef enum {
    HAL_RT_STATUS_ECMP,
    HAL_RT_STATUS_NON_ECMP,
    HAL_RT_STATUS_ECMP_INVALID
} t_fib_ecmp_status;

typedef struct _t_fib_link_node {
    std_dll  glue;
    void    *self;
} t_fib_link_node;

typedef struct _t_fib_config {
    uint32_t         max_num_npu;
    uint32_t         ecmp_max_paths;
    bool             ecmp_path_fall_back;
    uint8_t          ecmp_hash_sel;
} t_fib_config;

typedef struct _t_fib_gbl_info {
    uint32_t         num_tot_msg;
    uint32_t         num_int_msg;
    uint32_t         num_err_msg;
    uint32_t         num_route_msg;
    uint32_t         num_nei_msg;
    uint32_t         num_unk_msg;
    uint32_t         num_ip_msg;
    hal_mac_addr_t   base_mac_addr;
    bool             resilient_hash;
    std_rt_table     *leaked_rt_tree;  /* Each node in the tree is of type t_fib_leaked_rt */
} t_fib_gbl_info;

typedef struct _t_fib_tnl_key {
    hal_ifindex_t if_index;
    hal_vrf_id_t  vrf_id;
} t_fib_tnl_key;

typedef struct _t_fib_tnl_dest {
    std_rt_head    rt_head;
    t_fib_tnl_key  key;
    t_fib_ip_addr  dest_addr;
} t_fib_tnl_dest;

typedef struct _t_fib_dr_msg_info {
    hal_vrf_id_t   vrf_id;
    t_fib_ip_addr  prefix;
    uint8_t        prefix_len;
    rt_proto       proto;
    t_rt_type      rt_type;
} t_fib_dr_msg_info;

typedef struct _t_fib_nh_msg_info {
    hal_vrf_id_t   vrf_id;
    t_fib_ip_addr  ip_addr;
    hal_ifindex_t  if_index;
    uint32_t       flags;
    bool           is_nh_vrf_present;
} t_fib_nh_msg_info;

typedef struct _t_fib_arp_msg_info {
    hal_vrf_id_t   vrf_id;
    t_fib_ip_addr  ip_addr;
    hal_ifindex_t  if_index;
    uint8_t        mac_addr [HAL_RT_MAC_ADDR_LEN];
    uint32_t       out_if_index;
    uint8_t        is_l2_fh;
    uint8_t        status;
} t_fib_arp_msg_info;

typedef enum {
    FIB_AUDIT_NOT_STARTED,
    FIB_AUDIT_STARTED,
} t_fib_audit_status;

typedef struct _t_fib_audit {
    t_fib_audit_cfg     curr_cfg;
    t_fib_audit_cfg     next_cfg;
    t_fib_audit_status  status;
    uint8_t             enabled;
    uint8_t             af_index;
    uint8_t             to_be_stopped;
    uint8_t            is_first;
    uint8_t             hw_pass_over;
    uint8_t             sw_pass_over;
    uint32_t            num_audits_completed;
    uint64_t            last_audit_start_time;
    uint64_t            last_audit_end_time;
    uint64_t            last_audit_wake_up_time;
} t_fib_audit;

typedef struct _t_fib_vrf_info {
    hal_vrf_id_t        vrf_id;
    uint8_t             vrf_name [NAS_VRF_NAME_SZ + 1];
    uint8_t             af_index;
    bool                is_vrf_created;
    std_rt_table       *dr_tree;  /* Each node in the tree is of type t_fib_dR */
    std_rt_table       *nh_tree;  /* Each node in the tree is of type t_fib_nH */
    std_rt_table       *mp_md5_tree;  /* Each node in the tree is of type t_fib_mp_obj */
    std_rt_table       *nht_tree;  /* Each node in the tree is of type t_fib_nht */
    std_radical_ref_t   dr_radical_marker;
    std_radical_ref_t   nh_radical_marker;
    uint32_t            num_dr_processed_by_walker;
    uint32_t            num_nh_processed_by_walker;
    bool                clear_ip_fib_on;
    bool                clear_ip_route_on;
    bool                clear_arp_on;
    bool                dr_clear_on;
    bool                nh_clear_on;
    std_radix_version_t dr_clear_max_radix_ver;
    std_radix_version_t nh_clear_max_radix_ver;
    bool                dr_ha_on;
    bool                nh_ha_on;
    bool                is_catch_all_disabled;
    std_radix_version_t dr_ha_max_radix_ver;
    std_radix_version_t nh_ha_max_radix_ver;
    t_fib_route_summary route_summary;
    uint32_t            event_filter_info;
} t_fib_vrf_info;

typedef struct _t_fib_vrf_cntrs {
    uint32_t  num_route_add;
    uint32_t  num_route_del;
    uint32_t  num_vrf_add;
    uint32_t  num_vrf_del;
    uint32_t  num_route_clear;
    uint32_t  num_nbr_add;
    uint32_t  num_nbr_add_incomplete;
    uint32_t  num_nbr_add_reachable;
    uint32_t  num_nbr_add_stale;
    uint32_t  num_nbr_add_delay;
    uint32_t  num_nbr_add_probe;
    uint32_t  num_nbr_add_failed;
    uint32_t  num_nbr_add_permanent;
    uint32_t  num_nbr_add_noarp;
    uint32_t  num_nbr_del;
    uint32_t  num_nbr_resolving;
    uint32_t  num_nbr_un_rslvd;
    uint32_t  num_nbr_clear;
    uint32_t  num_unknown_msg;
    uint32_t  num_fib_host_entries;
    uint32_t  num_fib_route_entries;
    uint32_t  num_cam_host_entries;
    uint32_t  num_cam_route_entries;
    uint32_t  num_nht_entries;
    uint32_t  num_catch_all_intf_entries;
} t_fib_vrf_cntrs;

typedef struct _nas_rt_peer_mac_config_t{
    hal_vrf_id_t     vrf_id;
    char             if_name[HAL_IF_NAME_SZ];
    hal_mac_addr_t   mac;
    bool             ingress_only;
    ndi_vrf_id_t     vrf_obj_id; /* NDI VRF handle */
    ndi_rif_id_t     rif_obj_id; /* NDI RIF handle */
}nas_rt_peer_mac_config_t;

typedef struct _nas_rt_virtual_routing_ip_config_t{
    hal_vrf_id_t     vrf_id;
    char             vrf_name[NAS_VRF_NAME_SZ + 1];
    char             if_name[HAL_IF_NAME_SZ];
    hal_ip_addr_t    ip_addr;
}nas_rt_virtual_routing_ip_config_t;

typedef struct _t_fib_vrf {
    hal_vrf_id_t     vrf_id;
    ndi_vrf_id_t     vrf_obj_id;
    t_fib_vrf_info   info [FIB_MAX_AFINDEX];
    t_fib_vrf_cntrs  cntrs [FIB_MAX_AFINDEX];
    hal_mac_addr_t   router_mac; /* VRF router MAC */
} t_fib_vrf;

typedef enum _t_fib_cmp_result {
    FIB_CMP_RESULT_EQUAL = 1,
    FIB_CMP_RESULT_NOT_EQUAL = 2,
} t_fib_cmp_result;

typedef enum {
    FIB_MSG_TYPE_NL_INTF = 1, /* Admin status notification from the kernel */
    FIB_MSG_TYPE_NBR_MGR_INTF, /* Admin status notification from the Nbr mgr */
    FIB_MSG_TYPE_NL_ROUTE, /* Route notification from the kernel */
    FIB_MSG_TYPE_NBR_MGR_NBR_INFO, /* Nbr notification from the Nbr mgr */
    FIB_MSG_TYPE_NL_NBR,
    FIB_MSG_TYPE_INTF_IP_UNREACH_CFG, /* IP unreachable configuration from the user */
    FIB_MSG_TYPE_INTF_IP_REDIRECTS_CFG, /* IP redirects configuration from the user */
    FIB_MSG_TYPE_NEIGH_FLUSH /* IP neighbor flush mainly for the leaked ARPs/Neighbors from the user */
} t_fib_msg_type;

typedef struct  {
    unsigned short  family;
    t_fib_rt_msg_type msg_type;
    hal_ip_addr_t         nbr_addr;
    hal_mac_addr_t      nbr_hwaddr;
    hal_ifindex_t   if_index;
    hal_ifindex_t   parent_if;
    hal_ifindex_t   mbr_if_index; /* VLAN member port - physical/LAG */
    unsigned long   vrfid;
    uint8_t         vrf_name[NAS_VRF_NAME_SZ + 1];
    unsigned long   expire;
    unsigned long   flags;
    unsigned long   status;
} t_fib_neighbour_entry;

/* WECMP nh_list*/
typedef struct {
    hal_ifindex_t   nh_if_index;
    hal_ip_addr_t   nh_addr;
    uint32_t         nh_weight;
    uint32_t        nh_flags;
} t_fib_nh_info;

typedef struct  {
    t_fib_rt_msg_type msg_type;
    unsigned short  distance;
    unsigned short  protocol;
    unsigned long   vrfid;
    uint8_t         vrf_name[NAS_VRF_NAME_SZ + 1];
    hal_ip_addr_t       prefix;
    unsigned short      prefix_masklen;
    t_rt_type       rt_type;
    hal_ifindex_t   nh_if_index;
    unsigned long   nh_vrfid;
    uint8_t         nh_vrf_name[NAS_VRF_NAME_SZ + 1];
    hal_ip_addr_t         nh_addr;
    size_t hop_count;
    bool            is_nh_vrf_present; /* This is helpful to know
                                          whether the nh_vrfid value is filled or not. */

    /* variable size buffer to hold nh_list based on
     * the hop_count in received route event.
     */
    t_fib_nh_info nh_list[0];
} t_fib_route_entry;

typedef struct {
    hal_ifindex_t if_index;
    int admin_status;
    bool is_op_del;
    hal_mac_addr_t mac_addr;
    unsigned long  vrf_id;
    char if_name[HAL_IF_NAME_SZ]; /* interface name */
} t_fib_intf_entry;

/* IP unreachable msg to be generated
   from this interface for the non-routable
   packets in the kernel. */
typedef struct {
    hal_ifindex_t if_index;
    char          if_name[HAL_IF_NAME_SZ];
    char          vrf_name[NAS_VRF_NAME_SZ + 1];
    uint8_t af_index; /* This indicates IP unreachable to be generated
                         from the kernel for which address family (IPv4/IPv6) */
    bool is_op_del;
} t_fib_intf_ip_unreach_config;

/* IP redirects to be generated from this interface
   for the packets routed in the kernel when incoming and outgoing
   interfaces are same. */
typedef struct {
    hal_ifindex_t if_index;
    char          if_name[HAL_IF_NAME_SZ];
    char          vrf_name[NAS_VRF_NAME_SZ + 1];
    bool          is_op_del;
} t_fib_intf_ip_redirects_config;

typedef struct {
    unsigned long  vrf_id;
    uint32_t af_index;
    hal_ifindex_t if_index;
} t_fib_neigh_flush;

typedef struct {
    t_fib_msg_type type;
    union {
        t_fib_route_entry route;
        t_fib_neighbour_entry nbr;
        t_fib_intf_entry intf;
        t_fib_intf_ip_unreach_config     ip_unreach_cfg;
        t_fib_intf_ip_redirects_config   ip_redirects_cfg;
        t_fib_neigh_flush neigh_flush;
    };
} t_fib_msg;


typedef enum {
    FIB_OFFLOAD_MSG_TYPE_NEIGH_FLUSH = 1, /* Neighbor flush to kernel */
} t_fib_offload_msg_type;

/* Neighbor flush msg to be triggered to Kernel for the
   given interface and/or IP prefix/len. */
typedef struct {
    hal_vrf_id_t    vrf_id;
    hal_ifindex_t   if_index;
    t_fib_ip_addr   prefix;
    bool            is_neigh_flush_with_intf;
    char             vrf_name[NAS_VRF_NAME_SZ + 1];
    uint8_t         prefix_len;
} t_fib_offload_msg_neigh_flush;

typedef struct {
    t_fib_offload_msg_type type;
    union {
        t_fib_offload_msg_neigh_flush neigh_flush_msg;
    };
} t_fib_offload_msg;

t_fib_msg * hal_rt_alloc_mem_msg();
t_fib_msg *hal_rt_alloc_route_mem_msg(uint32_t buf_size);
void hal_rt_free_route_mem_msg(t_fib_msg *pmsg);
void hal_rt_cps_obj_to_neigh(cps_api_object_t obj, t_fib_neighbour_entry *n);
bool hal_rt_cps_obj_to_route(cps_api_object_t obj, t_fib_msg **p_msg_ret, bool is_app_flow);
bool hal_rt_cps_obj_to_route_nexthop(cps_api_object_t obj, t_fib_msg **p_msg_ret);
bool hal_rt_ip_addr_cps_obj_to_route (cps_api_object_t obj, t_fib_msg **p_msg_ret);
bool hal_rt_cps_obj_to_intf(cps_api_object_t obj, t_fib_intf_entry *p_intf);

t_fib_offload_msg *hal_rt_alloc_offload_msg();

#define FIB_RDX_MAX_NAME_LEN           64
#define FIB_DEFAULT_ECMP_HASH          0
#define RT_PER_TLV_MAX_LEN             (2 * (sizeof(unsigned long)))
#define FIB_RDX_INTF_KEY_LEN           (8 * (sizeof (t_fib_intf_key)))
#define FIB_RDX_NHT_KEY_LEN           (8 * (sizeof (t_fib_nht_key)))
#define FIB_RDX_LEAKED_RT_KEY_LEN     (8 * (sizeof (t_fib_leaked_rt_key)))


/* Common Data Structures */
#define FIB_DEFAULT_VRF                NAS_DEFAULT_VRF_ID
#define FIB_DEFAULT_VRF_NAME           NAS_DEFAULT_VRF_NAME
#define FIB_MGMT_VRF_NAME              NAS_MGMT_VRF_NAME

#define FIB_MIN_VRF                    NAS_MIN_VRF_ID
#define FIB_MGMT_VRF                   NAS_MGMT_VRF_ID
#define FIB_MAX_VRF                    (NAS_MAX_VRF_ID + 1)

#define FIB_GET_VRF(_vrf_id)                                 \
        (hal_rt_access_fib_vrf(_vrf_id))

#define FIB_IS_VRF_ID_VALID(_vrf_id)   (((_vrf_id) < FIB_MAX_VRF) && FIB_GET_VRF(_vrf_id))
#define FIB_IS_MGMT_ROUTE(_vrf_id, _dr)   (((_vrf_id) == FIB_MGMT_VRF) || ((_dr)->is_mgmt_route))
#define FIB_IS_MGMT_NH(_vrf_id, _nh)   (((_vrf_id) == FIB_MGMT_VRF) || ((_nh)->is_mgmt_nh))

#define FIB_MASK_V6_BYTES(_p_ip_addr1, _p_ip_addr2, _p_mask, _index)           \
        ((((_p_ip_addr1)->u.v6_addr[(_index)] &                                \
           ((_p_mask)->u.v6_addr[(_index)])) ==                                \
          ((_p_ip_addr2)->u.v6_addr[(_index)] &                                \
           ((_p_mask)->u.v6_addr[(_index)]))))

#define FIB_IS_IP_ADDR_IN_PREFIX(_p_prefix, _p_mask, _p_ip_addr)               \
        (((_p_prefix)->af_index == HAL_RT_V4_AFINDEX) ?                        \
         (FIB_IS_V4_ADDR_IN_PREFIX ((_p_prefix), (_p_mask), (_p_ip_addr))) :   \
         (FIB_IS_V6_ADDR_IN_PREFIX ((_p_prefix), (_p_mask), (_p_ip_addr))))

#define FIB_IS_V4_ADDR_IN_PREFIX(_p_prefix, _p_mask, _p_ip_addr)               \
        ((((_p_prefix)->u.v4_addr) & ((_p_mask)->u.v4_addr)) ==                \
         (((_p_ip_addr)->u.v4_addr) & ((_p_mask)->u.v4_addr)))

#define FIB_IS_V6_ADDR_IN_PREFIX(_p_prefix, _p_mask, _p_ip_addr)               \
        ((FIB_MASK_V6_BYTES(_p_prefix, _p_ip_addr, _p_mask, 0))  &&            \
         (FIB_MASK_V6_BYTES(_p_prefix, _p_ip_addr, _p_mask, 1))  &&            \
         (FIB_MASK_V6_BYTES(_p_prefix, _p_ip_addr, _p_mask, 2))  &&            \
         (FIB_MASK_V6_BYTES(_p_prefix, _p_ip_addr, _p_mask, 3))  &&            \
         (FIB_MASK_V6_BYTES(_p_prefix, _p_ip_addr, _p_mask, 4))  &&            \
         (FIB_MASK_V6_BYTES(_p_prefix, _p_ip_addr, _p_mask, 5))  &&            \
         (FIB_MASK_V6_BYTES(_p_prefix, _p_ip_addr, _p_mask, 6))  &&            \
         (FIB_MASK_V6_BYTES(_p_prefix, _p_ip_addr, _p_mask, 7))  &&            \
         (FIB_MASK_V6_BYTES(_p_prefix, _p_ip_addr, _p_mask, 8))  &&            \
         (FIB_MASK_V6_BYTES(_p_prefix, _p_ip_addr, _p_mask, 9))  &&            \
         (FIB_MASK_V6_BYTES(_p_prefix, _p_ip_addr, _p_mask, 10)) &&            \
         (FIB_MASK_V6_BYTES(_p_prefix, _p_ip_addr, _p_mask, 11)) &&            \
         (FIB_MASK_V6_BYTES(_p_prefix, _p_ip_addr, _p_mask, 12)) &&            \
         (FIB_MASK_V6_BYTES(_p_prefix, _p_ip_addr, _p_mask, 13)) &&            \
         (FIB_MASK_V6_BYTES(_p_prefix, _p_ip_addr, _p_mask, 14)) &&            \
         (FIB_MASK_V6_BYTES(_p_prefix, _p_ip_addr, _p_mask, 15)))


/* Macros to get/traverse the DLLs nodes in HAL Routing data structures */

#define FIB_DLL_GET_FIRST(_p_dll_head) std_dll_getfirst(_p_dll_head)

#define FIB_DLL_GET_NEXT(_p_dll_head, _p_dll)  \
        (((_p_dll) != NULL) ? std_dll_getnext((_p_dll_head), (_p_dll)) : NULL)

#define FIB_IS_AFINDEX_V6(_af_index)                                        \
        (((_af_index) == HAL_RT_V6_AFINDEX))

#define FIB_AFINDEX_TO_PREFIX_LEN(_af_index)                                \
        (((_af_index) == HAL_RT_V4_AFINDEX) ?                                  \
         HAL_RT_V4_PREFIX_LEN : HAL_RT_V6_PREFIX_LEN)

#define HAL_RT_ADDR_FAM_TO_AFINDEX(_family)                                 \
        (((_family) == AF_INET) ?                                           \
         HAL_RT_V4_AFINDEX : HAL_RT_V6_AFINDEX)

#define FIB_PORT_TYPE_VAL_TO_STR(_port_type, _if_index)                          \
        (((_port_type) == FIB_FH_PORT_TYPE_CPU) ? "Cpu" :                       \
        (((_port_type) == FIB_FH_PORT_TYPE_BLK_HOLE) ? "Black_hole" :            \
         (((_port_type) == FIB_FH_PORT_TYPE_ARP) ? FIB_IFINDEX_TO_STR(_if_index):\
          "Invalid")))

#define FIB_IS_PREFIX_LEN_VALID(_af_index, _prefix_len)                      \
        (((_prefix_len)) <= FIB_AFINDEX_TO_PREFIX_LEN ((_af_index)))

#define FIB_GET_VRF_INFO(_vrf_id, _af_index)                                 \
        (hal_rt_access_fib_vrf_info(_vrf_id, _af_index))

#define FIB_IS_VRF_CREATED(_vrf_id, _af_index)                               \
        (((hal_rt_access_fib_vrf_info(_vrf_id, _af_index))->is_vrf_created) == true)

#define FIB_IS_EVENT_FILTER_ENABLED(_vrf_id, _af_index, event_filter)  \
        (((hal_rt_access_fib_vrf_info(_vrf_id, _af_index))->event_filter_info) & event_filter)

#define FIB_GET_ROUTE_SUMMARY(_vrf_id, _af_index)                            \
        (&((hal_rt_access_fib_vrf_info(_vrf_id, _af_index))->route_summary))

#define FIB_INCR_CNTRS_TOTAL_MSGS(_vrf_id, _af_index)                     \
        (((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_total_msgs)++)
#define FIB_INCR_CNTRS_ROUTE_ADD(_vrf_id, _af_index)                     \
        (((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_route_add)++)

#define FIB_INCR_CNTRS_ROUTE_DEL(_vrf_id, _af_index)                     \
        (((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_route_del)++)

#define FIB_INCR_CNTRS_VRF_ADD(_vrf_id, _af_index)                       \
        (((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_vrf_add)++)

#define FIB_INCR_CNTRS_VRF_DEL(_vrf_id, _af_index)                       \
        (((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_vrf_del)++)

#define FIB_INCR_CNTRS_ROUTE_CLR(_vrf_id, _af_index)                     \
        (((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_route_clear)++)

#define FIB_INCR_CNTRS_UNKNOWN_MSG(_vrf_id, _af_index)                   \
        (((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_unknown_msg)++)

#define FIB_INCR_CNTRS_NBR_ADD(_vrf_id, _af_index)                          \
        (((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_nbr_add)++)

#define FIB_INCR_CNTRS_NBR_ADD_INCOMPLETE(_vrf_id, _af_index)                          \
        (((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_nbr_add_incomplete)++)

#define FIB_INCR_CNTRS_NBR_ADD_REACHABLE(_vrf_id, _af_index)                          \
        (((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_nbr_add_reachable)++)

#define FIB_INCR_CNTRS_NBR_ADD_STALE(_vrf_id, _af_index)                          \
        (((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_nbr_add_stale)++)

#define FIB_INCR_CNTRS_NBR_ADD_DELAY(_vrf_id, _af_index)                          \
        (((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_nbr_add_delay)++)

#define FIB_INCR_CNTRS_NBR_ADD_PROBE(_vrf_id, _af_index)                          \
        (((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_nbr_add_probe)++)

#define FIB_INCR_CNTRS_NBR_ADD_FAILED(_vrf_id, _af_index)                          \
        (((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_nbr_add_failed)++)

#define FIB_INCR_CNTRS_NBR_ADD_PERMANENT(_vrf_id, _af_index)                          \
        (((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_nbr_add_permanent)++)

#define FIB_INCR_CNTRS_NBR_ADD_NOARP(_vrf_id, _af_index)                          \
        (((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_nbr_add_noarp)++)

#define FIB_INCR_CNTRS_NBR_DEL(_vrf_id, _af_index)                          \
        (((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_nbr_del)++)

#define FIB_INCR_CNTRS_NBR_RESOLVING(_vrf_id, _af_index)                    \
        (((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_nbr_resolving)++)

#define FIB_INCR_CNTRS_NBR_UNRSLVD(_vrf_id, _af_index)                      \
        (((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_nbr_un_rslvd)++)

#define FIB_INCR_CNTRS_NBR_VRF_DEL(_vrf_id, _af_index)                      \
        (((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_nbr_vrf_del)++)

#define FIB_INCR_CNTRS_NBR_CLR(_vrf_id, _af_index)                          \
        (((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_nbr_clear)++)

#define FIB_INCR_CNTRS_FIB_HOST_ENTRIES(_vrf_id, _af_index)                  \
        (((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_fib_host_entries)++)

#define FIB_INCR_CNTRS_FIB_ROUTE_ENTRIES(_vrf_id, _af_index)                 \
        (((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_fib_route_entries)++)

#define FIB_INCR_CNTRS_CAM_HOST_ENTRIES(_vrf_id, _af_index)                  \
        (((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_cam_host_entries)++)

#define FIB_INCR_CNTRS_CAM_ROUTE_ENTRIES(_vrf_id, _af_index)                 \
        (((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_cam_route_entries)++)

#define FIB_INCR_CNTRS_NHT_ENTRIES(_vrf_id, _af_index)                 \
        (((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_nht_entries)++)

#define FIB_INCR_CNTRS_CATCH_ALL_ENTRIES(_vrf_id, _af_index)                 \
        (((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_catch_all_intf_entries)++)

#define FIB_DECR_CNTRS_FIB_HOST_ENTRIES(_vrf_id, _af_index)                  \
        if ((FIB_GET_CNTRS_FIB_HOST_ENTRIES ((_vrf_id), (_af_index))) > 0)   \
        {                                                                  \
            ((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_fib_host_entries)--;   \
        }

#define FIB_DECR_CNTRS_FIB_ROUTE_ENTRIES(_vrf_id, _af_index)                 \
        if ((FIB_GET_CNTRS_FIB_ROUTE_ENTRIES ((_vrf_id), (_af_index))) > 0)  \
        {                                                                  \
            ((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_fib_route_entries)--;  \
        }

#define FIB_DECR_CNTRS_CAM_HOST_ENTRIES(_vrf_id, _af_index)                  \
        if ((FIB_GET_CNTRS_CAM_HOST_ENTRIES ((_vrf_id), (_af_index))) > 0)   \
        {                                                                  \
            ((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_cam_host_entries)--;   \
        }

#define FIB_DECR_CNTRS_CAM_ROUTE_ENTRIES(_vrf_id, _af_index)                 \
        if ((FIB_GET_CNTRS_CAM_ROUTE_ENTRIES ((_vrf_id), (_af_index))) > 0)  \
        {                                                                  \
            ((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_cam_route_entries)--;  \
        }

#define FIB_DECR_CNTRS_NHT_ENTRIES(_vrf_id, _af_index)                 \
        if ((FIB_GET_CNTRS_NHT_ENTRIES ((_vrf_id), (_af_index))) > 0)  \
        {                                                                  \
            ((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_nht_entries)--;  \
        }

#define FIB_DECR_CNTRS_CATCH_ALL_ENTRIES(_vrf_id, _af_index)                 \
        if ((FIB_GET_CNTRS_CATCH_ALL_ENTRIES((_vrf_id), (_af_index))) > 0)  \
        {                                                                  \
            ((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_catch_all_intf_entries)--;  \
        }
#define FIB_GET_CNTRS_ROUTE_ADD(_vrf_id, _af_index)                      \
        ((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_route_add)

#define FIB_GET_CNTRS_ROUTE_DEL(_vrf_id, _af_index)                      \
        ((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_route_del)

#define FIB_GET_CNTRS_VRF_ADD(_vrf_id, _af_index)                        \
        ((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_vrf_add)

#define FIB_GET_CNTRS_VRF_DEL(_vrf_id, _af_index)                        \
        ((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_vrf_del)

#define FIB_GET_CNTRS_ROUTE_CLR(_vrf_id, _af_index)                      \
        ((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_route_clear)

#define FIB_GET_CNTRS_UNKNOWN_MSG(_vrf_id, _af_index)                    \
        ((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_unknown_msg)

#define FIB_GET_CNTRS_NBR_ADD(_vrf_id, _af_index)                           \
        ((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_nbr_add)

#define FIB_GET_CNTRS_NBR_DEL(_vrf_id, _af_index)                           \
        ((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_nbr_del)

#define FIB_GET_CNTRS_NBR_UNRSLVD(_vrf_id, _af_index)                       \
        ((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_nbr_un_rslvd)

#define FIB_GET_CNTRS_NBR_CLR(_vrf_id, _af_index)                           \
        ((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_nbr_clear)

#define FIB_GET_CNTRS_FIB_HOST_ENTRIES(_vrf_id, _af_index)                   \
        ((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_fib_host_entries)

#define FIB_GET_CNTRS_FIB_ROUTE_ENTRIES(_vrf_id, _af_index)                  \
        ((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_fib_route_entries)

#define FIB_GET_CNTRS_CAM_HOST_ENTRIES(_vrf_id, _af_index)                   \
        ((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_cam_host_entries)

#define FIB_GET_CNTRS_CAM_ROUTE_ENTRIES(_vrf_id, _af_index)                  \
        ((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_cam_route_entries)

#define FIB_GET_CNTRS_NHT_ENTRIES(_vrf_id, _af_index)                  \
        ((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_nht_entries)

#define FIB_GET_CNTRS_CATCH_ALL_ENTRIES(_vrf_id, _af_index)                  \
        ((hal_rt_access_fib_vrf_cntrs(_vrf_id, _af_index))->num_catch_all_intf_entries)

#define FIB_EVENT_FILTER_SET(_vrf_id, _af_index, event_filter)  \
        (((hal_rt_access_fib_vrf_info(_vrf_id, _af_index))->event_filter_info) |= event_filter)

#define FIB_EVENT_FILTER_RESET(_vrf_id, _af_index, event_filter)  \
        (((hal_rt_access_fib_vrf_info(_vrf_id, _af_index))->event_filter_info) &= ~event_filter)

#define FIB_GET_VRF_NAME(_vrf_id, _af_index)                   \
        ((hal_rt_access_fib_vrf_info(_vrf_id, _af_index))->vrf_name)
/*
 * Note : To verify if the newer log message arguments are not introducing any
 *        any issues, replace EV_LOGGING definition in the following file as...
 *
 *       .../usr/include/ngos/event_log.h
 *
 *       #define EV_LOGGING(MOD,LVL,ID,msg, ...) \
 *           printf(msg,##__VA_ARGS__)
 * */

#define HAL_RT_LOG_EMERG(ID, ...) EV_LOGGING(ROUTE, EMERG, ID, __VA_ARGS__)
#define HAL_RT_LOG_ALERT(ID, ...) EV_LOGGING(ROUTE, ALERT, ID, __VA_ARGS__)
#define HAL_RT_LOG_CRIT(ID, ...) EV_LOGGING(ROUTE, CRIT, ID, __VA_ARGS__)
#define HAL_RT_LOG_ERR(ID, ...) EV_LOGGING(ROUTE, ERR, ID, __VA_ARGS__)
#define HAL_RT_LOG_WARN(ID, ...) EV_LOGGING(ROUTE, WARN, ID, __VA_ARGS__)
#define HAL_RT_LOG_NOTICE(ID, ...) EV_LOGGING(ROUTE, NOTICE, ID, __VA_ARGS__)
#define HAL_RT_LOG_INFO(ID, ...) EV_LOGGING(ROUTE, INFO, ID, __VA_ARGS__)
#define HAL_RT_LOG_DEBUG(ID, ...) EV_LOGGING(ROUTE, DEBUG, ID, __VA_ARGS__)
/*
 * Function Prototypes
 */

int hal_rt_vrf_init (hal_vrf_id_t vrf_id, const char *vrf_name);

int hal_rt_vrf_de_init (hal_vrf_id_t vrf_id);

int hal_rt_task_init (void);

void hal_rt_task_exit (void);

const t_fib_config * hal_rt_access_fib_config(void);
t_fib_gbl_info * hal_rt_access_fib_gbl_info(void);

t_fib_vrf * hal_rt_access_fib_vrf(uint32_t vrf_id);

t_fib_vrf_info * hal_rt_access_fib_vrf_info(uint32_t vrf_id, uint8_t af_index);

t_fib_vrf_cntrs * hal_rt_access_fib_vrf_cntrs(uint32_t vrf_id, uint8_t af_index);

std_rt_table * hal_rt_access_fib_vrf_dr_tree(uint32_t vrf_id, uint8_t af_index);

std_rt_table * hal_rt_access_fib_vrf_nh_tree(uint32_t vrf_id, uint8_t af_index);

std_rt_table * hal_rt_access_intf_tree(void);

std_rt_table * hal_rt_access_fib_vrf_nht_tree(uint32_t vrf_id, uint8_t af_index);


void nas_l3_lock();

void nas_l3_unlock();

t_std_error hal_rt_process_peer_routing_config (uint32_t vrf_id, nas_rt_peer_mac_config_t*p_status, bool status);
t_std_error hal_rt_process_virtual_routing_ip_config (nas_rt_virtual_routing_ip_config_t *p_cfg, bool status);
int fib_create_nht_tree (t_fib_vrf_info *p_vrf_info);
int fib_destroy_nht_tree (t_fib_vrf_info *p_vrf_info);
bool hal_rt_process_intf_state_msg(t_fib_msg_type type, t_fib_intf_entry *p_intf);
bool fib_proc_ip_unreach_config_msg(t_fib_intf_ip_unreach_config *p_ip_unreach_cfg);
t_std_error fib_proc_ip_redirects_config_msg(t_fib_intf_ip_redirects_config *p_ip_redirects_cfg);
bool hal_rt_process_neigh_flush_offload_msg(t_fib_offload_msg_neigh_flush *p_flush_msg);
t_std_error fib_process_neigh_flush(t_fib_neigh_flush *flush);
#endif /* __HAL_RT_MAIN_H__ */
