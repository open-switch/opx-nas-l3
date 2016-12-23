/*
 * Copyright (c) 2016 Dell Inc.
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

/*
 * filename: nas_rt_api.h
 */


#ifndef NAS_RT_API_H
#define NAS_RT_API_H

#include "dell-base-routing.h"
#include "dell-base-common.h"
#include "ds_common_types.h"

#include "cps_api_operation.h"
#include "cps_api_object.h"
#include "cps_api_interface_types.h"
#include "event_log.h"
#include "hal_rt_route.h"
#include <stdint.h>

#define BASE_ROUTE_NEXT_HOP_MAX_COUNT   64
#define BASE_ROUTE_NEXT_HOP_DEF_WEIGHT (1)

typedef struct  {
    unsigned short                  af;
    unsigned short                  distance;
    unsigned short                  protocol;
    unsigned long                   vrfid;
    hal_ip_addr_t                   prefix;
    unsigned short                  prefix_masklen;
    hal_ifindex_t                   nh_if_index;
    unsigned long                   nh_vrfid;
    hal_ip_addr_t                   nh_addr;
    BASE_ROUTE_RT_OWNER_t           owner;
    BASE_ROUTE_NH_TYPE_t            nh_type;

    /* WECMP nh_list*/
    struct {
        hal_ifindex_t   nh_if_index;
        hal_ip_addr_t   nh_addr;
        uint32_t        nh_weight;
        uint32_t        nh_id;
    } nh_list[BASE_ROUTE_NEXT_HOP_MAX_COUNT];

    size_t              nh_count;
    uint32_t            group_id;

} nas_rt_entry_t;

typedef struct  {
    unsigned short              af;
    db_nbr_event_type_t         msg_type;
    hal_ip_addr_t               nbr_addr;
    hal_mac_addr_t              nbr_hwaddr;
    unsigned long               vrfid;
    hal_ifindex_t               if_index;
    hal_ifindex_t               phy_if_index;
    BASE_ROUTE_RT_OWNER_t       owner;
    BASE_ROUTE_RT_TYPE_t           type;
    unsigned long               flags;
    unsigned long               state;
    unsigned long               expire;
}  nas_rt_nbr_entry_t;

typedef struct  {
    unsigned short              af;
    unsigned long               vrfid;
    unsigned short              switch_id;
    BASE_ROUTE_RT_STATUS_t      status; /* up/down */
    bool                        nsf_enabled;
    bool                        eor;
} nas_route_domain_object_t;

typedef struct  {
    unsigned short                  af;
    unsigned long                   vrfid;
    hal_ip_addr_t                   nh_addr;
    unsigned short                  prefix_len;
    uint32_t                        nh_group_id;
    uint32_t                        *nh_group_data;
    hal_mac_addr_t                  smac_addr;
    hal_mac_addr_t                  dmac_addr;
    hal_vlan_id_t                   dmac_vlan_id;
    hal_ifindex_t                   if_index;
    hal_ifindex_t                   phy_if_index;
    BASE_ROUTE_RT_OWNER_t           owner;
    BASE_ROUTE_RT_TYPE_t               type;
    unsigned long                   flags;
    unsigned long                   state;
    bool                            esolved;
}  nas_rt_nht_entry_t;

typedef struct  {
    unsigned long                       vrfid;
    uint32_t                            has_algo_seed_val;
    bool                                enable_v4;
    bool                                enable_v6;
    bool                                deterministic_ecmp_enable_v4;
    bool                                deterministic_ecmp_enable_v6;
    BASE_ROUTE_FWD_TBL_CONFG_t          fwd_config_mode;
    bool                                nsf_enable_v4;
    uint32_t                            ecmp_group_max_paths;
    uint32_t                            ecmp_group_id;
    bool                                ecmp_group_path_fallback;
    bool                                start_rtm_download;
    bool                                stop_rtm_download;
    unsigned long                       flags;
    unsigned long                       state;
    bool                                resolved;
}  nas_rt_fwd_tbl_config_t;


typedef struct  {
    unsigned long               vrfid;
    uint32_t                    stack_unit;
    unsigned short              af;
    hal_ip_addr_t               ip_prefix;
    unsigned short              prefix_len;
    bool                        enable_v4;
    bool                        enable_v6;
    bool                        clear_v4;
    bool                        clear_v6;
    bool                        summary;
    bool                        wecmp;
    bool                        ecmp_details;
    uint32_t                    ecmp_grp_id;
}  nas_rt_fib_show_config_t;

typedef struct  {
    unsigned long               rfid;
    hal_ip_addr_t               ip_prefix;
    unsigned short              prefix_len;
    bool                        enable_v4;
    bool                        enable_v6;
    uint8_t                     level;
}  nas_rt_fib_debug_t;


t_std_error nas_routing_cps_init(cps_api_operation_handle_t nas_route_cps_handle);
t_std_error nas_routing_nht_cps_init(cps_api_operation_handle_t nas_route_nht_cps_handle);
cps_api_return_code_t  nas_route_process_cps_route(cps_api_transaction_params_t * param,
        size_t ix);
cps_api_return_code_t nas_route_process_cps_nbr(cps_api_transaction_params_t * param,
        size_t ix);
BASE_ROUTE_OBJ_t nas_route_check_route_key_attr(cps_api_object_t obj);

t_std_error nas_route_publish_object(cps_api_object_t obj);

t_std_error nas_route_nht_publish_object(cps_api_object_t obj);

t_std_error nas_route_get_all_arp_info(cps_api_object_list_t list, uint32_t vrf_id, uint32_t af,
                                       hal_ip_addr_t *p_nh_addr, bool is_specific_nh_get);

t_std_error nas_route_process_cps_peer_routing(cps_api_transaction_params_t * param,
                                        size_t ix);
t_std_error nas_route_get_all_peer_routing_config(cps_api_object_list_t list);
t_std_error nas_route_process_cps_nht(cps_api_transaction_params_t * param, size_t ix);
int nas_rt_publish_nht(t_fib_nht *p_nht, t_fib_dr *p_dr, t_fib_nh *p_nh, bool is_add);

t_fib_nht *fib_get_nht (uint32_t vrf_id, t_fib_ip_addr *p_dest_addr);
t_fib_nht *fib_get_first_nht (uint32_t vrf_id, uint8_t af_index);
t_fib_nht *fib_get_next_nht (uint32_t vrf_id, t_fib_ip_addr *p_dest_addr);
t_std_error nas_route_get_all_nht_info(cps_api_object_list_t list, unsigned int vrf_id,
                                       unsigned int af, t_fib_ip_addr *p_dest_addr);
t_std_error nas_route_get_all_route_info(cps_api_object_list_t list, uint32_t vrf_id, uint32_t af,
                                         hal_ip_addr_t *p_prefix, uint32_t pref_len, bool is_specific_prefix_get);
#endif /* NAS_RT_API_H */
