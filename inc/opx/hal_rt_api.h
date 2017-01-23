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

/*!
 * \file   hal_rt_api.h
 * \brief  Hal Routing functionality
 * \date   05-2014
 * \author Prince Sunny and Satish Mynam
 */

#ifndef __HAL_RT_API_H__
#define __HAL_RT_API_H__

#include "hal_rt_route.h"
#include "nas_ndi_route.h"
#include "nas_ndi_router_interface.h"

typedef enum _dn_hal_route_err {
    DN_HAL_ROUTE_E_NONE                =   0,
    DN_HAL_ROUTE_E_FAIL                =  -1,
    DN_HAL_ROUTE_E_FULL                =  -2,
    DN_HAL_ROUTE_E_HASH_COLLISION      =  -3,
    DN_HAL_ROUTE_E_DEGEN               =  -4,
    DN_HAL_ROUTE_E_MEM                 =  -5,
    DN_HAL_ROUTE_E_PARAM               =  -6,
    DN_HAL_ROUTE_E_UNSUPPORTED         =  -7,
    DN_HAL_ROUTE_E_NO_CAM_PARTITION    =  -8,
    /* All error codes should be added before DN_HAL_ROUTE_E_END */
    DN_HAL_ROUTE_E_END                 =  -9,
} dn_hal_route_err;

dn_hal_route_err hal_fib_init (void);

dn_hal_route_err hal_fib_de_init (void);

dn_hal_route_err hal_fib_vrf_init (uint32_t vrf_id, uint8_t af_index);

dn_hal_route_err hal_fib_vrf_de_init (uint32_t vrf_id, uint8_t af_index);

dn_hal_route_err hal_fib_host_add (uint32_t vrf_id, t_fib_nh *p_fh);

dn_hal_route_err hal_fib_host_del (uint32_t vrf_id, t_fib_nh *p_fh);

dn_hal_route_err hal_fib_route_add (uint32_t vrf_id, t_fib_dr *p_dr);

dn_hal_route_err hal_fib_route_del (uint32_t vrf_id, t_fib_dr *p_dr);

bool hal_fib_is_host_ready (int if_index);

bool hal_fib_is_route_ready (int if_index);

dn_hal_route_err hal_fib_set_ecmp_max_paths (uint32_t max_ecmp_paths);

dn_hal_route_err hal_fib_proc_egr_index_map (char *);

dn_hal_route_err hal_fib_get_cam_string (int pefix_len, uint8_t af_index, uint8_t is_host_add, uint8_t *p_str);

void hal_fib_help (char *p_pre_str);

dn_hal_route_err _hal_fib_route_add (uint32_t vrf_id, t_fib_dr *p_dr, t_fib_dr_fh *p_dr_fh);

dn_hal_route_err _hal_fib_route_del (uint32_t vrf_id, t_fib_dr *p_dr);

dn_hal_route_err hal_fib_ecmp_route_add (uint32_t vrf_id, t_fib_dr *p_dr);

dn_hal_route_err hal_fib_ecmp_route_del (uint32_t vrf_id, t_fib_dr *p_dr);

dn_hal_route_err hal_fib_ecmp_route_add_un_supp_mask (uint32_t vrf_id, t_fib_dr *p_dr);

bool hal_fib_is_route_really_ecmp (t_fib_dr *p_dr, bool *p_out_is_cpu_route);

int hal_fib_set_all_dr_fh_to_un_written (t_fib_dr *p_dr);

dn_hal_route_err _hal_fib_host_add (uint32_t vrf_id, t_fib_nh *p_fh);

dn_hal_route_err _hal_fib_host_del (uint32_t vrf_id, t_fib_nh *p_fh, bool error_occured);

dn_hal_route_err hal_fib_reserved_host_add (uint32_t vrf_id, t_fib_nh *p_fh);

dn_hal_route_err hal_fib_reserved_host_del (uint32_t vrf_id, t_fib_nh *p_fh);

dn_hal_route_err hal_fib_tunnel_remote_host_add (t_fib_nh *p_nh);

dn_hal_route_err hal_fib_tunnel_remote_host_del (t_fib_nh *p_nh);

t_std_error hal_form_nbr_entry(ndi_neighbor_t *p_nbr_entry, t_fib_nh *p_nh);

dn_hal_route_err hal_fib_next_hop_del(t_fib_nh *p_nh);
dn_hal_route_err hal_fib_next_hop_add(t_fib_nh *p_nh);

#endif /* __HAL_RT_API_H__ */
