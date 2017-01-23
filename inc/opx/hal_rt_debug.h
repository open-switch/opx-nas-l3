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
 * \file   hal_rt_debug.h
 * \brief  Hal Routing debug functionality
 * \date   05-2014
 * \author Prince Sunny and Satish Mynam
 */

#ifndef __HAL_RT_DEBUG_H__
#define __HAL_RT_DEBUG_H__

void fib_help (void);

void fib_dump_tcb (void);

void fib_dump_vrf_info_per_vrf_per_af (uint32_t vrf_id, uint32_t af_index);

void fib_dump_vrf_info_per_vrf (uint32_t vrf_id);

void fib_dump_vrf_info_per_af (uint32_t af_index);

void fib_dump_all_vrf_info (void);

void fib_dump_dr_node_key (t_fib_dr *p_dr);

void fib_dump_nh_node_key (t_fib_nh *p_nh);

void fib_dump_dr_node (t_fib_dr *p_dr);

void fib_dump_nh_node (t_fib_nh *p_nh);

void fib_dump_dr (uint32_t vrf_id, uint32_t af_index, uint8_t *p_in_prefix, uint32_t prefix_len);

void fib_dump_dr_per_vrf_per_af (uint32_t vrf_id, uint32_t af_index);

void fib_dump_dr_per_vrf (uint32_t vrf_id);

void fib_dump_dr_per_af (uint32_t af_index);

void fib_dump_all_dr (void);

void fib_dump_nh (uint32_t vrf_id, uint32_t af_index, uint8_t *p_in_ip_addr, uint32_t if_index);

void fib_dump_nh_per_vrf_per_af (uint32_t vrf_id, uint32_t af_index);

void fib_dump_nh_per_vrf (uint32_t vrf_id);

void fib_dump_nh_per_af (uint32_t af_index);

void fib_dump_all_nh (void);

void fib_dump_intf (uint32_t if_index, uint32_t vrf_id, uint32_t af_index);

void fib_dump_intf_per_if_index (uint32_t if_index);

void fib_dump_intf_per_if_index_per_vrf (uint32_t if_index, uint32_t vrf_id);

void fib_dump_all_intf (void);

void fib_dump_route_summary_per_vrf_per_af (uint32_t vrf_id, uint32_t af_index);

void fib_dump_route_summary_per_vrf (uint32_t vrf_id);

void fib_dump_route_summary_per_af (uint32_t af_index);

void fib_dump_all_route_summary (void);

void fib_dump_global_cntrs (void);

void fib_dump_vrf_cntrs_per_vrf_per_af (uint32_t vrf_id, uint32_t af_index);

void fib_dump_vrf_cntrs_per_vrf (uint32_t vrf_id);

void fib_dump_vrf_cntrs_per_af (uint32_t af_index);

void fib_dump_all_vrf_cntrs (void);

void fib_dump_all_cntrs (void);

void fib_dump_all_db (void);

void fib_dbg_clear_global_cntrs (void);

void fib_dbg_clear_vrf_cntrs_per_vrf_per_af (uint32_t vrf_id, uint32_t af_index);

void fib_dbg_clear_vrf_cntrs_per_vrf (uint32_t vrf_id);

void fib_dbg_clear_vrf_cntrs_per_af (uint32_t af_index);

void fib_dbg_clear_all_vrf_cntrs (void);

void fib_dbg_clear_all_cntrs (void);

void fib_dbg_clear_all_cntrs (void);

void fib_dump_peer_mac_db_get_all_with_vrf(hal_vrf_id_t vrf_id);

#endif /* __HAL_RT_DEBUG_H__ */
