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

/*
 * nas_rt_util_unittest.h
 * Utility functions used by unit tests
 */

#ifndef __NAS_RT_UTIL_UNITTEST_H__
#define __NAS_RT_UTIL_UNITTEST_H__

#include "std_mac_utils.h"
#include "std_ip_utils.h"
#include "cps_api_events.h"
#include "ds_common_types.h"
#include "cps_class_map.h"
#include "cps_api_object.h"
#include "cps_class_map.h"
#include "cps_api_object_key.h"

cps_api_return_code_t nas_ut_rt_cfg (const char *rt_vrf_name, bool is_add, const char *ip_addr, uint32_t prefix_len,
                                     uint8_t af, const char *nh_vrf_name, const char *nh_addr, const char *if_name, bool is_onlink_nh=false,
                                     bool is_replace=false);
cps_api_return_code_t nas_ut_neigh_cfg (bool is_add, const char *ip_addr, uint8_t af, const char *if_name, hal_mac_addr_t *hw_addr);
void nas_route_dump_arp_object_content(cps_api_object_t obj);
cps_api_return_code_t nas_ut_validate_neigh_cfg (const char *vrf_name, uint32_t af, const char *ip_addr,
                                                 uint32_t state, bool should_exist_in_npu, const char *nh_vrf_name);
cps_api_return_code_t nas_ut_validate_rt_cfg (const char *rt_vrf_name, uint32_t af, const char *ip_addr, uint32_t prefix_len,
                                              const char *nh_vrf_name, const char *nh_addr, const char *if_name, bool should_exist_in_npu,
                                              bool is_onlink_nh=false);
cps_api_return_code_t nas_ut_validate_rt_ecmp_cfg (const char *rt_vrf_name, uint32_t af, const char *ip_addr, uint32_t prefix_len,
                                              const char *nh_vrf_name, const char *nh_addr, const char *if_name, bool should_exist_in_npu,
                                              uint32_t rt_nh_cnt);
void nas_route_dump_route_object_content(cps_api_object_t obj);

cps_api_return_code_t nas_ut_rt_ipv6_nh_cfg (const char *rt_vrf_name, bool is_add, const char *ip_addr,
                                             uint32_t prefix_len, uint8_t af, const char *nh_vrf_name,
                                             const char *nh_addr1, const char *if_name1,
                                             const char *nh_addr2, const char *if_name2);
cps_api_return_code_t nas_ut_vrf_cfg (const char *vrf_name, bool is_add);
cps_api_return_code_t nas_ut_intf_vrf_cfg (const char *vrf_name, const char *if_name, bool is_add);
cps_api_return_code_t nas_ut_intf_mgmt_vrf_cfg(const char *vrf_name, const char *if_name, bool is_add);
cps_api_return_code_t nas_ut_route_op_spl_nh (bool is_add, const char *vrf_name, const char *ip_addr, uint32_t prefix_len,
                                              uint32_t spl_nh_option, uint8_t af);
#endif /* __NAS_RT_UTIL_UNITTEST_H__ */
