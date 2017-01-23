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
 * \file   hal_rt_util.h
 * \brief  Hal Routing Utilities
 * \date   05-2014
 * \author Prince Sunny and Satish Mynam
 */

#ifndef __HAL_RT_UTIL_H__
#define __HAL_RT_UTIL_H__

#include "hal_rt_route.h"
#include "hal_rt_api.h"
#include "std_error_codes.h"
#include "std_ip_utils.h"
#include "dell-base-common.h"
#include <arpa/inet.h>

#define FIB_MAX_SCRATCH_BUFSZ             256
#define FIB_NUM_SCRATCH_BUF               16
#define FIB_AUDIT_DEF_INTERVAL            60

#define HAL_RT_MAX_BUFSZ                  256
#define HAL_RT_NUM_HAL_ERR                (0 - (DN_HAL_ROUTE_E_END) + 1)
#define HAL_RT_MAX_HAL_ERR_LEN            64
#define HAL_RT_GET_ERR_STR(_hal_err)      hal_rt_get_hal_err_str(_hal_err)

#define HAL_RT_RIF_TABLE_MAX              512

#define FIB_IP_ADDR_TO_STR(_p_ip_addr)                                       \
        (((_p_ip_addr)->af_index == HAL_RT_V4_AFINDEX) ?                     \
         FIB_IPV4_ADDR_TO_STR (&((_p_ip_addr)->u.v4_addr)) :                 \
        (((_p_ip_addr)->af_index == HAL_RT_V6_AFINDEX) ?                     \
         FIB_IPV6_ADDR_TO_STR (&((_p_ip_addr)->u.v6_addr)) : ""))

#define FIB_IPV4_ADDR_TO_STR(_p_ip_addr)                                     \
        (inet_ntop (AF_INET, (const void *) (_p_ip_addr),                    \
                    (char *) fib_get_scratch_buf (), FIB_MAX_SCRATCH_BUFSZ))

#define FIB_IPV6_ADDR_TO_STR(_p_ip_addr)                                     \
        (inet_ntop (AF_INET6, (const void *) (_p_ip_addr),                   \
                   (char *) fib_get_scratch_buf (), FIB_MAX_SCRATCH_BUFSZ))

typedef struct _dn_hal_route_err_to_str {
    dn_hal_route_err   error;
    uint8_t        err_str [HAL_RT_MAX_HAL_ERR_LEN];
} dn_hal_route_err_to_str;

/*!
 * @brief Get scratch buffer for temporary calculations
 * @param none
 * @return scratch buffer pointer
 */
uint8_t *fib_get_scratch_buf ();

int fib_get_mask_from_prefix_len (uint8_t af_index, uint8_t prefix_len, t_fib_ip_addr *p_out_mask);

int fib_cmp_ip_addr (t_fib_ip_addr *p_ip_addr1, t_fib_ip_addr *p_ip_addr2);

void fib_cam_sys_log (dn_hal_route_err hal_err, int slot_id, uint8_t *p_cam_str, uint8_t *p_ip_str);

void fib_check_threshold_for_all_cams (int action);

unsigned long fib_tick_get( void );

t_std_error hal_rt_validate_intf(int if_index);

/*!
 * @brief Converts mac address to a string format
 * @param pointer to mac address array, pointer to string buffer
 * @return pointer to string
 */
char *hal_rt_mac_to_str (hal_mac_addr_t *mac_addr, char *p_buf, size_t len);

/*!
 * @brief  This routine get the string corresponding to specific routing error
 * @param  error number
 * @return pointer to string
 */
uint8_t *hal_rt_get_hal_err_str(dn_hal_route_err _hal_err);

bool hal_rt_is_mac_address_zero (const hal_mac_addr_t *p_mac);

bool hal_rt_is_reserved_ipv4(hal_ip_addr_t *p_ip_addr);

bool hal_rt_is_reserved_ipv6(hal_ip_addr_t *p_ip_addr);

ndi_rif_id_t hal_rif_index_get (npu_id_t npu_id, hal_vrf_id_t vrf_id, hal_ifindex_t if_index);

t_std_error hal_rif_index_remove (npu_id_t npu_id, hal_vrf_id_t vrf_id, hal_ifindex_t if_index);

ndi_vrf_id_t hal_vrf_obj_get (npu_id_t npu_id, hal_vrf_id_t vrf_id);

uint32_t hal_rt_rif_ref_inc(hal_ifindex_t if_index);

uint32_t hal_rt_rif_ref_dec(hal_ifindex_t if_index);

BASE_CMN_AF_TYPE_t nas_route_af_to_cps_af(unsigned short af);
t_std_error nas_rt_fill_opaque_data(cps_api_object_t obj, uint64_t attr, int npu_id, next_hop_id_t *p_ndi_id);

t_std_error hal_rt_get_intf_name(int if_index, char *p_if_name);
uint32_t nas_rt_get_clock_sec();
int nas_rt_process_msg(t_fib_msg *p_msg);
int fib_msg_main(void);
bool nas_rt_peer_mac_db_add (nas_rt_peer_mac_config_t* mac_info);
t_std_error nas_route_delete_vrf_peer_mac_config(uint32_t vrf_id);
bool nas_rt_peer_mac_get (const nas_rt_peer_mac_config_t* req,
                          nas_rt_peer_mac_config_t* reply_p);
bool nas_rt_peer_mac_db_del (nas_rt_peer_mac_config_t* mac_info);
cps_api_object_t nas_route_peer_routing_config_to_cps_object(uint32_t vrf_id,
                                                             nas_rt_peer_mac_config_t *p_status);
#endif /* __HAL_RT_UTIL_H__ */
