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
 * filename: nas_route_cps.c
 */


#include "nas_rt_api.h"
#include "event_log_types.h"
#include "event_log.h"

#include "cps_class_map.h"
#include "cps_api_object_key.h"
#include "cps_api_operation.h"
#include "cps_api_events.h"
#include "hal_rt_util.h"
#include "std_utils.h"
#include "hal_if_mapping.h"
#include "dell-base-l2-mac.h"
#include "dell-base-ip.h"
#include "vrf-mgmt.h"

#include <stdlib.h>
#include "std_mac_utils.h"
#include "dell-base-neighbor.h"

static cps_api_event_service_handle_t handle;
static cps_api_event_service_handle_t handle_nht;

static cps_api_return_code_t nas_route_cps_route_set_func(void *ctx,
                             cps_api_transaction_params_t * param, size_t ix) {

    if(param == NULL){
        HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Route Set with no param: "
                    "nas_route_cps_route_set_func");
        return cps_api_ret_code_ERR;
    }

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    if (obj==NULL) {
        HAL_RT_LOG_DEBUG("NAS-RT-CPS", "nas_route_cps_route_set_func: "
                            "NULL obj");
        return cps_api_ret_code_ERR;
    }

    /*
     * Check for keys in filter either Route Key:BASE_ROUTE_OBJ_ENTRY or
     * Neighbor Key:BASE_ROUTE_OBJ_NBR
     *
     */
    cps_api_return_code_t rc = cps_api_ret_code_ERR;

    switch (nas_route_check_route_key_attr(obj)) {
          case BASE_ROUTE_OBJ_ENTRY:
              rc = nas_route_process_cps_route(param,ix);
              break;

          case BASE_ROUTE_OBJ_NBR:
              rc = nas_route_process_cps_nbr(param,ix);
              break;

          default:
              HAL_RT_LOG_DEBUG("NAS-RT-CPS", "base route obj type unknown %d",
                      cps_api_key_get_subcat(cps_api_object_key(obj)));
              break;
      }

    return rc;
}

static cps_api_return_code_t nas_route_event_filter_set_func(void *ctx,
                             cps_api_transaction_params_t * param, size_t ix) {

    if(param == NULL){
        HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Route Set with no param: "
                    "nas_route_cps_route_set_func");
        return cps_api_ret_code_ERR;
    }

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    if (obj==NULL) {
        HAL_RT_LOG_DEBUG("NAS-RT-CPS", "nas_route_cps_route_set_func: "
                            "NULL obj");
        return cps_api_ret_code_ERR;
    }

    cps_api_return_code_t rc = cps_api_ret_code_ERR;

    nas_l3_lock();
    rc = nas_route_handle_event_filter(param, ix);
    nas_l3_unlock();

    return rc;
}

static cps_api_return_code_t nas_route_event_filter_get_func(void *ctx,
                                                             cps_api_get_params_t * param,
                                                             size_t ix) {
    t_std_error rc;

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Route event filter function");

    nas_l3_lock();
    if((rc = nas_route_get_all_event_filter_info(param->list)) != STD_ERR_OK){
        nas_l3_unlock();
        return (cps_api_return_code_t)rc;
    }
    nas_l3_unlock();

    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_route_event_filter_rollback_func (void * ctx,
                              cps_api_transaction_params_t * param, size_t ix){

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Route event filter rollback function");
    return cps_api_ret_code_OK;
}

/* This function is used to process route nexthop append/delete operation RPC */
static cps_api_return_code_t nas_route_nh_operation_handler (void * context,
                                                    cps_api_transaction_params_t * param,
                                                    size_t ix) {
    cps_api_object_attr_t route_af;
    cps_api_object_attr_t prefix;
    cps_api_object_attr_t pref_len;
    cps_api_object_attr_t route_nh_op;
    cps_api_object_attr_t nh_count;
    cps_api_return_code_t rc = cps_api_ret_code_ERR;
    uint32_t nhc = 0;

    if(param == NULL){
        HAL_RT_LOG_ERR("NAS-RT-CPS-ACTION", "Route NH Operation with no param");
        return cps_api_ret_code_ERR;
    }

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    if (obj == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-ACTION","Route NH Operation object is not present");
        return cps_api_ret_code_ERR;
    }

    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    if (op != cps_api_oper_ACTION) {
        HAL_RT_LOG_DEBUG("NAS-RT-CPS-ACTION", "Invalid Route NH operation action");
        return cps_api_ret_code_ERR;
    }

    /*
     * Check mandatory key attributes
     */
    route_af     = cps_api_get_key_data(obj, BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_AF);
    prefix       = cps_api_get_key_data(obj, BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_ROUTE_PREFIX);
    pref_len     = cps_api_get_key_data(obj, BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_PREFIX_LEN);
    route_nh_op  = cps_api_get_key_data(obj, BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_OPERATION);
    nh_count     = cps_api_get_key_data(obj, BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_COUNT);

    /*
     * for route nh append/delete operation check the mandatory attrs
     */
    if (route_af == CPS_API_ATTR_NULL || prefix == CPS_API_ATTR_NULL ||
        pref_len == CPS_API_ATTR_NULL || route_nh_op == CPS_API_ATTR_NULL ||
        nh_count == CPS_API_ATTR_NULL)
    {
        HAL_RT_LOG_ERR("NAS-RT-CPS-ACTION", "Missing route nh operation key params");
        return cps_api_ret_code_ERR;
    }

    nhc = cps_api_object_attr_data_u32(nh_count);

    /*
     * for route nh append/delete operation nh count should be non-zero.
     */
    if (nhc == 0)
    {
        HAL_RT_LOG_ERR("NAS-RT-CPS-ACTION", "NH Count cannot be zero for route nh append/delete operation");
        return cps_api_ret_code_ERR;
    }

    rc = nas_route_process_cps_route(param,ix);

    return rc;
}


static cps_api_return_code_t nas_route_cps_all_route_get_func (void *ctx,
                              cps_api_get_params_t * param, size_t ix) {
    uint32_t af = HAL_INET4_FAMILY, vrf = 0, pref_len = 0;
    hal_ip_addr_t ip;
    bool is_specific_prefix_get = false, is_specific_vrf_get = false;

    memset(&ip, 0, sizeof(ip));
    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "All route Get function");
    cps_api_object_t filt = cps_api_object_list_get(param->filters,ix);
    if (filt == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Route object is not present");
        return cps_api_ret_code_ERR;
    }
    cps_api_object_attr_t vrf_attr = cps_api_get_key_data(filt,BASE_ROUTE_OBJ_VRF_NAME);
    cps_api_object_attr_t af_attr = cps_api_get_key_data(filt,BASE_ROUTE_OBJ_ENTRY_AF);
    cps_api_object_attr_t prefix_attr = cps_api_get_key_data(filt,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX);
    cps_api_object_attr_t pref_len_attr = cps_api_get_key_data(filt,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN);

    if (((prefix_attr != NULL) && (pref_len_attr == NULL)) ||
        ((prefix_attr == NULL) && (pref_len_attr != NULL))) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Invlaid prefix info prefix:%s len:%s",
                       ((prefix_attr == NULL) ? "Not Present" : "Present"),
                       ((pref_len_attr == NULL) ? "Not Present" : "Present"));
        return cps_api_ret_code_ERR;
    }

    if (af_attr)
        af = cps_api_object_attr_data_u32(af_attr);

    char  vrf_name[NAS_VRF_NAME_SZ + 1];
    memset (vrf_name,0,sizeof(vrf_name));
    if (vrf_attr != NULL) {
        safestrncpy(vrf_name, (const char *)cps_api_object_attr_data_bin(vrf_attr),
                    sizeof(vrf_name));
        if (hal_rt_get_vrf_id(vrf_name, &vrf) == false) {
            HAL_RT_LOG_INFO("NAS-RT-CPS","Route get Error - Invalid VRF name:%s", vrf_name);
            return cps_api_ret_code_ERR;
        }
        is_specific_vrf_get = true;
    }
    if (pref_len_attr != NULL) {
        if (af_attr == NULL) {
            HAL_RT_LOG_ERR("NAS-RT-CPS","Error - Route address family is not present");
            return cps_api_ret_code_ERR;
        }
        is_specific_prefix_get = true;
        pref_len = cps_api_object_attr_data_u32(pref_len_attr);
        if(af == AF_INET) {
            struct in_addr *inp = (struct in_addr *) cps_api_object_attr_data_bin(prefix_attr);
            std_ip_from_inet(&ip,inp);
        } else {
            struct in6_addr *inp6 = (struct in6_addr *) cps_api_object_attr_data_bin(prefix_attr);
            std_ip_from_inet6(&ip,inp6);
        }
    }
    cps_api_return_code_t rc = cps_api_ret_code_OK;
    HAL_RT_LOG_DEBUG("RT-GET", "VRF:%d(%s) prefix:%s/%d is_specific_prefix_get:%d is_specific_vrf_get:%d",
                     vrf, vrf_name, FIB_IP_ADDR_TO_STR(&ip), pref_len, is_specific_prefix_get, is_specific_vrf_get);
    nas_l3_lock();
    do {
        if (is_specific_vrf_get && (!(FIB_IS_VRF_ID_VALID (vrf)))) {
            HAL_RT_LOG_ERR("RT-GET", "VRF name: %s(%d) is not valid!", ((vrf_attr != NULL) ? vrf_name : ""), vrf);
            rc = cps_api_ret_code_ERR;
            break;
        }

        /* if address family is not given, get all family routes */
        if ((af_attr == NULL) || (af == HAL_INET4_FAMILY)) {
            if(nas_route_get_all_route_info(param->list,vrf, HAL_INET4_FAMILY,
                                            &ip, pref_len, is_specific_prefix_get, is_specific_vrf_get) != STD_ERR_OK){
                HAL_RT_LOG_ERR("RT-GET","IPv4 Rt returned failure");
                rc = cps_api_ret_code_ERR;
                break;
            }
        }
        if ((af_attr == NULL) || (af == HAL_INET6_FAMILY)) {
            if(nas_route_get_all_route_info(param->list,vrf, HAL_INET6_FAMILY,
                                            &ip, pref_len, is_specific_prefix_get, is_specific_vrf_get) != STD_ERR_OK){
                HAL_RT_LOG_ERR("RT-GET","IPv6 Rt returned failure");
                rc = cps_api_ret_code_ERR;
                break;
            }
        }
    } while(0);
    nas_l3_unlock();
    return rc;
}

static cps_api_return_code_t nas_route_cps_route_get_func (void *ctx,
                              cps_api_get_params_t * param, size_t ix) {

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Route Get function");
    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_route_cps_route_rollback_func (void * ctx,
                              cps_api_transaction_params_t * param, size_t ix){

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Route Rollback function");
    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_route_cps_nht_set_func (void * ctx,
                             cps_api_transaction_params_t * param, size_t ix) {

    cps_api_object_t          obj;
    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "NHT Set function");


    if(param == NULL){
        HAL_RT_LOG_ERR("NAS-RT-CPS", "NHT set with no param: "
                     "nas_route_cps_nht_set_func");
        return cps_api_ret_code_ERR;
    }

    obj = cps_api_object_list_get (param->change_list, ix);

    if (obj == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS", "Missing NHT Object");
        return cps_api_ret_code_ERR;
    }

    cps_api_return_code_t rc = cps_api_ret_code_ERR;

    switch (cps_api_key_get_subcat (cps_api_object_key (obj))) {
        case BASE_ROUTE_NH_TRACK_OBJ:
            rc = nas_route_process_cps_nht(param,ix);
            break;

        default:
            HAL_RT_LOG_ERR("NAS-RT-CPS", "NHT obj type unknown %d",
                         cps_api_key_get_subcat(cps_api_object_key(obj)));
            break;
    }

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "NHT set Exit");

    return rc;
}
static cps_api_return_code_t nas_route_cps_nht_get_func (void * ctx,
                                cps_api_get_params_t * param, size_t ix) {

    cps_api_object_t filt = cps_api_object_list_get(param->filters,ix);
    cps_api_object_attr_t af_attr;
    cps_api_object_attr_t dest_attr;
    t_fib_ip_addr  dest_addr;
    unsigned int vrf_id =0;
    unsigned int af = HAL_INET4_FAMILY;
    bool is_specific_vrf_get = false;

    if (filt == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","NHT object is not present");
        return cps_api_ret_code_ERR;
    }
    const char *vrf_name = cps_api_object_get_data(filt, BASE_ROUTE_NH_TRACK_VRF_NAME);
    if (vrf_name) {
        if (hal_rt_get_vrf_id(vrf_name, &vrf_id) == false) {
            HAL_RT_LOG_INFO("NAS-RT-CPS-NHT","VRF-id get error - Invalid VRF name:%s", vrf_name);
            return cps_api_ret_code_ERR;
        }
        is_specific_vrf_get = true;
    }

    af_attr = cps_api_get_key_data(filt,BASE_ROUTE_NH_TRACK_AF);
    dest_attr = cps_api_get_key_data(filt,BASE_ROUTE_NH_TRACK_DEST_ADDR);

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "NHT Get function");


    if (af_attr) {
        af = cps_api_object_attr_data_u32(af_attr);
        HAL_RT_LOG_DEBUG("NAS-RT-CPS","Get NHT entries: af %d", af);
    }

    memset (&dest_addr, 0, sizeof (t_fib_ip_addr));

    if (dest_attr != NULL) {
        if (af_attr == NULL) {
            HAL_RT_LOG_ERR("NAS-RT-CPS","Error - NHT address family is not present");
            return cps_api_ret_code_ERR;
        }

        HAL_RT_LOG_DEBUG("HAL-RT-NHT", "Get NHT: input for specific dest_addr");
        if(af == HAL_INET4_FAMILY) {
            struct in_addr *inp = (struct in_addr *) cps_api_object_attr_data_bin(dest_attr);
            std_ip_from_inet(&dest_addr,inp);
        } else {
            struct in6_addr *inp6 = (struct in6_addr *) cps_api_object_attr_data_bin(dest_attr);
            std_ip_from_inet6(&dest_addr,inp6);
        }
    }

    cps_api_return_code_t rc = cps_api_ret_code_OK;
    nas_l3_lock();
    do {
        if (!(FIB_IS_VRF_ID_VALID (vrf_id))) {
            HAL_RT_LOG_ERR("HAL-RT-NHT", "VRF-id:%d  is not valid!", vrf_id);
            rc = cps_api_ret_code_ERR;
            break;
        }

        /* if address family is not given, get all family nhts */
        if ((af_attr == NULL) || (af == HAL_INET4_FAMILY)) {
            if (nas_route_get_all_nht_info(param->list, is_specific_vrf_get, vrf_id, HAL_INET4_FAMILY,
                                           ((dest_attr != NULL) ? (&dest_addr): NULL)) != STD_ERR_OK){
                rc = cps_api_ret_code_ERR;
                break;
            }
        }
        if ((af_attr == NULL) || (af == HAL_INET6_FAMILY)) {
            if (nas_route_get_all_nht_info(param->list, is_specific_vrf_get, vrf_id, HAL_INET6_FAMILY,
                                                ((dest_attr != NULL) ? (&dest_addr): NULL)) != STD_ERR_OK){
                rc = cps_api_ret_code_ERR;
                break;
            }
        }
    } while(0);
    nas_l3_unlock();
    return rc;
}

static cps_api_return_code_t nas_route_cps_nht_rollback_func (void * ctx,
                             cps_api_transaction_params_t * param, size_t ix) {

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "NHT Rollback function");
    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_route_cps_arp_get_func(void *context,
                                cps_api_get_params_t * param, size_t ix) {
    uint32_t af = HAL_INET4_FAMILY, vrf = 0;
    hal_ip_addr_t ip;
    bool is_specific_nh_get = false;
    bool is_specific_vrf_get = false;

    cps_api_object_t filt = cps_api_object_list_get(param->filters,ix);
    if (filt == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Neighbor object is not present");
        return cps_api_ret_code_ERR;
    }
    cps_api_object_attr_t vrf_attr = cps_api_get_key_data(filt,BASE_ROUTE_OBJ_VRF_NAME);
    cps_api_object_attr_t af_attr = cps_api_get_key_data(filt,BASE_ROUTE_OBJ_NBR_AF);
    cps_api_object_attr_t nh_attr = cps_api_get_key_data(filt,BASE_ROUTE_OBJ_NBR_ADDRESS);

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "All ARP get function");
    if (af_attr)
        af = cps_api_object_attr_data_u32(af_attr);

    if (vrf_attr != NULL) {
        char  vrf_name[NAS_VRF_NAME_SZ + 1];
        memset (vrf_name,0,sizeof(vrf_name));
        safestrncpy(vrf_name, (const char *)cps_api_object_attr_data_bin(vrf_attr),
                    sizeof(vrf_name));
        if (hal_rt_get_vrf_id(vrf_name, &vrf) == false) {
            HAL_RT_LOG_INFO("NAS-ARP-GET","Error - Invalid VRF name:%s", vrf_name);
            return cps_api_ret_code_ERR;
        }
        is_specific_vrf_get = true;
    }

    if (nh_attr != NULL) {
        if (af_attr == NULL) {
            HAL_RT_LOG_ERR("NAS-RT-CPS","Error - Neighbor address family is not present!");
            return cps_api_ret_code_ERR;
        }

        is_specific_nh_get = true;
        if(af == HAL_INET4_FAMILY) {
            struct in_addr *inp = (struct in_addr *) cps_api_object_attr_data_bin(nh_attr);
            std_ip_from_inet(&ip,inp);
        } else {
            struct in6_addr *inp6 = (struct in6_addr *) cps_api_object_attr_data_bin(nh_attr);
            std_ip_from_inet6(&ip,inp6);
        }
    }

    cps_api_return_code_t rc = cps_api_ret_code_OK;
    nas_l3_lock();

    do {
        if (!(FIB_IS_VRF_ID_VALID (vrf))) {
            HAL_RT_LOG_ERR("NAS-RT-CPS-GET", "VRF-id:%d is not valid!", vrf);
            rc = cps_api_ret_code_ERR;
            break;
        }
        /* if address family is not given, get all family neighbors  */
        if ((af_attr == NULL) || (af == HAL_INET4_FAMILY)) {
            if (nas_route_get_all_arp_info(param->list,vrf, HAL_INET4_FAMILY,
                                           &ip, is_specific_nh_get, false, is_specific_vrf_get) != STD_ERR_OK){
                rc = cps_api_ret_code_ERR;
                break;
            }
        }
        if ((af_attr == NULL) || (af == HAL_INET6_FAMILY)) {
            if (nas_route_get_all_arp_info(param->list,vrf, HAL_INET6_FAMILY,
                                           &ip, is_specific_nh_get, false, is_specific_vrf_get) != STD_ERR_OK){
                rc = cps_api_ret_code_ERR;
                break;
            }
        }

    } while (0);
    nas_l3_unlock();
    return rc;
}

static cps_api_return_code_t nas_route_cps_peer_routing_set_func(void *ctx,
                                                                 cps_api_transaction_params_t * param,
                                                                 size_t ix) {
    cps_api_object_t          obj;

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Peer Routing Entry");
    if(param == NULL){
        HAL_RT_LOG_ERR("NAS-RT-CPS", "Route Set with no param: "
                     "nas_route_cps_route_set_func");
        return cps_api_ret_code_ERR;
    }

    obj = cps_api_object_list_get (param->change_list, ix);
    if (obj == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS", "Missing Peer routing Object");
        return cps_api_ret_code_ERR;
    }

    cps_api_return_code_t rc = cps_api_ret_code_ERR;

    nas_l3_lock();
    switch (cps_api_key_get_subcat (cps_api_object_key (obj))) {
        case BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ:
            rc = nas_route_process_cps_peer_routing(param,ix);
            break;

        default:
            HAL_RT_LOG_ERR("NAS-RT-CPS", "base peer route obj type unknown %d",
                         cps_api_key_get_subcat(cps_api_object_key(obj)));
            break;
    }
    nas_l3_unlock();

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Peer Routing Exit");
    return rc;
}

static cps_api_return_code_t nas_route_cps_peer_routing_get_func (void *ctx,
                                                                  cps_api_get_params_t * param,
                                                                  size_t ix) {
    cps_api_return_code_t rc = cps_api_ret_code_OK;

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Peer Routing Status Get function");

    cps_api_object_t filt = cps_api_object_list_get(param->filters,ix);
    if (filt == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Peer routing IP object not present");
        return cps_api_ret_code_ERR;
    }

    hal_vrf_id_t vrf_id = 0;
    bool is_specific_vrf_get = false;
    const char *vrf_name = cps_api_object_get_data(filt, BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_NAME);
    if (vrf_name) {
        if (hal_rt_get_vrf_id(vrf_name, &vrf_id) == false) {
            HAL_RT_LOG_ERR("NAS-RT-CPS","VRF-id get error - Invalid VRF name:%s", vrf_name);
            return cps_api_ret_code_ERR;
        }
        is_specific_vrf_get = true;
    }

    const char     *p_if_name = cps_api_object_get_data(filt, BASE_ROUTE_PEER_ROUTING_CONFIG_IFNAME);
    const char     *p_mac_addr = cps_api_object_get_data(filt, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR);
    char            if_name[HAL_IF_NAME_SZ];
    hal_mac_addr_t  mac_addr;

    if (p_if_name) {
        memset(if_name, 0, sizeof (if_name));
        memcpy(if_name, p_if_name, strlen(p_if_name)+1);
    }

    if (p_mac_addr)
        std_string_to_mac(&mac_addr, (const char *)p_mac_addr, sizeof(mac_addr));

    nas_l3_lock();
    if(nas_route_get_all_peer_routing_config(is_specific_vrf_get, vrf_id,
                ((p_if_name) ? if_name:NULL),
                ((p_mac_addr)? &mac_addr:NULL), param->list) != STD_ERR_OK){
        rc = cps_api_ret_code_ERR;
    }
    nas_l3_unlock();

    return rc;
}

static cps_api_return_code_t nas_route_cps_peer_routing_rollback_func(void * ctx,
                              cps_api_transaction_params_t * param, size_t ix){

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Peer Routing Status Rollback function");
    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_route_cps_virtual_routing_ip_cfg_set_func(void *ctx,
                                                                 cps_api_transaction_params_t * param,
                                                                 size_t ix) {
    cps_api_object_t          obj;

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Virtual Routing IP Cfg Entry");
    if(param == NULL){
        HAL_RT_LOG_ERR("NAS-RT-CPS", "Set with no param: ");
        return cps_api_ret_code_ERR;
    }

    obj = cps_api_object_list_get (param->change_list, ix);
    if (obj == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS", "Missing Virtual routing IP Cfg Object");
        return cps_api_ret_code_ERR;
    }

    cps_api_return_code_t rc = cps_api_ret_code_ERR;

    nas_l3_lock();
    rc = nas_route_process_cps_virtual_routing_ip_cfg(param,ix);
    nas_l3_unlock();

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Virtual Routing IP Cfg Exit");
    return rc;
}

static cps_api_return_code_t nas_route_cps_virtual_routing_ip_cfg_get_func (void *ctx,
                                                                  cps_api_get_params_t * param,
                                                                  size_t ix) {
    cps_api_return_code_t rc = cps_api_ret_code_OK;
    bool                  show_all = false;
    cps_api_object_attr_t vrf_attr;
    cps_api_object_attr_t af_id_attr;
    cps_api_object_attr_t if_name_attr;
    cps_api_object_attr_t ip_addr_attr;
    nas_rt_virtual_routing_ip_config_t virtual_routing_ip_config;


    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Virtual Routing IP Cfg Get function");

    cps_api_object_t filt = cps_api_object_list_get(param->filters,ix);
    if (filt == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Virtual routing IP object not present");
        return cps_api_ret_code_ERR;
    }

    vrf_attr = cps_api_object_attr_get(filt, BASE_ROUTE_VIRTUAL_ROUTING_CONFIG_VIRTUAL_ROUTING_IP_CONFIG_VRF_NAME);
    af_id_attr = cps_api_object_attr_get(filt, BASE_ROUTE_VIRTUAL_ROUTING_CONFIG_VIRTUAL_ROUTING_IP_CONFIG_AF);
    if_name_attr = cps_api_object_attr_get(filt, BASE_ROUTE_VIRTUAL_ROUTING_CONFIG_VIRTUAL_ROUTING_IP_CONFIG_IFNAME);
    ip_addr_attr = cps_api_object_attr_get(filt, BASE_ROUTE_VIRTUAL_ROUTING_CONFIG_VIRTUAL_ROUTING_IP_CONFIG_IP);

    uint32_t af = 0;
    if ((vrf_attr == NULL) && (af_id_attr == NULL) &&
        (if_name_attr == NULL) && (ip_addr_attr == NULL)) {
        show_all = true;
    } else if ((vrf_attr == NULL) || (af_id_attr == NULL) ||
               (if_name_attr == NULL) || (ip_addr_attr == NULL)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Virtual routing IP config get. Missing key params.");
        return cps_api_ret_code_ERR;
    } else {
        memset(&virtual_routing_ip_config, 0, sizeof(virtual_routing_ip_config));

        if (vrf_attr) {
            safestrncpy(virtual_routing_ip_config.vrf_name, (const char *)cps_api_object_attr_data_bin(vrf_attr),
                        sizeof(virtual_routing_ip_config.vrf_name));
        }
        if (if_name_attr) {
            safestrncpy(virtual_routing_ip_config.if_name, (const char *)cps_api_object_attr_data_bin(if_name_attr),
                        sizeof(virtual_routing_ip_config.if_name));
        }
        if (af_id_attr) {
            af = cps_api_object_attr_data_u32(af_id_attr);
        }

        if (ip_addr_attr) {
            if(af == HAL_INET4_FAMILY) {
                struct in_addr *inp = (struct in_addr *) cps_api_object_attr_data_bin(ip_addr_attr);
                std_ip_from_inet(&virtual_routing_ip_config.ip_addr,inp);
            } else if(af == HAL_INET6_FAMILY) {
                struct in6_addr *inp6 = (struct in6_addr *) cps_api_object_attr_data_bin(ip_addr_attr);
                std_ip_from_inet6(&virtual_routing_ip_config.ip_addr,inp6);
            }
        }
    }
    nas_l3_lock();

    /* retrieve vrf-id for given vrf_name */
    if (vrf_attr) {
        if (!hal_rt_get_vrf_id(virtual_routing_ip_config.vrf_name, &virtual_routing_ip_config.vrf_id)) {
            HAL_RT_LOG_DEBUG ("NAS-RT-CPS","Virtual routing IP Get. VRF (%s) not present",
                              virtual_routing_ip_config.vrf_name);
            nas_l3_unlock();
            return cps_api_ret_code_ERR;
        }
        if (!(FIB_IS_VRF_ID_VALID (virtual_routing_ip_config.vrf_id))) {
            HAL_RT_LOG_ERR("NAS-RT-CPS", "Virtual routing VRF-id:%d is not valid!",
                           virtual_routing_ip_config.vrf_id);
            nas_l3_unlock();
            return cps_api_ret_code_ERR;
        }
    }

    if(nas_route_get_all_virtual_routing_ip_config(param->list, show_all, &virtual_routing_ip_config) != STD_ERR_OK){
        rc = cps_api_ret_code_ERR;
    }
    nas_l3_unlock();

    return rc;
}

static cps_api_return_code_t nas_route_cps_virtual_routing_ip_cfg_rollback_func(void * ctx,
                              cps_api_transaction_params_t * param, size_t ix){

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Virtual Routing IP Cfg Rollback function");
    return cps_api_ret_code_OK;
}


static t_std_error nas_route_event_handle_init(){

    if (cps_api_event_service_init() != cps_api_ret_code_OK) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Failed to init cps event service");
        return STD_ERR(ROUTE,FAIL,0);
    }

    if (cps_api_event_client_connect(&handle) != cps_api_ret_code_OK) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Failed to connect handle to cps event service");
        return STD_ERR(ROUTE,FAIL,0);
    }

    return STD_ERR_OK;
}

static cps_api_return_code_t nas_route_cps_fib_config_set_func(void *ctx,
                                                        cps_api_transaction_params_t * param,
                                                        size_t ix) {
    HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "FIB configuration set");
    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_route_cps_fib_config_get_func (void *ctx,
                                                         cps_api_get_params_t * param,
                                                         size_t ix) {
    uint32_t vrf_id = 0, is_fib_summary = false, itr = 0, cnt = 0, af_index = 0;
    t_fib_route_summary   *p_route_summary = NULL;

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "FIB Configuration Get function");

    cps_api_object_t filt = cps_api_object_list_get(param->filters,ix);
    if (filt == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","FIB object is not present");
        return cps_api_ret_code_ERR;
    }
    cps_api_object_attr_t vrf_id_attr = cps_api_get_key_data(filt,BASE_ROUTE_FIB_VRF_ID);
    cps_api_object_attr_t af_attr = cps_api_get_key_data(filt,BASE_ROUTE_FIB_AF);
    cps_api_object_attr_t fib_summary_attr = cps_api_get_key_data(filt,BASE_ROUTE_FIB_SUMMARY);
    if ((af_attr == NULL) || (fib_summary_attr == NULL)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "Missing FIB Summary attributes");
        return cps_api_ret_code_ERR;
    }

    if (vrf_id_attr) {
        vrf_id =  cps_api_object_attr_data_u32(vrf_id_attr);
            }
    is_fib_summary = cps_api_object_attr_data_u32(fib_summary_attr);
    HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "VRF-id:%d is_fib_summary_get:%d", vrf_id, is_fib_summary);
    if (is_fib_summary == false)
        return cps_api_ret_code_ERR;

    if(cps_api_object_attr_data_u32(af_attr) == AF_INET) {
        af_index = HAL_RT_V4_AFINDEX;
    } else if(cps_api_object_attr_data_u32(af_attr) == AF_INET6) {
        af_index = HAL_RT_V6_AFINDEX;
    } else {
        HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "Invalid Address Family");
        return cps_api_ret_code_ERR;
    }

    nas_l3_lock();
    if (!(FIB_IS_VRF_ID_VALID (vrf_id))) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "VRF-id:%d  is not valid!", vrf_id);
        nas_l3_unlock();
        return cps_api_ret_code_ERR;
    }

    p_route_summary = FIB_GET_ROUTE_SUMMARY (vrf_id, af_index);
    if (p_route_summary) {
        for (itr = 0; itr <= ((af_index == HAL_RT_V4_AFINDEX) ?
                              HAL_RT_V4_PREFIX_LEN : HAL_RT_V6_PREFIX_LEN); itr++) {
            cnt += p_route_summary->a_curr_count [itr];
        }
    }
    nas_l3_unlock();
    HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "VRF-id:%d %s route_cnt:%d",
                vrf_id, ((af_index == HAL_RT_V4_AFINDEX) ? "IPv4" : "IPv6"), cnt);
    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL){
        HAL_RT_LOG_ERR("HAL-RT-API","Failed to allocate memory to cps object");
        return cps_api_ret_code_ERR;
    }
    cps_api_key_t key;
    cps_api_operation_types_t op = cps_api_oper_NULL; // for now action is dummy for get request
    cps_api_key_from_attr_with_qual(&key, BASE_ROUTE_FIB_OBJ,
                                    cps_api_qualifier_TARGET);
    cps_api_object_set_type_operation(&key,op);
    cps_api_object_set_key(obj,&key);

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_FIB_ROUTE_COUNT,cnt);
    if (!cps_api_object_list_append(param->list,obj)) {
        cps_api_object_delete(obj);
        HAL_RT_LOG_ERR("HAL-RT-NHT","Failed to append object to object list");
        return cps_api_ret_code_ERR;
    }

    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_route_cps_fib_config_rollback_func(void * ctx,
                                                             cps_api_transaction_params_t * param, size_t ix){

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "FIB configuration Rollback function");
    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_route_flush_handler (void * context,
                                                    cps_api_transaction_params_t * param,
                                                    size_t ix) {
    uint32_t vrf_id = 0;

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    if (obj == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Route flush object is not present");
        return cps_api_ret_code_ERR;
    }

    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    if (op != cps_api_oper_ACTION) {
        HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Invalid FIB clear action");
        return cps_api_ret_code_ERR;
    }

    cps_api_object_attr_t vrf_id_attr = cps_api_object_attr_get(obj,BASE_ROUTE_FLUSH_INPUT_VRF_ID);
    cps_api_object_attr_t af_attr = cps_api_object_attr_get(obj,BASE_ROUTE_FLUSH_INPUT_AF);
    if (af_attr == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "Missing FIB flush addr family");
        return cps_api_ret_code_ERR;
    }

    if (vrf_id_attr) {
        vrf_id =  cps_api_object_attr_data_u32(vrf_id_attr);
        if (!(FIB_IS_VRF_ID_VALID (vrf_id))) {
            HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "VRF-id:%d  is not valid!", vrf_id);
            return cps_api_ret_code_ERR;
        }
    }

    HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "VRF-id:%d af:%d", vrf_id,
                cps_api_object_attr_data_u32(af_attr));
    /* @@TODO Clear FIB */

    return cps_api_ret_code_OK;
}

static t_std_error nas_route_nht_event_handle_init(){

    if (cps_api_event_service_init() != cps_api_ret_code_OK) {
        HAL_RT_LOG_ERR("NAS-RT-NHT-CPS","Failed to init route nht cps event service");
        return STD_ERR(ROUTE,FAIL,0);
    }

    if (cps_api_event_client_connect(&handle_nht) != cps_api_ret_code_OK) {
        HAL_RT_LOG_ERR("NAS-RT-NHT-CPS","Failed to connect handle to route nht cps event service");
        return STD_ERR(ROUTE,FAIL,0);
    }

    return STD_ERR_OK;
}

t_std_error nas_route_process_cps_nbr_intf_msg(cps_api_transaction_params_t * param, size_t ix) {

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    cps_api_return_code_t rc = cps_api_ret_code_OK;

    cps_api_object_attr_t vrf_id_attr =
        cps_api_object_attr_get(obj, VRF_MGMT_NI_IF_INTERFACES_INTERFACE_VRF_ID);
    cps_api_object_attr_t if_index_attr =
        cps_api_object_attr_get(obj, BASE_NEIGHBOR_IF_INTERFACES_STATE_INTERFACE_IF_INDEX);
    cps_api_object_attr_t enabled_attr = cps_api_object_attr_get(obj,
                                                                 IF_INTERFACES_INTERFACE_ENABLED);
    if ((vrf_id_attr == NULL) || (if_index_attr == NULL)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS", "Missing Nbr Intf Object");
        return cps_api_ret_code_ERR;
    }
    hal_vrf_id_t vrf_id = cps_api_object_attr_data_u32(vrf_id_attr);
    bool is_admin_up = (bool)cps_api_object_attr_data_u32(enabled_attr);
    hal_ifindex_t if_index = cps_api_object_attr_data_u32(if_index_attr);

    t_fib_msg *p_msg = hal_rt_alloc_mem_msg();
    if (p_msg) {
        memset(p_msg, 0, sizeof(t_fib_msg));
        p_msg->type = FIB_MSG_TYPE_NBR_MGR_INTF;
        p_msg->intf.vrf_id = vrf_id;
        p_msg->intf.if_index = if_index;
        p_msg->intf.admin_status = (is_admin_up ? RT_INTF_ADMIN_STATUS_UP : RT_INTF_ADMIN_STATUS_DOWN);
        if (cps_api_object_type_operation(cps_api_object_key(obj)) == cps_api_oper_DELETE)
            p_msg->intf.is_op_del = true;

        nas_rt_process_msg(p_msg);
    }

    return rc;
}

t_std_error nas_route_process_cps_nbr_msg(cps_api_transaction_params_t * param, size_t ix) {

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    cps_api_return_code_t rc = cps_api_ret_code_OK;

    t_fib_msg *p_msg = NULL;
    //g_fib_gbl_info.num_nei_msg++;
    p_msg = hal_rt_alloc_mem_msg();
    if (p_msg) {
        memset(p_msg, 0, sizeof(t_fib_msg));
        p_msg->type = FIB_MSG_TYPE_NBR_MGR_NBR_INFO;
        hal_rt_cps_obj_to_neigh(obj, &(p_msg->nbr));
        nas_rt_process_msg(p_msg);
    }
    return rc;
}

static cps_api_return_code_t nas_route_cps_nbr_set_func(void *ctx,
                                                        cps_api_transaction_params_t * param,
                                                        size_t ix) {
    cps_api_object_t          obj;

    HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "NBR configuration set");
    if(param == NULL){
        HAL_RT_LOG_ERR("NAS-RT-CPS", "Nbr set with no param: ");
        return cps_api_ret_code_ERR;
    }

    obj = cps_api_object_list_get (param->change_list, ix);
    if (obj == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS", "Missing Nbr Object");
        return cps_api_ret_code_ERR;
    }

    cps_api_return_code_t rc = cps_api_ret_code_OK;
    rc = nas_route_process_cps_nbr_msg(param,ix);

    return rc;
}

static cps_api_return_code_t nas_route_cps_nbr_get_func (void *ctx,
                                                         cps_api_get_params_t * param,
                                                         size_t ix) {
    uint32_t af = 0, vrf = 0;
    hal_ip_addr_t ip;
    bool is_specific_nh_get = false;
    bool is_specific_vrf_get = false;
    t_std_error rc;

    cps_api_object_t filt = cps_api_object_list_get(param->filters,ix);
    if (filt == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Neighbor object is not present");
        return cps_api_ret_code_ERR;
    }
    cps_api_object_attr_t vrf_attr = cps_api_get_key_data(filt,BASE_ROUTE_OBJ_NBR_VRF_ID);
    cps_api_object_attr_t af_attr = cps_api_get_key_data(filt,BASE_ROUTE_OBJ_NBR_AF);
    cps_api_object_attr_t nh_attr = cps_api_get_key_data(filt,BASE_ROUTE_OBJ_NBR_ADDRESS);

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "All neighbor get function");
    if(af_attr == NULL){
        HAL_RT_LOG_ERR("NAS-RT-CPS","No address family passed to get ARP entries");
        return cps_api_ret_code_ERR;
    }

    af = cps_api_object_attr_data_u32(af_attr);
    if (vrf_attr != NULL) {
        vrf = cps_api_object_attr_data_u32(vrf_attr);
        is_specific_vrf_get = true;
    }
    if (nh_attr != NULL) {
        is_specific_nh_get = true;
        if(af == AF_INET) {
            struct in_addr *inp = (struct in_addr *) cps_api_object_attr_data_bin(nh_attr);
            std_ip_from_inet(&ip,inp);
        } else {
            struct in6_addr *inp6 = (struct in6_addr *) cps_api_object_attr_data_bin(nh_attr);
            std_ip_from_inet6(&ip,inp6);
        }
    }

    nas_l3_lock();
    if (!(FIB_IS_VRF_ID_VALID (vrf))) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-GET", "VRF-id:%d is not valid!", vrf);
        nas_l3_unlock();
        return cps_api_ret_code_ERR;
    }

    if((rc = nas_route_get_all_arp_info(param->list,vrf, af, &ip, is_specific_nh_get, true,
                                        is_specific_vrf_get)) != STD_ERR_OK){
        nas_l3_unlock();
        return (cps_api_return_code_t)rc;
    }

    nas_l3_unlock();

    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_route_cps_nbr_rollback_func(void * ctx,
                                                             cps_api_transaction_params_t * param, size_t ix){

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "NBR configuration Rollback function");
    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_route_cps_nbr_intf_set_func(void *ctx,
                                                             cps_api_transaction_params_t * param,
                                                             size_t ix) {
    cps_api_object_t          obj;

    HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "NBR Intf set");
    if(param == NULL){
        HAL_RT_LOG_ERR("NAS-RT-CPS", "Nbr set with no param: ");
        return cps_api_ret_code_ERR;
    }

    obj = cps_api_object_list_get (param->change_list, ix);
    if (obj == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS", "Missing Nbr Object");
        return cps_api_ret_code_ERR;
    }

    cps_api_return_code_t rc = cps_api_ret_code_OK;
    rc = nas_route_process_cps_nbr_intf_msg(param,ix);

    return rc;
}

static cps_api_return_code_t nas_route_cps_nbr_intf_get_func (void *ctx,
                                                              cps_api_get_params_t * param,
                                                              size_t ix) {
    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Neighbor interface get function");
    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_route_cps_nbr_intf_rollback_func(void * ctx,
                                                                  cps_api_transaction_params_t * param, size_t ix){

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "NBR Interface Rollback function");
    return cps_api_ret_code_OK;
}

/* This function is used to process interface mode change notification RPC */
static cps_api_return_code_t nas_intf_mode_change_handler (void * context,
                                                    cps_api_transaction_params_t * param,
                                                    size_t ix) {
    cps_api_object_attr_t if_name_attr;
    cps_api_object_attr_t mode_attr;
    char                  if_name[HAL_IF_NAME_SZ];
    BASE_IF_MODE_t        mode = BASE_IF_MODE_MODE_NONE;
    uint32_t              if_index = 0;

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Interface mode change function");

    if(param == NULL){
        HAL_RT_LOG_ERR("NAS-RT-CPS-ACTION", "Interface mode change with no param");
        return cps_api_ret_code_ERR;
    }

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    if (obj == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-ACTION","Interface mode change operation object is not present");
        return cps_api_ret_code_ERR;
    }

    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    if (op != cps_api_oper_ACTION) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-ACTION", "Invalid Interface mode change operation action");
        return cps_api_ret_code_ERR;
    }
    /*
     * Check mandatory key attributes
     */
    if_name_attr = cps_api_object_attr_get(obj, BASE_ROUTE_INTERFACE_MODE_CHANGE_INPUT_IFNAME);
    mode_attr = cps_api_object_attr_get(obj, BASE_ROUTE_INTERFACE_MODE_CHANGE_INPUT_MODE);

    if (!if_name_attr || !mode_attr) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-ACTION", "Missing Interface mode change operation key params");
        return cps_api_ret_code_ERR;
    }

    memset (if_name,0,sizeof(if_name));

    safestrncpy(if_name,
                (const char *)cps_api_object_attr_data_bin(if_name_attr),
                sizeof(if_name));

    mode = (BASE_IF_MODE_t) cps_api_object_attr_data_u32(mode_attr);

    hal_vrf_id_t vrf_id = 0;
    if (hal_rt_get_if_index_from_if_name (if_name, &vrf_id, &if_index) != STD_ERR_OK) {
        HAL_RT_LOG_INFO ("NAS-RT-CPS-ACTION",
                         "Intf index get failed for if_name:%s, mode:%s ",
                         if_name, hal_rt_intf_mode_to_str(mode));
        return cps_api_ret_code_OK;
    }

    HAL_RT_LOG_INFO ("NAS-RT-CPS-ACTION", "Intf index for if_name:%s(%d), mode:%s",
                     if_name, if_index, hal_rt_intf_mode_to_str(mode));

    nas_l3_lock();
    if (!(FIB_IS_VRF_ID_VALID (vrf_id))) {
        HAL_RT_LOG_INFO("NAS-RT-CPS-ACTION", "VRF-id:%d  is not valid!", vrf_id);
        nas_l3_unlock();
        return cps_api_ret_code_OK;
    }

    /* Handle interface mode change for IPv4 and IPv6 address family */
    fib_process_intf_mode_change (vrf_id, HAL_RT_V4_AFINDEX, if_index, mode);
    fib_process_intf_mode_change (vrf_id, HAL_RT_V6_AFINDEX, if_index, mode);

    nas_l3_unlock();

    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_route_cps_ip_unreachables_set_func(void *ctx,
                                                             cps_api_transaction_params_t * param,
                                                             size_t ix) {
    cps_api_object_t          obj;

    HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "IP unreachables set");
    if(param == NULL){
        HAL_RT_LOG_ERR("NAS-RT-CPS", "IP unreachable with no param: ");
        return cps_api_ret_code_ERR;
    }

    obj = cps_api_object_list_get (param->change_list, ix);
    if (obj == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS", "Missing IP unreachable Object");
        return cps_api_ret_code_ERR;
    }

    cps_api_return_code_t rc = cps_api_ret_code_OK;
    rc = nas_route_process_cps_ip_unreachables_msg(param,ix);

    return rc;
}

static cps_api_return_code_t nas_route_cps_ip_unreachables_get_func (void *ctx,
                                                              cps_api_get_params_t * param,
                                                              size_t ix) {
    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "IP unreachables get function");

    cps_api_object_t filt = cps_api_object_list_get(param->filters,ix);
    if (filt == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","IP unreachable object is not present");
        return cps_api_ret_code_ERR;
    }

    cps_api_object_attr_t af_attr = cps_api_get_key_data(filt, BASE_ROUTE_IP_UNREACHABLES_CONFIG_AF);
    cps_api_object_attr_t if_name_attr = cps_api_get_key_data(filt, BASE_ROUTE_IP_UNREACHABLES_CONFIG_IFNAME);
    const char *vrf_name = cps_api_get_key_data(filt, BASE_ROUTE_IP_UNREACHABLES_CONFIG_VRF_NAME);
    bool is_specific_get = false;
    int32_t af = 0;
    if (af_attr) {
        af = cps_api_object_attr_data_u32(af_attr);
        if ((af != BASE_CMN_AF_TYPE_INET) && (af != BASE_CMN_AF_TYPE_INET6)) {
            HAL_RT_LOG_ERR("NAS-RT-CPS", "Invalid address family!");
            return cps_api_ret_code_ERR;
        }
        is_specific_get = true;
    }
    char if_name[HAL_IF_NAME_SZ];
    if (if_name_attr) {
        memset(if_name, '\0', sizeof(if_name));
        safestrncpy(if_name, (const char *)cps_api_object_attr_data_bin(if_name_attr),
                    sizeof(if_name));
        is_specific_get = true;
    }

    cps_api_return_code_t rc = cps_api_ret_code_OK;
    hal_vrf_id_t vrf_id = 0;

    if (vrf_name) {
        is_specific_get = true;
        /* retrieve vrf-id for given vrf_name */
        if (hal_rt_get_vrf_id(vrf_name, &vrf_id) == false) {
            HAL_RT_LOG_ERR("NAS-RT-CPS","IP unrehable get VRF(%s) not present.", vrf_name);
            return cps_api_ret_code_ERR;
        }
    }

    nas_l3_lock();
    rc = nas_route_get_all_ip_unreach_info(param->list, vrf_id, af, (if_name_attr ? if_name : NULL),
                                           is_specific_get);
    nas_l3_unlock();
    return rc;
}

static cps_api_return_code_t nas_route_cps_ip_unreachables_rollback_func(void * ctx,
                                                                  cps_api_transaction_params_t * param, size_t ix){

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "IP unreachables Rollback function");
    return cps_api_ret_code_OK;
}

/* This function is used to process VRF configuration RPC */
static cps_api_return_code_t nas_rt_vrf_config_handler (void * context,
                                                        cps_api_transaction_params_t * param,
                                                        size_t ix) {
    cps_api_object_attr_t vrf_id_attr;
    cps_api_object_attr_t oper_attr;

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "VRF config. function");

    if(param == NULL){
        HAL_RT_LOG_ERR("NAS-RT-CPS-ACTION", "VRF config with no param");
        return cps_api_ret_code_ERR;
    }

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    if (obj == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-ACTION","VRF config. object is not present");
        return cps_api_ret_code_ERR;
    }

    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    if (op != cps_api_oper_ACTION) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-ACTION", "Invalid VRF config. action");
        return cps_api_ret_code_ERR;
    }
    /*
     * Check mandatory key attributes
     */
    vrf_id_attr = cps_api_object_attr_get(obj, VRF_MGMT_VRF_CONFIG_INPUT_VRF_ID);
    const char *vrf_name  = cps_api_object_get_data(obj, VRF_MGMT_VRF_CONFIG_INPUT_NI_NAME);
    oper_attr = cps_api_object_attr_get(obj, VRF_MGMT_VRF_CONFIG_INPUT_OPERATION);

    if ((vrf_id_attr == NULL) || (vrf_name == NULL) || (oper_attr == NULL)){
        HAL_RT_LOG_ERR("NAS-RT-CPS-ACTION", "Missing VRF config. key params");
        return cps_api_ret_code_ERR;
    }
    hal_vrf_id_t vrf_id = cps_api_object_attr_data_u32(vrf_id_attr);
    uint32_t operation = cps_api_object_attr_data_u32(oper_attr);
    /* Return error for default VRF create/delete since it's created by default during NAS-L3 init. */
    if ((vrf_id == FIB_DEFAULT_VRF) ||
        ((operation == BASE_CMN_OPERATION_TYPE_CREATE) && (vrf_id == FIB_MGMT_VRF))) {
        HAL_RT_LOG_INFO("NAS-RT-CPS-ACTION", "No action required for VRF-id:%d operation:%d", vrf_id, operation);
        return cps_api_ret_code_OK;
    }

    nas_l3_lock();
    if (operation == BASE_CMN_OPERATION_TYPE_CREATE) {
        hal_rt_vrf_init(vrf_id, vrf_name);
    } else if (operation == BASE_CMN_OPERATION_TYPE_DELETE) {
        hal_rt_flush_vrf_info(vrf_id);
        if (vrf_id != FIB_MGMT_VRF) {
            hal_rt_vrf_de_init(vrf_id);
        }
    }

    nas_l3_unlock();

    return cps_api_ret_code_OK;
}


static cps_api_return_code_t nas_route_cps_ip_redirects_set_func(void *ctx,
                                                             cps_api_transaction_params_t * param,
                                                             size_t ix) {
    cps_api_object_t          obj;

    HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "IP redirects set");
    if(param == NULL){
        HAL_RT_LOG_ERR("NAS-RT-CPS", "IP redirects with no param: ");
        return cps_api_ret_code_ERR;
    }

    obj = cps_api_object_list_get (param->change_list, ix);
    if (obj == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS", "Missing IP redirects Object");
        return cps_api_ret_code_ERR;
    }

    cps_api_object_attr_t vrf_attr = cps_api_get_key_data(obj, BASE_ROUTE_IP_REDIRECTS_CONFIG_VRF_NAME);

    if (vrf_attr) {
        char  vrf_name[NAS_VRF_NAME_SZ + 1];
        memset (vrf_name,0,sizeof(vrf_name));
        safestrncpy(vrf_name, (const char *)cps_api_object_attr_data_bin(vrf_attr),
                    sizeof(vrf_name));

        if (strncmp(vrf_name, FIB_DEFAULT_VRF_NAME, sizeof(vrf_name))) {
            HAL_RT_LOG_ERR("NAS-RT-CPS", "VRF-name:%s is not valid!", vrf_name);
            return cps_api_ret_code_ERR;
        }
    }

    cps_api_return_code_t rc = cps_api_ret_code_OK;
    rc = nas_route_process_cps_ip_redirects_msg(param,ix);

    return rc;
}

static cps_api_return_code_t nas_route_cps_ip_redirects_get_func (void *ctx,
                                                              cps_api_get_params_t * param,
                                                              size_t ix) {
    hal_vrf_id_t vrf_id = FIB_DEFAULT_VRF;
    char         vrf_name[HAL_IF_NAME_SZ];

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "IP redirects get function");

    cps_api_object_t filt = cps_api_object_list_get(param->filters,ix);
    if (filt == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","IP redirects object is not present");
        return cps_api_ret_code_ERR;
    }

    cps_api_object_attr_t vrf_attr = cps_api_get_key_data(filt, BASE_ROUTE_IP_REDIRECTS_CONFIG_VRF_NAME);
    cps_api_object_attr_t if_name_attr = cps_api_get_key_data(filt, BASE_ROUTE_IP_REDIRECTS_CONFIG_IFNAME);

    memset (vrf_name,0,sizeof(vrf_name));

    if (vrf_attr) {
        safestrncpy(vrf_name, (const char *)cps_api_object_attr_data_bin(vrf_attr),
                    sizeof(vrf_name));
    }

    char if_name[HAL_IF_NAME_SZ];
    if_name[0] = '\0';

    if (if_name_attr) {
        safestrncpy(if_name, (const char *)cps_api_object_attr_data_bin(if_name_attr),
                    sizeof(if_name));
    }

    cps_api_return_code_t rc = cps_api_ret_code_OK;

    nas_l3_lock();

    /* retrieve vrf-id for given vrf_name */
    if (vrf_attr && !hal_rt_get_vrf_id(vrf_name, &vrf_id)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","IP redirects VRF(%s) not present.", vrf_name);
        nas_l3_unlock();
        return cps_api_ret_code_ERR;
    }

    rc = nas_route_get_all_ip_redirects_info(param->list, vrf_id, (if_name_attr ? if_name : NULL));
    nas_l3_unlock();
    return rc;
}

static cps_api_return_code_t nas_route_cps_ip_redirects_rollback_func(void * ctx,
                                                                  cps_api_transaction_params_t * param, size_t ix){

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "IP redirects Rollback function");
    return cps_api_ret_code_OK;
}

/* This function is used to process neigh flush RPC */
static cps_api_return_code_t nas_neigh_flush_handler(void * context,
                                                     cps_api_transaction_params_t * param,
                                                     size_t ix) {
    cps_api_object_attr_t af_attr;
    uint32_t af = HAL_RT_V4_AFINDEX;
    hal_vrf_id_t vrf_id = 0;
    hal_ifindex_t if_index = 0;
    HAL_RT_LOG_INFO("NAS-RT-CPS", "Neigh flush handler!");

    if(param == NULL){
        HAL_RT_LOG_ERR("NAS-RT-CPS-ACTION", "Neigh flush with no param");
        return cps_api_ret_code_ERR;
    }

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    if (obj == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-ACTION","Neigh flush object is not present");
        return cps_api_ret_code_ERR;
    }

    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    if (op != cps_api_oper_ACTION) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-ACTION", "Invalid Neigh flush operation action");
        return cps_api_ret_code_ERR;
    }
    /*
     * Check mandatory key attributes
     */
    const char *vrf_name = cps_api_object_get_data(obj, BASE_ROUTE_NBR_FLUSH_INPUT_VRF_NAME);
    if (vrf_name == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-ACTION", "Missing VRF name!");
        return cps_api_ret_code_ERR;
    }
    af_attr = cps_api_object_attr_get(obj, BASE_ROUTE_NBR_FLUSH_INPUT_AF);
    if (af_attr == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-ACTION", "Missing address family!");
        return cps_api_ret_code_ERR;
    }
    af = cps_api_object_attr_data_u32(af_attr);
    if (af == BASE_CMN_AF_TYPE_INET) {
        af = HAL_RT_V4_AFINDEX;
    } else if (BASE_CMN_AF_TYPE_INET6) {
        af = HAL_RT_V6_AFINDEX;
    } else {
        HAL_RT_LOG_ERR("NAS-RT-CPS-ACTION", "Invalid family");
        return cps_api_ret_code_ERR;
    }
    const char *if_name = cps_api_object_get_data(obj, BASE_ROUTE_NBR_FLUSH_INPUT_IFNAME);
    if (if_name) {
        if (hal_rt_get_if_index_from_if_name ((char*)if_name, &vrf_id, (uint32_t *)&if_index) != STD_ERR_OK) {
            HAL_RT_LOG_INFO ("NAS-RT-CPS-ACTION",
                             "Intf index get failed for if_name:%s ", if_name);
            return cps_api_ret_code_OK;
        }
    }
    if (vrf_name) {
        if (hal_rt_get_vrf_id(vrf_name, &vrf_id) == false) {
            HAL_RT_LOG_INFO("NAS-RT-CPS-ACTION","VRF-id get error - Invalid VRF name:%s", vrf_name);
            return cps_api_ret_code_ERR;
        }
    }

    HAL_RT_LOG_INFO ("NAS-RT-CPS-ACTION", "Neigh flush VRF:%s(%d) af:%d if_name:%s(%d) ",
                     vrf_name, vrf_id, af, (if_name ? if_name : ""), if_index);

    t_fib_msg *p_msg = hal_rt_alloc_mem_msg();
    if (p_msg) {
        memset(p_msg, 0, sizeof(t_fib_msg));
        p_msg->type = FIB_MSG_TYPE_NEIGH_FLUSH;
        p_msg->neigh_flush.vrf_id = vrf_id;
        p_msg->neigh_flush.af_index = af;
        p_msg->neigh_flush.if_index = if_index;

        nas_rt_process_msg(p_msg);
    }
    return cps_api_ret_code_OK;
}

static t_std_error nas_route_object_entry_init(cps_api_operation_handle_t nas_route_cps_handle ) {

    cps_api_registration_functions_t f;
    char buff[CPS_API_KEY_STR_MAX];

    memset(&f,0,sizeof(f));

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "NAS Routing CPS Initialization");


    /*
     * Initialize Base Route object Entry
     */



    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Registering for %s",
            cps_api_key_print(&f.key,buff,sizeof(buff)-1));


    f.handle                 = nas_route_cps_handle;
    f._read_function         = nas_route_cps_route_get_func;
    f._write_function         = nas_route_cps_route_set_func;
    f._rollback_function     = nas_route_cps_route_rollback_func;

   if (!cps_api_key_from_attr_with_qual(&f.key,BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Could not translate %d to key %s",
                (int)(BASE_ROUTE_OBJ_OBJ),cps_api_key_print(&f.key,buff,sizeof(buff)-1));
           return STD_ERR(ROUTE,FAIL,0);
    }


    if (cps_api_register(&f)!=cps_api_ret_code_OK) {
            return STD_ERR(ROUTE,FAIL,0);
    }

    memset(&f,0,sizeof(f));
    memset(buff,0,sizeof(buff));

    /* Register route flush object with CPS */
    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_ROUTE_FLUSH_OBJ,
                                         cps_api_qualifier_TARGET)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Could not translate %d to key %s",
                   (int)(BASE_ROUTE_FLUSH_OBJ),cps_api_key_print(&f.key,buff,sizeof(buff)-1));
        return STD_ERR(ROUTE,FAIL,0);
    }

    f.handle = nas_route_cps_handle;
    f._write_function = nas_route_flush_handler;

    if (cps_api_register(&f)!=cps_api_ret_code_OK) {
        return STD_ERR(ROUTE,FAIL,0);
    }


    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Registering for ROUTE NH OPERATION");

    memset(&f,0,sizeof(f));
    memset(buff,0,sizeof(buff));

    /* Register route flush object with CPS */
    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_ROUTE_ROUTE_NH_OPERATION_OBJ,
                                         cps_api_qualifier_TARGET)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Could not translate %d to key %s",
                   (int)(BASE_ROUTE_ROUTE_NH_OPERATION_OBJ),cps_api_key_print(&f.key,buff,sizeof(buff)-1));
        return STD_ERR(ROUTE,FAIL,0);
    }

    f.handle = nas_route_cps_handle;
    f._write_function = nas_route_nh_operation_handler;

    if (cps_api_register(&f)!=cps_api_ret_code_OK) {
        return STD_ERR(ROUTE,FAIL,0);
    }

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Registering for ROUTE Event filter");

    memset(&f,0,sizeof(f));
    memset(buff,0,sizeof(buff));

    /* Register event filter object with CPS */
    if (!cps_api_key_from_attr_with_qual(&f.key, BASE_ROUTE_EVENT_FILTER_OBJ,
                                         cps_api_qualifier_TARGET)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Could not translate %d to key %s",
                   (int)(BASE_ROUTE_EVENT_FILTER_OBJ),cps_api_key_print(&f.key,buff,sizeof(buff)-1));
        return STD_ERR(ROUTE,FAIL,0);
    }

    f.handle                 = nas_route_cps_handle;
    f._read_function         = nas_route_event_filter_get_func;
    f._write_function        = nas_route_event_filter_set_func;
    f._rollback_function     = nas_route_event_filter_rollback_func;

    if (cps_api_register(&f)!=cps_api_ret_code_OK) {
        return STD_ERR(ROUTE,FAIL,0);
    }


    return STD_ERR_OK;
}


/* route global container (resilient hash) */
static cps_api_return_code_t nas_route_cps_route_globals_get_func(void *ctx,
                                                                  cps_api_get_params_t *param,
                                                                  size_t ix) {
    cps_api_return_code_t rc = cps_api_ret_code_OK;
    cps_api_object_t      obj = cps_api_object_create();
    t_fib_gbl_info       *gbl_info;
    bool                  hash_enabled;

    // retrieve object
    cps_api_object_t filt = cps_api_object_list_get(param->filters, ix);
    if (filt == NULL) {
        cps_api_object_delete(obj);
        HAL_RT_LOG_ERR("NAS-RT-CPS", "global object is not present");
        return cps_api_ret_code_ERR;
    }

    nas_l3_lock();
    gbl_info = hal_rt_access_fib_gbl_info();
    hash_enabled = gbl_info->resilient_hash;
    nas_l3_unlock();

    cps_api_object_attr_add_u32(obj, BASE_ROUTE_ROUTING_GLOBALS_RESILIENT_HASH_ENABLE, hash_enabled);
    if (!cps_api_object_list_append(param->list, obj)) {
        cps_api_object_delete(obj);
        HAL_RT_LOG_ERR("HAL-RT-CPS", "Failed to append object to object list");
        return cps_api_ret_code_ERR;
    }

    return rc;
}

static cps_api_return_code_t nas_route_cps_route_globals_set_func(void *ctx,
                                                                 cps_api_transaction_params_t *param,
                                                                 size_t ix) {
    cps_api_return_code_t rc = cps_api_ret_code_OK;
    cps_api_object_t      obj;
    t_fib_gbl_info        *gbl_info;
    bool                  current_setting;
    cps_api_object_it_t   it;
    uint32_t              new_setting = 0;

    if (param == NULL) {
        HAL_RT_LOG_ERR("HAL-RT-CPS", "global-config set with no parameters");
        return cps_api_ret_code_ERR;
    }

    obj = cps_api_object_list_get(param->change_list, ix);
    if (obj == NULL) {
        HAL_RT_LOG_ERR("HAL-RT-CPS", "global-config missing parameters");
        return cps_api_ret_code_ERR;
    }

    /*  switch across create, set, delete */
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));
    switch (op) {
        case cps_api_oper_CREATE:
        case cps_api_oper_SET:
            break;
        case cps_api_oper_DELETE:
            break;
        default:
            break;
    }

    switch (cps_api_key_get_subcat(cps_api_object_key (obj))) {
        case BASE_ROUTE_ROUTING_GLOBALS:
            break;
        default:
            return cps_api_ret_code_ERR;
    }

    cps_api_object_it_begin(obj,&it);

    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {
        cps_api_attr_id_t id = cps_api_object_attr_id(it.attr);

        switch (id) {
            case BASE_ROUTE_ROUTING_GLOBALS_RESILIENT_HASH_ENABLE:
                new_setting = cps_api_object_attr_data_u32(it.attr);
                break;

            default:
                break;
        }
    }

    nas_l3_lock();
    gbl_info = hal_rt_access_fib_gbl_info();
    current_setting = gbl_info->resilient_hash;

    if (current_setting == new_setting) {
        HAL_RT_LOG_DEBUG("HAL-RT-CPS", "resilient hash, no change (%d)", new_setting);
    } else {
        gbl_info->resilient_hash = new_setting;

        /* update all existing routes */
        hal_rt_mpath_update_rh_all();
    }

    nas_l3_unlock();
    return rc;
}

static cps_api_return_code_t nas_route_cps_route_globals_rollback_func(void * ctx,
                              cps_api_transaction_params_t * param, size_t ix){

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Routing Globals rollback function");
    return cps_api_ret_code_OK;
}

/*
 * CPS registration for routing globals container
 */
static t_std_error nas_route_object_route_globals_init(cps_api_operation_handle_t nas_route_cps_handle) {

    cps_api_registration_functions_t f;
    char buff[CPS_API_KEY_STR_MAX];

    memset(&f,0,sizeof(f));

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Registering for %s",
            cps_api_key_print(&f.key,buff,sizeof(buff)-1));

    f.handle             = nas_route_cps_handle;
    f._read_function     = nas_route_cps_route_globals_get_func;
    f._write_function    = nas_route_cps_route_globals_set_func;
    f._rollback_function = nas_route_cps_route_globals_rollback_func;

   if (!cps_api_key_from_attr_with_qual(&f.key, BASE_ROUTE_ROUTING_GLOBALS_OBJ, cps_api_qualifier_TARGET)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Could not translate %d to key %s",
            (int)(BASE_ROUTE_ROUTING_GLOBALS_OBJ),
            cps_api_key_print(&f.key, buff, sizeof(buff)-1));
        return STD_ERR(ROUTE, FAIL, 0);
    }

    if (cps_api_register(&f) != cps_api_ret_code_OK) {
        return STD_ERR(ROUTE,FAIL,0);
    }

    return STD_ERR_OK;
}

static t_std_error nas_route_object_route_init(cps_api_operation_handle_t nas_route_cps_handle ) {

    cps_api_registration_functions_t f;
    char buff[CPS_API_KEY_STR_MAX];

    memset(&f,0,sizeof(f));

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "NAS ROUTE CPS Initialization");

    f.handle                 = nas_route_cps_handle;
    f._read_function         = nas_route_cps_all_route_get_func;

    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_ROUTE_OBJ_ENTRY,cps_api_qualifier_TARGET)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Could not translate %d to key %s",
                    (int)(BASE_ROUTE_OBJ_ENTRY),cps_api_key_print(&f.key,buff,sizeof(buff)-1));
        return STD_ERR(ROUTE,FAIL,0);
    }

    if (cps_api_register(&f)!=cps_api_ret_code_OK) {
        return STD_ERR(ROUTE,FAIL,0);
    }
    return STD_ERR_OK;
}

static t_std_error nas_route_object_arp_init(cps_api_operation_handle_t nas_route_cps_handle ) {

    cps_api_registration_functions_t f;
    char buff[CPS_API_KEY_STR_MAX];

    memset(&f,0,sizeof(f));

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "NAS ARP CPS Initialization");

    f.handle                 = nas_route_cps_handle;
    f._read_function         = nas_route_cps_arp_get_func;

    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_ROUTE_OBJ_NBR,cps_api_qualifier_TARGET)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Could not translate %d to key %s",
                    (int)(BASE_ROUTE_OBJ_NBR),cps_api_key_print(&f.key,buff,sizeof(buff)-1));
        return STD_ERR(ROUTE,FAIL,0);
    }

    if (cps_api_register(&f)!=cps_api_ret_code_OK) {
        return STD_ERR(ROUTE,FAIL,0);
    }
    return STD_ERR_OK;
}


static t_std_error nas_route_object_nht_init(cps_api_operation_handle_t nas_route_nht_cps_handle ) {

    cps_api_registration_functions_t f;
    char buff[CPS_API_KEY_STR_MAX];

    memset(&f,0,sizeof(f));

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "NAS NextHop Tracking CPS Initialization");

    /*
     * Initialize Base Route NHT object
     */
    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_ROUTE_NH_TRACK_OBJ,cps_api_qualifier_TARGET)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Could not translate %d to key %s",
                (int)(BASE_ROUTE_NH_TRACK_OBJ),cps_api_key_print(&f.key,buff,sizeof(buff)-1));
           return STD_ERR(ROUTE,FAIL,0);
    }

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Registering for %s",
            cps_api_key_print(&f.key,buff,sizeof(buff)-1));

    f.handle                 = nas_route_nht_cps_handle;
    f._read_function         = nas_route_cps_nht_get_func;
    f._write_function         = nas_route_cps_nht_set_func;
    f._rollback_function     = nas_route_cps_nht_rollback_func;

    if (cps_api_register(&f)!=cps_api_ret_code_OK) {
            return STD_ERR(ROUTE,FAIL,0);
    }

    return STD_ERR_OK;
}

static t_std_error nas_route_object_peer_routing_init(cps_api_operation_handle_t
                                                      nas_route_cps_handle ) {

    cps_api_registration_functions_t f;
    char buff[CPS_API_KEY_STR_MAX];

    memset(&f,0,sizeof(f));

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "NAS Peer Routing CPS Initialization");

    f.handle                 = nas_route_cps_handle;
    f._read_function         = nas_route_cps_peer_routing_get_func;
    f._write_function        = nas_route_cps_peer_routing_set_func;
    f._rollback_function     = nas_route_cps_peer_routing_rollback_func;

    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,
                                         cps_api_qualifier_TARGET)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Could not translate %d to key %s",
                    (int)(BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ),cps_api_key_print(&f.key,buff,sizeof(buff)-1));
        return STD_ERR(ROUTE,FAIL,0);
    }

    if (cps_api_register(&f)!=cps_api_ret_code_OK) {
        return STD_ERR(ROUTE,FAIL,0);
    }

    memset(&f,0,sizeof(f));

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "NAS Virtual Routing IP CFG CPS Initialization");

    f.handle                 = nas_route_cps_handle;
    f._read_function         = nas_route_cps_virtual_routing_ip_cfg_get_func;
    f._write_function        = nas_route_cps_virtual_routing_ip_cfg_set_func;
    f._rollback_function     = nas_route_cps_virtual_routing_ip_cfg_rollback_func;

    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_ROUTE_VIRTUAL_ROUTING_CONFIG_VIRTUAL_ROUTING_IP_CONFIG,
                                         cps_api_qualifier_TARGET)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Could not translate %d to key %s",
                    (int)(BASE_ROUTE_VIRTUAL_ROUTING_CONFIG_VIRTUAL_ROUTING_IP_CONFIG),cps_api_key_print(&f.key,buff,sizeof(buff)-1));
        return STD_ERR(ROUTE,FAIL,0);
    }

    if (cps_api_register(&f)!=cps_api_ret_code_OK) {
        return STD_ERR(ROUTE,FAIL,0);
    }

    return STD_ERR_OK;
}

static t_std_error nas_route_object_fib_config_init(cps_api_operation_handle_t nas_route_cps_handle ) {

    cps_api_registration_functions_t f;
    char buff[CPS_API_KEY_STR_MAX];

    memset(&f,0,sizeof(f));

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "NAS FIB CPS Initialization");

    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_ROUTE_FIB_OBJ,cps_api_qualifier_TARGET)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Could not translate %d to key %s",
                   (int)(BASE_ROUTE_FIB_OBJ),cps_api_key_print(&f.key,buff,sizeof(buff)-1));
        return STD_ERR(ROUTE,FAIL,0);
    }

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Registering for %s",
                 cps_api_key_print(&f.key,buff,sizeof(buff)-1));

    f.handle                 = nas_route_cps_handle;
    f._read_function         = nas_route_cps_fib_config_get_func;
    f._write_function        = nas_route_cps_fib_config_set_func;
    f._rollback_function     = nas_route_cps_fib_config_rollback_func;

    if (cps_api_register(&f)!=cps_api_ret_code_OK) {
        return STD_ERR(ROUTE,FAIL,0);
    }
    return STD_ERR_OK;
}

static t_std_error nas_route_object_nbr_init(cps_api_operation_handle_t nas_route_cps_handle ) {

    cps_api_registration_functions_t f;
    char buff[CPS_API_KEY_STR_MAX];

    memset(&f,0,sizeof(f));

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "NBR CPS Initialization");

    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_NEIGHBOR_BASE_ROUTE_OBJ_NBR_OBJ,cps_api_qualifier_TARGET)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Could not translate %d to key %s",
                   (int)(BASE_NEIGHBOR_BASE_ROUTE_OBJ_NBR_OBJ),cps_api_key_print(&f.key,buff,sizeof(buff)-1));
        return STD_ERR(ROUTE,FAIL,0);
    }

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Registering for %s",
                 cps_api_key_print(&f.key,buff,sizeof(buff)-1));

    f.handle                 = nas_route_cps_handle;
    f._read_function         = nas_route_cps_nbr_get_func;
    f._write_function        = nas_route_cps_nbr_set_func;
    f._rollback_function     = nas_route_cps_nbr_rollback_func;

    if (cps_api_register(&f)!=cps_api_ret_code_OK) {
        return STD_ERR(ROUTE,FAIL,0);
    }
    return STD_ERR_OK;
}

static t_std_error nas_route_object_nbr_intf_init(cps_api_operation_handle_t nas_route_cps_handle ) {

    cps_api_registration_functions_t f;
    char buff[CPS_API_KEY_STR_MAX];

    memset(&f,0,sizeof(f));

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "NBR Interface CPS Initialization");

    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_NEIGHBOR_IF_INTERFACES_STATE_INTERFACE_OBJ,cps_api_qualifier_TARGET)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Could not translate %d to key %s",
                   (int)(BASE_NEIGHBOR_IF_INTERFACES_STATE_INTERFACE_OBJ),cps_api_key_print(&f.key,buff,sizeof(buff)-1));
        return STD_ERR(ROUTE,FAIL,0);
    }

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Registering for %s",
                 cps_api_key_print(&f.key,buff,sizeof(buff)-1));

    f.handle                 = nas_route_cps_handle;
    f._read_function         = nas_route_cps_nbr_intf_get_func;
    f._write_function        = nas_route_cps_nbr_intf_set_func;
    f._rollback_function     = nas_route_cps_nbr_intf_rollback_func;

    if (cps_api_register(&f)!=cps_api_ret_code_OK) {
        return STD_ERR(ROUTE,FAIL,0);
    }
    return STD_ERR_OK;
}

/* register for interface operation objects */
static t_std_error nas_route_object_interface_init(cps_api_operation_handle_t nas_route_cps_handle ) {
    cps_api_registration_functions_t f;
    char buff[CPS_API_KEY_STR_MAX];

    memset(&f,0,sizeof(f));

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Interface operation CPS Initialization");

    /* Register interface mode change rpc object with CPS */
    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_ROUTE_INTERFACE_MODE_CHANGE_OBJ,
                                         cps_api_qualifier_TARGET)) {
        HAL_RT_LOG_ERR ("NAS-RT-CPS","Could not translate %d to key %s",
                        (int)(BASE_ROUTE_INTERFACE_MODE_CHANGE_OBJ),
                        cps_api_key_print(&f.key,buff,sizeof(buff)-1));

        return STD_ERR(ROUTE,FAIL,0);
    }

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Registering for %s",
                 cps_api_key_print(&f.key,buff,sizeof(buff)-1));

    f.handle = nas_route_cps_handle;
    f._write_function = nas_intf_mode_change_handler;

    if (cps_api_register(&f)!=cps_api_ret_code_OK) {
        return STD_ERR(ROUTE,FAIL,0);
    }
    return STD_ERR_OK;
}

static t_std_error nas_route_object_ip_unreachables_init(cps_api_operation_handle_t nas_route_cps_handle ) {

    cps_api_registration_functions_t f;
    char buff[CPS_API_KEY_STR_MAX];

    memset(&f,0,sizeof(f));

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "IP unreachales CPS Initialization");

    f.handle                 = nas_route_cps_handle;
    f._read_function         = nas_route_cps_ip_unreachables_get_func;
    f._write_function        = nas_route_cps_ip_unreachables_set_func;
    f._rollback_function     = nas_route_cps_ip_unreachables_rollback_func;

    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_ROUTE_IP_UNREACHABLES_CONFIG_OBJ,cps_api_qualifier_TARGET)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Could not translate %d to key %s",
                   (int)(BASE_ROUTE_IP_UNREACHABLES_CONFIG_OBJ),cps_api_key_print(&f.key,buff,sizeof(buff)-1));
        return STD_ERR(ROUTE,FAIL,0);
    }

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Registering for %s",
                 cps_api_key_print(&f.key,buff,sizeof(buff)-1));
    if (cps_api_register(&f)!=cps_api_ret_code_OK) {
        return STD_ERR(ROUTE,FAIL,0);
    }
    return STD_ERR_OK;
}

/* Register for VRF config. object */
static t_std_error nas_route_object_vrf_config_init(cps_api_operation_handle_t nas_route_cps_handle ) {
    cps_api_registration_functions_t f;
    char buff[CPS_API_KEY_STR_MAX];

    memset(&f,0,sizeof(f));

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "VRF config. CPS Initialization");

    /* Register VRF config rpc object with CPS */
    if (!cps_api_key_from_attr_with_qual(&f.key,VRF_MGMT_VRF_CONFIG_OBJ,
                                         cps_api_qualifier_TARGET)) {
        HAL_RT_LOG_ERR ("NAS-RT-CPS","Could not translate %d to key %s",
                        (int)(VRF_MGMT_VRF_CONFIG_OBJ),
                        cps_api_key_print(&f.key,buff,sizeof(buff)-1));

        return STD_ERR(ROUTE,FAIL,0);
    }

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Registering for %s",
                 cps_api_key_print(&f.key,buff,sizeof(buff)-1));

    f.handle = nas_route_cps_handle;
    f._write_function = nas_rt_vrf_config_handler;

    if (cps_api_register(&f)!=cps_api_ret_code_OK) {
        return STD_ERR(ROUTE,FAIL,0);
    }
    return STD_ERR_OK;
}

static t_std_error nas_route_object_ip_redirects_init (cps_api_operation_handle_t nas_route_cps_handle ) {

    cps_api_registration_functions_t f;
    char buff[CPS_API_KEY_STR_MAX];

    memset(&f,0,sizeof(f));

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "IP redirects CPS Initialization");

    f.handle                 = nas_route_cps_handle;
    f._read_function         = nas_route_cps_ip_redirects_get_func;
    f._write_function        = nas_route_cps_ip_redirects_set_func;
    f._rollback_function     = nas_route_cps_ip_redirects_rollback_func;

    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_ROUTE_IP_REDIRECTS_CONFIG_OBJ,cps_api_qualifier_TARGET)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Could not translate %d to key %s",
                   (int)(BASE_ROUTE_IP_REDIRECTS_CONFIG_OBJ),cps_api_key_print(&f.key,buff,sizeof(buff)-1));
        return STD_ERR(ROUTE,FAIL,0);
    }

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Registering for %s",
                 cps_api_key_print(&f.key,buff,sizeof(buff)-1));
    if (cps_api_register(&f)!=cps_api_ret_code_OK) {
        return STD_ERR(ROUTE,FAIL,0);
    }
    return STD_ERR_OK;
}

/* register for neighbor flush object */
static t_std_error nas_route_object_neigh_flush_init(cps_api_operation_handle_t nas_route_cps_handle ) {
    cps_api_registration_functions_t f;
    char buff[CPS_API_KEY_STR_MAX];

    memset(&f,0,sizeof(f));

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Neighbor flush operation CPS Initialization");

    /* Register neighbor flush rpc object with CPS */
    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_ROUTE_NBR_FLUSH_OBJ,
                                         cps_api_qualifier_TARGET)) {
        HAL_RT_LOG_ERR ("NAS-RT-CPS","Could not translate %d to key %s",
                        (int)(BASE_ROUTE_NBR_FLUSH_OBJ),
                        cps_api_key_print(&f.key,buff,sizeof(buff)-1));

        return STD_ERR(ROUTE,FAIL,0);
    }

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Registering for %s",
                 cps_api_key_print(&f.key,buff,sizeof(buff)-1));

    f.handle = nas_route_cps_handle;
    f._write_function = nas_neigh_flush_handler;

    if (cps_api_register(&f)!=cps_api_ret_code_OK) {
        return STD_ERR(ROUTE,FAIL,0);
    }
    return STD_ERR_OK;
}


t_std_error nas_routing_cps_init(cps_api_operation_handle_t nas_route_cps_handle) {

    t_std_error ret;

    if((ret = nas_route_object_entry_init(nas_route_cps_handle)) != STD_ERR_OK){
        return ret;
    }

    if((ret = nas_route_object_route_init(nas_route_cps_handle)) != STD_ERR_OK){
        return ret;
    }

    if((ret = nas_route_object_arp_init(nas_route_cps_handle)) != STD_ERR_OK){
        return ret;
    }

    if((ret = nas_route_object_peer_routing_init(nas_route_cps_handle)) != STD_ERR_OK){
        return ret;
    }

    if((ret = nas_route_object_fib_config_init(nas_route_cps_handle)) != STD_ERR_OK){
        return ret;
    }

    if((ret = nas_route_object_nbr_init(nas_route_cps_handle)) != STD_ERR_OK){
        return ret;
    }

    if((ret = nas_route_object_nbr_intf_init(nas_route_cps_handle)) != STD_ERR_OK){
        return ret;
    }

    if((ret = nas_route_object_interface_init(nas_route_cps_handle)) != STD_ERR_OK){
        return ret;
    }

    if((ret = nas_route_object_ip_unreachables_init(nas_route_cps_handle)) != STD_ERR_OK){
        return ret;
    }

    if((ret = nas_route_object_vrf_config_init(nas_route_cps_handle)) != STD_ERR_OK){
        return ret;
    }
    if((ret = nas_route_event_handle_init()) != STD_ERR_OK){
        return ret;
    }

    if((ret = nas_route_object_ip_redirects_init(nas_route_cps_handle)) != STD_ERR_OK){
        return ret;
    }

    if((ret = nas_route_object_neigh_flush_init(nas_route_cps_handle)) != STD_ERR_OK){
        return ret;
    }

    if((ret = nas_route_object_route_globals_init(nas_route_cps_handle)) != STD_ERR_OK){
        return ret;
    }

    return ret;
}

t_std_error nas_routing_nht_cps_init(cps_api_operation_handle_t nas_route_nht_cps_handle) {

    t_std_error ret;

    if((ret = nas_route_object_nht_init(nas_route_nht_cps_handle)) != STD_ERR_OK){
        return ret;
    }

    if((ret = nas_route_nht_event_handle_init()) != STD_ERR_OK){
        return ret;
    }

    return ret;
}

t_std_error nas_route_publish_object(cps_api_object_t obj){
    cps_api_return_code_t rc;
    if((rc = cps_api_event_publish(handle,obj))!= cps_api_ret_code_OK){
        HAL_RT_LOG_ERR("NAS-RT-CPS","Failed to publish cps event");
        cps_api_object_delete(obj);
        return (t_std_error)rc;
    }
    cps_api_object_delete(obj);
    return STD_ERR_OK;
}


t_std_error nas_route_nht_publish_object(cps_api_object_t obj){
    cps_api_return_code_t rc;

    if((rc = cps_api_event_publish(handle_nht,obj))!= cps_api_ret_code_OK){
        HAL_RT_LOG_ERR("NAS-RT-NHT-CPS","Failed to publish cps event");
        cps_api_object_delete(obj);
        return (t_std_error)rc;
    }
    cps_api_object_delete(obj);
    return STD_ERR_OK;
}


cps_api_return_code_t nas_route_process_cps_peer_routing(cps_api_transaction_params_t * param, size_t ix) {

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    cps_api_return_code_t rc = cps_api_ret_code_OK;
    cps_api_object_attr_t if_name_attr;
    cps_api_object_attr_t mac_addr_attr;
    cps_api_object_attr_t ingress_only_attr;
    nas_rt_peer_mac_config_t peer_routing_config;
    hal_mac_addr_t mac_addr;
    void *addr = NULL;
    uint32_t vrf_id = 0;
    bool status = false;
    char     p_buf[HAL_RT_MAX_BUFSZ];

    if (obj == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Peer routing object is not present");
        return cps_api_ret_code_ERR;
    }
    memset(&peer_routing_config, 0, sizeof(peer_routing_config));
    memset(peer_routing_config.if_name, '\0', sizeof(peer_routing_config.if_name));
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));
    /*
     * Check mandatory peer status attributes
     */
    if_name_attr   = cps_api_object_attr_get(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_IFNAME);
    mac_addr_attr = cps_api_object_attr_get(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR);
    if (mac_addr_attr == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "Missing peer routing key params");
        return cps_api_ret_code_ERR;
    }
    switch(op) {
        case cps_api_oper_CREATE:
            HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "In Peer Routing Create ");
            status = true;
            break;
        case cps_api_oper_SET:
            HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "In Peer Routing Set");
            status = true;
            break;
        case cps_api_oper_DELETE:
            HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "In Peer Routing Del");
            status = false;
            break;
        default:
            break;
    }
    const char *vrf_name = cps_api_object_get_data(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_NAME);
    if (vrf_name) {
        if (hal_rt_get_vrf_id(vrf_name, &vrf_id) == false) {
            HAL_RT_LOG_ERR("NAS-RT-CPS-SET","VRF-id get error - Invalid VRF name:%s", vrf_name);
            return cps_api_ret_code_ERR;
        }
    }
    if (!(FIB_IS_VRF_ID_VALID (vrf_id))) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "VRF-id:%d is not valid!", vrf_id);
        return cps_api_ret_code_ERR;
    }

    if (if_name_attr)
        safestrncpy(peer_routing_config.if_name, (const char *)cps_api_object_attr_data_bin(if_name_attr),
                    sizeof(peer_routing_config.if_name));

    addr = cps_api_object_attr_data_bin(mac_addr_attr);
    std_string_to_mac(&peer_routing_config.mac, (const char *)addr, sizeof(mac_addr));
    peer_routing_config.vrf_id = vrf_id;

    ingress_only_attr = cps_api_object_attr_get(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_INGRESS_ONLY);
    peer_routing_config.ingress_only = false;
    if (ingress_only_attr)
        peer_routing_config.ingress_only = (bool) cps_api_object_attr_data_u32(ingress_only_attr);

    HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "Peer-VRF:%d if-name:%s MAC:%s status:%d Ingress-only:%d",
                     peer_routing_config.vrf_id, peer_routing_config.if_name,
                     hal_rt_mac_to_str (&peer_routing_config.mac, p_buf, HAL_RT_MAX_BUFSZ),
                     status, peer_routing_config.ingress_only);

    if (hal_rt_process_peer_routing_config(vrf_id, &peer_routing_config, status) != STD_ERR_OK) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "hal_rt_process_peer_routing_config failed");
        return cps_api_ret_code_ERR;
    }
    return rc;
}

cps_api_return_code_t nas_route_process_cps_virtual_routing_ip_cfg (cps_api_transaction_params_t * param, size_t ix) {
    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    nas_rt_virtual_routing_ip_config_t virtual_routing_ip_config;
    cps_api_object_attr_t vrf_attr;
    cps_api_object_attr_t af_id_attr;
    cps_api_object_attr_t if_name_attr;
    cps_api_object_attr_t ip_addr_attr;
    cps_api_return_code_t rc = cps_api_ret_code_OK;
    bool                  status = false;

    if (obj == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Virtual routing IP object not present");
        return cps_api_ret_code_ERR;
    }
    memset(&virtual_routing_ip_config, 0, sizeof(virtual_routing_ip_config));
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    /*
     * Check mandatory attributes
     */
    vrf_attr = cps_api_object_attr_get(obj, BASE_ROUTE_VIRTUAL_ROUTING_CONFIG_VIRTUAL_ROUTING_IP_CONFIG_VRF_NAME);
    af_id_attr = cps_api_object_attr_get(obj, BASE_ROUTE_VIRTUAL_ROUTING_CONFIG_VIRTUAL_ROUTING_IP_CONFIG_AF);
    if_name_attr = cps_api_object_attr_get(obj, BASE_ROUTE_VIRTUAL_ROUTING_CONFIG_VIRTUAL_ROUTING_IP_CONFIG_IFNAME);
    ip_addr_attr = cps_api_object_attr_get(obj, BASE_ROUTE_VIRTUAL_ROUTING_CONFIG_VIRTUAL_ROUTING_IP_CONFIG_IP);

    if ((ip_addr_attr == NULL) || (af_id_attr == NULL) ||
        (if_name_attr == NULL) || (vrf_attr == NULL)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "Missing virtual routing IP key params");
        return cps_api_ret_code_ERR;
    }
    switch(op) {
        case cps_api_oper_CREATE:
            HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "In Virtual Routing IP Create ");
            status = true;
            break;
        case cps_api_oper_SET:
            HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "In Virtual Routing IP Set");
            status = true;
            break;
        case cps_api_oper_DELETE:
            HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "In Virtual Routing IP Del");
            status = false;
            break;
        default:
            break;
    }

    if (vrf_attr) {
        safestrncpy(virtual_routing_ip_config.vrf_name, (const char *)cps_api_object_attr_data_bin(vrf_attr),
                    sizeof(virtual_routing_ip_config.vrf_name));
    }
    safestrncpy(virtual_routing_ip_config.if_name, (const char *)cps_api_object_attr_data_bin(if_name_attr),
                sizeof(virtual_routing_ip_config.if_name));

    uint32_t af = cps_api_object_attr_data_u32(af_id_attr);

    if(af == HAL_INET4_FAMILY) {
        struct in_addr *inp = (struct in_addr *) cps_api_object_attr_data_bin(ip_addr_attr);
        std_ip_from_inet(&virtual_routing_ip_config.ip_addr,inp);
    } else if(af == HAL_INET6_FAMILY) {
        struct in6_addr *inp6 = (struct in6_addr *) cps_api_object_attr_data_bin(ip_addr_attr);
        std_ip_from_inet6(&virtual_routing_ip_config.ip_addr,inp6);
    } else {
        HAL_RT_LOG_ERR("NAS-RT-CPS", "Virtual routing IP cfg, af:%d is not valid!", af);
        return cps_api_ret_code_ERR;
    }

    /* For now, only IPv6 link local address can be configured through this.
     * In future if we need to support any other IP address, then modify this
     * as required.
     */
    if(af != HAL_INET6_FAMILY) {
        HAL_RT_LOG_ERR("NAS-RT-CPS", "Virtual routing IP cfg only IPv6 address family supported, af:%d not valid!", af);
        return cps_api_ret_code_ERR;
    }
    if (!STD_IP_IS_ADDR_LINK_LOCAL(&virtual_routing_ip_config.ip_addr)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS", "Virtual routing IP cfg only IPv6 link local address supported. IP:%s not valid!",
                       FIB_IP_ADDR_TO_STR(&virtual_routing_ip_config.ip_addr));
        return cps_api_ret_code_ERR;
    }

    HAL_RT_LOG_INFO("NAS-RT-CPS-SET", "Virtual-Routing-IP VRF:%s af:%d if-name:%s IP:%s status:%d",
                     virtual_routing_ip_config.vrf_name, af, virtual_routing_ip_config.if_name,
                     FIB_IP_ADDR_TO_STR(&virtual_routing_ip_config.ip_addr), status);

    if ((hal_rt_process_virtual_routing_ip_config(&virtual_routing_ip_config, status) != STD_ERR_OK)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "Virtual-Routing-IP config failed");
        rc = cps_api_ret_code_ERR;
    }
    return rc;
}

t_std_error nas_route_process_cps_nht(cps_api_transaction_params_t * param, size_t ix) {

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    cps_api_return_code_t rc = cps_api_ret_code_OK;
    cps_api_object_attr_t af_attr;
    cps_api_object_attr_t dest_attr;
    t_fib_nht fib_nht;
    bool isAdd = false;

    if (obj == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","NHT object is not present");
        return cps_api_ret_code_ERR;
    }

    memset(&fib_nht, 0, sizeof(t_fib_nht));
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));
    /*
     * Check mandatory NHT attributes
     */
    af_attr = cps_api_get_key_data(obj,BASE_ROUTE_NH_TRACK_AF);
    dest_attr = cps_api_get_key_data(obj,BASE_ROUTE_NH_TRACK_DEST_ADDR);

    if ((af_attr == NULL) || (dest_attr == NULL)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "Missing NHT attributes");
        return cps_api_ret_code_ERR;
    }
    switch(op) {
        case cps_api_oper_CREATE:
            HAL_RT_LOG_DEBUG("NAS-RT-CPS-NHT", "Create");
        case cps_api_oper_SET:
            if (op == cps_api_oper_SET)
                HAL_RT_LOG_DEBUG("NAS-RT-CPS-NHT", "Set");
            isAdd = true;
            break;
        case cps_api_oper_DELETE:
            HAL_RT_LOG_DEBUG("NAS-RT-CPS-NHT", "Del");
            isAdd = false;
            break;
        default:
            break;
    }

    const char *vrf_name = cps_api_object_get_data(obj, BASE_ROUTE_NH_TRACK_VRF_NAME);
    if (vrf_name) {
        if (hal_rt_get_vrf_id(vrf_name, &fib_nht.vrf_id) == false) {
            HAL_RT_LOG_INFO("NAS-RT-CPS-NHT","VRF-id get error - Invalid VRF name:%s", vrf_name);
            return cps_api_ret_code_ERR;
        }
    }
    if(cps_api_object_attr_data_u32(af_attr) == AF_INET) {
        struct in_addr *inp = (struct in_addr *) cps_api_object_attr_data_bin(dest_attr);
        std_ip_from_inet(&fib_nht.key.dest_addr,inp);
    } else {
        struct in6_addr *inp6 = (struct in6_addr *) cps_api_object_attr_data_bin(dest_attr);
        std_ip_from_inet6(&fib_nht.key.dest_addr,inp6);
    }

    HAL_RT_LOG_DEBUG("NAS-RT-CPS-NHT", "VRF:%d NHT Addr:%s isAdd:%d",
                 fib_nht.vrf_id, FIB_IP_ADDR_TO_STR(&fib_nht.key.dest_addr), isAdd);
    nas_l3_lock();
    if ((rc = nas_rt_handle_nht(&fib_nht, isAdd, false)) != STD_ERR_OK) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-NHT", "NHT handling failed");
        nas_l3_unlock();
        return cps_api_ret_code_ERR;
    }
    nas_l3_unlock();
    return rc;
}

bool nas_route_fdb_add_cps_msg (t_fib_nh *p_nh) {
    /* Dont program the MAC since SAI is taking care of learning
     * the MAC from ARP response.
     *
     * @@TODO This function needs to be removed once the complete
     * testing is done successfully with new SAI changes
     * that enqueue the MAC updates from NPU into the SAI FIFO queue */
    return false;
}

bool hal_rt_ip_addr_cps_obj_to_route(cps_api_object_t obj, t_fib_msg **p_msg_ret) {
    t_fib_msg             *p_msg = NULL;
    t_fib_route_entry     self_ip;
    cps_api_object_attr_t attr_v4 = CPS_API_ATTR_NULL;
    cps_api_object_attr_t attr_v6 = CPS_API_ATTR_NULL;
    cps_api_object_attr_t attr = CPS_API_ATTR_NULL;
    cps_api_attr_id_t attr_id, attr_vrf;
    cps_api_attr_id_t pref_len_attr_id;
    uint32_t addr_len = HAL_INET6_LEN;
    uint32_t nh_count;

    HAL_RT_LOG_DEBUG("HAL-RT-IP", "Intf msg received");

    *p_msg_ret = NULL;
    memset(&self_ip, 0, sizeof(t_fib_route_entry));

    attr_v4 = cps_api_get_key_data (obj, BASE_IP_IPV4_IFINDEX);
    attr_v6 = cps_api_get_key_data (obj, BASE_IP_IPV6_IFINDEX);

    if ((attr_v4 == CPS_API_ATTR_NULL) && (attr_v6 == CPS_API_ATTR_NULL))
        return false;

    self_ip.hop_count = 1;

    /* Get if-index from key data */
    hal_ifindex_t nh_if_index =
        (attr_v4 != CPS_API_ATTR_NULL) ?
        cps_api_object_attr_data_u32(attr_v4) :
        cps_api_object_attr_data_u32(attr_v6);

    if (attr_v4 != CPS_API_ATTR_NULL) {
        /** Get the ipv4 address */
        self_ip.prefix.af_index = HAL_RT_V4_AFINDEX;
        attr_id = BASE_IP_IPV4_ADDRESS_IP;
        attr_vrf = BASE_IP_IPV4_VRF_NAME;
        pref_len_attr_id = BASE_IP_IPV4_ADDRESS_PREFIX_LENGTH;
        addr_len = HAL_INET4_LEN;
    } else if (attr_v6 != CPS_API_ATTR_NULL) {
        /** Get the ipv6 address */
        self_ip.prefix.af_index = HAL_RT_V6_AFINDEX;
        attr_id = BASE_IP_IPV6_ADDRESS_IP;
        attr_vrf = BASE_IP_IPV6_VRF_NAME;
        pref_len_attr_id = BASE_IP_IPV6_ADDRESS_PREFIX_LENGTH;
        addr_len = HAL_INET6_LEN;
    }

    attr = cps_api_object_e_get(obj, &attr_id, 1);
    if (attr == CPS_API_ATTR_NULL)
        return false;

    memcpy(&self_ip.prefix.u,
           cps_api_object_attr_data_bin(attr), addr_len);

    attr = cps_api_object_e_get(obj, &attr_vrf, 1);
    bool is_mgmt_intf = false;
    if (attr) {
        safestrncpy((char*)self_ip.vrf_name, (const char *)cps_api_object_attr_data_bin(attr),
                    sizeof(self_ip.vrf_name));

        if (hal_rt_get_vrf_id((const char*)self_ip.vrf_name, (hal_vrf_id_t*)&self_ip.vrfid) == false) {
            HAL_RT_LOG_ERR("HAL-RT-IP", "VRF-name:%s to VRF-id mapping not present",
                           self_ip.vrf_name);
            return false;
        }
        self_ip.nh_vrfid = self_ip.vrfid;
        if (hal_rt_validate_intf(self_ip.vrfid, nh_if_index, &is_mgmt_intf) == STD_ERR_OK) {
            if (is_mgmt_intf) {
                /* Ignore the mgmt. IP address handling, since App is expected
                 * to subscribe for IP events directly. */
                return false;
            }
        }
        if (self_ip.vrfid == FIB_MGMT_VRF) {
            /* Ignore the mgmt. IP address handling, since App is expected
             * to subscribe for IP events directly. */
            return false;
        }
    }
    HAL_RT_LOG_DEBUG("HAL-RT-IP", "VRF id:%lu name:%s Intf:%d Addr:%s",
                     self_ip.vrfid, self_ip.vrf_name, nh_if_index,
                     FIB_IP_ADDR_TO_STR(&self_ip.prefix));

    attr = cps_api_object_e_get(obj, &pref_len_attr_id, 1);
    if (attr == CPS_API_ATTR_NULL)
        return false;

    self_ip.prefix_masklen = cps_api_object_attr_data_u32(attr);

    switch(cps_api_object_type_operation(cps_api_object_key(obj)))
    {
        case cps_api_oper_CREATE:
            self_ip.msg_type = FIB_RT_MSG_ADD;
            break;
        case cps_api_oper_SET:
            self_ip.msg_type = FIB_RT_MSG_UPD;
            break;
        case cps_api_oper_DELETE:
            self_ip.msg_type = FIB_RT_MSG_DEL;
            break;
        default:
            break;
    }

    /* Allow the LLA from MAC-VLAN interface */
    if (hal_rt_is_intf_mac_vlan(self_ip.vrfid, nh_if_index)) {
        if (FIB_AFINDEX_TO_PREFIX_LEN (self_ip.prefix.af_index) == self_ip.prefix_masklen) {
            /* Program only the full address with max. prefix len
             * @@TODO Explore on how to handle the route/nbr with
             MAC-VLAN interface in NAS-L3 */
            if (STD_IP_IS_ADDR_LINK_LOCAL(&self_ip.prefix)) {
                self_ip.rt_type = RT_UNREACHABLE;
            } else {
                /* Dont program in the HW, keep it only in the cache */
                self_ip.rt_type = RT_CACHE;
            }
            self_ip.hop_count = 0;
            nh_if_index = 0;
        } else {
            HAL_RT_LOG_INFO("HAL-RT-IP", "Ignored VRF id:%lu name:%s Intf:%d Addr:%s/%d op:%s",
                            self_ip.vrfid, self_ip.vrf_name, nh_if_index,
                            FIB_IP_ADDR_TO_STR(&self_ip.prefix),
                            self_ip.prefix_masklen,
                            ((self_ip.msg_type == FIB_RT_MSG_ADD) ? "Add" :
                             ((self_ip.msg_type == FIB_RT_MSG_DEL) ? "Del" : "Update")));
            return false;
        }
    } else if (!STD_IP_IS_ADDR_LINK_LOCAL(&self_ip.prefix)) {
        /* Allow only the full address route into NPU since other routes
         * with less than /32 and /128 are programmed using route events.
         * Prefix-len 0 is expected for an address with /32 or /128 prefix len
         * configuration in the kernel. */
        if ((self_ip.prefix_masklen != 0) &&
            (FIB_AFINDEX_TO_PREFIX_LEN (self_ip.prefix.af_index) != self_ip.prefix_masklen)) {
            self_ip.rt_type = RT_CACHE;
        }
    } else {
        /* @@TODO In the data VRF namespace, for VRRP, the MAC-VLAN intf is created
         * on top of VRF L3 interface (MAC-VLAN interface), for now, NAS-common does not
         * aware of this interface, in future, if this assumption is changed, no need to handle
         * for interface not exist case here. */
        if ((FIB_AFINDEX_TO_PREFIX_LEN (self_ip.prefix.af_index) == self_ip.prefix_masklen) &&
            (self_ip.vrfid != FIB_DEFAULT_VRF) &&
            (hal_rt_validate_intf(self_ip.vrfid, nh_if_index, &is_mgmt_intf) != STD_ERR_OK)) {
            self_ip.rt_type = RT_UNREACHABLE;
            self_ip.hop_count = 0;
            nh_if_index = 0;
        }
    }
    /* Validate the interface only for the interface is valid case */
    if (nh_if_index) {
        if (cps_api_object_type_operation(cps_api_object_key(obj)) != cps_api_oper_DELETE) {
            if (hal_rt_validate_intf(self_ip.vrfid, nh_if_index, &is_mgmt_intf) != STD_ERR_OK) {
                HAL_RT_LOG_DEBUG("HAL-RT-RIF", "Invalid interface:%d", nh_if_index);
                return false;
            }
        }
    }

    HAL_RT_LOG_INFO("HAL-RT-IP", "VRF %s(%lu) Intf:%d Addr:%s/%d op:%s",
                    self_ip.vrf_name, self_ip.vrfid, nh_if_index,
                    FIB_IP_ADDR_TO_STR(&self_ip.prefix),
                    self_ip.prefix_masklen,
                    ((self_ip.msg_type == FIB_RT_MSG_ADD) ? "Add" :
                     ((self_ip.msg_type == FIB_RT_MSG_DEL) ? "Del" : "Update")));

    /* Update the prefix len to 32/128 based on the address family,
     * since we need to install full address for trap to CPU action.
     */
    /* Dont override the prefix len of an IP address with full prefix len since
     * it is required to clean-up the routes that are reachable via the IP subnet */
    if (self_ip.rt_type != RT_CACHE) {
        self_ip.prefix_masklen = FIB_AFINDEX_TO_PREFIX_LEN (self_ip.prefix.af_index);
    }
    nh_count = 1;
    /* allocate the memory for the ip addr message for 1 nh */
    uint32_t buf_size = sizeof(t_fib_msg) + (sizeof (t_fib_nh_info) * nh_count);
    p_msg = hal_rt_alloc_route_mem_msg(buf_size);

    if (!p_msg) {
        HAL_RT_LOG_ERR("HAL-RT", "Memory alloc failed for ip_addr msg");
        return false;
    }

    HAL_RT_LOG_DEBUG("HAL-RT", "allocated buffer for ip address event "
                     "message:%p for bytes:%d", p_msg, buf_size);

    memset(p_msg, 0, buf_size);
    p_msg->type = FIB_MSG_TYPE_NL_ROUTE;
    t_fib_route_entry *p_route = &(p_msg->route);
    memcpy(p_route, &self_ip, sizeof(self_ip));
    safestrncpy((char*)p_route->nh_vrf_name, (const char*)self_ip.vrf_name, sizeof(p_route->nh_vrf_name));
    p_route->nh_list[0].nh_if_index = nh_if_index;

    *p_msg_ret = p_msg;

    return true;
}

