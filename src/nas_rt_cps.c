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

#include <stdlib.h>
#include "std_mac_utils.h"

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

static cps_api_return_code_t nas_route_cps_all_route_get_func (void *ctx,
                              cps_api_get_params_t * param, size_t ix) {
    uint32_t af = 0, vrf = 0, pref_len = 0;
    hal_ip_addr_t ip;
    bool is_specific_prefix_get = false;

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "All route Get function");
    cps_api_object_t filt = cps_api_object_list_get(param->filters,ix);
    if (filt == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Route object is not present");
        return cps_api_ret_code_ERR;
    }
    cps_api_object_attr_t vrf_attr = cps_api_get_key_data(filt,BASE_ROUTE_OBJ_ENTRY_VRF_ID);
    cps_api_object_attr_t af_attr = cps_api_get_key_data(filt,BASE_ROUTE_OBJ_ENTRY_AF);
    cps_api_object_attr_t prefix_attr = cps_api_get_key_data(filt,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX);
    cps_api_object_attr_t pref_len_attr = cps_api_get_key_data(filt,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN);

    if(af_attr == NULL){
        HAL_RT_LOG_ERR("NAS-RT-CPS","No address family passed to get Route entries");
        return cps_api_ret_code_ERR;
    } else if (((prefix_attr != NULL) && (pref_len_attr == NULL)) ||
               ((prefix_attr == NULL) && (pref_len_attr != NULL))) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Invlaid prefix info prefix:%s len:%s",
               ((prefix_attr == NULL) ? "Not Present" : "Present"),
               ((pref_len_attr == NULL) ? "Not Present" : "Present"));
        return cps_api_ret_code_ERR;
    }

    af = cps_api_object_attr_data_u32(af_attr);
    if (vrf_attr != NULL) {
        vrf = cps_api_object_attr_data_u32(vrf_attr);
        if (!(FIB_IS_VRF_ID_VALID (vrf))) {
            HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "VRF-id:%d is not valid!", vrf);
            return cps_api_ret_code_ERR;
        }
    }
    if (pref_len_attr != NULL) {
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
    t_std_error rc;

    nas_l3_lock();
    if((rc = nas_route_get_all_route_info(param->list,vrf, af, &ip, pref_len, is_specific_prefix_get)) != STD_ERR_OK){
        nas_l3_unlock();
        return cps_api_ret_code_ERR;
    }
    nas_l3_unlock();
    return cps_api_ret_code_OK;
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
    cps_api_object_attr_t vrf_id_attr;
    cps_api_object_attr_t af_attr;
    cps_api_object_attr_t dest_attr;
    t_fib_ip_addr  dest_addr;
    unsigned int vrf_id =0;
    unsigned int af = 0;
    t_std_error rc;

    if (filt == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","NHT object is not present");
        return cps_api_ret_code_ERR;
    }
    vrf_id_attr = cps_api_get_key_data(filt,BASE_ROUTE_NH_TRACK_VRF_ID);
    af_attr = cps_api_get_key_data(filt,BASE_ROUTE_NH_TRACK_AF);
    dest_attr = cps_api_get_key_data(filt,BASE_ROUTE_NH_TRACK_DEST_ADDR);

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "NHT Get function");


    if(vrf_id_attr != NULL) {
        vrf_id =  cps_api_object_attr_data_u32(vrf_id_attr);
        HAL_RT_LOG_DEBUG("NAS-RT-CPS","Get NHT entries: vrf_id %d", vrf_id);
    }

    if(af_attr == NULL) {
        HAL_RT_LOG_DEBUG(
                     "NAS-RT-CPS","Get NHT entries: No address family given");
        return cps_api_ret_code_ERR;
    } else {
        af = cps_api_object_attr_data_u32(af_attr);
        HAL_RT_LOG_DEBUG("NAS-RT-CPS","Get NHT entries: af %d", af);
    }

    memset (&dest_addr, 0, sizeof (t_fib_ip_addr));

    if (dest_attr != NULL) {
        HAL_RT_LOG_DEBUG("HAL-RT-NHT", "Get NHT: input for specific dest_addr\r\n");
        if(af == AF_INET) {
            struct in_addr *inp = (struct in_addr *) cps_api_object_attr_data_bin(dest_attr);
            std_ip_from_inet(&dest_addr,inp);
        } else {
            struct in6_addr *inp6 = (struct in6_addr *) cps_api_object_attr_data_bin(dest_attr);
            std_ip_from_inet6(&dest_addr,inp6);
        }
    }


    nas_l3_lock();
    if((rc = nas_route_get_all_nht_info(param->list, vrf_id, af,
                                        ((dest_attr != NULL) ? (&dest_addr): NULL))) != STD_ERR_OK){
        nas_l3_unlock();
        return (cps_api_return_code_t)rc;
    }

    nas_l3_unlock();
    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_route_cps_nht_rollback_func (void * ctx,
                             cps_api_transaction_params_t * param, size_t ix) {

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "NHT Rollback function");
    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_route_cps_arp_get_func(void *context,
                                cps_api_get_params_t * param, size_t ix) {
    uint32_t af = 0, vrf = 0;
    hal_ip_addr_t ip;
    bool is_specific_nh_get = false;
    t_std_error rc;

    cps_api_object_t filt = cps_api_object_list_get(param->filters,ix);
    if (filt == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Neighbor object is not present");
        return cps_api_ret_code_ERR;
    }
    cps_api_object_attr_t vrf_attr = cps_api_get_key_data(filt,BASE_ROUTE_OBJ_NBR_VRF_ID);
    cps_api_object_attr_t af_attr = cps_api_get_key_data(filt,BASE_ROUTE_OBJ_NBR_AF);
    cps_api_object_attr_t nh_attr = cps_api_get_key_data(filt,BASE_ROUTE_OBJ_NBR_ADDRESS);

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "All ARP get function");
    if(af_attr == NULL){
        HAL_RT_LOG_ERR("NAS-RT-CPS","No address family passed to get ARP entries");
        return cps_api_ret_code_ERR;
    }

    af = cps_api_object_attr_data_u32(af_attr);
    if (vrf_attr != NULL) {
        vrf = cps_api_object_attr_data_u32(vrf_attr);
        if (!(FIB_IS_VRF_ID_VALID (vrf))) {
            HAL_RT_LOG_ERR("NAS-RT-CPS-GET", "VRF-id:%d is not valid!", vrf);
            return cps_api_ret_code_ERR;
        }
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
    if((rc = nas_route_get_all_arp_info(param->list,vrf, af, &ip, is_specific_nh_get)) != STD_ERR_OK){
        nas_l3_unlock();
        return (cps_api_return_code_t)rc;
    }

    nas_l3_unlock();
    return cps_api_ret_code_OK;
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

    switch (cps_api_key_get_subcat (cps_api_object_key (obj))) {
        case BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ:
            rc = nas_route_process_cps_peer_routing(param,ix);
            break;

        default:
            HAL_RT_LOG_ERR("NAS-RT-CPS", "base peer route obj type unknown %d",
                         cps_api_key_get_subcat(cps_api_object_key(obj)));
            break;
    }

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Peer Routing Exit");
    return rc;
}

static cps_api_return_code_t nas_route_cps_peer_routing_get_func (void *ctx,
                                                                  cps_api_get_params_t * param,
                                                                  size_t ix) {
    t_std_error rc;

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Peer Routing Status Get function");

    nas_l3_lock();
    if((rc = nas_route_get_all_peer_routing_config(param->list)) != STD_ERR_OK){
        nas_l3_unlock();
        return (cps_api_return_code_t)rc;
    }
    nas_l3_unlock();

    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_route_cps_peer_routing_rollback_func(void * ctx,
                              cps_api_transaction_params_t * param, size_t ix){

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Peer Routing Status Rollback function");
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
        if (!(FIB_IS_VRF_ID_VALID (vrf_id))) {
            HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "VRF-id:%d  is not valid!", vrf_id);
            return cps_api_ret_code_ERR;
        }
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
    return STD_ERR_OK;
}

static t_std_error nas_route_object_fib_config_init(cps_api_operation_handle_t nas_route_cps_handle ) {

    cps_api_registration_functions_t f;
    char buff[CPS_API_KEY_STR_MAX];

    memset(&f,0,sizeof(f));

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "NAS FIB CPS Initialization");

    HAL_RT_LOG_DEBUG("NAS-RT-CPS", "Registering for %s",
                 cps_api_key_print(&f.key,buff,sizeof(buff)-1));

    f.handle                 = nas_route_cps_handle;
    f._read_function         = nas_route_cps_fib_config_get_func;
    f._write_function        = nas_route_cps_fib_config_set_func;
    f._rollback_function     = nas_route_cps_fib_config_rollback_func;

    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_ROUTE_FIB_OBJ,cps_api_qualifier_TARGET)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Could not translate %d to key %s",
                   (int)(BASE_ROUTE_FIB_OBJ),cps_api_key_print(&f.key,buff,sizeof(buff)-1));
        return STD_ERR(ROUTE,FAIL,0);
    }

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
    if((ret = nas_route_event_handle_init()) != STD_ERR_OK){
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


t_std_error nas_route_process_cps_peer_routing(cps_api_transaction_params_t * param, size_t ix) {

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    cps_api_return_code_t rc = cps_api_ret_code_OK;
    cps_api_object_attr_t vrf_id_attr;
    cps_api_object_attr_t if_name_attr;
    cps_api_object_attr_t mac_addr_attr;
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
    vrf_id_attr   = cps_api_object_attr_get(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_ID);
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

    if (vrf_id_attr) {
        vrf_id =  cps_api_object_attr_data_u32(vrf_id_attr);
        if (!(FIB_IS_VRF_ID_VALID (vrf_id))) {
            HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "VRF-id:%d  is not valid!", vrf_id);
            return cps_api_ret_code_ERR;
        }
    }
    if (if_name_attr)
        safestrncpy(peer_routing_config.if_name, (const char *)cps_api_object_attr_data_bin(if_name_attr),
                    cps_api_object_attr_len(if_name_attr));

    addr = cps_api_object_attr_data_bin(mac_addr_attr);
    std_string_to_mac(&peer_routing_config.mac, (const char *)addr, sizeof(mac_addr));
    peer_routing_config.vrf_id = vrf_id;
    HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "Peer-VRF:%d if-name:%s MAC:%s status:%d",
                     peer_routing_config.vrf_id, peer_routing_config.if_name, hal_rt_mac_to_str (&peer_routing_config.mac,
                                                                                                 p_buf, HAL_RT_MAX_BUFSZ), status);
    if ((rc = hal_rt_process_peer_routing_config(vrf_id, &peer_routing_config, status)) != STD_ERR_OK) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "hal_rt_process_peer_routing_config failed");
        return cps_api_ret_code_ERR;
    }
    return rc;
}



t_std_error nas_route_process_cps_nht(cps_api_transaction_params_t * param, size_t ix) {

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    cps_api_return_code_t rc = cps_api_ret_code_OK;
    cps_api_object_attr_t vrf_id_attr;
    cps_api_object_attr_t af_attr;
    cps_api_object_attr_t dest_attr;
    t_fib_nht fib_nht;
    bool isAdd = false;

    if (obj == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","NHT object is not present");
        return cps_api_ret_code_ERR;
    }

    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));
    /*
     * Check mandatory NHT attributes
     */
    vrf_id_attr = cps_api_get_key_data(obj,BASE_ROUTE_NH_TRACK_VRF_ID);
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

    if(cps_api_object_attr_data_u32(af_attr) == AF_INET) {
        struct in_addr *inp = (struct in_addr *) cps_api_object_attr_data_bin(dest_attr);
        std_ip_from_inet(&fib_nht.key.dest_addr,inp);
    } else {
        struct in6_addr *inp6 = (struct in6_addr *) cps_api_object_attr_data_bin(dest_attr);
        std_ip_from_inet6(&fib_nht.key.dest_addr,inp6);
    }

    fib_nht.vrf_id =  cps_api_object_attr_data_u32(vrf_id_attr);

    HAL_RT_LOG_DEBUG("NAS-RT-CPS-NHT", "VRF:%d NHT Addr:%s isAdd:%d",
                 fib_nht.vrf_id, FIB_IP_ADDR_TO_STR(&fib_nht.key.dest_addr), isAdd);
    nas_l3_lock();
    if ((rc = nas_rt_handle_nht(&fib_nht, isAdd)) != STD_ERR_OK) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-NHT", "NHT handling failed");
        nas_l3_unlock();
        return cps_api_ret_code_ERR;
    }
    nas_l3_unlock();
    return rc;
}

