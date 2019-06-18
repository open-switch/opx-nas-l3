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
 * filename: nas_route_api.c
 */


#include "dell-base-routing.h"
#include "os-icmp-config.h"
#include "nas_rt_api.h"
#include "nas_os_l3.h"
#include "hal_rt_util.h"
#include "hal_if_mapping.h"
#include "event_log_types.h"
#include "event_log.h"
#include "std_mutex_lock.h"
#include "std_utils.h"
#include "nas_switch.h"

#include "cps_class_map.h"
#include "cps_api_object_key.h"
#include "cps_api_operation.h"
#include "cps_api_events.h"
#include "hal_rt_util.h"
#include "limits.h"
#include <stdio.h>
#include "dell-base-neighbor.h"
#include "dell-base-acl.h"
#include "os-routing-events.h"

BASE_ROUTE_OBJ_t nas_route_check_route_key_attr(cps_api_object_t obj) {

    BASE_ROUTE_OBJ_t  default_type = BASE_ROUTE_OBJ_ENTRY;

    /*
     * Route Key
     */
    cps_api_object_attr_t route_af;
    cps_api_object_attr_t prefix;
    cps_api_object_attr_t pref_len;
    /*
     * Nbr Key
     */
    cps_api_object_attr_t nbr_af;
    cps_api_object_attr_t nbr_addr;

    /*
     * Check mandatory key attributes
     */
    route_af     = cps_api_get_key_data(obj, BASE_ROUTE_OBJ_ENTRY_AF);
    prefix       = cps_api_get_key_data(obj, BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX);
    pref_len     = cps_api_get_key_data(obj, BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN);
    nbr_af       = cps_api_get_key_data(obj, BASE_ROUTE_OBJ_NBR_AF);
    nbr_addr     = cps_api_get_key_data(obj, BASE_ROUTE_OBJ_NBR_ADDRESS);

    /*
     * If route delete case, check the key mandatory attrs for delete case first
     */

    if (route_af != CPS_API_ATTR_NULL && prefix != CPS_API_ATTR_NULL &&
         pref_len != CPS_API_ATTR_NULL) {
        return BASE_ROUTE_OBJ_ENTRY;
    } else if ((nbr_af != CPS_API_ATTR_NULL && nbr_addr != CPS_API_ATTR_NULL) ||
               (nbr_addr != CPS_API_ATTR_NULL)){
        return BASE_ROUTE_OBJ_NBR;
    }

    return default_type;
}


static inline bool nas_route_validate_route_attr(cps_api_object_t obj, bool del) {

    cps_api_object_attr_t af;
    cps_api_object_attr_t prefix;
    cps_api_object_attr_t pref_len;
    cps_api_object_attr_t nh_count;

    /*
     * Check mandatory route attributes
     */
    af       = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_AF);
    prefix   = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX);
    pref_len = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN);

    /*
     * If route delete case, check the key mandatory attrs for delete case first
     */

    /* @@TODO Mandate the vrf_name once the app updated the CPS route object
     * with the vrf-name.
     * const char *vrf_name  = cps_api_object_get_data(obj,BASE_ROUTE_OBJ_VRF_NAME);
     * */
    if  ((af == CPS_API_ATTR_NULL) || (prefix == CPS_API_ATTR_NULL) ||
         (pref_len == CPS_API_ATTR_NULL)) {
        HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "Missing route mandatory attr params");
        return false;
    }

    /*
     * Route delete case
     */
    if (del == true) {
        return true;
    }

    /*
     * If route add/update case, check for NH attributes or special NH attribute
     */
    nh_count = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_NH_COUNT);

    cps_api_attr_id_t ids[3] = { BASE_ROUTE_OBJ_ENTRY_NH_LIST, 0,
                                 BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR};
    const int ids_len = sizeof(ids)/sizeof(*ids);

    cps_api_object_attr_t gw = cps_api_object_e_get(obj, ids, ids_len);

    ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFINDEX;
    cps_api_object_attr_t gwix = cps_api_object_e_get(obj, ids, ids_len);

    cps_api_object_attr_t spl_nexthop_option =
          cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_SPECIAL_NEXT_HOP);

    if (spl_nexthop_option) {
        uint32_t spl_nh_type = cps_api_object_attr_data_u32(spl_nexthop_option);
        switch(spl_nh_type) {
            case BASE_ROUTE_SPECIAL_NEXT_HOP_BLACKHOLE:
            case BASE_ROUTE_SPECIAL_NEXT_HOP_UNREACHABLE:
            case BASE_ROUTE_SPECIAL_NEXT_HOP_PROHIBIT:
            case BASE_ROUTE_SPECIAL_NEXT_HOP_RECEIVE:
                /* for special next hop no other additional params required */
                return true;
            default:
                HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "Invalid special next-hop value");
                return false;
        }
    }

    ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFNAME;
    cps_api_object_attr_t gw_if_name = cps_api_object_e_get(obj, ids, ids_len);
    if ((nh_count == CPS_API_ATTR_NULL) ||
        ((gw == CPS_API_ATTR_NULL) && (gwix == CPS_API_ATTR_NULL) && (gw_if_name == CPS_API_ATTR_NULL))) {
        HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "Missing route nh params");
        return false;
    }

    if (cps_api_object_attr_data_u32(nh_count) > HAL_RT_MAX_ECMP_PATH) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "Nexthop count is more than "
                     "the allowed limit %d", HAL_RT_MAX_ECMP_PATH);
        return false;
    }
    return true;
}


static cps_api_return_code_t nas_route_filter_route_func(cps_api_object_t obj,
                    cps_api_transaction_params_t * param,size_t ix,
                    cps_api_operation_types_t op) {
    /*
     *  @@TODO     Call filter function to filter the route
     *  either as Management route, App route etc
     *
     */
    return cps_api_ret_code_OK;

}


static inline bool nas_route_validate_nbr_attr(cps_api_object_t obj, bool del) {

    cps_api_object_attr_t af;
    cps_api_object_attr_t ipaddr;
    cps_api_object_attr_t mac_addr;
    cps_api_object_attr_t if_index;
    cps_api_object_attr_t if_name;

    /*
     * Check mandatory nbr attributes
     */
    ipaddr   = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_NBR_ADDRESS);
    af       = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_NBR_AF);
    mac_addr = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_NBR_MAC_ADDR);
    if_index = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_NBR_IFINDEX);
    if_name = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_NBR_IFNAME);

    /*
     * If route delete case, check the key mandatory attrs for delete case first
     */
    if (ipaddr == CPS_API_ATTR_NULL || af == CPS_API_ATTR_NULL ||
        (if_index == CPS_API_ATTR_NULL && if_name == CPS_API_ATTR_NULL)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "Missing Neighbor mandatory attr params");
        return false;
    }

    /*
     * Route delete case
     */
    if (del == true) {
        return true;
    }

    /*
     * If route add/update case, check for NH attributes also
     */

    if (mac_addr == CPS_API_ATTR_NULL){
        HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "Missing Neighbor mac attr for update");
        return false;
    }

    return true;
}

static cps_api_return_code_t nas_route_filter_nbr_func(cps_api_object_t obj,
                    cps_api_transaction_params_t * param,size_t ix,
                    cps_api_operation_types_t op) {
    /*
     *  @@TODO     Call filter function to filter the Nbr
     *  either as Management or App entry etc
     *
     */
    return cps_api_ret_code_OK;

}

cps_api_return_code_t  nas_route_process_cps_route(cps_api_transaction_params_t * param, size_t ix) {

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    cps_api_return_code_t rc = cps_api_ret_code_OK;
    t_fib_msg *p_msg = NULL;

    if (obj == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Route object is not present");
        return cps_api_ret_code_ERR;
    }

    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    /* for CPS ACTION, caller has validated the route attribute */
    if (op != cps_api_oper_ACTION) {
        if (nas_route_validate_route_attr(obj, (op == cps_api_oper_DELETE)? true:false) == false) {
            HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "Missing route key params");
            return cps_api_ret_code_ERR;
        }
    }

    /*
     *  Call filter function to filter the route
     *  either as Management route, App route and
     *  once conditions are satisfied, install the route into kernel
     *  via cps-api-os interface
     */
    if(nas_route_filter_route_func(obj, param, ix, op) != cps_api_ret_code_OK){
        rc = cps_api_ret_code_ERR;
    }

    cps_api_object_t cloned = cps_api_object_create();
    if (!cloned) {
        HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "CPS malloc error");
        return cps_api_ret_code_ERR;
    }
    cps_api_object_clone(cloned,obj);
    cps_api_object_list_append(param->prev,cloned);

    if (op == cps_api_oper_CREATE) {
        HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "In OS Route CREATE ");
        if(nas_os_add_route(obj) != STD_ERR_OK){
            HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "OS Route add failed");
            rc = cps_api_ret_code_ERR;
        }
    } else if (op == cps_api_oper_DELETE) {
        HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "In Route del ");
        if(nas_os_del_route(obj) != STD_ERR_OK){
            HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "OS Route del failed");
            rc = cps_api_ret_code_ERR;
        }
    } else if (op == cps_api_oper_SET) {
        HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "In Route update ");
        if(nas_os_set_route(obj) != STD_ERR_OK){
            HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", " OS Route update failed");
            rc = cps_api_ret_code_ERR;
        }
    } else if (op == cps_api_oper_ACTION) {
        HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "In Route NH update ");
        if(nas_os_update_route_nexthop(obj) != STD_ERR_OK){
            HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", " OS Route NH update failed");
            rc = cps_api_ret_code_ERR;
        }
    }

    /* Program the HW here when there is no OS route updates for HW programming. */
    if ((nas_switch_get_os_event_flag() == false) && (rc == cps_api_ret_code_OK)) {
        if (op == cps_api_oper_ACTION) {
            if (hal_rt_cps_obj_to_route_nexthop(obj, &p_msg)) {
                nas_rt_process_msg(p_msg);
            } else {
                rc = cps_api_ret_code_ERR;
            }
        } else {
            if (hal_rt_cps_obj_to_route(obj, &p_msg, true)) {
                nas_rt_process_msg(p_msg);
            } else {
                rc = cps_api_ret_code_ERR;
            }
        }
    }
    return rc;
}

/* This function handles the flag setting on nbr entry for age-out enable/disable cases. */
static t_std_error nas_route_update_flag_config(cps_api_object_t obj, cps_api_operation_types_t op) {
    cps_api_object_attr_t flags_attr = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_NBR_FLAGS);
    if (flags_attr == NULL) {
        return STD_ERR_OK;
    }
    t_fib_neighbour_entry entry;

    memset(&entry, 0, sizeof(t_fib_neighbour_entry));
    const char *vrf_name      = cps_api_object_get_data(obj,BASE_ROUTE_OBJ_VRF_NAME);
    if (vrf_name) {
        if (hal_rt_get_vrf_id(vrf_name, (hal_vrf_id_t *)&entry.vrfid) == false) {
            HAL_RT_LOG_ERR("NEIGH-FLAG-UPD", "VRF name:%s to id conversion failed", vrf_name);
            return STD_ERR(ROUTE,FAIL,0);
        }
    }
    cps_api_object_attr_t ip  = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_NBR_ADDRESS);
    cps_api_object_attr_t af  = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_NBR_AF);
    cps_api_object_attr_t if_index = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_NBR_IFINDEX);
    cps_api_object_attr_t if_name = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_NBR_IFNAME);
    if ((ip == NULL) || (af == NULL) || ((if_index == NULL) && (if_name == NULL))) {
        HAL_RT_LOG_ERR("NEIGH-FLAG-UPD", "Mandatory attributes are missing!");
        return STD_ERR(ROUTE,FAIL,0);
    }
    memcpy(&entry.nbr_addr.u, cps_api_object_attr_data_bin(ip),
           cps_api_object_attr_len (ip));
    entry.family = cps_api_object_attr_data_u32(af);

    if (if_index) {
        entry.if_index = cps_api_object_attr_data_u32(if_index);
    } else {
        interface_ctrl_t intf_ctrl;
        t_std_error rc = STD_ERR_OK;

        memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
        intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;
        safestrncpy(intf_ctrl.if_name, (const char *)cps_api_object_attr_data_bin(if_name),
                    cps_api_object_attr_len(if_name));

        if((rc= dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
            HAL_RT_LOG_ERR("NEIGH-FLAG-UPD",
                           "Interface %s to if_index returned error %d", intf_ctrl.if_name, rc);
            return STD_ERR(ROUTE,FAIL,0);
        }

        entry.if_index = intf_ctrl.if_index;
    }

    uint32_t flags = cps_api_object_attr_data_u32(flags_attr);
    /* If the Nbr dependent MAC is learnt via VXLAN network port, dont refresh the Nbr upon age-out. */
    if (flags == BASE_ROUTE_NBR_FLAGS_AGE_OUT_1D_BRIDGE_REMOTE_MAC_DISABLE) {
        nas_route_nbr_entry_to_nbr_cps_object(&entry, op,
                                              NAS_RT_NBR_FLAGS_DISABLE_AGE_OUT_1D_BRIDGE_REMOTE_MAC);
    } else if (flags == BASE_ROUTE_NBR_FLAGS_AGE_OUT_ENABLE) {
        /* Enable the age-out back again after the above setting. */
        nas_route_nbr_entry_to_nbr_cps_object(&entry, op,
                                              NAS_RT_NBR_FLAGS_ENABLE_AGE_OUT);
    }
    return STD_ERR_OK;
}

cps_api_return_code_t nas_route_process_cps_nbr(cps_api_transaction_params_t * param, size_t ix) {

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);

    if (obj == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Neighbor object is not present");
        return cps_api_ret_code_ERR;
    }

    cps_api_return_code_t rc = cps_api_ret_code_OK;
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    if (nas_route_validate_nbr_attr(obj, (op == cps_api_oper_DELETE)? true:false) == false) {
        HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "Missing Neighbbr key params");
        return cps_api_ret_code_ERR;
    }

    /*
     *  Call filter function to filter the Nbr
     *  either as Management entry, App. entry
     *  once conditions are satisfied, install the entry into kernel
     *  via cps-api-os interface
     */
    if(nas_route_filter_nbr_func(obj, param, ix, op) != cps_api_ret_code_OK){
        rc = cps_api_ret_code_ERR;
    }

    cps_api_object_t cloned = cps_api_object_create();
    if (!cloned) {
        HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "CPS malloc error");
        return cps_api_ret_code_ERR;
    }
    cps_api_object_clone(cloned,obj);
    cps_api_object_list_append(param->prev,cloned);

    if (op == cps_api_oper_CREATE) {
        if(nas_os_add_neighbor(obj) != STD_ERR_OK){
            HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "OS Neighbor add failed");
            rc = cps_api_ret_code_ERR;
        }
    } else if (op == cps_api_oper_DELETE) {
        if(nas_os_del_neighbor(obj) != STD_ERR_OK){
            HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "OS Neighbor del failed");
            rc = cps_api_ret_code_ERR;
        }
    } else if (op == cps_api_oper_SET) {
        cps_api_object_attr_t nbr_state = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_NBR_STATE);
        if (nbr_state && cps_api_object_attr_data_u32(nbr_state) == BASE_ROUTE_NEIGHBOR_STATE_PROBE) {
            if(nas_os_refresh_neighbor(obj) != STD_ERR_OK){
                HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", " OS Neighbor refresh failed");
                rc = cps_api_ret_code_ERR;
            }
        } else if(nas_os_set_neighbor(obj) != STD_ERR_OK){
            HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", " OS Neighbor update failed");
            rc = cps_api_ret_code_ERR;
        }
    }
    if (rc == cps_api_ret_code_OK) {
        nas_route_update_flag_config(obj, op);
    }
    return rc;
}

/* ARP refresh upon stale state */
int nas_route_process_nbr_refresh(cps_api_object_t obj) {
    return(nas_os_refresh_neighbor(obj));
}

static inline bool nas_rt_is_route_npu_prg_done(t_fib_dr *p_entry) {
    int unit = 0;
    for (unit = 0; unit < hal_rt_access_fib_config()->max_num_npu; unit++) {
        if(p_entry->a_is_written [unit] == false)
            return false;
    }
    return true;
}

static inline uint32_t hal_rt_type_to_cps_obj_type (t_rt_type rt_type)
{
    /* return packet action according to the route type */
    return ((rt_type == RT_BLACKHOLE) ? BASE_ROUTE_SPECIAL_NEXT_HOP_BLACKHOLE:
            (rt_type == RT_UNREACHABLE) ? BASE_ROUTE_SPECIAL_NEXT_HOP_UNREACHABLE:
            (rt_type == RT_PROHIBIT) ? BASE_ROUTE_SPECIAL_NEXT_HOP_PROHIBIT:
            (rt_type == RT_LOCAL) ? BASE_ROUTE_SPECIAL_NEXT_HOP_RECEIVE:
             0);
}

bool nas_rt_is_nh_npu_prg_done(t_fib_nh *p_entry) {
    int unit = 0;
    for (unit = 0; unit < hal_rt_access_fib_config()->max_num_npu; unit++) {
        if(p_entry->a_is_written [unit] == false)
            return false;
    }
    return true;
}

static cps_api_object_t nas_intf_ip_unreach_info_to_cps_object(t_fib_intf *p_intf){

    if(p_intf == NULL){
        HAL_RT_LOG_ERR("HAL-RT-API","Null Intf entry pointer passed to convert it to cps object");
        return NULL;
    }

    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL){
        HAL_RT_LOG_ERR("HAL-RT-API","Failed to allocate memory to cps object");
        return NULL;
    }

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key, BASE_ROUTE_IP_UNREACHABLES_CONFIG_OBJ,
                                    cps_api_qualifier_TARGET);
    cps_api_object_set_key(obj,&key);

    cps_api_set_key_data (obj, BASE_ROUTE_IP_UNREACHABLES_CONFIG_VRF_NAME, cps_api_object_ATTR_T_BIN,
                          FIB_GET_VRF_NAME(p_intf->key.vrf_id, p_intf->key.af_index),
                          strlen((const char*)FIB_GET_VRF_NAME(p_intf->key.vrf_id, p_intf->key.af_index))+1);
    uint32_t af = p_intf->key.af_index;
    cps_api_set_key_data (obj, BASE_ROUTE_IP_UNREACHABLES_CONFIG_AF, cps_api_object_ATTR_T_U32, &af,
                          sizeof(af));
    cps_api_set_key_data (obj, BASE_ROUTE_IP_UNREACHABLES_CONFIG_IFNAME, cps_api_object_ATTR_T_BIN,
                          p_intf->if_name, (strlen(p_intf->if_name)+1));
    return obj;
}

static cps_api_object_t nas_intf_ip_redirects_info_to_cps_object(t_fib_intf *p_intf){

    if(p_intf == NULL){
        HAL_RT_LOG_ERR("HAL-RT-API","Null Intf entry pointer passed to convert it to cps object");
        return NULL;
    }

    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL){
        HAL_RT_LOG_ERR("HAL-RT-API","Failed to allocate memory to cps object");
        return NULL;
    }

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key, BASE_ROUTE_IP_REDIRECTS_CONFIG_OBJ,
                                    cps_api_qualifier_TARGET);
    cps_api_object_set_key(obj,&key);

    char  vrf_name[NAS_VRF_NAME_SZ + 1];
    memset (vrf_name,0,sizeof(vrf_name));

    if (!hal_rt_get_vrf_name (p_intf->key.vrf_id, vrf_name)) {
        HAL_RT_LOG_ERR("HAL-RT-API","Failed to retrieve vrf_name for vrf_id:%d", p_intf->key.vrf_id);
        return NULL;
    }

    cps_api_set_key_data (obj, BASE_ROUTE_IP_REDIRECTS_CONFIG_VRF_NAME, cps_api_object_ATTR_T_BIN,
                          vrf_name, (strlen(vrf_name)+1));
    cps_api_set_key_data (obj, BASE_ROUTE_IP_REDIRECTS_CONFIG_IFNAME, cps_api_object_ATTR_T_BIN,
                          p_intf->if_name, (strlen(p_intf->if_name)+1));
    return obj;
}


static cps_api_object_t nas_route_event_filter_info_to_cps_object(char *vrf_name, uint8_t type,
                                                                  uint8_t enable) {

    if(vrf_name == NULL){
        HAL_RT_LOG_ERR("HAL-RT-API","Invalid VRF name!");
        return NULL;
    }

    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL){
        HAL_RT_LOG_ERR("HAL-RT-API","Failed to allocate memory to cps object");
        return NULL;
    }

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key, BASE_ROUTE_EVENT_FILTER_OBJ,
                                    cps_api_qualifier_TARGET);
    cps_api_object_set_key(obj,&key);

    cps_api_set_key_data (obj, BASE_ROUTE_EVENT_FILTER_VRF_NAME, cps_api_object_ATTR_T_BIN,
                          vrf_name, (strlen(vrf_name)+1));
    uint32_t type_val = type;
    cps_api_set_key_data (obj, BASE_ROUTE_EVENT_FILTER_TYPE, cps_api_object_ATTR_T_U32,
                          &type_val, sizeof(type_val));
    cps_api_object_attr_add_u32(obj, BASE_ROUTE_EVENT_FILTER_ENABLE, enable);
    return obj;
}

cps_api_return_code_t nas_route_get_all_event_filter_info(cps_api_object_list_t list) {
    hal_vrf_id_t    vrf_id = 0;
    t_fib_vrf      *p_vrf = NULL;
    t_fib_vrf_info *p_vrf_info = NULL;

    for (vrf_id = FIB_MIN_VRF; vrf_id < FIB_MAX_VRF; vrf_id ++) {
        p_vrf = hal_rt_access_fib_vrf(vrf_id);
        if (p_vrf == NULL) {
            continue;
        }
        p_vrf_info = hal_rt_access_fib_vrf_info(vrf_id, HAL_RT_V4_AFINDEX);
        cps_api_object_t obj =
            nas_route_event_filter_info_to_cps_object((char*)p_vrf_info->vrf_name,
                                                      p_vrf_info->event_filter_info,
                                                      (p_vrf_info->event_filter_info ? true : false));
        if(obj != NULL){
            if (!cps_api_object_list_append(list,obj)) {
                cps_api_object_delete(obj);
                HAL_RT_LOG_ERR("HAL-RT-API","Failed to append object to object list");
                return STD_ERR(ROUTE,FAIL,0);
            }
        }
    }
    return STD_ERR_OK;
}

cps_api_return_code_t nas_route_get_all_ip_unreach_info(cps_api_object_list_t list, hal_vrf_id_t vrf_id,
                                                        uint32_t af, char *if_name, bool is_specific_get) {

    t_fib_intf *p_intf = NULL;

    if (af >= FIB_MAX_AFINDEX)
    {
        HAL_RT_LOG_ERR("HAL-RT-ARP","Invalid Address family");
        return cps_api_ret_code_ERR;
    }

    p_intf = fib_get_first_intf();
    while (p_intf != NULL){
        if ((is_specific_get && (p_intf->key.vrf_id != vrf_id)) ||
            (((p_intf->key.af_index == HAL_RT_V4_AFINDEX) &&
              (p_intf->is_ipv4_unreachables_set == false)) ||
             ((p_intf->key.af_index == HAL_RT_V6_AFINDEX) &&
              (p_intf->is_ipv6_unreachables_set == false)))) {

            p_intf = fib_get_next_intf (p_intf->key.if_index,
                                        p_intf->key.vrf_id, p_intf->key.af_index);
            continue;
        }
        bool is_cps_obj_add_ok = true;
        if (is_specific_get) {
            /* Both the keys af and ifname are given in the CPS get */
            if (af != 0 && if_name && ((af != p_intf->key.af_index) ||
                                       (strncmp(if_name, p_intf->if_name, strlen(if_name))))) {
                is_cps_obj_add_ok = false;
                /* The key af is given in the CPS get */
            } else if (af != 0 && ((af != p_intf->key.af_index))) {
                is_cps_obj_add_ok = false;
                /* The key ifname is given in the CPS get */
            } else if ((if_name != 0) && (strncmp(if_name, p_intf->if_name, strlen(if_name)))) {
                is_cps_obj_add_ok = false;
            }
        }
        if (is_cps_obj_add_ok) {
            cps_api_object_t obj = nas_intf_ip_unreach_info_to_cps_object(p_intf);
            if(obj != NULL){
                if (!cps_api_object_list_append(list,obj)) {
                    cps_api_object_delete(obj);
                    HAL_RT_LOG_ERR("HAL-RT-API","Failed to append object to object list");
                    return STD_ERR(ROUTE,FAIL,0);
                }
                if (is_specific_get && af && if_name)
                    break;
            }
        }
        p_intf = fib_get_next_intf (p_intf->key.if_index, p_intf->key.vrf_id, p_intf->key.af_index);
    }
    return cps_api_ret_code_OK;
}

cps_api_return_code_t nas_route_get_all_ip_redirects_info (cps_api_object_list_t list,
                                                           hal_vrf_id_t vrf_id, char *if_name) {
    t_fib_intf *p_intf = NULL;
    uint32_t    if_index = 0;

    if (if_name) {
        hal_vrf_id_t intf_vrf_id = 0;
        if (hal_rt_get_if_index_from_if_name (if_name, &intf_vrf_id, &if_index) != STD_ERR_OK) {
            return cps_api_ret_code_OK;
        }
        /* User given vrf-id is not matching with the interface associated VRF-id */
        if (vrf_id != intf_vrf_id) {
            return cps_api_ret_code_OK;
        }
        /* retrieve the info for IPv4 only for now */
        p_intf = fib_get_intf (if_index, vrf_id, HAL_RT_V4_AFINDEX);
    } else {
        p_intf = fib_get_first_intf();
    }

    while (p_intf != NULL) {
        /* retrieve the info for IPv4 only for now */
        if ((p_intf->is_ip_redirects_set == true) &&
            (p_intf->key.af_index == HAL_RT_V4_AFINDEX) &&
            (p_intf->key.vrf_id == vrf_id) &&
            (!if_name || (strncmp(if_name, p_intf->if_name, strlen(if_name)) == 0))) {

            cps_api_object_t obj = nas_intf_ip_redirects_info_to_cps_object (p_intf);

            if(obj != NULL){
                if (!cps_api_object_list_append(list,obj)) {

                    cps_api_object_delete(obj);
                    HAL_RT_LOG_ERR("HAL-RT-API","Failed to append object to object list");
                    return cps_api_ret_code_ERR;
                }
                if (if_name)
                    break;
            }
        }
        p_intf = fib_get_next_intf (p_intf->key.if_index, p_intf->key.vrf_id, p_intf->key.af_index);
    }
    return cps_api_ret_code_OK;
}


static cps_api_object_t nas_route_info_to_cps_object(cps_api_operation_types_t op, t_fib_dr *entry,
                                                     bool is_pub){
    t_fib_nh       *p_nh = NULL;
    t_fib_nh_holder nh_holder1;
    uint32_t weight = 0, is_npu_prg_done;
    uint32_t addr_len = 0, nh_itr = 0, is_arp_resolved = false;

    if(entry == NULL){
        HAL_RT_LOG_ERR("HAL-RT-API","Null DR entry pointer passed to convert it to cps object");
        return NULL;
    }

    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL){
        HAL_RT_LOG_ERR("HAL-RT-API","Failed to allocate memory to cps object");
        return NULL;
    }

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key, BASE_ROUTE_OBJ_ENTRY,
                                    (is_pub ? cps_api_qualifier_OBSERVED : cps_api_qualifier_TARGET));
    if (is_pub) {
        cps_api_object_set_type_operation(&key, op);
    }
    cps_api_object_set_key(obj,&key);
    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_VRF_NAME,
                            FIB_GET_VRF_NAME(entry->vrf_id, entry->key.prefix.af_index),
                            strlen((const char*)FIB_GET_VRF_NAME(entry->vrf_id, entry->key.prefix.af_index))+1);
    if(entry->key.prefix.af_index == HAL_INET4_FAMILY){
        addr_len = HAL_INET4_LEN;
        cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,&(entry->key.prefix.u.v4_addr), addr_len);
    }else{
        addr_len = HAL_INET6_LEN;
        cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,&(entry->key.prefix.u.v6_addr), addr_len);
    }
    cps_api_object_attr_add_u32(obj, BASE_ROUTE_OBJ_ENTRY_AF, entry->key.prefix.af_index);
    cps_api_object_attr_add_u32(obj, BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN, entry->prefix_len);
    cps_api_object_attr_add_u32(obj, BASE_ROUTE_OBJ_ENTRY_PROTOCOL, entry->proto);
    cps_api_object_attr_add_u32(obj, BASE_ROUTE_OBJ_ENTRY_OWNER, entry->default_dr_owner);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_NPU_PRG_DONE,nas_rt_is_route_npu_prg_done(entry));

    if (FIB_IS_RESERVED_RT_TYPE (entry->rt_type)) {
        cps_api_object_attr_add_u32 (obj,
                BASE_ROUTE_OBJ_ENTRY_SPECIAL_NEXT_HOP,
                hal_rt_type_to_cps_obj_type(entry->rt_type));
    }
    FIB_FOR_EACH_NH_FROM_DR (entry, p_nh, nh_holder1)
    {
        cps_api_attr_id_t parent_list[3];

        cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_ENTRY_NH_VRF_NAME,
                            FIB_GET_VRF_NAME(p_nh->vrf_id, entry->key.prefix.af_index),
                            strlen((const char*)FIB_GET_VRF_NAME(p_nh->vrf_id, entry->key.prefix.af_index))+1);
        parent_list[0] = BASE_ROUTE_OBJ_ENTRY_NH_LIST;
        parent_list[1] = nh_itr;
        parent_list[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR;

        if(entry->key.prefix.af_index == HAL_INET4_FAMILY) {
            cps_api_object_e_add(obj, parent_list, 3,
                                 cps_api_object_ATTR_T_BIN, &p_nh->key.ip_addr.u.v4_addr, addr_len);
        } else {
            cps_api_object_e_add(obj, parent_list, 3,
                                 cps_api_object_ATTR_T_BIN, &p_nh->key.ip_addr.u.v6_addr, addr_len);
        }

        parent_list[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFINDEX;
        cps_api_object_e_add(obj, parent_list, 3,
                             cps_api_object_ATTR_T_U32, &p_nh->key.if_index, sizeof(p_nh->key.if_index));

        t_fib_intf *p_intf = fib_get_intf (p_nh->key.if_index, p_nh->vrf_id,
                               p_nh->key.ip_addr.af_index);
        if (p_intf != NULL) {
            HAL_RT_LOG_DEBUG("HAL-RT-API","get the interface name for :%d (%s)",
                           p_nh->key.if_index, p_intf->if_name);
            parent_list[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFNAME;
            cps_api_object_e_add(obj, parent_list, 3, cps_api_object_ATTR_T_BIN,
                                 (const void *)p_intf->if_name, strlen(p_intf->if_name)+1);

        } else {
            HAL_RT_LOG_ERR("HAL-RT-API","Failed to get the interface name for :%d", p_nh->key.if_index);
            cps_api_object_delete(obj);
            return NULL;
        }
        parent_list[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_WEIGHT;
        cps_api_object_e_add(obj, parent_list, 3,
                             cps_api_object_ATTR_T_U32, &weight, sizeof(weight));

        if (p_nh->flags == BASE_ROUTE_NH_FLAGS_ONLINK) {
            uint32_t nh_flags = BASE_ROUTE_NH_FLAGS_ONLINK;
            parent_list[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_FLAGS;
            cps_api_object_e_add(obj, parent_list, 3,
                                 cps_api_object_ATTR_T_U32, &nh_flags, sizeof(nh_flags));
        }

        parent_list[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_RESOLVED;
        if (p_nh->p_arp_info != NULL)
        {
            is_arp_resolved = ((p_nh->p_arp_info->state == FIB_ARP_RESOLVED) ? true : false);
        }
        cps_api_object_e_add(obj, parent_list, 3,
                             cps_api_object_ATTR_T_U32, &is_arp_resolved, sizeof(is_arp_resolved));
        parent_list[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_NPU_PRG_DONE;
        is_npu_prg_done = nas_rt_is_nh_npu_prg_done(p_nh);
        cps_api_object_e_add(obj, parent_list, 3,
                             cps_api_object_ATTR_T_U32, &is_npu_prg_done, sizeof(is_npu_prg_done));

        nh_itr++;
    }
    cps_api_object_attr_add_u32(obj, BASE_ROUTE_OBJ_ENTRY_NH_COUNT, nh_itr);

    return obj;
}

cps_api_object_t nas_route_nh_to_arp_cps_object(t_fib_nh *entry, cps_api_operation_types_t op){

    if(entry == NULL){
        HAL_RT_LOG_ERR("HAL-RT-ARP","Null NH entry pointer passed to convert it to cps object");
        return NULL;
    }

    if(entry->p_arp_info == NULL){
        HAL_RT_LOG_ERR("HAL-RT-ARP","No ARP info associated with next hop");
        return NULL;
    }

    char mac_addr[HAL_RT_MAX_BUFSZ];
    memset(mac_addr, '\0', sizeof(mac_addr));
    hal_rt_mac_to_str (&entry->p_arp_info->mac_addr, mac_addr, HAL_RT_MAX_BUFSZ);

    HAL_RT_LOG_INFO("HAL-RT-NH-PUB", "VRF %d. Addr: %s, Interface: %d MAC:%s age-out:%d op:%d",
                     entry->vrf_id, FIB_IP_ADDR_TO_STR (&entry->key.ip_addr),
                     entry->key.if_index, mac_addr, entry->reachable_state_time_stamp, op);

    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL){
        HAL_RT_LOG_ERR("HAL-RT-ARP","Failed to allocate memory to cps object");
        return NULL;
    }

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key, BASE_ROUTE_OBJ_NBR,
                                    cps_api_qualifier_OBSERVED);
    cps_api_object_set_type_operation(&key,op);
    cps_api_object_set_key(obj,&key);

    if(entry->key.ip_addr.af_index == HAL_INET4_FAMILY){
        cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_ADDRESS,entry->key.ip_addr.u.ipv4.s_addr);
    }else{
        cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_ADDRESS,(void *)entry->key.ip_addr.u.ipv6.s6_addr,HAL_INET6_LEN);
    }
    cps_api_object_attr_add(obj, BASE_ROUTE_OBJ_NBR_MAC_ADDR, (const void *)mac_addr,
                            strlen(mac_addr)+1);
    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_VRF_NAME,
                            FIB_GET_VRF_NAME(entry->vrf_id, entry->key.ip_addr.af_index),
                            strlen((const char*)FIB_GET_VRF_NAME(entry->vrf_id, entry->key.ip_addr.af_index))+1);
    if (hal_rt_access_fib_vrf (entry->parent_vrf_id)) {
        cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_VRF_NAME,
                                FIB_GET_VRF_NAME(entry->parent_vrf_id, entry->key.ip_addr.af_index),
                                strlen((const char*)FIB_GET_VRF_NAME(entry->parent_vrf_id, entry->key.ip_addr.af_index))+1);
    }
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_AF,entry->key.ip_addr.af_index);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_IFINDEX,entry->key.if_index);

    t_fib_intf *p_intf = fib_get_intf (entry->key.if_index, entry->parent_vrf_id,
                                       entry->key.ip_addr.af_index);
    if (p_intf != NULL) {
        HAL_RT_LOG_DEBUG("HAL-RT-API","NH to ARP - get the interface name for :%d(%s)",
                       entry->key.if_index, p_intf->if_name);
        cps_api_object_attr_add(obj, BASE_ROUTE_OBJ_NBR_IFNAME, (const void *)p_intf->if_name,
                                strlen(p_intf->if_name)+1);
    } else {
        /* While publishing the Neighbor del, it's expected to get the get_intf_name failure,
         * because interface (VLAN/LAG) delete could have triggered the neighbor delete(s) */
        HAL_RT_LOG_ERR("HAL-RT-ARP","Failed to get the interface name for :%d",
                       entry->p_arp_info->if_index);
        cps_api_object_delete(obj);
        return NULL;
    }

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_STATE,entry->p_arp_info->arp_status);
    if (entry->p_arp_info->arp_status & RT_NUD_PERMANENT) {
        cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_TYPE,BASE_ROUTE_RT_TYPE_STATIC);
    }else {
        cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_TYPE,BASE_ROUTE_RT_TYPE_DYNAMIC);
    }
    /* Find the max timeout for ARP neighbor */
    uint32_t timeout = 0;
    if (entry->reachable_state_time_stamp) {
        uint32_t time_stamp = nas_rt_get_clock_sec();
        if (time_stamp >= entry->reachable_state_time_stamp) {
            timeout = time_stamp - entry->reachable_state_time_stamp;
        } else {
            /* clock sec wrapped around */
            timeout = time_stamp + (LONG_MAX - entry->reachable_state_time_stamp);
        }
        /* Since the neighbor timeout can happen anywhere between
         * base_reachable_time/2 and 3*base_reachable_time/2 (HAL_RT_NBR_TIMEOUT),
         * we assume HAL_RT_NBR_TIMEOUT and reducing the elapsed seconds from it, to
         * get the remaining time for the max. timeout */
        if (HAL_RT_NBR_TIMEOUT > timeout) {
            timeout = HAL_RT_NBR_TIMEOUT - timeout;
        } else {
            /* If we dont get the notification from kernel beyond max. timeout value,
             * something wrong in the netlink notification, simply set the timeout as 0 */
            timeout = 0;
        }
    }
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_AGE_TIMEOUT, timeout);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_NPU_PRG_DONE, nas_rt_is_nh_npu_prg_done(entry));

    return obj;
}

static t_std_error nas_route_get_all_vrf_routes_info(cps_api_object_list_t list, uint32_t vrf_id_get,
                                                     uint32_t af_index, bool is_specific_vrf_get) {
    t_fib_dr *p_dr = NULL;
    uint32_t vrf_id = (is_specific_vrf_get ? vrf_id_get : FIB_MIN_VRF);

    for (; vrf_id < FIB_MAX_VRF; vrf_id++) {
        if ((hal_rt_access_fib_vrf(vrf_id) == NULL) ||
            (FIB_GET_VRF_INFO (vrf_id, af_index) == NULL)) {
            if (is_specific_vrf_get) {
                break;
            }
            continue;
        }
        p_dr = fib_get_first_dr(vrf_id, af_index);
        while (p_dr != NULL){
            cps_api_object_t obj = nas_route_info_to_cps_object(0, p_dr, false);
            if(obj != NULL){
                if (!cps_api_object_list_append(list,obj)) {
                    cps_api_object_delete(obj);
                    HAL_RT_LOG_ERR("HAL-RT-API","Failed to append object to object list");
                    return STD_ERR(ROUTE,FAIL,0);
                }
            }

            p_dr = fib_get_next_dr (vrf_id, &p_dr->key.prefix, p_dr->prefix_len);
        }

        if (is_specific_vrf_get) {
            break;
        }
    }
    return STD_ERR_OK;
}

t_std_error nas_route_get_all_route_info(cps_api_object_list_t list, uint32_t vrf_id, uint32_t af,
                                         hal_ip_addr_t *p_prefix, uint32_t pref_len, bool is_specific_prefix_get,
                                         bool is_specific_vrf_get) {

    t_fib_dr *p_dr = NULL;

    if (is_specific_prefix_get == false) {
        if (is_specific_vrf_get == false) {
            return (nas_route_get_all_vrf_routes_info(list, vrf_id, af, false));
        } else {
            return (nas_route_get_all_vrf_routes_info(list, vrf_id, af, true));
        }
    }

    if (af >= FIB_MAX_AFINDEX)
    {
        HAL_RT_LOG_ERR("HAL-RT-ARP","Invalid Address family");
        return STD_ERR(ROUTE,FAIL,0);
    }

    p_dr = fib_get_dr (vrf_id, p_prefix, pref_len);
    if (p_dr != NULL) {
        cps_api_object_t obj = nas_route_info_to_cps_object(0, p_dr, false);
        if(obj != NULL){
            if (!cps_api_object_list_append(list,obj)) {
                cps_api_object_delete(obj);
                HAL_RT_LOG_ERR("HAL-RT-API","Failed to append object to object list");
                return STD_ERR(ROUTE,FAIL,0);
            }
        }
    }
    return STD_ERR_OK;
}


static void nas_route_nht_add_nh_info_to_cps_object (cps_api_object_t obj, t_fib_nh *p_nh, int nh_count) {
    cps_api_attr_id_t parent_list[3];
    uint32_t af;
    uint32_t addr_len = 0, is_arp_resolved, is_npu_prg_done;

    parent_list[0] = BASE_ROUTE_NH_TRACK_NH_INFO;
    parent_list[1] = nh_count;
    parent_list[2] = BASE_ROUTE_NH_TRACK_NH_INFO_ADDRESS;

    if(p_nh->key.ip_addr.af_index == HAL_INET4_FAMILY) {
        addr_len = HAL_INET4_LEN;
        cps_api_object_e_add(obj, parent_list, 3,
                             cps_api_object_ATTR_T_BIN, &p_nh->key.ip_addr.u.v4_addr, addr_len);
    } else {
        addr_len = HAL_INET6_LEN;
        cps_api_object_e_add(obj, parent_list, 3,
                             cps_api_object_ATTR_T_BIN, &p_nh->key.ip_addr.u.v6_addr, addr_len);
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NHT", "Get NHT: Adding NH info to NH-List vrf_id: %d, af: %d, dest: %s ",
                 p_nh->vrf_id, p_nh->key.ip_addr.af_index, FIB_IP_ADDR_TO_STR (&(p_nh->key.ip_addr)));

    parent_list[2] = BASE_ROUTE_NH_TRACK_NH_INFO_MAC_ADDR;
    cps_api_object_e_add(obj, parent_list, 3,
                         cps_api_object_ATTR_T_BIN, p_nh->p_arp_info->mac_addr,HAL_MAC_ADDR_LEN);

    parent_list[2] = BASE_ROUTE_NH_TRACK_NH_INFO_VRF_ID;
    cps_api_object_e_add(obj, parent_list, 3,
                         cps_api_object_ATTR_T_U32, &p_nh->vrf_id, sizeof(p_nh->vrf_id));

    cps_api_object_attr_add(obj,BASE_ROUTE_NH_TRACK_NH_INFO_VRF_NAME,
                            FIB_GET_VRF_NAME(p_nh->parent_vrf_id, p_nh->key.ip_addr.af_index),
                            strlen((const char*)FIB_GET_VRF_NAME(p_nh->parent_vrf_id, p_nh->key.ip_addr.af_index))+1);

    af = p_nh->key.ip_addr.af_index;
    parent_list[2] = BASE_ROUTE_NH_TRACK_NH_INFO_AF;
    cps_api_object_e_add(obj, parent_list, 3,
                         cps_api_object_ATTR_T_U32, &af, sizeof(af));

    parent_list[2] = BASE_ROUTE_NH_TRACK_NH_INFO_IFINDEX;
    cps_api_object_e_add(obj, parent_list, 3,
                         cps_api_object_ATTR_T_U32, &p_nh->key.if_index, sizeof(p_nh->key.if_index));
    t_fib_intf *p_intf = fib_get_intf (p_nh->key.if_index, p_nh->vrf_id,
                                       p_nh->key.ip_addr.af_index);
    if (p_intf != NULL) {
        HAL_RT_LOG_DEBUG("HAL-RT-API","get the interface name for :%d (%s)",
                       p_nh->key.if_index, p_intf->if_name);
        parent_list[2] = BASE_ROUTE_NH_TRACK_NH_INFO_IFNAME;
        cps_api_object_e_add(obj, parent_list, 3, cps_api_object_ATTR_T_BIN,
                             (const void *)p_intf->if_name, strlen(p_intf->if_name)+1);
    } else {
        HAL_RT_LOG_ERR("HAL-RT-API","Failed to get the interface name for :%d",
                       p_nh->key.if_index);
    }

    is_arp_resolved = true;
    parent_list[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_RESOLVED;
    cps_api_object_e_add(obj, parent_list, 3,
                         cps_api_object_ATTR_T_U32, &is_arp_resolved, sizeof(is_arp_resolved));

    parent_list[2] = BASE_ROUTE_NH_TRACK_NH_INFO_NPU_PRG_DONE;
    is_npu_prg_done = nas_rt_is_nh_npu_prg_done(p_nh);
    cps_api_object_e_add(obj, parent_list, 3,
                         cps_api_object_ATTR_T_U32, &is_npu_prg_done, sizeof(is_npu_prg_done));

    return;
}

static cps_api_object_t nas_route_nht_info_to_cps_object(t_fib_nht *entry, cps_api_operation_types_t op,
                                                         t_fib_dr *p_best_dr, t_fib_nh *p_nh) {
    t_fib_nh_holder    nh_holder;
    int                addr_len = 0;
    int                nh_count = 0;

    if(entry == NULL){
        HAL_RT_LOG_ERR("HAL-RT-API","Null NHT entry pointer passed to convert it to cps object");
        return NULL;
    }

    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL){
        HAL_RT_LOG_ERR("HAL-RT-API","Failed to allocate memory to cps object");
        return NULL;
    }

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key, BASE_ROUTE_NH_TRACK_OBJ,
                                    cps_api_qualifier_OBSERVED);

    cps_api_object_set_type_operation(&key,op);
    cps_api_object_set_key(obj,&key);

    cps_api_set_key_data (obj, BASE_ROUTE_NH_TRACK_VRF_ID, cps_api_object_ATTR_T_U32,&entry->vrf_id,
                          sizeof(entry->vrf_id));
    uint32_t af = entry->key.dest_addr.af_index;
    cps_api_set_key_data (obj, BASE_ROUTE_NH_TRACK_AF, cps_api_object_ATTR_T_U32,&af, sizeof(af));
    cps_api_object_attr_add(obj,BASE_ROUTE_NH_TRACK_VRF_NAME,
                            FIB_GET_VRF_NAME(entry->vrf_id, entry->key.dest_addr.af_index),
                            strlen((const char*)FIB_GET_VRF_NAME(entry->vrf_id, entry->key.dest_addr.af_index))+1);
    if(entry->key.dest_addr.af_index == HAL_INET4_FAMILY){
        addr_len = HAL_INET4_LEN;
        cps_api_set_key_data (obj, BASE_ROUTE_NH_TRACK_DEST_ADDR, cps_api_object_ATTR_T_BIN,&(entry->key.dest_addr.u.v4_addr),
                              addr_len);
    }else{
        addr_len = HAL_INET6_LEN;
        cps_api_set_key_data (obj, BASE_ROUTE_NH_TRACK_DEST_ADDR, cps_api_object_ATTR_T_BIN,&(entry->key.dest_addr.u.v6_addr),
                              addr_len);
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NHT", "Get NHT: vrf_id: %d, af: %d, dest: %s best_match_addr: %s",
                 entry->vrf_id, entry->key.dest_addr.af_index, FIB_IP_ADDR_TO_STR (&(entry->key.dest_addr)),
                 FIB_IP_ADDR_TO_STR (&(entry->fib_match_dest_addr)));

    /* entry->fib_match_dest_addr can be 0 in few scenarios:
     * 1. there is no best match DR/NH with NH resolved for this NHT dest address or
     * 2. the best match nothing but the default route with a NH resolved.
     * 2. the best match nothing but the default route but no NH resolved/nh_handle is not valid.
     */
    if (FIB_IS_AFINDEX_VALID (entry->fib_match_dest_addr.af_index))
    {

        /* for create or delete, either p_best_dr or p_nh will be valid,
         * so no need to lookup nh/dr again. lookup only if it's called from GET flow */
        if (op == cps_api_oper_NULL) {
            /* Check if this dest_addr is already resolved in NextHop or Route table */
            p_nh = fib_get_next_nh(entry->vrf_id, &entry->fib_match_dest_addr, 0);
        }
        if ((p_nh != NULL) && (memcmp (&p_nh->key.ip_addr, &entry->fib_match_dest_addr, sizeof (t_fib_ip_addr)) == 0) &&
            (p_nh->p_arp_info != NULL) && (p_nh->p_arp_info->state == FIB_ARP_RESOLVED)) {

            nas_rt_fill_opaque_data(obj, BASE_ROUTE_NH_TRACK_DATA, 0, &p_nh->next_hop_id);

            nas_route_nht_add_nh_info_to_cps_object (obj, p_nh, nh_count);
            nh_count = 1;

        } else {
            /* for create or delete, either p_best_dr or p_nh will be valid,
             * so no need to lookup nh/dr again. lookup only if it's called from GET flow */
            if (op == cps_api_oper_NULL) {
                p_best_dr = fib_get_dr(entry->vrf_id, &entry->fib_match_dest_addr, entry->prefix_len);
            }
            if (p_best_dr != NULL) {
                nas_rt_fill_opaque_data(obj, BASE_ROUTE_NH_TRACK_DATA, 0, &p_best_dr->nh_handle);
                FIB_FOR_EACH_NH_FROM_DR (p_best_dr, p_nh, nh_holder)
                {
                    if ((p_nh->p_arp_info == NULL) || (p_nh->p_arp_info->state != FIB_ARP_RESOLVED))
                        continue;
                    nas_route_nht_add_nh_info_to_cps_object (obj, p_nh, nh_count);

                    nh_count++;
                }
            }
        }
    }
    HAL_RT_LOG_DEBUG("HAL-RT-NHT", "Get NHT: NH Count %d", nh_count);
    cps_api_object_attr_add_u32(obj, BASE_ROUTE_NH_TRACK_NH_COUNT, nh_count);
    if (p_nh) {
        cps_api_object_attr_add(obj,BASE_ROUTE_NH_TRACK_NH_INFO_VRF_NAME,
                                FIB_GET_VRF_NAME(p_nh->parent_vrf_id, p_nh->key.ip_addr.af_index),
                                strlen((const char*)FIB_GET_VRF_NAME(p_nh->parent_vrf_id, p_nh->key.ip_addr.af_index))+1);
    }

    if (FIB_IS_AFINDEX_VALID (entry->fib_match_dest_addr.af_index)) {
        HAL_RT_LOG_INFO("HAL-RT-NHT",
                     "NHT Event publish for nht_dest:%s, nh_count:%d, nht_best_match_dest:%s/%d ",
                     FIB_IP_ADDR_TO_STR (&entry->key.dest_addr), nh_count,
                     FIB_IP_ADDR_TO_STR (&entry->fib_match_dest_addr), entry->prefix_len);
    } else {
        HAL_RT_LOG_INFO("HAL-RT-NHT",
                     "NHT Event publish for nht_dest:%s, nh_count:%d, nht_best_match_dest:-",
                     FIB_IP_ADDR_TO_STR (&entry->key.dest_addr), nh_count);

    }

    return obj;
}

static t_std_error nas_route_get_all_vrf_nht_info(cps_api_object_list_t list, uint32_t af) {
    t_fib_nht *p_nht = NULL;
    uint32_t vrf_id = FIB_MIN_VRF;

    for (; vrf_id < FIB_MAX_VRF; vrf_id++) {
        if ((hal_rt_access_fib_vrf(vrf_id) == NULL) ||
            (FIB_GET_VRF_INFO (vrf_id, af) == NULL)) {
            continue;
        }

        cps_api_operation_types_t op = cps_api_oper_NULL; // for now action is dummy for get request
        p_nht = fib_get_first_nht(vrf_id, af);
        while (p_nht != NULL) {

            HAL_RT_LOG_DEBUG("HAL-RT-NHT", "Get NHT: vrf_id: %d, af: %d, dest: %s ",
                             vrf_id, af, FIB_IP_ADDR_TO_STR (&(p_nht->key.dest_addr)));

            cps_api_object_t obj = nas_route_nht_info_to_cps_object(p_nht, op, NULL, NULL);
            if(obj != NULL){
                if (!cps_api_object_list_append(list,obj)) {
                    cps_api_object_delete(obj);
                    HAL_RT_LOG_ERR("HAL-RT-NHT","Failed to append object to object list");

                    return STD_ERR(ROUTE,FAIL,0);
                }
            }
            p_nht = fib_get_next_nht (vrf_id, &p_nht->key.dest_addr);
        }
    }
    return STD_ERR_OK;
}

t_std_error nas_route_get_all_nht_info(cps_api_object_list_t list, bool is_specific_vrf_get,
                                       unsigned int vrf_id,
                                       unsigned int af,
                                       t_fib_ip_addr *p_dest_addr) {

    t_fib_nht *p_nht = NULL;

    HAL_RT_LOG_DEBUG("HAL-RT-NHT", "Get NHT: is_specific_vrf_get:%d vrf_id: %d, af: %d ",
                     is_specific_vrf_get, vrf_id, af);

    if (af >= FIB_MAX_AFINDEX)
    {
        HAL_RT_LOG_ERR("HAL-RT-NHT","Invalid Address family");
        return STD_ERR(ROUTE,FAIL,0);
    }

    if (is_specific_vrf_get == false) {
        return (nas_route_get_all_vrf_nht_info(list, af));
    }
    if (p_dest_addr != NULL) {
        HAL_RT_LOG_DEBUG("HAL-RT-NHT", "Get NHT: for dest:%s ",
                     FIB_IP_ADDR_TO_STR (p_dest_addr));
        p_nht = fib_get_nht (vrf_id, p_dest_addr);
    } else {
        p_nht = fib_get_first_nht(vrf_id, af);
    }

    cps_api_operation_types_t op = cps_api_oper_NULL; // for now action is dummy for get request
    while (p_nht != NULL) {

        HAL_RT_LOG_DEBUG("HAL-RT-NHT", "Get NHT: vrf_id: %d, af: %d, dest: %s ",
                     vrf_id, af, FIB_IP_ADDR_TO_STR (&(p_nht->key.dest_addr)));

        cps_api_object_t obj = nas_route_nht_info_to_cps_object(p_nht, op, NULL, NULL);
        if(obj != NULL){
            if (!cps_api_object_list_append(list,obj)) {
                cps_api_object_delete(obj);
                HAL_RT_LOG_ERR("HAL-RT-NHT","Failed to append object to object list");

                return STD_ERR(ROUTE,FAIL,0);
            }
        }
        if (p_dest_addr != NULL) break;
        p_nht = fib_get_next_nht (vrf_id, &p_nht->key.dest_addr);
    }
    return STD_ERR_OK;
}

int nas_rt_publish_nht(t_fib_nht *p_nht, t_fib_dr *p_dr, t_fib_nh *p_nh, bool is_add) {

    HAL_RT_LOG_DEBUG("HAL-RT-NHT", "Publishing a NHT information dest_addr:%s p_dr:%p p_nh:%p is_add:%d",
                     FIB_IP_ADDR_TO_STR (&p_nht->key.dest_addr), p_dr, p_nh, is_add);

    if (p_nht == NULL)
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));

    cps_api_operation_types_t op;

    if (is_add) {
        if (p_nht->is_create_pub == false) {
            op = cps_api_oper_CREATE;
            p_nht->is_create_pub = true;
        } else {
            op = cps_api_oper_SET;
        }
    } else {
        op = cps_api_oper_DELETE;
    }
    cps_api_object_t obj = nas_route_nht_info_to_cps_object(p_nht, op, p_dr, p_nh);
    if(obj != NULL){
        if(nas_route_nht_publish_object(obj)!= STD_ERR_OK){
            HAL_RT_LOG_ERR("HAL-RT-NHT","Failed to publish NHT entry");
        }
    }

    return STD_ERR_OK;
}

cps_api_object_t nas_route_nh_to_nbr_cps_object(t_fib_nh *entry, cps_api_operation_types_t op, bool is_pub){

    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL){
        HAL_RT_LOG_ERR("HAL-RT-ARP","Failed to allocate memory to cps object");
        return NULL;
    }

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key, BASE_NEIGHBOR_BASE_ROUTE_OBJ_NBR_OBJ,
                                    (is_pub ? cps_api_qualifier_OBSERVED : cps_api_qualifier_TARGET));
    if (is_pub)
        cps_api_object_set_type_operation(&key,op);

    cps_api_object_set_key(obj,&key);

    if(entry->key.ip_addr.af_index == HAL_INET4_FAMILY){
        cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_ADDRESS,entry->key.ip_addr.u.ipv4.s_addr);
    }else{
        cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_ADDRESS,(void *)entry->key.ip_addr.u.ipv6.s6_addr,HAL_INET6_LEN);
    }
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_VRF_ID,entry->parent_vrf_id);
    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_VRF_NAME,
                            FIB_GET_VRF_NAME(entry->parent_vrf_id, entry->key.ip_addr.af_index),
                            strlen((const char*)FIB_GET_VRF_NAME(entry->parent_vrf_id, entry->key.ip_addr.af_index))+1);
    if (hal_rt_access_fib_vrf (entry->parent_vrf_id)) {
        cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_VRF_NAME,
                                FIB_GET_VRF_NAME(entry->parent_vrf_id, entry->key.ip_addr.af_index),
                                strlen((const char*)FIB_GET_VRF_NAME(entry->parent_vrf_id, entry->key.ip_addr.af_index))+1);
    }
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_AF,entry->key.ip_addr.af_index);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_IFINDEX,entry->key.if_index);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_FLAGS,NAS_RT_NBR_FLAGS_PROACTIVE_RESOLVE);

    HAL_RT_LOG_INFO("HAL-RT-NH-PUB", "op:%d Resolve ARP for VRF %d(%s) parent:%d (%s) Addr: %s, Interface: %d "
                   "route-cnt:%d nht-active:%d",
                   op, entry->vrf_id, FIB_GET_VRF_NAME(entry->vrf_id, entry->key.ip_addr.af_index),
                   entry->parent_vrf_id, FIB_GET_VRF_NAME(entry->parent_vrf_id, entry->key.ip_addr.af_index),
                   FIB_IP_ADDR_TO_STR (&entry->key.ip_addr),
                   entry->key.if_index, entry->rtm_ref_count, entry->is_nht_active);
    return obj;
}

t_std_error nas_route_nbr_entry_to_nbr_cps_object(t_fib_neighbour_entry *entry,
                                                  cps_api_operation_types_t op, uint32_t flags){
    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL){
        HAL_RT_LOG_ERR("HAL-RT-ARP","Failed to allocate memory to cps object");
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key, BASE_NEIGHBOR_BASE_ROUTE_OBJ_NBR_OBJ, cps_api_qualifier_OBSERVED);
    cps_api_object_set_type_operation(&key, op);

    cps_api_object_set_key(obj,&key);

    if(entry->family == HAL_INET4_FAMILY){
        cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_ADDRESS,entry->nbr_addr.u.ipv4.s_addr);
    }else{
        cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_ADDRESS,(void *)entry->nbr_addr.u.ipv6.s6_addr,HAL_INET6_LEN);
    }
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_VRF_ID, entry->vrfid);
    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_VRF_NAME,
                            FIB_GET_VRF_NAME(entry->vrfid, entry->family),
                            strlen((const char*)FIB_GET_VRF_NAME(entry->vrfid, entry->family))+1);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_AF,entry->family);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_IFINDEX,entry->if_index);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_FLAGS,flags);
    cps_api_object_attr_add_u32(obj,OS_RE_BASE_ROUTE_OBJ_NBR_LOWER_LAYER_IF,entry->parent_if);

    HAL_RT_LOG_INFO("HAL-RT-NH-PUB", "Trigger resolve Nbr for op:%d VRF %d Addr:%s af:%d "
                    "flags:%d Intf:%d parent:%d status:%d", op, entry->vrfid, FIB_IP_ADDR_TO_STR (&entry->nbr_addr),
                    entry->family, flags, entry->if_index, entry->parent_if, entry->status);
    if(nas_route_publish_object(obj)!= STD_ERR_OK){
        HAL_RT_LOG_ERR("HAL-RT-ARP","Failed to publish the parent nbr resolve trigger!");
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }
    return STD_ERR_OK;
}

/* Publish the NH to Nbr-mgr for proactive resolution */
bool nas_route_resolve_nh(t_fib_nh *entry, bool is_add) {

    if(entry == NULL){
        HAL_RT_LOG_ERR("HAL-RT-ARP","Null NH entry pointer passed to convert it to cps object");
        return NULL;
    }

    HAL_RT_LOG_INFO("HAL-RT-NH-PUB", "Resolve ARP for VRF %d. Parent VRF:%d Addr: %s, Interface: %d route-cnt:%d nht-active:%d is_add:%d",
                   entry->vrf_id, entry->parent_vrf_id, FIB_IP_ADDR_TO_STR (&entry->key.ip_addr),
                   entry->key.if_index, entry->rtm_ref_count, entry->is_nht_active, is_add);
    cps_api_object_t obj = nas_route_nh_to_nbr_cps_object(entry, (is_add ? cps_api_oper_CREATE: cps_api_oper_DELETE), true);
    if(obj && (nas_route_publish_object(obj)!= STD_ERR_OK)){
        HAL_RT_LOG_ERR("HAL-RT-NH-PUB","Failed to publish NH entry for resolution");
        return false;
    }
    return true;
}

bool nas_route_publish_route(t_fib_dr *p_dr, t_fib_rt_msg_type type) {
    cps_api_operation_types_t op;
    if (!FIB_IS_EVENT_FILTER_ENABLED(p_dr->vrf_id, p_dr->key.prefix.af_index,
                                     (p_dr->is_mgmt_route ? BASE_ROUTE_RT_OWNER_MGMTROUTE: 0))) {
        HAL_RT_LOG_INFO("HAL-RT-PUB", "Route VRF %d. Prefix: %s/%d mgmt_route:%d publish ignored"
                        " since event-filter is not present!",
                        p_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                        p_dr->prefix_len, p_dr->is_mgmt_route);
        return true;
    }
    switch(type) {
        case FIB_RT_MSG_ADD:
            op = cps_api_oper_CREATE;
            break;
        case FIB_RT_MSG_UPD:
            op = cps_api_oper_SET;
            break;
        case FIB_RT_MSG_DEL:
            op = cps_api_oper_DELETE;
            break;
        default:
            return false;
    }

    cps_api_object_t obj = nas_route_info_to_cps_object(op, p_dr, true);
    if(obj && (nas_route_publish_object(obj)!= STD_ERR_OK)){
        HAL_RT_LOG_ERR("HAL-RT-NH-PUB","Failed to publish route entry!");
        return false;
    }
    return true;
}

bool nas_route_is_rsvd_intf(hal_ifindex_t if_index) {

    interface_ctrl_t intf_ctrl;
    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
    intf_ctrl.if_index = if_index;

    if(dn_hal_get_interface_info(&intf_ctrl) != STD_ERR_OK) {
        return false;
    }

    return false;
}

cps_api_return_code_t nas_route_os_ip_unreachable_config(char *vrf_name, uint32_t af, char *if_name,
                                                         bool is_del, bool is_enable) {
    cps_api_transaction_params_t tran;

    memset (&tran, 0, sizeof(tran));
    if (cps_api_transaction_init(&tran) != cps_api_ret_code_OK) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "CPS Transaction init failed!");
        return cps_api_ret_code_ERR;
    }
    cps_api_object_t obj = cps_api_object_create();
    if (!obj) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "CPS malloc error");
        return cps_api_ret_code_ERR;
    }

    bool is_failed = false;
    do {
        if(!cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                            OS_ICMP_CFG_IP_UNREACHABLES_CONFIG_OBJ,
                                            cps_api_qualifier_TARGET)) {
            is_failed = true;
            break;
        }
        uint32_t operation = is_del ? BASE_CMN_OPERATION_TYPE_DELETE : BASE_CMN_OPERATION_TYPE_CREATE;
        if (!cps_api_object_attr_add_u32(obj, OS_ICMP_CFG_IP_UNREACHABLES_CONFIG_INPUT_OPERATION,
                                         operation)) {
            is_failed = true;
            break;
        }

        if (!cps_api_object_attr_add_u32(obj, OS_ICMP_CFG_IP_UNREACHABLES_CONFIG_INPUT_AF,
                                         af)) {
            is_failed = true;
            break;
        }
        if (!cps_api_object_attr_add_u32(obj, OS_ICMP_CFG_IP_UNREACHABLES_CONFIG_INPUT_ENABLE,
                                         is_enable)) {
            is_failed = true;
            break;
        }
        if (vrf_name) {
            if (!cps_api_object_attr_add(obj, OS_ICMP_CFG_IP_UNREACHABLES_CONFIG_INPUT_VRF_NAME,
                                         vrf_name, strlen(vrf_name)+1)) {
                is_failed = true;
                break;
            }
        }

        if (if_name) {
            if (!cps_api_object_attr_add(obj, OS_ICMP_CFG_IP_UNREACHABLES_CONFIG_INPUT_IFNAME,
                                         if_name, strlen(if_name)+1)) {
                is_failed = true;
                break;
            }
        }
        if (cps_api_action(&tran, obj) != cps_api_ret_code_OK) {
            is_failed = true;
            break;
        }
        obj = NULL;
        if (cps_api_commit(&tran) != cps_api_ret_code_OK) {
            is_failed = true;
            break;
        }

    } while(0);
    if (is_failed) {
        cps_api_transaction_close(&tran);
        if (obj != NULL) {
            cps_api_object_delete(obj);
        }
        HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "CPS OS IP Unreachable configuration failed!");
        return cps_api_ret_code_ERR;
    }
    HAL_RT_LOG_INFO("NAS-RT-CPS-SET", "CPS OS IP Unreachable RPC successful!");
    cps_api_transaction_close(&tran);
    return cps_api_ret_code_OK;
}

cps_api_return_code_t nas_route_handle_event_filter(cps_api_transaction_params_t * param, size_t ix) {

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    cps_api_object_t cloned = cps_api_object_create();
    if (!cloned) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "CPS malloc error");
        return cps_api_ret_code_ERR;
    }

    cps_api_object_attr_t vrf_attr = cps_api_get_key_data(obj, BASE_ROUTE_EVENT_FILTER_VRF_NAME);
    cps_api_object_attr_t type_attr = cps_api_get_key_data(obj, BASE_ROUTE_EVENT_FILTER_TYPE);
    cps_api_object_attr_t enable_attr   = cps_api_object_attr_get(obj, BASE_ROUTE_EVENT_FILTER_ENABLE);
    if ((vrf_attr == NULL) || (type_attr == NULL)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS", "Missing VRF-name/route type attribute");
        return cps_api_ret_code_ERR;
    }
    int32_t type = cps_api_object_attr_data_u32(type_attr);
    if (type != BASE_ROUTE_RT_OWNER_MGMTROUTE) {
        HAL_RT_LOG_ERR("NAS-RT-CPS", "Invalid route type filter!");
        return cps_api_ret_code_ERR;
    }
    char  vrf_name[NAS_VRF_NAME_SZ + 1];
    memset (vrf_name,0,sizeof(vrf_name));
    safestrncpy(vrf_name, (const char *)cps_api_object_attr_data_bin(vrf_attr),
                sizeof(vrf_name));
    hal_vrf_id_t  vrf_id = 0;

    if (hal_rt_get_vrf_id(vrf_name, &vrf_id) == false) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "VRF-name:%s is not valid!", vrf_name);
        return cps_api_ret_code_ERR;
    }

    if (!(FIB_IS_VRF_ID_VALID (vrf_id))) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "Event filter - VRF:%d is not valid!", vrf_id);
        return cps_api_ret_code_ERR;
    }
    int32_t enable = false;
    if (enable_attr) {
        enable = cps_api_object_attr_data_uint(enable_attr);
        if ((enable != true) && (enable != false)) {
            HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "Enable attribute value:%d is not valid!", enable);
            return cps_api_ret_code_ERR;
        }
    }
    cps_api_object_clone(cloned,obj);
    cps_api_object_list_append(param->prev,cloned);
    if (cps_api_object_type_operation(cps_api_object_key(obj)) == cps_api_oper_DELETE) {
        enable = false;
    }
    if (enable) {
        FIB_EVENT_FILTER_SET(vrf_id, HAL_RT_V4_AFINDEX, type);
        FIB_EVENT_FILTER_SET(vrf_id, HAL_RT_V6_AFINDEX, type);
    } else {
        FIB_EVENT_FILTER_RESET(vrf_id, HAL_RT_V4_AFINDEX, type);
        FIB_EVENT_FILTER_RESET(vrf_id, HAL_RT_V6_AFINDEX, type);
    }
    return cps_api_ret_code_OK;
}

cps_api_return_code_t nas_route_process_cps_ip_unreachables_msg(cps_api_transaction_params_t * param, size_t ix) {

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);

    cps_api_object_attr_t af_attr = cps_api_get_key_data(obj, BASE_ROUTE_IP_UNREACHABLES_CONFIG_AF);
    cps_api_object_attr_t if_name_attr = cps_api_get_key_data(obj, BASE_ROUTE_IP_UNREACHABLES_CONFIG_IFNAME);
    cps_api_object_attr_t vrf_attr = cps_api_get_key_data(obj, BASE_ROUTE_IP_UNREACHABLES_CONFIG_VRF_NAME);
    if ((af_attr == NULL) || (if_name_attr == NULL)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS", "Missing Address family/Intf name attribute");
        return cps_api_ret_code_ERR;
    }
    int32_t af = cps_api_object_attr_data_u32(af_attr);
    if ((af != BASE_CMN_AF_TYPE_INET) && (af != BASE_CMN_AF_TYPE_INET6)) {
        HAL_RT_LOG_ERR("NAS-RT-CPS", "Invalid address family!");
        return cps_api_ret_code_ERR;
    }
    char if_name[HAL_IF_NAME_SZ];
    memset(if_name, '\0', sizeof(if_name));
    safestrncpy(if_name, (const char *)cps_api_object_attr_data_bin(if_name_attr),
                sizeof(if_name));

    hal_vrf_id_t vrf_id = 0;
    char  vrf_name[NAS_VRF_NAME_SZ + 1];
    if (vrf_attr) {
        memset (vrf_name,0,sizeof(vrf_name));
        safestrncpy(vrf_name, (const char *)cps_api_object_attr_data_bin(vrf_attr),
                    sizeof(vrf_name));
        if (hal_rt_get_vrf_id(vrf_name, &vrf_id) == false) {
            HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "VRF-name:%s is not valid!", vrf_name);
            return cps_api_ret_code_ERR;
        }
    }
    uint32_t if_index = 0;
    if (hal_rt_get_if_index_from_if_name(if_name, &vrf_id, &if_index) != STD_ERR_OK) {
        HAL_RT_LOG_ERR("NAS-RT-CPS", "Unable to get if-index from if-name:%s",
                       if_name);
        return cps_api_ret_code_ERR;
    }

    cps_api_object_t cloned = cps_api_object_create();
    if (!cloned) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "CPS malloc error");
        return cps_api_ret_code_ERR;
    }

    cps_api_object_clone(cloned,obj);
    cps_api_object_list_append(param->prev,cloned);

    t_fib_msg *p_msg = hal_rt_alloc_mem_msg();
    if (p_msg) {
        memset(p_msg, 0, sizeof(t_fib_msg));
        p_msg->type = FIB_MSG_TYPE_INTF_IP_UNREACH_CFG;
        p_msg->ip_unreach_cfg.if_index = if_index;
        safestrncpy(p_msg->ip_unreach_cfg.if_name, if_name,
                    sizeof(p_msg->ip_unreach_cfg.if_name));
        if (vrf_attr) {
            safestrncpy(p_msg->ip_unreach_cfg.vrf_name, (const char *) vrf_name,
                        sizeof(p_msg->ip_unreach_cfg.vrf_name));
        } else {
            safestrncpy(p_msg->ip_unreach_cfg.vrf_name, (const char *) FIB_DEFAULT_VRF_NAME,
                        sizeof(p_msg->ip_unreach_cfg.vrf_name));
        }
        p_msg->ip_unreach_cfg.af_index = ((af == BASE_CMN_AF_TYPE_INET) ?
                                          HAL_RT_V4_AFINDEX : HAL_RT_V6_AFINDEX);
        if (cps_api_object_type_operation(cps_api_object_key(obj)) == cps_api_oper_DELETE)
            p_msg->ip_unreach_cfg.is_op_del = true;

        nas_rt_process_msg(p_msg);
    }
    return cps_api_ret_code_OK;
}


cps_api_return_code_t nas_route_process_cps_ip_redirects_msg(cps_api_transaction_params_t * param, size_t ix) {
    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);

    cps_api_object_attr_t vrf_attr = cps_api_get_key_data(obj, BASE_ROUTE_IP_REDIRECTS_CONFIG_VRF_NAME);
    cps_api_object_attr_t if_name_attr = cps_api_get_key_data(obj, BASE_ROUTE_IP_REDIRECTS_CONFIG_IFNAME);

    if (if_name_attr == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS", "Missing interface name attribute");
        return cps_api_ret_code_ERR;
    }
    char if_name[HAL_IF_NAME_SZ];
    memset(if_name, '\0', sizeof(if_name));
    safestrncpy(if_name, (const char *)cps_api_object_attr_data_bin(if_name_attr),
                sizeof(if_name));

    uint32_t if_index = 0;
    hal_vrf_id_t vrf_id = 0;
    if (hal_rt_get_if_index_from_if_name(if_name, &vrf_id, &if_index) != STD_ERR_OK) {
        HAL_RT_LOG_ERR("NAS-RT-CPS", "Unable to get if-index from if-name:%s",
                       if_name);
        return cps_api_ret_code_ERR;
    }

    cps_api_object_t cloned = cps_api_object_create();
    if (!cloned) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "CPS malloc error");
        return cps_api_ret_code_ERR;
    }

    cps_api_object_clone(cloned,obj);
    cps_api_object_list_append(param->prev,cloned);

    t_fib_msg *p_msg = hal_rt_alloc_mem_msg();
    if (p_msg) {
        memset(p_msg, 0, sizeof(t_fib_msg));
        p_msg->type = FIB_MSG_TYPE_INTF_IP_REDIRECTS_CFG;
        p_msg->ip_redirects_cfg .if_index = if_index;
        safestrncpy(p_msg->ip_redirects_cfg.if_name, if_name,
                    sizeof(p_msg->ip_redirects_cfg.if_name));
        if (vrf_attr == NULL) {
            safestrncpy(p_msg->ip_redirects_cfg.vrf_name, (const char *) FIB_DEFAULT_VRF_NAME,
                        sizeof(p_msg->ip_redirects_cfg.vrf_name));
        } else {
            safestrncpy(p_msg->ip_redirects_cfg.vrf_name, (const char *) cps_api_object_attr_data_bin(vrf_attr),
                        sizeof(p_msg->ip_redirects_cfg.vrf_name));
        }
        if (cps_api_object_type_operation(cps_api_object_key(obj)) == cps_api_oper_DELETE)
            p_msg->ip_redirects_cfg.is_op_del = true;

        nas_rt_process_msg(p_msg);
    }
    return cps_api_ret_code_OK;
}


cps_api_return_code_t nas_route_flush_acls(next_hop_id_t *next_hop_id) {
    cps_api_transaction_params_t tran;

    memset (&tran, 0, sizeof(tran));
    if (cps_api_transaction_init(&tran) != cps_api_ret_code_OK) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "CPS Transaction init failed!");
        return cps_api_ret_code_ERR;
    }
    cps_api_object_t obj = cps_api_object_create();
    if (!obj) {
        HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "CPS malloc error");
        return cps_api_ret_code_ERR;
    }

    bool is_failed = false;
    do {
        if(!cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                            BASE_ACL_CLEAR_ACL_ENTRIES_FOR_NH_OBJ,
                                            cps_api_qualifier_TARGET)) {
            is_failed = true;
            break;
        }
        if (nas_rt_fill_opaque_data(obj, BASE_ACL_CLEAR_ACL_ENTRIES_FOR_NH_INPUT_DATA,
                                    0, next_hop_id) != STD_ERR_OK) {
            HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "Filling Opaque data from next-hop id failed!");
            is_failed = true;
            break;
        }
        if (cps_api_action(&tran, obj) != cps_api_ret_code_OK) {
            is_failed = true;
            break;
        }
        obj = NULL;
        if (cps_api_commit(&tran) != cps_api_ret_code_OK) {
            is_failed = true;
            break;
        }

    } while(0);
    if (is_failed) {
        cps_api_transaction_close(&tran);
        if (obj != NULL) {
            cps_api_object_delete(obj);
        }
        HAL_RT_LOG_ERR("NAS-RT-CPS-SET", "CPS flush ACLs failed!");
        return cps_api_ret_code_ERR;
    }
    HAL_RT_LOG_INFO("NAS-RT-CPS-SET", "CPS flush ACLs successful!");
    cps_api_transaction_close(&tran);
    return cps_api_ret_code_OK;
}

