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
 * filename: nas_route_api.c
 */


#include "dell-base-routing.h"
#include "nas_rt_api.h"
#include "nas_os_l3.h"
#include "hal_rt_util.h"
#include "event_log_types.h"
#include "event_log.h"
#include "std_mutex_lock.h"

#include "cps_class_map.h"
#include "cps_api_object_key.h"
#include "cps_api_operation.h"
#include "cps_api_events.h"
#include "hal_rt_util.h"
#include "limits.h"
#include <stdio.h>
#include <stdint.h>

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
    cps_api_object_attr_t vrf_id;
    cps_api_object_attr_t prefix;
    cps_api_object_attr_t pref_len;
    cps_api_object_attr_t nh_count;

    /*
     * Check mandatory route attributes
     */
    af       = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_AF);
    vrf_id   = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_VRF_ID);
    prefix   = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX);
    pref_len = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN);

    /*
     * If route delete case, check the key mandatory attrs for delete case first
     */

    if  (af == CPS_API_ATTR_NULL || vrf_id == CPS_API_ATTR_NULL ||
            prefix == CPS_API_ATTR_NULL || pref_len == CPS_API_ATTR_NULL) {
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
     * If route add/update case, check for NH attributes also
     */
    nh_count = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_NH_COUNT);

    cps_api_attr_id_t ids[3] = { BASE_ROUTE_OBJ_ENTRY_NH_LIST, 0,
                                 BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR};
    const int ids_len = sizeof(ids)/sizeof(*ids);

    cps_api_object_attr_t gw = cps_api_object_e_get(obj, ids, ids_len);

    ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFINDEX;
    cps_api_object_attr_t gwix = cps_api_object_e_get(obj, ids, ids_len);

    if (nh_count == CPS_API_ATTR_NULL || (gw == CPS_API_ATTR_NULL && gwix == CPS_API_ATTR_NULL)) {
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

    if (obj == NULL) {
        HAL_RT_LOG_ERR("NAS-RT-CPS","Route object is not present");
        return cps_api_ret_code_ERR;
    }

    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    if (nas_route_validate_route_attr(obj, (op == cps_api_oper_DELETE)? true:false) == false) {
        HAL_RT_LOG_DEBUG("NAS-RT-CPS-SET", "Missing route key params");
        return cps_api_ret_code_ERR;
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
    }
    return rc;
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

static inline bool nas_rt_is_nh_npu_prg_done(t_fib_nh *p_entry) {
    int unit = 0;
    for (unit = 0; unit < hal_rt_access_fib_config()->max_num_npu; unit++) {
        if(p_entry->a_is_written [unit] == false)
            return false;
    }
    return true;
}

static cps_api_object_t nas_route_info_to_cps_object(t_fib_dr *entry){
    t_fib_nh       *p_nh = NULL;
    t_fib_nh_holder nh_holder1;
    int weight = 0;
    int addr_len = 0, nh_itr = 0, is_arp_resolved = false;

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
                                    cps_api_qualifier_TARGET);
    cps_api_object_set_key(obj,&key);

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_VRF_ID,entry->vrf_id);
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

    FIB_FOR_EACH_NH_FROM_DR (entry, p_nh, nh_holder1)
    {
        cps_api_attr_id_t parent_list[3];

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

        char if_name[HAL_IF_NAME_SZ];
        if (hal_rt_get_intf_name(p_nh->key.if_index, if_name) == STD_ERR_OK) {
            cps_api_object_attr_add(obj, BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFNAME, (const void *)if_name,
                                    strlen(if_name)+1);
        } else {
            HAL_RT_LOG_ERR("HAL-RT-API","Failed to get the interface name for :%d", p_nh->key.if_index);
            cps_api_object_delete(obj);
            return NULL;
        }
        parent_list[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_WEIGHT;
        cps_api_object_e_add(obj, parent_list, 3,
                             cps_api_object_ATTR_T_U32, &weight, sizeof(weight));

        parent_list[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_RESOLVED;
        if (p_nh->p_arp_info != NULL)
        {
            is_arp_resolved = ((p_nh->p_arp_info->state == FIB_ARP_RESOLVED) ? true : false);
        }
        cps_api_object_e_add(obj, parent_list, 3,
                             cps_api_object_ATTR_T_U32, &is_arp_resolved, sizeof(is_arp_resolved));
        parent_list[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_NPU_PRG_DONE;
        bool is_npu_prg_done = nas_rt_is_nh_npu_prg_done(p_nh);
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

    HAL_RT_LOG_DEBUG("HAL-RT-NH-PUB", "VRF %d. Addr: %s, Interface: %d MAC:%s age-out:%d op:%d\r\n",
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
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_VRF_ID,entry->vrf_id);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_AF,entry->key.ip_addr.af_index);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_IFINDEX,entry->key.if_index);

    char if_name[HAL_IF_NAME_SZ];
    if (hal_rt_get_intf_name(entry->key.if_index, if_name) == STD_ERR_OK) {
        cps_api_object_attr_add(obj, BASE_ROUTE_OBJ_NBR_IFNAME, (const void *)if_name,
                                strlen(if_name)+1);
    } else if (op != cps_api_oper_DELETE) {
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


t_std_error nas_route_get_all_route_info(cps_api_object_list_t list, uint32_t vrf_id, uint32_t af,
                                         hal_ip_addr_t *p_prefix, uint32_t pref_len, bool is_specific_prefix_get) {

    t_fib_dr *p_dr = NULL;

    if (af >= FIB_MAX_AFINDEX)
    {
        HAL_RT_LOG_ERR("HAL-RT-ARP","Invalid Address family");
        return STD_ERR(ROUTE,FAIL,0);
    }

    if (is_specific_prefix_get) {
        p_dr = fib_get_dr (vrf_id, p_prefix, pref_len);
    } else {
        p_dr = fib_get_first_dr(vrf_id, af);
    }
    while (p_dr != NULL){
        cps_api_object_t obj = nas_route_info_to_cps_object(p_dr);
        if(obj != NULL){
            if (!cps_api_object_list_append(list,obj)) {
                cps_api_object_delete(obj);
                HAL_RT_LOG_ERR("HAL-RT-API","Failed to append object to object list");
                return STD_ERR(ROUTE,FAIL,0);
            }
        }

        if (is_specific_prefix_get)
            break;

        p_dr = fib_get_next_dr (vrf_id, &p_dr->key.prefix, p_dr->prefix_len);
    }
    return STD_ERR_OK;
}


static void nas_route_nht_add_nh_info_to_cps_object (cps_api_object_t obj, t_fib_nh *p_nh, int nh_count) {
    cps_api_attr_id_t parent_list[3];
    unsigned int       af;
    int addr_len = 0, is_arp_resolved;

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

    HAL_RT_LOG_DEBUG("HAL-RT-NHT", "Get NHT: Adding NH info to NH-List vrf_id: %d, af: %d, dest: %s \r\n",
                 p_nh->vrf_id, p_nh->key.ip_addr.af_index, FIB_IP_ADDR_TO_STR (&(p_nh->key.ip_addr)));

    parent_list[2] = BASE_ROUTE_NH_TRACK_NH_INFO_MAC_ADDR;
    cps_api_object_e_add(obj, parent_list, 3,
                         cps_api_object_ATTR_T_BIN, p_nh->p_arp_info->mac_addr,HAL_MAC_ADDR_LEN);

    parent_list[2] = BASE_ROUTE_NH_TRACK_NH_INFO_VRF_ID;
    cps_api_object_e_add(obj, parent_list, 3,
                         cps_api_object_ATTR_T_U32, &p_nh->vrf_id, sizeof(p_nh->vrf_id));

    af = p_nh->key.ip_addr.af_index;
    parent_list[2] = BASE_ROUTE_NH_TRACK_NH_INFO_AF;
    cps_api_object_e_add(obj, parent_list, 3,
                         cps_api_object_ATTR_T_U32, &af, sizeof(af));

    parent_list[2] = BASE_ROUTE_NH_TRACK_NH_INFO_IFINDEX;
    cps_api_object_e_add(obj, parent_list, 3,
                         cps_api_object_ATTR_T_U32, &p_nh->key.if_index, sizeof(p_nh->key.if_index));

    is_arp_resolved = true;
    parent_list[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_RESOLVED;
    cps_api_object_e_add(obj, parent_list, 3,
                         cps_api_object_ATTR_T_U32, &is_arp_resolved, sizeof(is_arp_resolved));

    parent_list[2] = BASE_ROUTE_NH_TRACK_NH_INFO_NPU_PRG_DONE;
    bool is_npu_prg_done = nas_rt_is_nh_npu_prg_done(p_nh);
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
    cps_api_set_key_data (obj, BASE_ROUTE_NH_TRACK_AF, cps_api_object_ATTR_T_U32,&entry->key.dest_addr.af_index,
                          sizeof(entry->key.dest_addr.af_index));
    if(entry->key.dest_addr.af_index == HAL_INET4_FAMILY){
        addr_len = HAL_INET4_LEN;
        cps_api_set_key_data (obj, BASE_ROUTE_NH_TRACK_DEST_ADDR, cps_api_object_ATTR_T_BIN,&(entry->key.dest_addr.u.v4_addr),
                              addr_len);
    }else{
        addr_len = HAL_INET6_LEN;
        cps_api_set_key_data (obj, BASE_ROUTE_NH_TRACK_DEST_ADDR, cps_api_object_ATTR_T_BIN,&(entry->key.dest_addr.u.v6_addr),
                              addr_len);
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NHT", "Get NHT: vrf_id: %d, af: %d, dest: %s best_match_addr: %s\r\n",
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
        if (((op != cps_api_oper_CREATE) && (op != cps_api_oper_DELETE))) {
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
            if (((op != cps_api_oper_CREATE) && (op != cps_api_oper_DELETE))) {
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
    HAL_RT_LOG_DEBUG("HAL-RT-NHT", "Get NHT: NH Count %d\r\n", nh_count);
    cps_api_object_attr_add_u32(obj, BASE_ROUTE_NH_TRACK_NH_COUNT, nh_count);


    if (FIB_IS_AFINDEX_VALID (entry->fib_match_dest_addr.af_index)) {
        HAL_RT_LOG_DEBUG("HAL-RT-NHT",
                     "NHT Event publish for nht_dest:%s, nh_count:%d, nht_best_match_dest:%s/%d \r\n",
                     FIB_IP_ADDR_TO_STR (&entry->key.dest_addr), nh_count,
                     FIB_IP_ADDR_TO_STR (&entry->fib_match_dest_addr), entry->prefix_len);
    } else {
        HAL_RT_LOG_DEBUG("HAL-RT-NHT",
                     "NHT Event publish for nht_dest:%s, nh_count:%d, nht_best_match_dest:-\r\n",
                     FIB_IP_ADDR_TO_STR (&entry->key.dest_addr), nh_count);

    }

    return obj;
}


t_std_error nas_route_get_all_nht_info(cps_api_object_list_t list,
                                       unsigned int vrf_id,
                                       unsigned int af,
                                       t_fib_ip_addr *p_dest_addr) {

    t_fib_nht *p_nht = NULL;

    HAL_RT_LOG_DEBUG("HAL-RT-NHT", "Get NHT: vrf_id: %d, af: %d \r\n",
                 vrf_id, af);

    if (af >= FIB_MAX_AFINDEX)
    {
        HAL_RT_LOG_ERR("HAL-RT-NHT","Invalid Address family");
        return STD_ERR(ROUTE,FAIL,0);
    }

    if (p_dest_addr != NULL) {
        HAL_RT_LOG_DEBUG("HAL-RT-NHT", "Get NHT: for dest:%s \r\n",
                     FIB_IP_ADDR_TO_STR (p_dest_addr));
        p_nht = fib_get_nht (vrf_id, p_dest_addr);
    } else {
        p_nht = fib_get_first_nht(vrf_id, af);
    }

    while (p_nht != NULL) {

        HAL_RT_LOG_DEBUG("HAL-RT-NHT", "Get NHT: vrf_id: %d, af: %d, dest: %s \r\n",
                     vrf_id, af, FIB_IP_ADDR_TO_STR (&(p_nht->key.dest_addr)));

        cps_api_operation_types_t op = cps_api_oper_NULL; // for now action is dummy for get request
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

    HAL_RT_LOG_DEBUG("HAL-RT-NHT", "Publishing a NHT information dest_addr:%s p_dr:%p p_nh:%p is_add:%d\r\n",
                 FIB_IP_ADDR_TO_STR (&p_nht->key.dest_addr), p_dr, p_nh, is_add);

    if ((p_nht == NULL) || ((p_dr == NULL) && (p_nh == NULL)))
    {
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    cps_api_operation_types_t op = (is_add) ? cps_api_oper_CREATE :cps_api_oper_DELETE;

    cps_api_object_t obj = nas_route_nht_info_to_cps_object(p_nht, op, p_dr, p_nh);
    if(obj != NULL){
        if(nas_route_nht_publish_object(obj)!= STD_ERR_OK){
            HAL_RT_LOG_ERR("HAL-RT-NHT","Failed to publish NHT entry");
        }
    }


    return STD_ERR_OK;
}


