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
 * \file   hal_rt_arp.c
 * \brief  Hal Routing arp functionality
 * \date   05-2014
 * \author Prince Sunny and Satish Mynam
 */

#include "hal_rt_main.h"
#include "hal_rt_route.h"
#include "hal_rt_util.h"
#include "hal_rt_debug.h"
#include "nas_rt_api.h"
#include "hal_rt_util.h"
#include "nas_os_l3.h"

#include "ds_common_types.h"
#include "cps_api_interface_types.h"
#include "cps_api_route.h"
#include "cps_api_operation.h"
#include "cps_api_events.h"
#include "cps_class_map.h"
#include "dell-base-routing.h"
#include "dell-base-if.h"
#include "dell-base-if-linux.h"
#include "hal_if_mapping.h"

#include "event_log.h"
#include "std_ip_utils.h"

#include <string.h>

static cps_api_object_t nas_neigh_to_cps_obj(t_fib_neighbour_entry *entry,cps_api_operation_types_t op){
    if(entry == NULL){
        HAL_RT_LOG_ERR("HAL-RT-ARP","Null ARP entry pointer passed to convert it to cps object");
        return NULL;
    }

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
    if(entry->family == HAL_INET4_FAMILY){
        cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_ADDRESS,entry->nbr_addr.u.ipv4.s_addr);
    }else{
        cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_ADDRESS,(void *)entry->nbr_addr.u.ipv6.s6_addr,HAL_INET6_LEN);
    }
    char mac_addr[HAL_RT_MAX_BUFSZ];
    memset(mac_addr, '\0', sizeof(mac_addr));
    hal_rt_mac_to_str (&entry->nbr_hwaddr, mac_addr, HAL_RT_MAX_BUFSZ);
    cps_api_object_attr_add(obj, BASE_ROUTE_OBJ_NBR_MAC_ADDR, (const void *)mac_addr,
                            strlen(mac_addr)+1);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_VRF_ID,entry->vrfid);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_AF,entry->family);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_IFINDEX,entry->if_index);

    char if_name[HAL_IF_NAME_SZ];
    if (hal_rt_get_intf_name(entry->if_index, if_name) == STD_ERR_OK) {
        cps_api_object_attr_add(obj, BASE_ROUTE_OBJ_NBR_IFNAME, (const void *)if_name,
                                strlen(if_name)+1);
    } else {
        HAL_RT_LOG_ERR("HAL-RT-ARP","Failed to get the interface name for :%d",
               entry->if_index);
        cps_api_object_delete(obj);
        return NULL;
    }
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_FLAGS,entry->flags);
    if ((entry->status & RT_NUD_REACHABLE) || (entry->status & RT_NUD_PERMANENT)) {
        cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_STATE,FIB_ARP_RESOLVED);
    } else {
        cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_STATE,FIB_ARP_UNRESOLVED);
    }
    if (entry->status & RT_NUD_PERMANENT) {
        cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_TYPE,BASE_ROUTE_RT_TYPE_STATIC);
    } else {
        cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_TYPE,BASE_ROUTE_RT_TYPE_DYNAMIC);
    }
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_AGE_TIMEOUT,HAL_RT_NBR_TIMEOUT);
    return obj;
}


void hal_rt_cps_obj_to_neigh(cps_api_object_t obj,t_fib_neighbour_entry *n) {
    cps_api_object_attr_t list[cps_api_if_NEIGH_A_MAX];
    cps_api_object_attr_fill_list(obj,0,list,sizeof(list)/sizeof(*list));

    memset(n,0,sizeof(*n));

    if (list[cps_api_if_NEIGH_A_FAMILY]!=NULL)
        n->family = cps_api_object_attr_data_u32(list[cps_api_if_NEIGH_A_FAMILY]);
    if (list[cps_api_if_NEIGH_A_OPERATION]!=NULL)
        n->msg_type = cps_api_object_attr_data_u32(list[cps_api_if_NEIGH_A_OPERATION]);
    if (list[cps_api_if_NEIGH_A_NBR_ADDR]!=NULL)
        memcpy(&n->nbr_addr,
                cps_api_object_attr_data_bin(list[cps_api_if_NEIGH_A_NBR_ADDR]),
                sizeof(n->nbr_addr));
    if (list[cps_api_if_NEIGH_A_NBR_MAC]!=NULL)
        memcpy(n->nbr_hwaddr,
                cps_api_object_attr_data_bin(list[cps_api_if_NEIGH_A_NBR_MAC]),
                sizeof(n->nbr_hwaddr));
    if (list[cps_api_if_NEIGH_A_IFINDEX]!=NULL)
        n->if_index = cps_api_object_attr_data_u32(list[cps_api_if_NEIGH_A_IFINDEX]);
    if (list[cps_api_if_NEIGH_A_VRF]!=NULL)
        n->vrfid = cps_api_object_attr_data_u32(list[cps_api_if_NEIGH_A_VRF]);
    if (list[cps_api_if_NEIGH_A_EXPIRE]!=NULL)
        n->expire= cps_api_object_attr_data_u32(list[cps_api_if_NEIGH_A_EXPIRE]);
    if (list[cps_api_if_NEIGH_A_FLAGS]!=NULL)
        n->flags = cps_api_object_attr_data_u32(list[cps_api_if_NEIGH_A_FLAGS]);
    if (list[cps_api_if_NEIGH_A_STATE]!=NULL)
        n->status = cps_api_object_attr_data_u32(list[cps_api_if_NEIGH_A_STATE]);
}

t_std_error fib_proc_nbr_download (t_fib_neighbour_entry *p_arp_info_msg)
{
    uint32_t           vrf_id = 0;
    uint32_t           sub_cmd = 0;
    uint8_t            af_index = 0;
    bool               nbr_change = false;
    char               p_buf[HAL_RT_MAX_BUFSZ];

    if(!p_arp_info_msg) {
        HAL_RT_LOG_ERR("HAL-RT-ARP", "%s (): NULL nbr entry\n", __FUNCTION__);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_INFO("HAL-RT-ARP_OStoNAS", "cmd:%s(%d) vrf_id:%d, family:%d state:0x%x ip_addr:%s, "
                  "mac_addr:%s, out_if_index:%d phy:%d expire:%d status:0x%x",
                  ((p_arp_info_msg->msg_type == NBR_ADD) ? "Nbr-Add" : ((p_arp_info_msg->msg_type == NBR_DEL) ?
                                                                       "Nbr-Del" : "Unknown")),
                  p_arp_info_msg->msg_type, p_arp_info_msg->vrfid,
                  p_arp_info_msg->family, p_arp_info_msg->status,
                  FIB_IP_ADDR_TO_STR (&p_arp_info_msg->nbr_addr),
                  hal_rt_mac_to_str (&p_arp_info_msg->nbr_hwaddr, p_buf, HAL_RT_MAX_BUFSZ),
                  p_arp_info_msg->if_index,
                  p_arp_info_msg->phy_if_index, p_arp_info_msg->expire, p_arp_info_msg->status);


    if(hal_rt_validate_intf(p_arp_info_msg->if_index) != STD_ERR_OK) {
        return STD_ERR_OK;
    }

    sub_cmd  = p_arp_info_msg->msg_type;
    vrf_id   = p_arp_info_msg->vrfid;
    af_index = HAL_RT_ADDR_FAM_TO_AFINDEX(p_arp_info_msg->family);

    if (!(FIB_IS_VRF_ID_VALID (vrf_id))) {
        HAL_RT_LOG_ERR("HAL-RT-ARP", "%s (): Invalid vrf_id. vrf_id: %d\r\n",
                    __FUNCTION__, vrf_id);
        return STD_ERR_OK;
    }

    p_arp_info_msg->nbr_addr.af_index = af_index;
    if (hal_rt_is_reserved_ipv4(&p_arp_info_msg->nbr_addr)) {
        HAL_RT_LOG_DEBUG("HAL-RT-DR", "Skipping rsvd ipv4 addr %s on if_indx %d",
                     FIB_IP_ADDR_TO_STR(&p_arp_info_msg->nbr_addr), p_arp_info_msg->if_index);
        return STD_ERR_OK;
    }

    if (hal_rt_is_reserved_ipv6(&p_arp_info_msg->nbr_addr)) {
        HAL_RT_LOG_DEBUG("HAL-RT-DR", "Skipping rsvd ipv6 addr %s on if_indx %d",
                     FIB_IP_ADDR_TO_STR(&p_arp_info_msg->nbr_addr), p_arp_info_msg->if_index);
        return STD_ERR_OK;
    }
    /* Delete the failed neighbor entries from the DB */
    if ((sub_cmd == NBR_ADD) && (p_arp_info_msg->status == RT_NUD_FAILED)) {
        sub_cmd = NBR_DEL;
        FIB_INCR_CNTRS_NBR_ADD_FAILED (vrf_id, af_index);
    }

    switch (sub_cmd) {
        case NBR_ADD:
            FIB_INCR_CNTRS_NBR_ADD (vrf_id, af_index);
            if (p_arp_info_msg->status == RT_NUD_REACHABLE)
                FIB_INCR_CNTRS_NBR_ADD_REACHABLE (vrf_id, af_index);
            else if (p_arp_info_msg->status == RT_NUD_STALE)
                FIB_INCR_CNTRS_NBR_ADD_STALE (vrf_id, af_index);
            else if (p_arp_info_msg->status == RT_NUD_PROBE)
                FIB_INCR_CNTRS_NBR_ADD_PROBE (vrf_id, af_index);
            else if (p_arp_info_msg->status == RT_NUD_INCOMPLETE)
                FIB_INCR_CNTRS_NBR_ADD_INCOMPLETE (vrf_id, af_index);
            else if (p_arp_info_msg->status == RT_NUD_DELAY)
                FIB_INCR_CNTRS_NBR_ADD_DELAY (vrf_id, af_index);
            else if (p_arp_info_msg->status == RT_NUD_PERMANENT)
                FIB_INCR_CNTRS_NBR_ADD_PERMANENT (vrf_id, af_index);

            if (fib_proc_arp_add (af_index, p_arp_info_msg) == STD_ERR_OK){
                nbr_change = true;
            }
            break;

        case NBR_DEL:
            FIB_INCR_CNTRS_NBR_DEL (vrf_id, af_index);
            if (fib_proc_arp_del (af_index, p_arp_info_msg) == STD_ERR_OK){
                nbr_change = true;
            }
            break;

        default:
            HAL_RT_LOG_DEBUG("HAL-RT-ARP", "Unknown sub_cmd: %d\r\n", sub_cmd);
            FIB_INCR_CNTRS_UNKNOWN_MSG (vrf_id, af_index);
            break;
    }

    if(nbr_change) {
        /* If Neighbor is in stale state, refresh the neighbor */
        if ((sub_cmd == NBR_ADD) && (p_arp_info_msg->status == RT_NUD_STALE)) {
            cps_api_operation_types_t op = cps_api_oper_CREATE;
            cps_api_object_t tmp_obj = nas_neigh_to_cps_obj(p_arp_info_msg,op);
            if (tmp_obj) {
                if(nas_route_process_nbr_refresh(tmp_obj) != STD_ERR_OK){
                    HAL_RT_LOG_ERR("NAS-RT-NBR-REFRESH", " Neighbor refresh failed");
                }
                cps_api_object_delete(tmp_obj);
            }
        }
        fib_resume_nh_walker_thread(af_index);
    }
    return STD_ERR_OK;
}

t_std_error fib_proc_arp_add (uint8_t af_index, void *p_arp_info)
{
    t_fib_arp_msg_info   fib_arp_msg_info;
    t_fib_nh          *p_nh = NULL;
    char               p_buf[HAL_RT_MAX_BUFSZ];

    if (!p_arp_info) {
        HAL_RT_LOG_ERR("HAL-RT-ARP", "%s (): Invalid input param. p_arp_info: %p\r\n",
                    __FUNCTION__, p_arp_info);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    memset (&fib_arp_msg_info, 0, sizeof (t_fib_arp_msg_info));

    fib_form_arp_msg_info (af_index, p_arp_info, &fib_arp_msg_info, false);

    nas_l3_lock();

    p_nh = fib_get_nh (fib_arp_msg_info.vrf_id, &fib_arp_msg_info.ip_addr,
                       fib_arp_msg_info.if_index);
    if(p_nh != NULL) {
        if((p_nh->p_arp_info) && (p_nh->p_arp_info->if_index == fib_arp_msg_info.out_if_index) &&
           (!memcmp((uint8_t *)&p_nh->p_arp_info->mac_addr,
                    (uint8_t *)&fib_arp_msg_info.mac_addr,
                    HAL_RT_MAC_ADDR_LEN))) {

            HAL_RT_LOG_INFO("HAL-RT-ARP", "Duplicate Neighbor add Msg "
                            "vrf_id: %d, ip_addr: %s, if_index: 0x%x status:0x%x NPU status:%d\r\n",
                            fib_arp_msg_info.vrf_id, FIB_IP_ADDR_TO_STR (&fib_arp_msg_info.ip_addr),
                            fib_arp_msg_info.if_index, fib_arp_msg_info.status, p_nh->a_is_written [0]);
            /* Duplicate status notification, if NPU failed already, this could be because
             * of the ARP refresh triggered by AFS, allow it, otherwise skip it */
            if ((p_nh->p_arp_info->arp_status == fib_arp_msg_info.status) &&
                (p_nh->a_is_written [0])) {
                nas_l3_unlock();
                return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
            }

            p_nh->p_arp_info->arp_status = fib_arp_msg_info.status;

            /* Mark the timestamp on REACHABLE state, otherwise, reset the timeout to 0 */
            if (fib_arp_msg_info.status == RT_NUD_REACHABLE) {
                p_nh->reachable_state_time_stamp = nas_rt_get_clock_sec();
            } else {
                p_nh->reachable_state_time_stamp = 0;
            }

            if ((fib_arp_msg_info.status == RT_NUD_INCOMPLETE) ||
                (fib_arp_msg_info.status == RT_NUD_REACHABLE)) {
                /* 1. Incomplete - To install a blackhole entry while
                 * the ARP resolution in progress.
                 * 2. Reachable - Allow the regular ARP entry with forward action programming
                 * again, this could be from kernel because of the ARP refresh/ARP del and
                 * add when AFS aware of the ARP dependent MAC to resolve NPU failed ARP entry */
                fib_mark_nh_for_resolution (p_nh);
                nas_l3_unlock();
                return STD_ERR_OK;
            }

            /* @@TODO, if all the states to be published, publish for probe and delay states also.
             * To avoid too many publish msgs, dont publish the transient states probe and delay */
            if ((fib_arp_msg_info.status != RT_NUD_PROBE) &&
                (fib_arp_msg_info.status != RT_NUD_DELAY)) {
                cps_api_object_t obj = nas_route_nh_to_arp_cps_object(p_nh, cps_api_oper_CREATE);
                if(obj && (nas_route_publish_object(obj)!= STD_ERR_OK)){
                    HAL_RT_LOG_ERR("HAL-RT-NH","Failed to publish neighbor entry");
                }
            }

            nas_l3_unlock();
            if (fib_arp_msg_info.status == RT_NUD_STALE) {
                /* Stale - Returning succes for Neighbor refresh */
                return STD_ERR_OK;
            }
            return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
        }
    }

    HAL_RT_LOG_INFO("HAL-RT-ARP(ARP-START)", "Neighbor add - vrf_id: %d, ip_addr: %s, "
            "if_index: %d, mac_addr: %s, out_if_index: %d status:%d", fib_arp_msg_info.vrf_id,
            FIB_IP_ADDR_TO_STR (&fib_arp_msg_info.ip_addr),
            fib_arp_msg_info.if_index,
            hal_rt_mac_to_str (&fib_arp_msg_info.mac_addr, p_buf, HAL_RT_MAX_BUFSZ),
            fib_arp_msg_info.out_if_index, fib_arp_msg_info.status);

    p_nh = fib_proc_nh_add (fib_arp_msg_info.vrf_id, &fib_arp_msg_info.ip_addr,
                            fib_arp_msg_info.if_index, FIB_NH_OWNER_TYPE_ARP, 0);
    if (p_nh == NULL) {
        HAL_RT_LOG_ERR("HAL-RT-ARP", "%s (): NH addition failed. "
                    "vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n", __FUNCTION__,
                    fib_arp_msg_info.vrf_id, FIB_IP_ADDR_TO_STR (&fib_arp_msg_info.ip_addr),
                    fib_arp_msg_info.if_index);

        nas_l3_unlock();
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    if (p_nh->p_arp_info == NULL) {
        HAL_RT_LOG_ERR("HAL-RT-ARP", "%s (): NH's arp info NULL. "
                "vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n", __FUNCTION__,
                fib_arp_msg_info.vrf_id, FIB_IP_ADDR_TO_STR (&fib_arp_msg_info.ip_addr),
                fib_arp_msg_info.if_index);

        nas_l3_unlock();
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    p_nh->p_arp_info->if_index = fib_arp_msg_info.out_if_index;
    p_nh->p_arp_info->vlan_id = 0;  //unused
    memcpy((uint8_t *)&p_nh->p_arp_info->mac_addr, (uint8_t *)&fib_arp_msg_info.mac_addr, HAL_RT_MAC_ADDR_LEN);
    p_nh->p_arp_info->arp_status = fib_arp_msg_info.status;
    if (fib_arp_msg_info.status == RT_NUD_REACHABLE)
        p_nh->reachable_state_time_stamp = nas_rt_get_clock_sec();

    if(hal_rt_is_mac_address_zero((const hal_mac_addr_t *)&fib_arp_msg_info.mac_addr)) {
        p_nh->p_arp_info->state = FIB_ARP_UNRESOLVED;
    } else {
        p_nh->p_arp_info->state = FIB_ARP_RESOLVED;
    }
    p_nh->p_arp_info->is_l2_fh = fib_arp_msg_info.is_l2_fh;

    nas_l3_unlock();
    return STD_ERR_OK;
}

t_std_error fib_proc_arp_del (uint8_t af_index, void *p_arp_info)
{
    t_fib_arp_msg_info  fib_arp_msg_info;
    t_fib_nh           *p_nh = NULL;
    char                p_buf[HAL_RT_MAX_BUFSZ];

    if (!p_arp_info) {
        HAL_RT_LOG_ERR("HAL-RT-ARP", "%s (): Invalid input param. p_arp_info: %p\r\n",
                    __FUNCTION__, p_arp_info);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    memset (&fib_arp_msg_info, 0, sizeof (t_fib_arp_msg_info));
    fib_form_arp_msg_info (af_index, p_arp_info, &fib_arp_msg_info, false);

    HAL_RT_LOG_INFO("HAL-RT-ARP(ARP-START)", "ARP Del vrf_id: %d, ip_addr: %s, "
                    "if_index: %d, mac_addr: %s, out_if_index: %d", fib_arp_msg_info.vrf_id,
                    FIB_IP_ADDR_TO_STR (&fib_arp_msg_info.ip_addr),
                    fib_arp_msg_info.if_index,
                    hal_rt_mac_to_str (&fib_arp_msg_info.mac_addr, p_buf, HAL_RT_MAX_BUFSZ),
                    fib_arp_msg_info.out_if_index);

    if (!(FIB_IS_VRF_ID_VALID (fib_arp_msg_info.vrf_id))) {
        HAL_RT_LOG_ERR("HAL-RT-ARP", "%s (): Invalid vrf_id. vrf_id: %d\r\n",
                    __FUNCTION__, fib_arp_msg_info.vrf_id);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    nas_l3_lock();

    p_nh = fib_get_nh (fib_arp_msg_info.vrf_id,
                       &fib_arp_msg_info.ip_addr, fib_arp_msg_info.if_index);
    if (p_nh == NULL) {
        /* During ARP scalbility, we could get the ARP add with failed state
         * (if ARP retrans exceeded the limit to get the ARP response and
         * also hard max limit of failed entries crossed - gc_thresh3), this is being ignored
         * as it's not required since we have connected route to lift all the data traffic,
         * so, ARP del for those ARP entries can simply be ignored here without marking them as an error */
        HAL_RT_LOG_DEBUG("HAL-RT-ARP", "%s (): NH not found. "
                         "vrf_id: %d, ip_addr: %s, if_index: %d\r\n", __FUNCTION__,
                         fib_arp_msg_info.vrf_id, FIB_IP_ADDR_TO_STR (&fib_arp_msg_info.ip_addr),
                         fib_arp_msg_info.if_index);

        nas_l3_unlock();
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    if (p_nh->p_arp_info == NULL) {
        HAL_RT_LOG_ERR("HAL-RT-ARP", "%s (): NH's arp info NULL. "
                   "vrf_id: %d, ip_addr: %s, if_index: %d\r\n", __FUNCTION__,
                   fib_arp_msg_info.vrf_id, FIB_IP_ADDR_TO_STR (&fib_arp_msg_info.ip_addr),
                   fib_arp_msg_info.if_index);

        nas_l3_unlock();
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    fib_proc_nh_delete (p_nh, FIB_NH_OWNER_TYPE_ARP, 0);

    nas_l3_unlock();

    return STD_ERR_OK;
}

t_std_error fib_form_arp_msg_info (uint8_t af_index, void *p_arp_info,
                                   t_fib_arp_msg_info *p_fib_arp_msg_info, bool is_clear_msg)
{
    t_fib_neighbour_entry *p_arp_info_msg = NULL;
    t_fib_neighbour_entry *p_ndpm_info = NULL;
    char                  p_buf[HAL_RT_MAX_BUFSZ];

    if ((!p_arp_info) || (!p_fib_arp_msg_info)) {
        HAL_RT_LOG_ERR("HAL-RT-ARP", "%s (): Invalid input param. p_arp_info: %p, "
                    "p_fib_arp_msg_info: %p\r\n", __FUNCTION__, p_arp_info, p_fib_arp_msg_info);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-ARP", "af_index: %d, is_clear_msg: %d\r\n",
                  af_index, is_clear_msg);

    memset (p_fib_arp_msg_info, 0, sizeof (t_fib_arp_msg_info));

    if (STD_IP_IS_AFINDEX_V4 (af_index))
    {
        if (is_clear_msg == false)
        {
            p_arp_info_msg = (t_fib_neighbour_entry *)p_arp_info;
            p_fib_arp_msg_info->vrf_id = p_arp_info_msg->vrfid;
            memcpy(&p_fib_arp_msg_info->ip_addr,&p_arp_info_msg->nbr_addr,
                    sizeof(p_fib_arp_msg_info->ip_addr));
            p_fib_arp_msg_info->ip_addr.af_index = HAL_RT_V4_AFINDEX;

            p_fib_arp_msg_info->if_index    = p_arp_info_msg->if_index;
            p_fib_arp_msg_info->out_if_index = p_arp_info_msg->if_index;
            memcpy (&p_fib_arp_msg_info->mac_addr, &p_arp_info_msg->nbr_hwaddr, HAL_RT_MAC_ADDR_LEN);
            p_fib_arp_msg_info->status = p_arp_info_msg->status;
        }
    }
    else if (FIB_IS_AFINDEX_V6 (af_index))
    {
        if (is_clear_msg == false)
        {
            p_ndpm_info = (t_fib_neighbour_entry *)p_arp_info;
            p_fib_arp_msg_info->vrf_id = FIB_DEFAULT_VRF;

            memcpy(&p_fib_arp_msg_info->ip_addr,
                    &p_ndpm_info->nbr_addr,sizeof(p_fib_arp_msg_info->ip_addr));
            p_fib_arp_msg_info->ip_addr.af_index = HAL_RT_V6_AFINDEX;

            p_fib_arp_msg_info->if_index    = p_ndpm_info->if_index;
            p_fib_arp_msg_info->out_if_index = p_ndpm_info->if_index;
            memcpy (&p_fib_arp_msg_info->mac_addr, &p_ndpm_info->nbr_hwaddr, HAL_RT_MAC_ADDR_LEN);
            p_fib_arp_msg_info->status = p_ndpm_info->status;
        }
    }

    HAL_RT_LOG_DEBUG("HAL-RT-ARP", "vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "mac_addr: %s, out_if_index: 0x%x status:0x%x\r\n", p_fib_arp_msg_info->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_fib_arp_msg_info->ip_addr),
               p_fib_arp_msg_info->if_index,
               hal_rt_mac_to_str (&p_fib_arp_msg_info->mac_addr, p_buf, HAL_RT_MAX_BUFSZ),
               p_fib_arp_msg_info->out_if_index, p_fib_arp_msg_info->status);
    return STD_ERR_OK;
}

t_fib_cmp_result fib_arp_info_cmp (t_fib_nh *p_fh, t_fib_arp_msg_info *p_fib_arp_msg_info, uint32_t state)
{
    uint16_t  new_vlan_id = 0;
    char      p_buf[HAL_RT_MAX_BUFSZ];

    if ((!p_fh) || (!p_fib_arp_msg_info)) {
        HAL_RT_LOG_DEBUG("HAL-RT-ARP", "Invalid input param. p_fh: %p, "
                      "p_fib_arp_msg_info: %p\r\n", p_fh, p_fib_arp_msg_info);
        return FIB_CMP_RESULT_NOT_EQUAL;
    }

    if (p_fh->p_arp_info == NULL) {
        HAL_RT_LOG_DEBUG("HAL-RT-ARP", "Arp info NULL. vrf_id: %d, ip_addr: %s, "
                      "if_index: 0x%x\r\n", p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                      p_fh->key.if_index);
        return FIB_CMP_RESULT_NOT_EQUAL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-ARP", "vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "mac_addr: %s, out_if_index: 0x%x, state: %d\r\n",
               p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fib_arp_msg_info->ip_addr),
               p_fib_arp_msg_info->if_index,
               hal_rt_mac_to_str (&p_fib_arp_msg_info->mac_addr, p_buf, HAL_RT_MAX_BUFSZ),
               p_fib_arp_msg_info->out_if_index, state);

    new_vlan_id = 0;    //unused

    if ((p_fh->p_arp_info->vlan_id == new_vlan_id) &&
        ((memcmp (&p_fh->p_arp_info->mac_addr, &p_fib_arp_msg_info->mac_addr, HAL_RT_MAC_ADDR_LEN))==0)&&
        (p_fh->p_arp_info->state == state) &&
        (p_fh->p_arp_info->if_index == p_fib_arp_msg_info->out_if_index)) {
        return FIB_CMP_RESULT_EQUAL;
    }

    return FIB_CMP_RESULT_NOT_EQUAL;
}

t_std_error nas_route_get_all_arp_info(cps_api_object_list_t list, uint32_t vrf_id, uint32_t af,
                                       hal_ip_addr_t *p_nh_addr, bool is_specific_nh_get){

    t_fib_nh *p_nh = NULL;

    if (af >= FIB_MAX_AFINDEX)
    {
        HAL_RT_LOG_ERR("HAL-RT-ARP","Invalid Address family");
        return STD_ERR(ROUTE,FAIL,0);
    }

    if (is_specific_nh_get) {
        /* As we dont expect the user to provide the nh if-index, do the partial nh key get next
         * if NH is NULL, return, if there is a NH address mismatch on the get next entry, return */
        p_nh = fib_get_next_nh(vrf_id, p_nh_addr, 0);
        if ((p_nh == NULL) || (memcmp(&p_nh->key.ip_addr, p_nh_addr, sizeof(t_fib_ip_addr)))) {
            return STD_ERR_OK;
        }
    } else {
        p_nh = fib_get_first_nh (vrf_id, af);
    }
    while (p_nh != NULL){
        /* Notify the ARP information for the incomplete, reachable and stale neighbors */
        if ((FIB_IS_NH_OWNER_ARP (p_nh)) && (p_nh->p_arp_info != NULL) &&
            ((p_nh->p_arp_info->arp_status != RT_NUD_PROBE) &&
             (p_nh->p_arp_info->arp_status != RT_NUD_DELAY))) {
            cps_api_object_t obj = nas_route_nh_to_arp_cps_object(p_nh, cps_api_oper_CREATE);
            if(obj != NULL){
                if (!cps_api_object_list_append(list,obj)) {
                    cps_api_object_delete(obj);
                    HAL_RT_LOG_ERR("HAL-RT-ARP","Failed to append object to object list");
                    return STD_ERR(ROUTE,FAIL,0);
                }
            }
        }
        if (is_specific_nh_get)
            break;

        p_nh = fib_get_next_nh (vrf_id, &p_nh->key.ip_addr, p_nh->key.if_index);
    }
    return STD_ERR_OK;
}

bool hal_rt_cps_obj_to_intf(cps_api_object_t obj, t_fib_intf_entry *p_intf) {
    bool is_admin_up = false;
    bool is_op_del = false;

    HAL_RT_LOG_DEBUG("HAL-RT","Interface admin status change notification");

    /* Get the IfIndex and admin status attributes */
    cps_api_object_attr_t ifix_attr = cps_api_object_attr_get(obj,DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX);
    if (ifix_attr == NULL) {
        HAL_RT_LOG_ERR("HAL-RT","If-Index is not present");
        return false;
    }
    hal_ifindex_t index = cps_api_object_attr_data_u32(ifix_attr);
    cps_api_object_attr_t if_master_attr = cps_api_object_attr_get(obj,BASE_IF_LINUX_IF_INTERFACES_INTERFACE_IF_MASTER);
    if (if_master_attr) {
        hal_ifindex_t if_master_index = cps_api_object_attr_data_u32(if_master_attr);
        HAL_RT_LOG_DEBUG("HAL-RT","Intf:%d Master intf:%d, L3 can be configured on master interfaces, not on member ports, ignored!",
                         index, if_master_index);
        return false;
    }

    /* If the interface VLAN/LAG deleted, flush all the neighbors and routes associated with it */
    if (cps_api_object_type_operation(cps_api_object_key(obj)) != cps_api_oper_DELETE) {
        cps_api_object_attr_t admin_attr = cps_api_object_attr_get(obj,IF_INTERFACES_INTERFACE_ENABLED);

        if(admin_attr == NULL){
            HAL_RT_LOG_INFO("HAL-RT","admin status is not present for intf:%d",index);
            return false;
        }

        is_admin_up = cps_api_object_attr_data_u32(admin_attr);
        HAL_RT_LOG_DEBUG("HAL-RT","Intf:%d status:%s",
                         index, (is_admin_up ? "Up" : "Down"));
    } else {
        is_op_del = true;
    }
    p_intf->if_index = index;
    p_intf->is_admin_up = is_admin_up;
    p_intf->is_op_del = is_op_del;
    return true;
}

bool hal_rt_process_intf_state_msg(t_fib_intf_entry *p_intf) {

    HAL_RT_LOG_INFO("HAL-RT","Interface status change notification %d admin:%d",
                   p_intf->if_index, p_intf->is_admin_up);

    if (p_intf->is_op_del != true) {
        interface_ctrl_t intf_ctrl;
        memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
        intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
        intf_ctrl.if_index = p_intf->if_index;

        if ((dn_hal_get_interface_info(&intf_ctrl)) == STD_ERR_OK) {
            if(intf_ctrl.int_type == nas_int_type_LPBK) {
                /* Ignore the loopback interface status change notifications
                 * 1. If we do the admin down and up on front panel ports, kernel notifies the connected route information,
                 * whereas on loopback interface, kernel does not notify the route configuration again, so, ignoring
                 * the route flush on interface admin down for loopback interface */
                HAL_RT_LOG_DEBUG("HAL-RT","Intf:%d admin status handling ignored for loopback intf!", index);
                return false;
            }
        }
    }
    nas_l3_lock();
    /* Handle interface admin status changes for IPv4 and IPv6 routes */
    fib_handle_intf_admin_status_change(p_intf->if_index, 0, HAL_RT_V4_AFINDEX,
                                        p_intf->is_admin_up);
    /* Now, the kernel behaviour is to notify all the route deletes
     * on interface down for IPv6, but we delete the IPv6 routes below
     * to have the consistent behavior across IPv4 and IPv6 address family */
    fib_handle_intf_admin_status_change(p_intf->if_index, 0, HAL_RT_V6_AFINDEX,
                                        p_intf->is_admin_up);
    nas_l3_unlock();
    return true;
}

