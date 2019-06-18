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
#include "dell-base-neighbor.h"
#include "dell-interface.h"
#include "vrf-mgmt.h"
#include "os-routing-events.h"

#include "event_log.h"
#include "std_ip_utils.h"
#include "std_mac_utils.h"
#include "std_utils.h"

#include <string.h>

void hal_rt_cps_obj_to_neigh(cps_api_object_t obj,t_fib_neighbour_entry *p_nbr_msg) {
    cps_api_object_it_t it;
    cps_api_attr_id_t id = 0;

    if (obj == NULL)
        return;

    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));
    switch (op) {
        case cps_api_oper_CREATE:
        case cps_api_oper_SET:
            p_nbr_msg->msg_type = FIB_RT_MSG_ADD;
            break;
        case cps_api_oper_DELETE:
            p_nbr_msg->msg_type = FIB_RT_MSG_DEL;
            break;
        default:
            break;
    }

    cps_api_object_it_begin(obj,&it);

    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {
        id = cps_api_object_attr_id(it.attr);

        switch (id) {
            case BASE_ROUTE_OBJ_NBR_ADDRESS:
                memcpy(&p_nbr_msg->nbr_addr.u, cps_api_object_attr_data_bin(it.attr),
                       cps_api_object_attr_len (it.attr));
                break;
            case BASE_ROUTE_OBJ_NBR_MAC_ADDR:
                {
                    void *addr = NULL;
                    addr = cps_api_object_attr_data_bin(it.attr);
                    std_string_to_mac(&p_nbr_msg->nbr_hwaddr, (const char *)addr,
                                      sizeof(p_nbr_msg->nbr_hwaddr));
                }
                break;

            case BASE_ROUTE_OBJ_NBR_VRF_ID:
                p_nbr_msg->vrfid = cps_api_object_attr_data_uint(it.attr);
                break;
            case BASE_ROUTE_OBJ_VRF_NAME:
                safestrncpy((char*)p_nbr_msg->vrf_name, (const char *)cps_api_object_attr_data_bin(it.attr),
                            sizeof(p_nbr_msg->vrf_name));
                break;
            case BASE_ROUTE_OBJ_NBR_AF:
                p_nbr_msg->family = cps_api_object_attr_data_uint(it.attr);
                p_nbr_msg->nbr_addr.af_index = p_nbr_msg->family;
                break;
            case BASE_ROUTE_OBJ_NBR_IFINDEX:
                p_nbr_msg->if_index = cps_api_object_attr_data_uint(it.attr);
                break;
            case OS_RE_BASE_ROUTE_OBJ_NBR_LOWER_LAYER_IF:
                p_nbr_msg->parent_if = cps_api_object_attr_data_uint(it.attr);
                break;
            case BASE_ROUTE_OBJ_NBR_IFNAME:
                //ip_ifname = (char*) cps_api_object_attr_data_bin(it.attr);
                break;
            case BASE_NEIGHBOR_BASE_ROUTE_OBJ_NBR_PHY_IFINDEX:
                p_nbr_msg->mbr_if_index = cps_api_object_attr_data_uint(it.attr);
                break;
            case BASE_ROUTE_OBJ_NBR_FLAGS:
                p_nbr_msg->flags = cps_api_object_attr_data_uint(it.attr);
                break;
            case BASE_ROUTE_OBJ_NBR_STATE:
                p_nbr_msg->status = cps_api_object_attr_data_uint(it.attr);
                break;
            default:
                break;
        }
    }
}

t_std_error fib_proc_nbr_download (t_fib_neighbour_entry *p_arp_info_msg)
{
    uint32_t           vrf_id = 0;
    uint32_t           sub_cmd = 0, parent_if = 0;
    uint8_t            af_index = 0;
    bool               nbr_change = false;
    char               p_buf[HAL_RT_MAX_BUFSZ];

    if(!p_arp_info_msg) {
        HAL_RT_LOG_ERR("HAL-RT-ARP", "%s (): NULL nbr entry\n", __FUNCTION__);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_INFO("HAL-RT-ARP_OStoNAS", "cmd:%s(%d) vrf:%s(%lu), family:%d state:0x%lx ip_addr:%s, "
                    "mac_addr:%s, out_if_index:%d mbr:%d expire:%lu status:0x%lx parent-if:%d",
                    ((p_arp_info_msg->msg_type == FIB_RT_MSG_ADD) ? "Nbr-Add" :
                     ((p_arp_info_msg->msg_type == FIB_RT_MSG_DEL) ?
                      "Nbr-Del" : "Unknown")),
                    p_arp_info_msg->msg_type, p_arp_info_msg->vrf_name, p_arp_info_msg->vrfid,
                    p_arp_info_msg->family, p_arp_info_msg->status,
                    FIB_IP_ADDR_TO_STR (&p_arp_info_msg->nbr_addr),
                  hal_rt_mac_to_str (&p_arp_info_msg->nbr_hwaddr, p_buf, HAL_RT_MAX_BUFSZ),
                  p_arp_info_msg->if_index,
                  p_arp_info_msg->mbr_if_index, p_arp_info_msg->expire, p_arp_info_msg->status, p_arp_info_msg->parent_if);

    vrf_id = p_arp_info_msg->vrfid;
    if (!(FIB_IS_VRF_ID_VALID (vrf_id))) {
        HAL_RT_LOG_ERR("HAL-RT-ARP", "%s (): Invalid vrf_id. vrf_id: %d",
                       __FUNCTION__, vrf_id);
        return STD_ERR_OK;
    }

    if (hal_rt_is_vrf_valid(vrf_id) == false) {
        return STD_ERR_OK;
    }
    sub_cmd  = p_arp_info_msg->msg_type;
    bool is_mgmt_intf = false;

    t_fib_dr *p_best_dr = fib_get_best_fit_dr(vrf_id, &p_arp_info_msg->nbr_addr);
    while (p_best_dr && (!(STD_IP_IS_ADDR_ZERO(&p_best_dr->key.prefix)))) {
        t_fib_nh_holder nh_holder;
        t_fib_nh *p_nh = NULL;
        if (((p_nh = FIB_GET_FIRST_NH_FROM_DR(p_best_dr, nh_holder)) != NULL) &&
            (FIB_IS_NH_ZERO(p_nh))) {
            if (p_best_dr->vrf_id != p_nh->vrf_id) {
                /* If the nbr dependent route is reachable via different VRF, ignore the nbr update,
                 * since we program the nbr based on parent VRF nbr updates. */
                return STD_ERR_OK;
            }
        }
        break;
    }
    /* If this Nbr is learnt on MAC-VLAN intf which does not have any parent intf,
     * trigger the ARP resolution on the parent interface after getting the subnet from route based on this neighbor. */
    if ((sub_cmd == FIB_RT_MSG_ADD) && (p_arp_info_msg->parent_if == p_arp_info_msg->if_index) &&
        (hal_rt_is_intf_mac_vlan(p_arp_info_msg->vrfid, p_arp_info_msg->if_index))) {

        /* Avoid the LLA neighbor handling since the host is expected to use global unicast address. */
        if (STD_IP_IS_ADDR_LINK_LOCAL(&p_arp_info_msg->nbr_addr)) {
            return STD_ERR_OK;
        }
        HAL_RT_LOG_INFO("HAL-RT-ARP_OStoNAS", "Anycast Nbr cmd:%s(%d) vrf:%s(%lu), family:%d state:0x%lx ip_addr:%s, "
                        "mac_addr:%s, out_if_index:%d mbr:%d expire:%lu status:0x%lx",
                        ((p_arp_info_msg->msg_type == FIB_RT_MSG_ADD) ? "Nbr-Add" :
                         ((p_arp_info_msg->msg_type == FIB_RT_MSG_DEL) ?
                          "Nbr-Del" : "Unknown")),
                        p_arp_info_msg->msg_type, p_arp_info_msg->vrf_name, p_arp_info_msg->vrfid,
                        p_arp_info_msg->family, p_arp_info_msg->status,
                        FIB_IP_ADDR_TO_STR (&p_arp_info_msg->nbr_addr),
                        hal_rt_mac_to_str (&p_arp_info_msg->nbr_hwaddr, p_buf, HAL_RT_MAX_BUFSZ),
                        p_arp_info_msg->if_index,
                        p_arp_info_msg->mbr_if_index, p_arp_info_msg->expire, p_arp_info_msg->status);

        bool is_route_found = false;
        t_fib_dr *p_best_dr = fib_get_best_fit_dr(vrf_id, &p_arp_info_msg->nbr_addr);
        while (p_best_dr && (!(STD_IP_IS_ADDR_ZERO(&p_best_dr->key.prefix)))) {
            t_fib_nh_holder nh_holder;
            t_fib_nh *p_nh = NULL;
            if ((p_best_dr->rt_type != RT_CACHE) && ((p_nh = FIB_GET_FIRST_NH_FROM_DR(p_best_dr, nh_holder)) != NULL) &&
                (FIB_IS_NH_ZERO(p_nh)) && (p_nh->key.if_index)) {

                parent_if = p_nh->key.if_index;
                p_nh = fib_get_nh (p_arp_info_msg->vrfid, &p_arp_info_msg->nbr_addr,
                                   p_nh->key.if_index);
                /* 3 cases are handled below, when the nbr is learnt on the anycast interface,
                 * we should trigger the resolution on the parent intf as well.
                 * 1. The nbr does not exist on the parent intf, resolve the nbr on the parent intf.
                 * 2. The nbr exists on the parent intf but in unresolved state, resolve the nbr.
                 * 3. The nbr exists but with different MAC, resolve the nbr to correct the MAC. */
                is_route_found = true;
                p_arp_info_msg->parent_if = parent_if;
                nas_route_nbr_entry_to_nbr_cps_object(p_arp_info_msg, cps_api_oper_CREATE,
                                                      NAS_RT_NBR_FLAGS_UPDATE_PARENT_IF);
                if ((p_nh == NULL) ||
                    ((p_nh->p_arp_info) &&
                     ((p_nh->p_arp_info->state == FIB_ARP_UNRESOLVED) ||
                      ((p_nh->p_arp_info->state == FIB_ARP_RESOLVED) &&
                       (memcmp(&p_nh->p_arp_info->mac_addr, &p_arp_info_msg->nbr_hwaddr,
                               sizeof(hal_mac_addr_t))))))) {
                    /* Trigger the proactive resolution to learn
                     * the neigbor on the parent interface. */
                    p_arp_info_msg->if_index = parent_if;
                    nas_route_nbr_entry_to_nbr_cps_object(p_arp_info_msg, cps_api_oper_CREATE,
                                                          NAS_RT_NBR_FLAGS_TRIGGER_RESOLVE);
                }
                break;
            }
            p_best_dr = fib_get_next_best_fit_dr(vrf_id, &p_best_dr->key.prefix, p_best_dr->prefix_len);
        }
        if (is_route_found == false) {
            p_arp_info_msg->parent_if = 0;
            nas_route_nbr_entry_to_nbr_cps_object(p_arp_info_msg, cps_api_oper_CREATE,
                                                  NAS_RT_NBR_FLAGS_UPDATE_PARENT_IF);
        }
        /* Since this is not valid a valid neighbor, no further handling is required. */
        return STD_ERR_OK;
    }
    if(hal_rt_validate_intf(p_arp_info_msg->vrfid, p_arp_info_msg->if_index, &is_mgmt_intf) != STD_ERR_OK) {
        return STD_ERR_OK;
    }

    af_index = HAL_RT_ADDR_FAM_TO_AFINDEX(p_arp_info_msg->family);

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
    if ((sub_cmd == FIB_RT_MSG_ADD) && (p_arp_info_msg->status == RT_NUD_FAILED)) {
        sub_cmd = FIB_RT_MSG_DEL;
        FIB_INCR_CNTRS_NBR_ADD_FAILED (vrf_id, af_index);
    }

    switch (sub_cmd) {
        case FIB_RT_MSG_ADD:
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
            else if (p_arp_info_msg->status == RT_NUD_NOARP)
                FIB_INCR_CNTRS_NBR_ADD_NOARP (vrf_id, af_index);

            if (fib_proc_arp_add (af_index, p_arp_info_msg, is_mgmt_intf) == STD_ERR_OK){
                nbr_change = true;
            }
            break;

        case FIB_RT_MSG_DEL:
            FIB_INCR_CNTRS_NBR_DEL (vrf_id, af_index);
            if (fib_proc_arp_del (af_index, p_arp_info_msg) == STD_ERR_OK){
                nbr_change = true;
            }
            break;

        default:
            HAL_RT_LOG_DEBUG("HAL-RT-ARP", "Unknown sub_cmd: %d", sub_cmd);
            FIB_INCR_CNTRS_UNKNOWN_MSG (vrf_id, af_index);
            break;
    }

    if(nbr_change)
        fib_resume_nh_walker_thread(af_index);

    return STD_ERR_OK;
}

t_std_error fib_proc_arp_add (uint8_t af_index, void *p_arp_info, bool is_mgmt_intf)
{
    t_fib_arp_msg_info   fib_arp_msg_info;
    t_fib_nh          *p_nh = NULL;
    char               p_buf[HAL_RT_MAX_BUFSZ];

    if (!p_arp_info) {
        HAL_RT_LOG_ERR("HAL-RT-ARP", "%s (): Invalid input param. p_arp_info: %p",
                    __FUNCTION__, p_arp_info);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    memset (&fib_arp_msg_info, 0, sizeof (t_fib_arp_msg_info));

    fib_form_arp_msg_info (af_index, p_arp_info, &fib_arp_msg_info, false);

    /* Check if there is an exact matching connected route for this neighbor,
     * if yes, ignore the programming of neighbor. */
    if (hal_rt_is_local_ip_conflict (fib_arp_msg_info.vrf_id, &fib_arp_msg_info.ip_addr)) {
        return STD_ERR_OK;
    }
    p_nh = fib_get_nh (fib_arp_msg_info.vrf_id, &fib_arp_msg_info.ip_addr,
                       fib_arp_msg_info.if_index);
    if(p_nh != NULL) {
        if((p_nh->p_arp_info) && (p_nh->p_arp_info->if_index == fib_arp_msg_info.if_index) &&
           (!memcmp((uint8_t *)&p_nh->p_arp_info->mac_addr,
                    (uint8_t *)&fib_arp_msg_info.mac_addr,
                    HAL_RT_MAC_ADDR_LEN))) {

            /* Incase the port changed in the ARP dependent MAC during ARP refresh,
             * program the MAC in the NPU for L3 traffic as there is no Guarantee that
             * the NPU will always learn the MAC while FIFO is full due to lot of L2 MACs learning */
            if (fib_arp_msg_info.status == RT_NUD_NOARP) {
                /* If there is no change in the MAC info. and Nbr is already programmed in the NPU,
                 * ignore the msg here */
                bool npu_prg_done = nas_rt_is_nh_npu_prg_done(p_nh);
                if ((p_nh->p_arp_info->mbr_if_index == fib_arp_msg_info.out_if_index) &&
                    npu_prg_done) {
                    return STD_ERR_OK;
                }
                p_nh->p_arp_info->mbr_if_index = fib_arp_msg_info.out_if_index;

                if (nas_route_fdb_add_cps_msg(p_nh)) {
                    HAL_RT_LOG_INFO("HAL-RT-ARP", "Neighbor MAC prg success - vrf_id: %d, ip_addr: %s, "
                                    "if_index: %d, mac_addr: %s, out_if_index:%d status:%d NPU status:%d", fib_arp_msg_info.vrf_id,
                                    FIB_IP_ADDR_TO_STR (&fib_arp_msg_info.ip_addr),
                                    fib_arp_msg_info.if_index,
                                    hal_rt_mac_to_str (&fib_arp_msg_info.mac_addr, p_buf, HAL_RT_MAX_BUFSZ),
                                    fib_arp_msg_info.out_if_index, fib_arp_msg_info.status, p_nh->a_is_written [0]);
                } else {
                    HAL_RT_LOG_ERR("HAL-RT-ARP", "Neighbor MAC prg failed - vrf_id: %d, ip_addr: %s, "
                                   "if_index: %d, mac_addr: %s, out_if_index:%d status:%d NPU status:%d", fib_arp_msg_info.vrf_id,
                                   FIB_IP_ADDR_TO_STR (&fib_arp_msg_info.ip_addr),
                                   fib_arp_msg_info.if_index,
                                   hal_rt_mac_to_str (&fib_arp_msg_info.mac_addr, p_buf, HAL_RT_MAX_BUFSZ),
                                   fib_arp_msg_info.out_if_index, fib_arp_msg_info.status, p_nh->a_is_written [0]);
                    return STD_ERR_OK;
                }
                /* NPU is already programmed with ARP/Nbr, return */
                if (npu_prg_done) {
                    return STD_ERR_OK;
                }

                /* NPU is not programmed, copy the existing ARP status,
                 * do the NPU programming since the dependent MAC programming is done above */
                fib_arp_msg_info.status = p_nh->p_arp_info->arp_status;
            } else {
                p_nh->p_arp_info->arp_status = fib_arp_msg_info.status;
            }
            /* Mark the timestamp on REACHABLE state, otherwise, reset the timeout to 0 */
            if (fib_arp_msg_info.status == RT_NUD_REACHABLE) {
                p_nh->reachable_state_time_stamp = nas_rt_get_clock_sec();
            } else {
                p_nh->reachable_state_time_stamp = 0;
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

            return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
        }
    }

    HAL_RT_LOG_INFO("HAL-RT-ARP(ARP-START)", "Neighbor add - vrf_id: %d, ip_addr: %s, "
            "if_index: %d, mac_addr: %s, out_if_index: %d status:%d NH:%p", fib_arp_msg_info.vrf_id,
            FIB_IP_ADDR_TO_STR (&fib_arp_msg_info.ip_addr),
            fib_arp_msg_info.if_index,
            hal_rt_mac_to_str (&fib_arp_msg_info.mac_addr, p_buf, HAL_RT_MAX_BUFSZ),
            fib_arp_msg_info.out_if_index, fib_arp_msg_info.status, p_nh);

    p_nh = fib_proc_nh_add (fib_arp_msg_info.vrf_id, &fib_arp_msg_info.ip_addr,
                            fib_arp_msg_info.if_index, FIB_NH_OWNER_TYPE_ARP, 0, is_mgmt_intf,
                            fib_arp_msg_info.vrf_id, 0);
    if (p_nh == NULL) {
        HAL_RT_LOG_ERR("HAL-RT-ARP", "%s (): NH addition failed. "
                    "vrf_id: %d, ip_addr: %s, if_index: 0x%x", __FUNCTION__,
                    fib_arp_msg_info.vrf_id, FIB_IP_ADDR_TO_STR (&fib_arp_msg_info.ip_addr),
                    fib_arp_msg_info.if_index);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    if (p_nh->p_arp_info == NULL) {
        HAL_RT_LOG_ERR("HAL-RT-ARP", "%s (): NH's arp info NULL. "
                "vrf_id: %d, ip_addr: %s, if_index: 0x%x", __FUNCTION__,
                fib_arp_msg_info.vrf_id, FIB_IP_ADDR_TO_STR (&fib_arp_msg_info.ip_addr),
                fib_arp_msg_info.if_index);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    p_nh->p_arp_info->if_index = fib_arp_msg_info.if_index;
    p_nh->p_arp_info->mbr_if_index = fib_arp_msg_info.out_if_index;
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

    return STD_ERR_OK;
}

t_std_error fib_proc_arp_del (uint8_t af_index, void *p_arp_info)
{
    t_fib_arp_msg_info  fib_arp_msg_info;
    t_fib_nh           *p_nh = NULL;
    char                p_buf[HAL_RT_MAX_BUFSZ];

    if (!p_arp_info) {
        HAL_RT_LOG_ERR("HAL-RT-ARP", "%s (): Invalid input param. p_arp_info: %p",
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
        HAL_RT_LOG_ERR("HAL-RT-ARP", "%s (): Invalid vrf_id. vrf_id: %d",
                    __FUNCTION__, fib_arp_msg_info.vrf_id);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    p_nh = fib_get_nh (fib_arp_msg_info.vrf_id,
                       &fib_arp_msg_info.ip_addr, fib_arp_msg_info.if_index);
    if (p_nh == NULL) {
        /* During ARP scalbility, we could get the ARP add with failed state
         * (if ARP retrans exceeded the limit to get the ARP response and
         * also hard max limit of failed entries crossed - gc_thresh3), this is being ignored
         * as it's not required since we have connected route to lift all the data traffic,
         * so, ARP del for those ARP entries can simply be ignored here without marking them as an error */
        HAL_RT_LOG_DEBUG("HAL-RT-ARP", "%s (): NH not found. "
                         "vrf_id: %d, ip_addr: %s, if_index: %d", __FUNCTION__,
                         fib_arp_msg_info.vrf_id, FIB_IP_ADDR_TO_STR (&fib_arp_msg_info.ip_addr),
                         fib_arp_msg_info.if_index);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    if (p_nh->p_arp_info == NULL) {
        HAL_RT_LOG_ERR("HAL-RT-ARP", "%s (): NH's arp info NULL. "
                   "vrf_id: %d, ip_addr: %s, if_index: %d", __FUNCTION__,
                   fib_arp_msg_info.vrf_id, FIB_IP_ADDR_TO_STR (&fib_arp_msg_info.ip_addr),
                   fib_arp_msg_info.if_index);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    fib_proc_nh_delete (p_nh, FIB_NH_OWNER_TYPE_ARP, 0);

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
                    "p_fib_arp_msg_info: %p", __FUNCTION__, p_arp_info, p_fib_arp_msg_info);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-ARP", "af_index: %d, is_clear_msg: %d",
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
            p_fib_arp_msg_info->out_if_index = p_arp_info_msg->mbr_if_index;
            memcpy (&p_fib_arp_msg_info->mac_addr, &p_arp_info_msg->nbr_hwaddr, HAL_RT_MAC_ADDR_LEN);
            p_fib_arp_msg_info->status = p_arp_info_msg->status;
        }
    }
    else if (FIB_IS_AFINDEX_V6 (af_index))
    {
        if (is_clear_msg == false)
        {
            p_ndpm_info = (t_fib_neighbour_entry *)p_arp_info;
            p_fib_arp_msg_info->vrf_id = p_ndpm_info->vrfid;

            memcpy(&p_fib_arp_msg_info->ip_addr,
                    &p_ndpm_info->nbr_addr,sizeof(p_fib_arp_msg_info->ip_addr));
            p_fib_arp_msg_info->ip_addr.af_index = HAL_RT_V6_AFINDEX;

            p_fib_arp_msg_info->if_index    = p_ndpm_info->if_index;
            p_fib_arp_msg_info->out_if_index = p_ndpm_info->mbr_if_index;
            memcpy (&p_fib_arp_msg_info->mac_addr, &p_ndpm_info->nbr_hwaddr, HAL_RT_MAC_ADDR_LEN);
            p_fib_arp_msg_info->status = p_ndpm_info->status;
        }
    }

    HAL_RT_LOG_DEBUG("HAL-RT-ARP", "vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "mac_addr: %s, out_if_index: 0x%x status:0x%x",
               p_fib_arp_msg_info->vrf_id, FIB_IP_ADDR_TO_STR (&p_fib_arp_msg_info->ip_addr),
               p_fib_arp_msg_info->if_index,
               hal_rt_mac_to_str (&p_fib_arp_msg_info->mac_addr, p_buf, HAL_RT_MAX_BUFSZ),
               p_fib_arp_msg_info->out_if_index,
               p_fib_arp_msg_info->status);
    return STD_ERR_OK;
}

t_fib_cmp_result fib_arp_info_cmp (t_fib_nh *p_fh, t_fib_arp_msg_info *p_fib_arp_msg_info, uint32_t state)
{
    uint16_t  new_vlan_id = 0;
    char      p_buf[HAL_RT_MAX_BUFSZ];

    if ((!p_fh) || (!p_fib_arp_msg_info)) {
        HAL_RT_LOG_DEBUG("HAL-RT-ARP", "Invalid input param. p_fh: %p, "
                      "p_fib_arp_msg_info: %p", p_fh, p_fib_arp_msg_info);
        return FIB_CMP_RESULT_NOT_EQUAL;
    }

    if (p_fh->p_arp_info == NULL) {
        HAL_RT_LOG_DEBUG("HAL-RT-ARP", "Arp info NULL. vrf_id: %d, ip_addr: %s, "
                      "if_index: 0x%x", p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                      p_fh->key.if_index);
        return FIB_CMP_RESULT_NOT_EQUAL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-ARP", "vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "mac_addr: %s, out_if_index: 0x%x, state: %d",
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

static t_std_error nas_route_get_all_vrf_arp_info(cps_api_object_list_t list, uint32_t af,
                                                  bool is_proactive_nh_get) {
    t_fib_nh *p_nh = NULL;
    uint32_t vrf_id = FIB_MIN_VRF;

    for (; vrf_id < FIB_MAX_VRF; vrf_id++) {
        if ((hal_rt_access_fib_vrf(vrf_id) == NULL) ||
            (FIB_GET_VRF_INFO (vrf_id, af) == NULL)) {
            continue;
        }
        p_nh = fib_get_first_nh (vrf_id, af);
        while (p_nh != NULL){
            cps_api_object_t obj = NULL;
            /* Publish the NHs (Route associated and/or NHT used) that need to be resolved proactively */
            if (is_proactive_nh_get && (!(STD_IP_IS_ADDR_ZERO(&p_nh->key.ip_addr))) &&
                ((p_nh->rtm_ref_count) || (p_nh->is_nht_active))) {
                obj = nas_route_nh_to_nbr_cps_object(p_nh, cps_api_oper_CREATE, false);
                /* Notify the ARP information for the incomplete, reachable and stale neighbors */
            } else if ((!is_proactive_nh_get) && (FIB_IS_NH_OWNER_ARP (p_nh))
                       && (p_nh->p_arp_info != NULL) &&
                       ((p_nh->p_arp_info->arp_status != RT_NUD_PROBE) &&
                        (p_nh->p_arp_info->arp_status != RT_NUD_DELAY))) {
                obj = nas_route_nh_to_arp_cps_object(p_nh, cps_api_oper_CREATE);
            }
            if(obj != NULL){
                if (!cps_api_object_list_append(list,obj)) {
                    cps_api_object_delete(obj);
                    HAL_RT_LOG_ERR("HAL-RT-ARP","Failed to append object to object list");
                    return STD_ERR(ROUTE,FAIL,0);
                }
            }

            p_nh = fib_get_next_nh (vrf_id, &p_nh->key.ip_addr, p_nh->key.if_index);
        }
    }
    return STD_ERR_OK;
}

t_std_error nas_route_get_all_arp_info(cps_api_object_list_t list, uint32_t vrf_id, uint32_t af,
                                       hal_ip_addr_t *p_nh_addr, bool is_specific_nh_get,
                                       bool is_proactive_nh_get, bool is_specific_vrf_get) {
    t_fib_nh *p_nh = NULL;

    if (af >= FIB_MAX_AFINDEX)
    {
        HAL_RT_LOG_ERR("HAL-RT-ARP","Invalid Address family");
        return STD_ERR(ROUTE,FAIL,0);
    }

    if (is_specific_vrf_get == false) {
        return (nas_route_get_all_vrf_arp_info(list, af, is_proactive_nh_get));
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
        cps_api_object_t obj = NULL;
        /* Publish the NHs (Route associated and/or NHT used) that need to be resolved proactively */
        if (is_proactive_nh_get && (!(STD_IP_IS_ADDR_ZERO(&p_nh->key.ip_addr))) &&
            ((p_nh->rtm_ref_count) || (p_nh->is_nht_active))) {
            obj = nas_route_nh_to_nbr_cps_object(p_nh, cps_api_oper_CREATE, false);
            /* Notify the ARP information for the incomplete, reachable and stale neighbors */
        } else if ((!is_proactive_nh_get) && (FIB_IS_NH_OWNER_ARP (p_nh))
                   && (p_nh->p_arp_info != NULL) &&
                   ((p_nh->p_arp_info->arp_status != RT_NUD_PROBE) &&
                    (p_nh->p_arp_info->arp_status != RT_NUD_DELAY))) {
            obj = nas_route_nh_to_arp_cps_object(p_nh, cps_api_oper_CREATE);
        }
        if(obj != NULL){
            if (!cps_api_object_list_append(list,obj)) {
                cps_api_object_delete(obj);
                HAL_RT_LOG_ERR("HAL-RT-ARP","Failed to append object to object list");
                return STD_ERR(ROUTE,FAIL,0);
            }
        }
        if (is_specific_nh_get)
            break;

        p_nh = fib_get_next_nh (vrf_id, &p_nh->key.ip_addr, p_nh->key.if_index);
    }
    return STD_ERR_OK;
}

bool hal_rt_cps_obj_to_intf(cps_api_object_t obj, t_fib_intf_entry *p_intf) {
    int admin_status = RT_INTF_ADMIN_STATUS_NONE;
    bool is_op_del = false;

    HAL_RT_LOG_DEBUG("HAL-RT-INTF","Interface admin status change notification");

    /* Get the IfIndex and admin status attributes */
    cps_api_object_attr_t ifix_attr = cps_api_object_attr_get(obj,DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX);
    if (ifix_attr == NULL) {
        HAL_RT_LOG_ERR("HAL-RT-INTF","If-Index is not present");
        return false;
    }
    hal_ifindex_t index = cps_api_object_attr_data_u32(ifix_attr);
    cps_api_object_attr_t _vrf_attr = cps_api_object_attr_get(obj, VRF_MGMT_NI_IF_INTERFACES_INTERFACE_VRF_ID);
    if (_vrf_attr) {
        p_intf->vrf_id = cps_api_object_attr_data_u32(_vrf_attr);
        HAL_RT_LOG_INFO ("HAL-RT-INTF", "VRF:%lu Intf:%d", p_intf->vrf_id, index);
    }
    cps_api_object_attr_t vrf_name_attr = cps_api_object_attr_get(obj,NI_IF_INTERFACES_INTERFACE_BIND_NI_NAME);
    if (vrf_name_attr) {
        char vrf_name [NAS_VRF_NAME_SZ + 1];
        memset(vrf_name, '\0', sizeof(vrf_name));
        safestrncpy(vrf_name, (const char *)cps_api_object_attr_data_bin(vrf_name_attr),
                    sizeof(vrf_name));
        /* Get the VRF-id from VRF-name if not present in the object */
        if ((_vrf_attr == NULL) && (hal_rt_get_vrf_id (vrf_name, (hal_vrf_id_t *)&(p_intf->vrf_id)) == false)) {
            HAL_RT_LOG_ERR ("HAL-RT-INTF", "VRF:%s to id mapping is not present for Intf:%d", vrf_name, index);
            return false;
        }
    }
    cps_api_object_attr_t if_name_attr = cps_api_object_attr_get(obj,IF_INTERFACES_INTERFACE_NAME);
    if (if_name_attr) {
        safestrncpy(p_intf->if_name, (const char *)cps_api_object_attr_data_bin(if_name_attr),
                    sizeof(p_intf->if_name));

        HAL_RT_LOG_INFO ("HAL-RT-INTF", "Intf:%d name:%s", index, p_intf->if_name);
    } else {
        HAL_RT_LOG_INFO("HAL-RT-INTF","If-name is not present for index:%d", index);
    }
    cps_api_object_attr_t if_master_attr = cps_api_object_attr_get(obj,BASE_IF_LINUX_IF_INTERFACES_INTERFACE_IF_MASTER);
    if (if_master_attr) {
        /* allow processing of admin status/interface delete notifications
         * for bridged interfaces; these notifications are needed to cache
         * the current admin status so that on interface mode change/admin
         * status changes route/nh information can be deleted/re-programmed
         * to hardware as required.
         */

        hal_ifindex_t if_master_index = cps_api_object_attr_data_u32(if_master_attr);

        cps_api_object_attr_t if_name_attr = cps_api_object_attr_get(obj,IF_INTERFACES_INTERFACE_NAME);
        if (if_name_attr != NULL) {
            const char *name = (const char*)cps_api_object_attr_data_bin(if_name_attr);

            HAL_RT_LOG_INFO ("HAL-RT-INTF", "Intf:%d name:%s Master intf:%d.",
                             index, name, if_master_index);
        } else {
            HAL_RT_LOG_INFO ("HAL-RT-INTF", "Intf:%d Master intf:%d.",
                             index, if_master_index);
        }
    }

    /* If the interface VLAN/LAG deleted, flush all the neighbors and routes associated with it */
    if (cps_api_object_type_operation(cps_api_object_key(obj)) != cps_api_oper_DELETE) {
        cps_api_object_attr_t mac_attr = cps_api_object_attr_get (obj, DELL_IF_IF_INTERFACES_INTERFACE_PHYS_ADDRESS);
        cps_api_object_attr_t admin_attr = cps_api_object_attr_get(obj,IF_INTERFACES_INTERFACE_ENABLED);
        if ((mac_attr == NULL) && (admin_attr == NULL))
            return false;

        if (mac_attr != NULL) {
            std_string_to_mac(&(p_intf->mac_addr),
                              cps_api_object_attr_data_bin(mac_attr),
                              cps_api_object_attr_len(mac_attr));
        }
        if(admin_attr != NULL){
            if (cps_api_object_attr_data_u32(admin_attr)) {
                admin_status = RT_INTF_ADMIN_STATUS_UP;
            } else {
                admin_status = RT_INTF_ADMIN_STATUS_DOWN;
            }
        }
    } else {
        is_op_del = true;
        admin_status = RT_INTF_ADMIN_STATUS_DOWN;
    }

    /* Removing the member port from the logical intf(VLAN/LAG) should not be
     * considered as the logical intf delete, allow only the L2/L3/LAG intfs */
    uint32_t type = 0;
    cps_api_object_attr_t intf_type =
        cps_api_object_attr_get(obj, BASE_IF_LINUX_IF_INTERFACES_INTERFACE_DELL_TYPE);
    if (intf_type) {
        type = cps_api_object_attr_data_u32(intf_type);
        cps_api_object_attr_t intf_member_port =
            cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_MEMBER_PORTS_NAME);
        HAL_RT_LOG_INFO("HAL-RT-INTF","Intf:%d admin_status:%d is_op_del:%d type:%d mbr:%s",
                        index, admin_status, is_op_del, type,
                        (intf_member_port ? ((char*)cps_api_object_attr_data_bin(intf_member_port)) : "NA"));
        /* Allow only the L2 (bridge) and L3 ports for L3 operations */
        if ((type != BASE_CMN_INTERFACE_TYPE_BRIDGE) && (type != BASE_CMN_INTERFACE_TYPE_L3_PORT) &&
            (type != BASE_CMN_INTERFACE_TYPE_LAG) && (type != BASE_CMN_INTERFACE_TYPE_MACVLAN) &&
            (type != BASE_CMN_INTERFACE_TYPE_MANAGEMENT)) {
            return false;
        }
        /* Incase of LAG member add/delete, ignore it, allow only LAG intf admin down/up and delete */
        if (intf_member_port && (type == BASE_CMN_INTERFACE_TYPE_LAG)) {
            return false;
        }
    }

    p_intf->if_index = index;
    p_intf->admin_status = admin_status;
    p_intf->is_op_del = is_op_del;

    char p_buf[HAL_RT_MAX_BUFSZ];
    HAL_RT_LOG_INFO("HAL-RT-INTF", "VRF-id:%lu Intf:%s(%d) admin_status:%d is_del:%d mac:%s",
                    p_intf->vrf_id, p_intf->if_name, index, admin_status, is_op_del,
                    hal_rt_mac_to_str (&(p_intf->mac_addr), p_buf, HAL_RT_MAX_BUFSZ));
    return true;
}

bool fib_proc_ip_unreach_config_msg(t_fib_intf_ip_unreach_config *p_ip_unreach_cfg) {
    bool os_gbl_cfg_req = false, os_gbl_cfg_enable = false, os_intf_cfg_enable = true;

    bool rc = hal_rt_handle_ip_unreachable_config(p_ip_unreach_cfg, &os_gbl_cfg_req);
    if (rc == false)
        return false;

    if (os_gbl_cfg_req) {
        /* @@TODO This needs to be enabled/disabled per VRF level globally */
        if (nas_route_os_ip_unreachable_config(p_ip_unreach_cfg->vrf_name, p_ip_unreach_cfg->af_index,
                                               NULL, p_ip_unreach_cfg->is_op_del,
                                               os_gbl_cfg_enable)
            != cps_api_ret_code_OK) {
            HAL_RT_LOG_ERR("HAL-RT-OS-UNREACH", "Failed to config global rule in OS for IP unreachable"
                           " is_del:%d if-index:%d af:%d",
                           p_ip_unreach_cfg->is_op_del, p_ip_unreach_cfg->if_index,
                           p_ip_unreach_cfg->af_index);
            return false;
        }
    }

    /* Program the IP table filter to allow the ICMP unreachable message
     * generation on this interface for a non-routable packets */
    if (nas_route_os_ip_unreachable_config(p_ip_unreach_cfg->vrf_name, p_ip_unreach_cfg->af_index,
                                           p_ip_unreach_cfg->if_name,
                                           p_ip_unreach_cfg->is_op_del,
                                           os_intf_cfg_enable) !=
        cps_api_ret_code_OK) {
        HAL_RT_LOG_ERR("HAL-RT-OS-UNREACH", "Failed to config intf rule in OS for IP unreachable"
                       " is_del:%d if-index:%d af:%d",
                       p_ip_unreach_cfg->is_op_del, p_ip_unreach_cfg->if_index,
                       p_ip_unreach_cfg->af_index);
        if (os_gbl_cfg_req && (p_ip_unreach_cfg->is_op_del == false)) {
            nas_route_os_ip_unreachable_config(p_ip_unreach_cfg->vrf_name, p_ip_unreach_cfg->af_index,
                                               NULL, true, os_gbl_cfg_enable);
        }
        return false;
    }
    return rc;
}


t_std_error fib_proc_ip_redirects_config_msg(t_fib_intf_ip_redirects_config *p_ip_redirects_cfg) {
    bool           is_intf_present = false;
    hal_vrf_id_t   vrf_id = 0;
    t_fib_intf    *p_intf = NULL;

    HAL_RT_LOG_DEBUG("HAL-RT","IP ICMP Redirects config event "
                     "vrf:%s, intf:%s(%d), is_op_del:%d",
                     p_ip_redirects_cfg->vrf_name, p_ip_redirects_cfg->if_name,
                     p_ip_redirects_cfg->if_index, p_ip_redirects_cfg->is_op_del);

    nas_l3_lock();

    if (!hal_rt_get_vrf_id (p_ip_redirects_cfg->vrf_name, &vrf_id)) {
        HAL_RT_LOG_ERR ("HAL-RT","IP ICMP Redirects config failed "
                    "Invalid VRF:%s", p_ip_redirects_cfg->vrf_name);
        nas_l3_unlock();
        return STD_ERR(ROUTE,FAIL,0);
    }

    /* For now this IP redirect config status has to be updated in
     * in interface cache both address family, as RIF create can happen
     * at first for any address family.
     */
    p_intf = fib_get_or_create_intf(p_ip_redirects_cfg->if_index, vrf_id,
                                    HAL_RT_V4_AFINDEX, &is_intf_present);

    if (!p_intf) {
        HAL_RT_LOG_ERR ("HAL-RT","IP ICMP Redirects config update failed "
                  "vrf:%s, if_name:%s(%d), af:%d, is_op_del:%d",
                  p_ip_redirects_cfg->vrf_name, p_ip_redirects_cfg->if_name,
                  p_ip_redirects_cfg->if_index, HAL_RT_V4_AFINDEX, p_ip_redirects_cfg->is_op_del);

        nas_l3_unlock();
        return STD_ERR(ROUTE,FAIL,0);
    }

    bool rif_update = false;
    bool ip_redirects_set = (p_ip_redirects_cfg->is_op_del) ? false : true;

    if (p_intf->is_ip_redirects_set != ip_redirects_set) {
        rif_update = true;
    }

    p_intf->is_ip_redirects_set = ip_redirects_set;

    p_intf = fib_get_or_create_intf(p_ip_redirects_cfg->if_index, vrf_id,
                                    HAL_RT_V6_AFINDEX, &is_intf_present);

    if (!p_intf) {
        HAL_RT_LOG_ERR ("HAL-RT","IP ICMP Redirects config update failed "
                  "vrf:%s, if_name:%s(%d), af:%d, is_op_del:%d",
                  p_ip_redirects_cfg->vrf_name, p_ip_redirects_cfg->if_name,
                  p_ip_redirects_cfg->if_index, HAL_RT_V6_AFINDEX, p_ip_redirects_cfg->is_op_del);

        nas_l3_unlock();
        return STD_ERR(ROUTE,FAIL,0);
    }

    p_intf->is_ip_redirects_set = ip_redirects_set;

    if (rif_update) {
        ndi_rif_id_t rif_id = hal_rif_id_get(0, vrf_id, p_ip_redirects_cfg->if_index);

        /*
         * Configure RIF IP Redirect
         */
        if (rif_id != 0) {
            ndi_rif_entry_t     rif_entry;
            memset (&rif_entry, 0, sizeof (ndi_rif_entry_t));

            rif_entry.npu_id = 0;
            rif_entry.rif_id = rif_id;
            rif_entry.flags = NDI_RIF_ATTR_IP_REDIRECT;
            rif_entry.ip_redirect_state = p_intf->is_ip_redirects_set;

            HAL_RT_LOG_DEBUG("HAL-RT-RIF", "RIF attribute set for IP redirect config:%d, rif-id:0x%lx, if_index:%d",
                             p_intf->is_ip_redirects_set, rif_id, p_ip_redirects_cfg->if_index);

            if (ndi_rif_set_attribute(&rif_entry) != STD_ERR_OK) {
                HAL_RT_LOG_ERR ("NAS-RT-RIF",
                                "Failed! RIF attribute set for IP redirect config:%d, rif-id:0x%lx, if_index:%d",
                                p_intf->is_ip_redirects_set, rif_id, p_ip_redirects_cfg->if_index);
            }
        } else {
            HAL_RT_LOG_DEBUG ("HAL-RT", "RIF does not exist! IP ICMP Redirect will be enabled on RIF create. "
                              "vrf:%s, if_name:%s(%d)",
                              p_ip_redirects_cfg->vrf_name, p_ip_redirects_cfg->if_name,
                              p_ip_redirects_cfg->if_index);
        }
    }

    nas_l3_unlock();
    return STD_ERR_OK;
}


bool hal_rt_process_intf_state_msg(t_fib_msg_type type, t_fib_intf_entry *p_intf) {

    HAL_RT_LOG_INFO("HAL-RT","Interface status change notification type:%d "
                    "VRF:%lu intf:%d is_admin_up:%d(val:%d) is_del:%d",
                    type, p_intf->vrf_id, p_intf->if_index,
                    (p_intf->admin_status == RT_INTF_ADMIN_STATUS_UP), p_intf->admin_status,
                    p_intf->is_op_del);

    if (!(FIB_IS_VRF_ID_VALID (p_intf->vrf_id))) {
        HAL_RT_LOG_INFO("HAL-RT","Invalid VRF - Interface status change notification type:%d "
                       "VRF:%lu intf:%d is_admin_up:%d(val:%d) is_del:%d",
                       type, p_intf->vrf_id, p_intf->if_index,
                       (p_intf->admin_status == RT_INTF_ADMIN_STATUS_UP), p_intf->admin_status,
                       p_intf->is_op_del);
        return true;
    }
    if (type == FIB_MSG_TYPE_NBR_MGR_INTF) {
        /* If the interface down is from neighbor manager, delete the Nbrs (owner - ARP) */
        if ((p_intf->admin_status == RT_INTF_ADMIN_STATUS_DOWN) || (p_intf->is_op_del)) {
            fib_nbr_del_on_intf_down(p_intf->if_index, p_intf->vrf_id, HAL_RT_V4_AFINDEX);
            fib_resume_nh_walker_thread(HAL_RT_V4_AFINDEX);
            fib_nbr_del_on_intf_down(p_intf->if_index, p_intf->vrf_id, HAL_RT_V6_AFINDEX);
            fib_resume_nh_walker_thread(HAL_RT_V6_AFINDEX);
        }
        return true;
    }

    if ((p_intf->is_op_del != true) && (hal_rt_is_intf_lpbk(p_intf->vrf_id, p_intf->if_index))) {
        /* Ignore the loopback interface status change notifications
         * 1. If we do the admin down and up on front panel ports, kernel notifies the connected route information,
         * whereas on loopback interface, kernel does not notify the route configuration again, so, ignoring
         * the route flush on interface admin down for loopback interface */
        HAL_RT_LOG_DEBUG("HAL-RT","Intf:%d admin status handling ignored for loopback intf!", p_intf->if_index);
        return false;
    }

    /* Handle interface admin status changes for IPv4 and IPv6 routes */
    fib_handle_intf_admin_status_change(p_intf->vrf_id, HAL_RT_V4_AFINDEX, p_intf);
    /* Now, the kernel behaviour is to notify all the route deletes
     * on interface down for IPv6, but we delete the IPv6 routes below
     * to have the consistent behavior across IPv4 and IPv6 address family */
    fib_handle_intf_admin_status_change(p_intf->vrf_id, HAL_RT_V6_AFINDEX, p_intf);
    return true;
}

