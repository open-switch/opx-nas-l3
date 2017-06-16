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
#include "dell-base-neighbor.h"
#include "dell-interface.h"

#include "event_log.h"
#include "std_ip_utils.h"
#include "std_mac_utils.h"

#include <string.h>

bool hal_rt_validate_cps_obj_neigh_family(cps_api_object_t obj) {
    cps_api_object_attr_t list[cps_api_if_NEIGH_A_MAX];
    cps_api_object_attr_fill_list(obj,0,list,sizeof(list)/sizeof(*list));

    if (list[cps_api_if_NEIGH_A_FAMILY]!=NULL) {
        unsigned short  family = cps_api_object_attr_data_u32(list[cps_api_if_NEIGH_A_FAMILY]);
        /* Skip the non IPv4 and IPv6 family neighbors here */
        if ((family != HAL_RT_V4_AFINDEX) && (family != HAL_RT_V6_AFINDEX))
            return false;
    }

    return true;
}

void hal_rt_cps_obj_to_neigh(cps_api_object_t obj,t_fib_neighbour_entry *p_nbr_msg) {
    cps_api_object_it_t it;
    cps_api_attr_id_t id = 0;

    if (obj == NULL)
        return;

    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));
    switch (op) {
        case cps_api_oper_CREATE:
        case cps_api_oper_SET:
            p_nbr_msg->msg_type = NBR_ADD;
            break;
        case cps_api_oper_DELETE:
            p_nbr_msg->msg_type = NBR_DEL;
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
            case BASE_ROUTE_OBJ_NBR_AF:
                p_nbr_msg->family = cps_api_object_attr_data_uint(it.attr);
                p_nbr_msg->nbr_addr.af_index = p_nbr_msg->family;
                break;
            case BASE_ROUTE_OBJ_NBR_IFINDEX:
                p_nbr_msg->if_index = cps_api_object_attr_data_uint(it.attr);
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
    uint32_t           sub_cmd = 0;
    uint8_t            af_index = 0;
    bool               nbr_change = false;
    char               p_buf[HAL_RT_MAX_BUFSZ];

    if(!p_arp_info_msg) {
        HAL_RT_LOG_ERR("HAL-RT-ARP", "%s (): NULL nbr entry\n", __FUNCTION__);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_INFO("HAL-RT-ARP_OStoNAS", "cmd:%s(%d) vrf_id:%d, family:%d state:0x%x ip_addr:%s, "
                  "mac_addr:%s, out_if_index:%d mbr:%d expire:%d status:0x%x",
                  ((p_arp_info_msg->msg_type == NBR_ADD) ? "Nbr-Add" : ((p_arp_info_msg->msg_type == NBR_DEL) ?
                                                                       "Nbr-Del" : "Unknown")),
                  p_arp_info_msg->msg_type, p_arp_info_msg->vrfid,
                  p_arp_info_msg->family, p_arp_info_msg->status,
                  FIB_IP_ADDR_TO_STR (&p_arp_info_msg->nbr_addr),
                  hal_rt_mac_to_str (&p_arp_info_msg->nbr_hwaddr, p_buf, HAL_RT_MAX_BUFSZ),
                  p_arp_info_msg->if_index,
                  p_arp_info_msg->mbr_if_index, p_arp_info_msg->expire, p_arp_info_msg->status);


    if(hal_rt_validate_intf(p_arp_info_msg->if_index) != STD_ERR_OK) {
        return STD_ERR_OK;
    }

    sub_cmd  = p_arp_info_msg->msg_type;
    vrf_id   = p_arp_info_msg->vrfid;
    af_index = HAL_RT_ADDR_FAM_TO_AFINDEX(p_arp_info_msg->family);

    if (!(FIB_IS_VRF_ID_VALID (vrf_id))) {
        HAL_RT_LOG_ERR("HAL-RT-ARP", "%s (): Invalid vrf_id. vrf_id: %d",
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
            else if (p_arp_info_msg->status == RT_NUD_NOARP)
                FIB_INCR_CNTRS_NBR_ADD_NOARP (vrf_id, af_index);

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
            HAL_RT_LOG_DEBUG("HAL-RT-ARP", "Unknown sub_cmd: %d", sub_cmd);
            FIB_INCR_CNTRS_UNKNOWN_MSG (vrf_id, af_index);
            break;
    }

    if(nbr_change)
        fib_resume_nh_walker_thread(af_index);

    return STD_ERR_OK;
}

t_std_error fib_proc_arp_add (uint8_t af_index, void *p_arp_info)
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

    nas_l3_lock();

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
                    nas_l3_unlock();
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
                    nas_l3_unlock();
                    return STD_ERR_OK;
                }
                /* NPU is already programmed with ARP/Nbr, return */
                if (npu_prg_done) {
                    nas_l3_unlock();
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

            nas_l3_unlock();
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
                    "vrf_id: %d, ip_addr: %s, if_index: 0x%x", __FUNCTION__,
                    fib_arp_msg_info.vrf_id, FIB_IP_ADDR_TO_STR (&fib_arp_msg_info.ip_addr),
                    fib_arp_msg_info.if_index);

        nas_l3_unlock();
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    if (p_nh->p_arp_info == NULL) {
        HAL_RT_LOG_ERR("HAL-RT-ARP", "%s (): NH's arp info NULL. "
                "vrf_id: %d, ip_addr: %s, if_index: 0x%x", __FUNCTION__,
                fib_arp_msg_info.vrf_id, FIB_IP_ADDR_TO_STR (&fib_arp_msg_info.ip_addr),
                fib_arp_msg_info.if_index);

        nas_l3_unlock();
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

    nas_l3_unlock();
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
                         "vrf_id: %d, ip_addr: %s, if_index: %d", __FUNCTION__,
                         fib_arp_msg_info.vrf_id, FIB_IP_ADDR_TO_STR (&fib_arp_msg_info.ip_addr),
                         fib_arp_msg_info.if_index);

        nas_l3_unlock();
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    if (p_nh->p_arp_info == NULL) {
        HAL_RT_LOG_ERR("HAL-RT-ARP", "%s (): NH's arp info NULL. "
                   "vrf_id: %d, ip_addr: %s, if_index: %d", __FUNCTION__,
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
            p_fib_arp_msg_info->vrf_id = FIB_DEFAULT_VRF;

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

t_std_error nas_route_get_all_arp_info(cps_api_object_list_t list, uint32_t vrf_id, uint32_t af,
                                       hal_ip_addr_t *p_nh_addr, bool is_specific_nh_get,
                                       bool is_proactive_nh_get) {

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
        HAL_RT_LOG_INFO("HAL-RT-INTF","Intf:%d admin_status:%d is_op_del:%d type:%d",
                        index, admin_status, is_op_del, type);
        /* Allow only the L2 (bridge) and L3 ports for L3 operations */
        if ((type != BASE_CMN_INTERFACE_TYPE_L2_PORT) && (type != BASE_CMN_INTERFACE_TYPE_L3_PORT) &&
            (type != BASE_CMN_INTERFACE_TYPE_LAG)) {
            return false;
        }
        cps_api_object_attr_t intf_member_port =
            cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_MEMBER_PORTS_NAME);
        /* Incase of LAG member delete, ignore it, allow only LAG intf admin down/up and delete */
        if (is_op_del && intf_member_port && (type == BASE_CMN_INTERFACE_TYPE_LAG)) {
            return false;
        }
    }

    p_intf->if_index = index;
    p_intf->admin_status = admin_status;
    p_intf->is_op_del = is_op_del;

    char p_buf[HAL_RT_MAX_BUFSZ];
    HAL_RT_LOG_INFO("HAL-RT-INTF", "Intf:%d admin_status:%d is_del:%d mac:%s",
                    index, admin_status, is_op_del,
                    hal_rt_mac_to_str (&(p_intf->mac_addr), p_buf, HAL_RT_MAX_BUFSZ));
    return true;
}

bool hal_rt_process_intf_state_msg(t_fib_msg_type type, t_fib_intf_entry *p_intf) {

    HAL_RT_LOG_INFO("HAL-RT","Interface status change notification type:%d "
                    "intf:%d admin:%d is_del:%d",
                   type, p_intf->if_index, p_intf->admin_status, p_intf->is_op_del);

    if (type == FIB_MSG_TYPE_NBR_MGR_INTF) {
        /* If the interface down is from neighbor manager, delete the Nbrs (owner - ARP) */
        if ((p_intf->admin_status == RT_INTF_ADMIN_STATUS_DOWN) || (p_intf->is_op_del)) {
            nas_l3_lock();
            fib_nbr_del_on_intf_down(p_intf->if_index, 0, HAL_RT_V4_AFINDEX);
            fib_resume_nh_walker_thread(HAL_RT_V4_AFINDEX);
            fib_nbr_del_on_intf_down(p_intf->if_index, 0, HAL_RT_V6_AFINDEX);
            fib_resume_nh_walker_thread(HAL_RT_V6_AFINDEX);
            nas_l3_unlock();
        }
        return true;
    }

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
    fib_handle_intf_admin_status_change(0, HAL_RT_V4_AFINDEX, p_intf);
    /* Now, the kernel behaviour is to notify all the route deletes
     * on interface down for IPv6, but we delete the IPv6 routes below
     * to have the consistent behavior across IPv4 and IPv6 address family */
    fib_handle_intf_admin_status_change(0, HAL_RT_V6_AFINDEX, p_intf);
    nas_l3_unlock();
    return true;
}

