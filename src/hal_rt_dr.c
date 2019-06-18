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
 * \file   hal_rt_dr.c
 * \brief  Hal Routing DR functionality
 * \date   05-2014
 * \author Prince Sunny & Satish Mynam
 */

#include "dell-base-routing.h"
#include "hal_rt_main.h"
#include "hal_rt_mem.h"
#include "hal_rt_route.h"
#include "hal_rt_util.h"
#include "hal_rt_api.h"
#include "hal_rt_mem.h"
#include "nas_rt_api.h"

#include "event_log.h"
#include "std_ip_utils.h"
#include "std_utils.h"

#include "cps_api_interface_types.h"
#include "cps_api_events.h"

#include <string.h>
#include <stdio.h>
#include <pthread.h>

/* Min. threshold percent of route messages to be processed from message queue
 * before signalling DR walker thread.
 */
#define NAS_RT_DR_WALKER_SIG_MIN_THRESHOLD_PERCENT 30

pthread_mutex_t fib_dr_mutex;
pthread_cond_t  fib_dr_cond;
static bool     is_dr_pending_for_processing = 0; //initialize the predicate for signal

bool hal_rt_cps_obj_nh_list_to_route_nh_list(cps_api_object_it_t nhit, t_fib_route_entry *r) {

    size_t hop = 0;
    cps_api_object_attr_t gw_if_name = CPS_API_ATTR_NULL;
    for (cps_api_object_it_inside(&nhit); cps_api_object_it_valid(&nhit);
         cps_api_object_it_next(&nhit), ++hop) {
        cps_api_object_it_t node = nhit;
        for (cps_api_object_it_inside(&node); cps_api_object_it_valid(&node);
             cps_api_object_it_next(&node)) {

            switch(cps_api_object_attr_id(node.attr)) {
                case BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFINDEX:
                    r->nh_list[hop].nh_if_index = cps_api_object_attr_data_u32(node.attr);
                    break;
                case BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFNAME:
                    gw_if_name = node.attr;
                    break;
                case BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR:
                    memcpy(&r->nh_list[hop].nh_addr.u, cps_api_object_attr_data_bin(node.attr),
                           cps_api_object_attr_len (node.attr));
                    break;
                case BASE_ROUTE_OBJ_ENTRY_NH_LIST_WEIGHT:
                    r->nh_list[hop].nh_weight = cps_api_object_attr_data_u32(node.attr);
                    break;
                case BASE_ROUTE_OBJ_ENTRY_NH_LIST_FLAGS:
                    r->nh_list[hop].nh_flags = cps_api_object_attr_data_u32(node.attr);
                    break;
                default:
                    break;
            }
        }
        if ((r->nh_list[hop].nh_if_index == 0) && (gw_if_name != CPS_API_ATTR_NULL)) {
            interface_ctrl_t intf_ctrl;
            t_std_error rc = STD_ERR_OK;
            memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
            intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;
            safestrncpy(intf_ctrl.if_name, (const char *)cps_api_object_attr_data_bin(gw_if_name),
                        cps_api_object_attr_len(gw_if_name));

            if((rc= dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
                HAL_RT_LOG_ERR("ROUTE-UPD", "Interface %s to if_index returned error %d",
                               intf_ctrl.if_name, rc);
                /* Ignore nexthop if the associated intf is not present in the cache. */
                continue;
            }
            r->nh_list[hop].nh_if_index = intf_ctrl.if_index;
        }
    }
    return true;
}

bool hal_rt_cps_obj_to_route(cps_api_object_t obj, t_fib_msg **p_msg_ret, bool is_app_flow) {
    t_fib_msg *p_msg = NULL;
    cps_api_object_attr_t nh_count_attr = CPS_API_ATTR_NULL;
    uint32_t nh_count = 1, rt_type = 0;

    *p_msg_ret = NULL;
    nh_count_attr = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_NH_COUNT);

    if (nh_count_attr)
        nh_count = cps_api_object_attr_data_u32(nh_count_attr);

    /* allocate the memory for the route msg based on the nexthop count
     * in the received event.
     */
    uint32_t buf_size = sizeof(t_fib_msg) + (sizeof (t_fib_nh_info) * nh_count);
    p_msg = hal_rt_alloc_route_mem_msg(buf_size);

    if (!p_msg) {
        HAL_RT_LOG_ERR("HAL-RT", "Memory alloc failed for route msg");
        return false;
    }

    HAL_RT_LOG_DEBUG("HAL-RT", " allocated buffer for route message:%p"
                     " bytes:%d nh_count:%d", p_msg, buf_size, nh_count);

    *p_msg_ret = p_msg;

    memset(p_msg, 0, buf_size);
    p_msg->type = FIB_MSG_TYPE_NL_ROUTE;
    t_fib_route_entry *r = &(p_msg->route);

    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    switch (op) {
        case cps_api_oper_CREATE:
            r->msg_type = FIB_RT_MSG_ADD;
            break;
        case cps_api_oper_SET:
            r->msg_type = FIB_RT_MSG_UPD;
            break;
        case cps_api_oper_DELETE:
            r->msg_type = FIB_RT_MSG_DEL;
            break;
        default:
            break;
    }
    cps_api_object_it_t it;
    cps_api_attr_id_t id = 0;
    cps_api_object_it_begin(obj,&it);

    bool is_rt_vrf_name_present = false, is_nh_vrf_name_present = false;
    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {
        id = cps_api_object_attr_id(it.attr);

        switch (id) {
            case BASE_ROUTE_OBJ_ENTRY_PROTOCOL:
                r->protocol = cps_api_object_attr_data_uint(it.attr);
                break;
            case BASE_ROUTE_OBJ_ENTRY_AF:
                r->prefix.af_index = cps_api_object_attr_data_uint(it.attr);
                break;
            case BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX:
                memcpy(&r->prefix.u, cps_api_object_attr_data_bin(it.attr),
                       cps_api_object_attr_len (it.attr));
                break;
            case BASE_ROUTE_OBJ_VRF_ID:
                if (is_app_flow == false) {
                    r->vrfid = cps_api_object_attr_data_uint(it.attr);
                }
                break;
            case BASE_ROUTE_OBJ_VRF_NAME:
                is_rt_vrf_name_present = true;
                safestrncpy((char*)r->vrf_name, (const char *)cps_api_object_attr_data_bin(it.attr),
                            sizeof(r->vrf_name));
                break;
            case BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN:
                r->prefix_masklen = cps_api_object_attr_data_uint(it.attr);
                break;
            case BASE_ROUTE_OBJ_ENTRY_SPECIAL_NEXT_HOP:
                rt_type = cps_api_object_attr_data_uint(it.attr);
                if (is_app_flow) {
                    if (rt_type == BASE_ROUTE_SPECIAL_NEXT_HOP_BLACKHOLE) {
                        r->rt_type = RT_BLACKHOLE;
                    } else if (rt_type == BASE_ROUTE_SPECIAL_NEXT_HOP_UNREACHABLE) {
                        r->rt_type = RT_UNREACHABLE;
                    } else if (rt_type == BASE_ROUTE_SPECIAL_NEXT_HOP_PROHIBIT) {
                        r->rt_type = RT_PROHIBIT;
                    } else if (rt_type == BASE_ROUTE_SPECIAL_NEXT_HOP_RECEIVE) {
                        r->rt_type = RT_LOCAL;
                    }
                } else {
                    r->rt_type = rt_type;
                }
                break;
            case BASE_ROUTE_OBJ_ENTRY_NH_COUNT:
                r->hop_count = cps_api_object_attr_data_uint(it.attr);
                break;
            case BASE_ROUTE_OBJ_ENTRY_VRF_ID:
                if (is_app_flow == false) {
                    r->nh_vrfid = cps_api_object_attr_data_uint(it.attr);
                }
                r->is_nh_vrf_present = true;
                break;
            case BASE_ROUTE_OBJ_ENTRY_NH_VRF_NAME:
                is_nh_vrf_name_present = true;
                safestrncpy((char*)r->nh_vrf_name, (const char *)cps_api_object_attr_data_bin(it.attr),
                            sizeof(r->nh_vrf_name));
                break;
            case BASE_ROUTE_OBJ_ENTRY_NH_LIST:
                if (hal_rt_cps_obj_nh_list_to_route_nh_list(it, r) == false) {
                    hal_rt_free_route_mem_msg(*p_msg_ret);
                    *p_msg_ret = NULL;
                    return false;
                }
                break;
        }
    }

    if (is_app_flow) {
        if (is_rt_vrf_name_present) {
            if (hal_rt_get_vrf_id((const char *)r->vrf_name,
                                  (hal_vrf_id_t *)&(r->vrfid)) == false) {
                hal_rt_free_route_mem_msg(*p_msg_ret);
                *p_msg_ret = NULL;
                return false;
            }
        }
        if (is_nh_vrf_name_present) {
            if (hal_rt_get_vrf_id((const char *)r->nh_vrf_name,
                                  (hal_vrf_id_t *)&(r->nh_vrfid)) == false) {
                hal_rt_free_route_mem_msg(*p_msg_ret);
                *p_msg_ret = NULL;
                return false;
            }
            r->is_nh_vrf_present = true;
        } else if (is_rt_vrf_name_present) {
            /* If NH vrf name is not set, assume route VRF name is same as NH VRF name */
            r->nh_vrfid = r->vrfid;
        }
    }
    return true;
}

bool hal_rt_cps_obj_nh_list_to_route_nexthop_nh_list(cps_api_object_it_t nhit, t_fib_route_entry *r) {

    size_t hop = 0;
    cps_api_object_attr_t gw_if_name = CPS_API_ATTR_NULL;
    for (cps_api_object_it_inside(&nhit); cps_api_object_it_valid(&nhit);
         cps_api_object_it_next(&nhit), ++hop) {
        cps_api_object_it_t node = nhit;
        for (cps_api_object_it_inside(&node); cps_api_object_it_valid(&node);
             cps_api_object_it_next(&node)) {

            switch(cps_api_object_attr_id(node.attr)) {
                case BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_LIST_IFINDEX:
                    r->nh_list[hop].nh_if_index = cps_api_object_attr_data_u32(node.attr);
                    break;
                case BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_LIST_IFNAME:
                    gw_if_name = node.attr;
                    break;
                case BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_LIST_NH_ADDR:
                    memcpy(&r->nh_list[hop].nh_addr.u, cps_api_object_attr_data_bin(node.attr),
                           cps_api_object_attr_len (node.attr));
                    break;
                case BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_LIST_WEIGHT:
                    r->nh_list[hop].nh_weight = cps_api_object_attr_data_u32(node.attr);
                    break;
                default:
                    break;
            }
        }
        if ((r->nh_list[hop].nh_if_index == 0) && (gw_if_name != CPS_API_ATTR_NULL)) {
            interface_ctrl_t intf_ctrl;
            t_std_error rc = STD_ERR_OK;
            memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
            intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;
            safestrncpy(intf_ctrl.if_name, (const char *)cps_api_object_attr_data_bin(gw_if_name),
                        cps_api_object_attr_len(gw_if_name));

            if((rc= dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
                HAL_RT_LOG_ERR("ROUTE-UPD", "Interface %s to if_index returned error %d",
                               intf_ctrl.if_name, rc);
                continue;
            }
            r->nh_list[hop].nh_if_index = intf_ctrl.if_index;
        }
    }
    return true;
}

bool hal_rt_cps_obj_to_route_nexthop(cps_api_object_t obj, t_fib_msg **p_msg_ret) {
    t_fib_msg *p_msg = NULL;
    cps_api_object_attr_t nh_count_attr = CPS_API_ATTR_NULL;
    uint32_t nh_count = 1;

    *p_msg_ret = NULL;
    nh_count_attr = cps_api_object_attr_get(obj, BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_COUNT);

    if (nh_count_attr)
        nh_count = cps_api_object_attr_data_u32(nh_count_attr);

    /* allocate the memory for the route msg based on the nexthop count
     * in the received event.
     */
    uint32_t buf_size = sizeof(t_fib_msg) + (sizeof (t_fib_nh_info) * nh_count);
    p_msg = hal_rt_alloc_route_mem_msg(buf_size);

    if (!p_msg) {
        HAL_RT_LOG_ERR("HAL-RT", "Memory alloc failed for route msg");
        return false;
    }

    HAL_RT_LOG_DEBUG("HAL-RT", " allocated buffer for route message:%p"
                     " bytes:%d nh_count:%d", p_msg, buf_size, nh_count);

    *p_msg_ret = p_msg;

    memset(p_msg, 0, buf_size);
    p_msg->type = FIB_MSG_TYPE_NL_ROUTE;
    t_fib_route_entry *r = &(p_msg->route);

    cps_api_object_attr_t op_attr  = cps_api_object_attr_get(obj, BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_OPERATION);
    if (op_attr == NULL) {
        hal_rt_free_route_mem_msg(*p_msg_ret);
        *p_msg_ret = NULL;
        return false;
    }
    uint32_t op = cps_api_object_attr_data_u32(op_attr);
    switch (op) {
        case BASE_ROUTE_RT_OPERATION_TYPE_APPEND:
            r->msg_type = FIB_RT_MSG_ADD;
            break;
        case BASE_ROUTE_RT_OPERATION_TYPE_DELETE:
            r->msg_type = FIB_RT_MSG_DEL;
            break;
        default:
            break;
    }
    cps_api_object_it_t it;
    cps_api_attr_id_t id = 0;
    cps_api_object_it_begin(obj,&it);

    bool is_rt_vrf_name_present = false, is_nh_vrf_name_present = false;
    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {
        id = cps_api_object_attr_id(it.attr);

        switch (id) {
            case BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_AF:
                r->prefix.af_index = cps_api_object_attr_data_uint(it.attr);
                break;
            case BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_ROUTE_PREFIX:
                memcpy(&r->prefix.u, cps_api_object_attr_data_bin(it.attr),
                       cps_api_object_attr_len (it.attr));
                break;
            case BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_VRF_NAME:
                is_rt_vrf_name_present = true;
                safestrncpy((char*)r->vrf_name, (const char *)cps_api_object_attr_data_bin(it.attr),
                            sizeof(r->vrf_name));
                break;
            case BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_PREFIX_LEN:
                r->prefix_masklen = cps_api_object_attr_data_uint(it.attr);
                break;
            case BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_COUNT:
                r->hop_count = cps_api_object_attr_data_uint(it.attr);
                break;
            case BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_VRF_NAME:
                is_nh_vrf_name_present = true;
                safestrncpy((char*)r->nh_vrf_name, (const char *)cps_api_object_attr_data_bin(it.attr),
                            sizeof(r->nh_vrf_name));
                break;
            case BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_LIST:
                if (hal_rt_cps_obj_nh_list_to_route_nexthop_nh_list(it, r) == false) {
                    hal_rt_free_route_mem_msg(*p_msg_ret);
                    *p_msg_ret = NULL;
                    return false;
                }
                break;
        }
    }

    if (is_rt_vrf_name_present) {
        if (hal_rt_get_vrf_id((const char *)r->vrf_name,
                              (hal_vrf_id_t *)&(r->vrfid)) == false) {
            hal_rt_free_route_mem_msg(*p_msg_ret);
            *p_msg_ret = NULL;
            return false;
        }
    }
    if (is_nh_vrf_name_present) {
        if (hal_rt_get_vrf_id((const char *)r->nh_vrf_name,
                              (hal_vrf_id_t *)&(r->nh_vrfid)) == false) {
            hal_rt_free_route_mem_msg(*p_msg_ret);
            *p_msg_ret = NULL;
            return false;
        }
        r->is_nh_vrf_present = true;
    } else if (is_rt_vrf_name_present) {
        /* If NH vrf name is not set, assume route VRF name is same as NH VRF name */
        r->nh_vrfid = r->vrfid;
    }

    return true;
}


int fib_create_dr_tree (t_fib_vrf_info *p_vrf_info)
{
    char tree_name_str [FIB_RDX_MAX_NAME_LEN];

    if (!p_vrf_info)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR", "%s (): Invalid input param. p_vrf_info: %p",
                   __FUNCTION__, p_vrf_info);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR", "Vrf_id: %d, af_index: %s",
                p_vrf_info->vrf_id,
               STD_IP_AFINDEX_TO_STR (p_vrf_info->af_index));

    if (p_vrf_info->dr_tree != NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR", "DR tree already created. "
                   "vrf_id: %d, af_index: %d",
                    p_vrf_info->vrf_id, p_vrf_info->af_index);

        return STD_ERR_OK;
    }

    memset (tree_name_str, 0, FIB_RDX_MAX_NAME_LEN);

    snprintf (tree_name_str, FIB_RDX_MAX_NAME_LEN, "Fib%s_dr_tree_vrf%d",
             STD_IP_AFINDEX_TO_STR (p_vrf_info->af_index), p_vrf_info->vrf_id);

    p_vrf_info->dr_tree = std_radix_create (tree_name_str, FIB_RDX_DR_KEY_LEN,
                                       NULL, NULL, 0);

    if (p_vrf_info->dr_tree == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): std_radix_create failed. Vrf_id: %d, "
                   "af_index: %s", __FUNCTION__, p_vrf_info->vrf_id,
                   STD_IP_AFINDEX_TO_STR (p_vrf_info->af_index));

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    std_radix_enable_radical (p_vrf_info->dr_tree);

    return STD_ERR_OK;
}

int fib_destroy_dr_tree (t_fib_vrf_info *p_vrf_info)
{
    if (!p_vrf_info)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_vrf_info: %p",
                   __FUNCTION__, p_vrf_info);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    if (p_vrf_info->dr_tree == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): DR tree not present. "
                   "vrf_id: %d, af_index: %d",
                   __FUNCTION__, p_vrf_info->vrf_id, p_vrf_info->af_index);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    std_radix_destroy (p_vrf_info->dr_tree);

    p_vrf_info->dr_tree = NULL;

    return STD_ERR_OK;
}

int fib_proc_dr_download (t_fib_route_entry *p_rt_entry, uint32_t nas_num_route_msgs_in_queue)
{
    int           ix,nh_info_size = 0;
    uint32_t      vrf_id = 0;
    uint8_t       af_index = 0;
    bool          rt_change = false, is_rt_replace = false, is_mgmt_intf = false;
    hal_ifindex_t nh_if_index = 0;
    static uint32_t num_route_msgs_processed_before_signalling_dr_walker = 0;
    static bool     pending_dr_walker_thread_wakeup = false;

    num_route_msgs_processed_before_signalling_dr_walker++;

    vrf_id   = p_rt_entry->vrfid;
    if ((!(FIB_IS_VRF_ID_VALID (vrf_id))) || (!(FIB_IS_VRF_ID_VALID (p_rt_entry->nh_vrfid)))) {
        HAL_RT_LOG_INFO("HAL-RT-DR", "Invalid vrf_id. rt-vrf_id: %d nh-vrf-id:%lu",
                       vrf_id, p_rt_entry->nh_vrfid);
        return STD_ERR_OK;
    }

    /* If VRF related info. already cleared, return success */
    if ((hal_rt_is_vrf_valid(vrf_id) == false) || (hal_rt_is_vrf_valid(p_rt_entry->nh_vrfid) == false)) {
        return STD_ERR_OK;
    }
    af_index = HAL_RT_ADDR_FAM_TO_AFINDEX(p_rt_entry->prefix.af_index);

    /* if there are no more route msgs in queue and there is pending
     * walker wakeup, then resume dr walker. This trigger is to handle
     * cases where there were lots of invalid msgs after the min threshold
     * was reached, but then didn't had a chance to wake up the walker
     * due to invalid msgs.
     */
    if (pending_dr_walker_thread_wakeup && !nas_num_route_msgs_in_queue)
        fib_resume_dr_walker_thread (af_index);

    HAL_RT_LOG_INFO("HAL-RT-MSG", "Route %s rt-vrf:%s(%d), af-index:%d"
                    " prefix:%s/%d nh-vrf:%s(%lu) nh_cnt:%lu distance:%d type:%d",
                    ((p_rt_entry->msg_type == FIB_RT_MSG_ADD) ? "Add" :
                     ((p_rt_entry->msg_type == FIB_RT_MSG_DEL) ? "Del" : "Update")),
                    p_rt_entry->vrf_name, vrf_id, af_index, FIB_IP_ADDR_TO_STR(&p_rt_entry->prefix),
                    p_rt_entry->prefix_masklen, p_rt_entry->nh_vrf_name,
                    p_rt_entry->nh_vrfid, p_rt_entry->hop_count,
                    p_rt_entry->distance, p_rt_entry->rt_type);
    /*
     * Check for ECMP NHs and check for nh_if_index appropriately
     * either single NH case or multiple NH  case got from nh_list
     * (currently the cps_linux_api sends single NH and nhlist[] separately)
     */

    /* @@TODO better solution should be explored -
     * There is an issue where Nas-interface deletes the interface first then receives
     * the route del from the kernel.
     * * Since link local is assigned as soon as the interface becomes oper. up,
     * there are vadalition failures for both link-local route add and del
     * because Nas-interface deletes the interface before route cleanup */
    if ((p_rt_entry->msg_type != FIB_RT_MSG_DEL) &&
        !(FIB_IS_RESERVED_RT_TYPE(p_rt_entry->rt_type))  &&
        (!(STD_IP_IS_ADDR_LINK_LOCAL(&p_rt_entry->prefix)))) {
        for (ix=0; ix<p_rt_entry->hop_count; ix++) {
            nh_if_index = p_rt_entry->nh_list[ix].nh_if_index;
            if (nh_if_index == 0) {
                continue;
            }
            if(hal_rt_validate_intf(p_rt_entry->nh_vrfid, nh_if_index, &is_mgmt_intf) != STD_ERR_OK) {
                HAL_RT_LOG_INFO("HAL-RT", "Invalid interface, so skipping route add. msg_type: %d rt-vrf_id %d, af-index %d"
                                " nh-vrf-id:%lu nh_count %lu addr:%s on if_index %d",
                                p_rt_entry->msg_type, vrf_id, af_index, p_rt_entry->nh_vrfid, p_rt_entry->hop_count,
                                FIB_IP_ADDR_TO_STR(&p_rt_entry->prefix), nh_if_index);
                return STD_ERR_OK;
            }
        }
    } else if (STD_IP_IS_ADDR_LINK_LOCAL(&p_rt_entry->prefix)) {
        for (ix=0; ix<p_rt_entry->hop_count; ix++) {
            nh_if_index = p_rt_entry->nh_list[ix].nh_if_index;
            if (nh_if_index == 0) {
                continue;
            }
            if ((hal_rt_is_intf_lpbk(p_rt_entry->nh_vrfid, nh_if_index)) ||
                (hal_rt_is_intf_mgmt(p_rt_entry->nh_vrfid, nh_if_index))) {
                HAL_RT_LOG_INFO("HAL-RT", "skipping link local route with loopback/mgmt intf msg_type: %d"
                                "rt-vrf_id %d, af-index %d"
                                " nh-vrf-id:%lu nh_count %lu addr:%s on if_index %d",
                                p_rt_entry->msg_type, vrf_id, af_index, p_rt_entry->nh_vrfid, p_rt_entry->hop_count,
                                FIB_IP_ADDR_TO_STR(&p_rt_entry->prefix), nh_if_index);
                return STD_ERR_OK;
            }
        }
    }
    HAL_RT_LOG_DEBUG("HAL-RT", "type: %d vrf_id %d, af-index %d"
                     " route count %d, nh_count %lu distance %d", p_rt_entry->msg_type,
                     vrf_id, af_index, 1, p_rt_entry->hop_count, p_rt_entry->distance);

    p_rt_entry->prefix.af_index = af_index;
    if (hal_rt_is_reserved_ipv4(&p_rt_entry->prefix)) {
        HAL_RT_LOG_DEBUG("HAL-RT-DR", "Skipping rsvd ipv4 addr %s on if_indx %d",
                     FIB_IP_ADDR_TO_STR(&p_rt_entry->prefix), nh_if_index);
        return STD_ERR_OK;
    }

    if (hal_rt_is_reserved_ipv6(&p_rt_entry->prefix)) {
        HAL_RT_LOG_DEBUG("HAL-RT-DR", "Skipping rsvd ipv6 addr %s on if_indx %d",
                     FIB_IP_ADDR_TO_STR(&p_rt_entry->prefix), nh_if_index);
        return STD_ERR_OK;
    }

    switch (p_rt_entry->msg_type) {
        case FIB_RT_MSG_UPD:
            is_rt_replace = true;
        case FIB_RT_MSG_ADD:
            FIB_INCR_CNTRS_ROUTE_ADD (vrf_id, af_index);
            fib_proc_dr_add_msg (af_index, p_rt_entry, &nh_info_size, is_rt_replace, is_mgmt_intf);
            rt_change = true;
            break;

        case FIB_RT_MSG_DEL:
            FIB_INCR_CNTRS_ROUTE_DEL (vrf_id, af_index);
            fib_proc_dr_del_msg (af_index, p_rt_entry);
            rt_change = true;
            break;
        default:
            HAL_RT_LOG_ERR("HAL-RT-DR", "%s (): Invalid case. ", __FUNCTION__);
            break;
    }

    if(rt_change) {
        /* Wake-up DR walker only after processing min. threshold percentage of
         * route messages from the queue.
         */
        if (((nas_num_route_msgs_in_queue * NAS_RT_DR_WALKER_SIG_MIN_THRESHOLD_PERCENT/100)
              < num_route_msgs_processed_before_signalling_dr_walker)) {
            fib_resume_dr_walker_thread (af_index);
            num_route_msgs_processed_before_signalling_dr_walker = 0;
            pending_dr_walker_thread_wakeup = false;
        } else {
            pending_dr_walker_thread_wakeup = true;
        }
    }

    return STD_ERR_OK;
}

t_std_error fib_add_intf_ip (t_fib_intf *p_intf, t_fib_ip_addr *p_ip_conf)
{
    if ((!p_intf) || (!p_ip_conf))
    {
        HAL_RT_LOG_ERR("HAL-RT-IP", "Invalid input param. p_intf: %p, p_ip_conf: %p",
                       p_intf, p_ip_conf);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_INFO("HAL-RT-IP-ADD",
               "Intf: if_index: %d, vrf_id: %d, af_index: %d, "
               "ip_addr: %s",
               p_intf->key.if_index, p_intf->key.vrf_id, p_intf->key.af_index,
               FIB_IP_ADDR_TO_STR (p_ip_conf));

    t_fib_link_node  *p_link_node = (t_fib_link_node *) FIB_LINK_NODE_MEM_MALLOC ();
    if (p_link_node == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-IP", "Memory alloc failed for IP link node");
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    t_fib_ip_addr *p_ip = (t_fib_ip_addr *) FIB_IP_MEM_MALLOC ();
    if (p_ip == NULL)
    {
        FIB_LINK_NODE_MEM_FREE(p_link_node);
        HAL_RT_LOG_ERR("HAL-RT-NH", "Memory alloc failed for IP");
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    memcpy(p_ip, p_ip_conf, sizeof(t_fib_ip_addr));

    memset (p_link_node, 0, sizeof (t_fib_link_node));

    p_link_node->self = p_ip;

    std_dll_insertatback (&p_intf->ip_list, &p_link_node->glue);

    return STD_ERR_OK;
}

int fib_del_intf_ip (t_fib_intf *p_intf, t_fib_link_node *p_link_node)
{
    if ((!p_intf) ||
        (!p_link_node))
    {
        HAL_RT_LOG_ERR("HAL-RT-IP", "Invalid input param. p_intf: %p, p_link_node: %p",
                       p_intf, p_link_node);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_INFO("HAL-RT-IP-DEL", "Intf: if_index: %d, vrf_id: %d, af_index: %d IP:%s",
               p_intf->key.if_index, p_intf->key.vrf_id,
               p_intf->key.af_index, FIB_IP_ADDR_TO_STR((t_fib_ip_addr *)p_link_node->self));

    std_dll_remove (&p_intf->ip_list, &p_link_node->glue);

    FIB_IP_MEM_FREE (p_link_node->self);
    memset (p_link_node, 0, sizeof (t_fib_link_node));
    FIB_LINK_NODE_MEM_FREE (p_link_node);

    return STD_ERR_OK;
}

t_fib_link_node *fib_get_intf_ip (t_fib_intf *p_intf, t_fib_ip_addr *p_ip)
{
    t_fib_link_node  *p_link_node = NULL;
    t_fib_ip_addr    *p_temp_ip = NULL;
    t_fib_ip_holder  ip_holder;

    if ((!p_intf) || (!p_ip))
    {
        HAL_RT_LOG_ERR("HAL-RT-IP", "Invalid input param. p_intf: %p, p_ip: %p",
                       p_intf, p_ip);
        return NULL;
    }

    FIB_FOR_EACH_IP_FROM_INTF (p_intf, p_temp_ip, ip_holder)
    {
        HAL_RT_LOG_INFO("HAL-RT-IP-GET", "ip_addr: %s, if_index: %d",
                   FIB_IP_ADDR_TO_STR (p_temp_ip),
                   p_intf->key.if_index);
        if ((memcmp (p_ip, p_temp_ip, sizeof (t_fib_ip_addr))) == 0)
        {
            p_link_node = FIB_GET_LINK_NODE_FROM_IP_HOLDER (ip_holder);
            return p_link_node;
        }
    }

    return NULL;
}

t_std_error fib_del_all_intf_ip (t_fib_intf *p_intf)
{
    t_fib_link_node  *p_link_node = NULL;
    t_fib_ip_addr    *p_temp_ip = NULL;
    t_fib_ip_holder  ip_holder;

    if (p_intf == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-IP", "Interface is NULL");
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    FIB_FOR_EACH_IP_FROM_INTF (p_intf, p_temp_ip, ip_holder)
    {
        HAL_RT_LOG_INFO("HAL-RT-IP-GET", "ip_addr: %s, if_index: %d",
                        FIB_IP_ADDR_TO_STR (p_temp_ip),
                        p_intf->key.if_index);
        p_link_node = FIB_GET_LINK_NODE_FROM_IP_HOLDER (ip_holder);
        fib_del_intf_ip(p_intf, p_link_node);
    }

    return STD_ERR_OK;
}


int fib_proc_dr_add_msg (uint8_t af_index, void *p_rtm_fib_cmd, int *p_nh_info_size,
                         bool is_rt_replace, bool is_mgmt_route)
{
    t_fib_dr           *p_dr = NULL;
    t_fib_offload_msg   offload_msg;
    t_fib_nh           *p_fh = NULL;
    t_fib_nh_holder     nh_holder;
    t_fib_dr_msg_info   dr_msg_info;
    bool                is_route_present = false;
    bool                is_skip_route_install = false;
    bool                is_neigh_flush_required = false;
    ndi_rif_id_t        rif_id = 0;
    uint8_t             rt_cfg_prefix_len = 0;

    if (!p_rtm_fib_cmd) {
        HAL_RT_LOG_ERR("HAL-RT-DR", "%s (): Invalid input param. p_rtm_fib_cmd: %p",
                   __FUNCTION__, p_rtm_fib_cmd);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    memset (&dr_msg_info, 0, sizeof (dr_msg_info));

    fib_form_dr_msg_info (af_index, p_rtm_fib_cmd, &dr_msg_info);
    HAL_RT_LOG_DEBUG("HAL-RT-DR(RT-START)",
                     "vrf_id: %d, prefix: %s, prefix_len: %d, proto: %d",
                dr_msg_info.vrf_id,
               FIB_IP_ADDR_TO_STR (&dr_msg_info.prefix), dr_msg_info.prefix_len,
               dr_msg_info.proto);

    if (!(FIB_IS_VRF_ID_VALID (dr_msg_info.vrf_id)))
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid vrf_id. vrf_id: %d",
                   __FUNCTION__, dr_msg_info.vrf_id);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    if (!(FIB_IS_PREFIX_LEN_VALID (af_index, dr_msg_info.prefix_len)))
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid prefix length. "
                   "prefix_len: %d", __FUNCTION__,
                   dr_msg_info.prefix_len);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    rt_cfg_prefix_len = dr_msg_info.prefix_len;
    if (dr_msg_info.rt_type == RT_CACHE) {
        /* For IP address as route, always assume full prefix len (32 for ipv4 and 128 for ipv6)
         * since there would be a conflict with connected route if we dont use the full prefix len */
        dr_msg_info.prefix_len = FIB_AFINDEX_TO_PREFIX_LEN (af_index);
    }
    /* Check if there is any neighbor already present for this local IP,
     * if yes, remove it since local IP takes precedence than remote neighbor */
    if (FIB_AFINDEX_TO_PREFIX_LEN (af_index) == dr_msg_info.prefix_len) {
        HAL_RT_LOG_INFO("HAL-RT-NH-CHK", "Check Local IP:%s",  FIB_IP_ADDR_TO_STR (&dr_msg_info.prefix));
        t_fib_nh *p_nh = fib_get_next_nh(dr_msg_info.vrf_id, &dr_msg_info.prefix, 0);
        if (p_nh && (memcmp(&p_nh->key.ip_addr, &dr_msg_info.prefix, sizeof(t_fib_ip_addr)) == 0)) {
            HAL_RT_LOG_INFO("HAL-RT-NH-DEL", "NH:%s found", FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr));
            /* Mark as dead to remove this neighbor from HW not from cache,
             * nbr data cache is expected to be deleted from nbr-mgr nbr delete. */
            p_nh->status_flag |= FIB_NH_STATUS_DEAD;
            fib_proc_nh_dead (p_nh);
            p_nh->status_flag &= ~FIB_NH_STATUS_DEAD;
            cps_api_object_t obj = nas_route_nh_to_arp_cps_object(p_nh, cps_api_oper_DELETE);
            if(obj && (nas_route_publish_object(obj)!= STD_ERR_OK)){
                HAL_RT_LOG_ERR("HAL-RT-DR","Failed to publish neighbor delete");
            }
        }
        if (dr_msg_info.rt_type == RT_CACHE) {
            is_skip_route_install =  true;
        }
    }
    p_dr = fib_get_dr (dr_msg_info.vrf_id, &dr_msg_info.prefix, dr_msg_info.prefix_len);
    /* if there is a default route thru mgmt interface received from the kernel and
     * FIB route added in the NPU for generating the ICMP unreachable already,
     * override the existing FIB default route with the mgmt default route.
     *
     * If the route event being received is for mgmt route and there is a matching non-mgmt route already
     * delete the route that's programmed in the NPU first and then handle the mgmt route.
     * */
    if (p_dr && (((FIB_IS_DR_DEFAULT (p_dr)) && (FIB_IS_DEFAULT_DR_OWNER_FIB (p_dr))) ||
        ((p_dr->is_mgmt_route == false) && is_mgmt_route))) {
        p_dr->status_flag |= FIB_DR_STATUS_DEL;
        fib_proc_dr_del (p_dr);
        p_dr = NULL;
    }
    if (p_dr == NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                         "Adding DR. vrf_id: %d, prefix: %s, "
                   "prefix_len: %d",
                   dr_msg_info.vrf_id,
                   FIB_IP_ADDR_TO_STR (&dr_msg_info.prefix),
                   dr_msg_info.prefix_len);

        p_dr = fib_add_dr (dr_msg_info.vrf_id, &dr_msg_info.prefix,
                        dr_msg_info.prefix_len);

        if (p_dr == NULL)
        {
            HAL_RT_LOG_ERR("HAL-RT-DR",
                       "%s (): DR addition failed. vrf_id: %d, prefix: %s, "
                       "prefix_len: %d", __FUNCTION__,
                       dr_msg_info.vrf_id,
                       FIB_IP_ADDR_TO_STR (&dr_msg_info.prefix),
                       dr_msg_info.prefix_len);

            return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
        }

        std_dll_init (&p_dr->nh_list);
        std_dll_init (&p_dr->fh_list);
        std_dll_init (&p_dr->dep_nh_list);
        std_dll_init (&p_dr->degen_dr_fh.tunnel_fh_list);

        p_dr->vrf_id = dr_msg_info.vrf_id;
        p_dr->parent_vrf_id = dr_msg_info.vrf_id;
        FIB_INCR_CNTRS_FIB_ROUTE_ENTRIES (dr_msg_info.vrf_id, af_index);

        fib_update_route_summary (dr_msg_info.vrf_id, af_index,
                               dr_msg_info.prefix_len, true);
    } else {
        is_route_present = true;
    }
    p_dr->is_mgmt_route = is_mgmt_route;
    if ((dr_msg_info.rt_type != RT_UNREACHABLE) &&
        (STD_IP_IS_ADDR_LINK_LOCAL(&dr_msg_info.prefix))) {
        if (((t_fib_route_entry  *)p_rtm_fib_cmd)->msg_type != FIB_RT_MSG_ADD) {
            return STD_ERR_OK;
        }
        /* @@TODO If there is a duplicate link local route update from kernel,
         * this link local count will cause the stale RIF in the NPU,
         * Now, the assumption is, kernel wont notify duplicate link local route */
        p_dr->num_ipv6_link_local++;
        hal_ifindex_t if_index = ((t_fib_route_entry  *)p_rtm_fib_cmd)->nh_list[0].nh_if_index;
        HAL_RT_LOG_INFO("HAL-RT-LLA", "LLA add vrf_id: %d, prefix: %s/%d,"
                        " proto: %d out-if:%d updated link-local-cnt:%d route-present:%d RIF-ref-cnt:%d",
                        dr_msg_info.vrf_id, FIB_IP_ADDR_TO_STR (&dr_msg_info.prefix),
                        dr_msg_info.prefix_len, dr_msg_info.proto, if_index,
                        p_dr->num_ipv6_link_local, is_route_present,
                        hal_rt_rif_ref_get(dr_msg_info.vrf_id, if_index));

        t_fib_intf *p_intf = fib_get_intf (if_index, dr_msg_info.vrf_id, af_index);
        if (p_intf == NULL) {
            if ((p_intf = fib_add_intf (if_index, dr_msg_info.vrf_id,
                                        af_index)) == NULL) {
                HAL_RT_LOG_ERR ("HAL-RT-DR", "Intf addition failed. "
                                "if_index: 0x%x, vrf_id: %d, af_index: %d",
                                if_index, dr_msg_info.vrf_id, af_index);

                return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
            }

            std_dll_init (&p_intf->fh_list);
            std_dll_init (&p_intf->pending_fh_list);
            std_dll_init (&p_intf->ip_list);
            /* initialize the mode to none if interface doesn't exists already */
            p_intf->mode = BASE_IF_MODE_MODE_NONE;
        }
        /* Check if this is LLA is already present in the ip_list,
         * if not, add it to the list*/
        if (fib_get_intf_ip (p_intf, &dr_msg_info.prefix) != NULL) {
            HAL_RT_LOG_ERR("HAL-RT-LLA", "IP already exists vrf_id: %d, prefix: %s/%d,"
                           " proto: %d out-if:%d link-local-cnt:%d RIF-ref-cnt:%d route-present:%d RIF-ref-cnt:%d",
                           dr_msg_info.vrf_id, FIB_IP_ADDR_TO_STR (&dr_msg_info.prefix),
                           dr_msg_info.prefix_len, dr_msg_info.proto, if_index,
                           p_dr->num_ipv6_link_local, p_dr->num_ipv6_rif_link_local, is_route_present,
                           hal_rt_rif_ref_get(dr_msg_info.vrf_id, if_index));

            return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
        }
        if (fib_add_intf_ip(p_intf, &dr_msg_info.prefix) != STD_ERR_OK) {
            HAL_RT_LOG_ERR("HAL-RT-LLA", "IP add failed vrf_id: %d, prefix: %s/%d,"
                           " proto: %d out-if:%d link-local-cnt:%d route-present:%d RIF-ref-cnt:%d",
                           dr_msg_info.vrf_id, FIB_IP_ADDR_TO_STR (&dr_msg_info.prefix),
                           dr_msg_info.prefix_len, dr_msg_info.proto, if_index,
                           p_dr->num_ipv6_link_local, is_route_present,
                           hal_rt_rif_ref_get(dr_msg_info.vrf_id, if_index));

            return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
        }

        /* increment RIF ref count only when the mode is L3.
         * In other modes, cache the route and return w/o adding RIF.
         * RIF for this LLA will be created when the interface mode
         * changes from L2 to L3.
         */
        bool is_lla_prg_required = false;
        if (FIB_IS_INTF_MODE_L3(p_intf->mode) &&
            (p_intf->admin_status == RT_INTF_ADMIN_STATUS_UP)) {
            if (hal_rif_index_get_or_create(0, dr_msg_info.vrf_id, if_index, &rif_id) == STD_ERR_OK) {
                hal_rt_rif_ref_inc(dr_msg_info.vrf_id, if_index);
                p_dr->num_ipv6_rif_link_local++;
                /* Since the LLA programming is not done yet for this LLA,
                 * program when the mode is L3 and admin status is up for any LLA */
                if (p_dr->num_ipv6_rif_link_local == 1) {
                    is_lla_prg_required = true;
                }
            } else {
                HAL_RT_LOG_ERR("HAL-RT-LLA", " RIF get failed for Route add vrf_id: %d, prefix: %s/%d,"
                               " proto: %d out-if:%d link-local-cnt:%d route-present:%d RIF-ref-cnt:%d",
                               dr_msg_info.vrf_id, FIB_IP_ADDR_TO_STR (&dr_msg_info.prefix),
                               dr_msg_info.prefix_len, dr_msg_info.proto, if_index,
                               p_dr->num_ipv6_link_local, is_route_present,
                               hal_rt_rif_ref_get(dr_msg_info.vrf_id, if_index));
            }
        }

        if (is_route_present && (is_lla_prg_required == false)) {
            p_dr->last_update_time = fib_tick_get ();
            return STD_ERR_OK;
        }

        /* Don't process route further if the mode is not L3 or
         * admin status is not UP.
         * When mode changes to L3 and admin is UP, link local route
         * would be programmed to NDI.
         */
        if ((!FIB_IS_INTF_MODE_L3(p_intf->mode)) ||
           (p_intf->admin_status != RT_INTF_ADMIN_STATUS_UP)) {
            is_skip_route_install =  true;
        }
    }

    p_dr->vrf_id = dr_msg_info.vrf_id;
    p_dr->proto = dr_msg_info.proto;
    p_dr->rt_type = dr_msg_info.rt_type;
    p_dr->rt_cfg_prefix_len = rt_cfg_prefix_len;

    p_dr->last_update_time = fib_tick_get ();

    /*
     * @Todo - Temporary work-around to support IPv6 ECMP
     * Multiple Add requests for the same IPv6 routes are treated as ECMP
     * The following command triggered route replace is handled in the FIB_RT_MSG_UPD route type
     * "ip -6 route change", "ip -6 route replace"
     */
    /* In case of IPv4 when netlink is received with replace flag, then it is handled as FIB_RT_MSG_UPD */
    if(is_rt_replace) {
        p_fh = FIB_GET_FIRST_NH_FROM_DR(p_dr, nh_holder);
        if (!is_mgmt_route) {
            /* On route replace, trigger neighbor flush for the route prefix and interface.
             * This is done for following cases:
             * 1) Connected route replace
             * 2) Route with exit interface replaced with another exit interface or with Gw.
             * Currently kernel wouldn't flush the neighbors learnt on that route subnet
             * whenever the existing route is replaced. Hence this work around is done
             * to ensure that the traffic forwarding ceases to those neighbors when
             * the route is deleted.
             */
            if (p_fh && FIB_IS_NH_ZERO(p_fh) && (p_dr->vrf_id == p_fh->vrf_id)) {
                is_neigh_flush_required = true;
                hal_rt_form_neigh_flush_msg (&offload_msg, p_dr, false, 0);
            }
        }

        /* Ignore the connected route duplicate updates, sometimes, the parent route VRF is getting
         * overriden with duplicate NH update and this causes to clear the leaked route references,
         * If route with next-hop IP is leaked to different VRF in the future, add the similar duplicate check
         * for that case as well. */
        if ((p_dr->num_nh == 1) && p_fh && FIB_IS_NH_ZERO(p_fh) &&
            (((t_fib_route_entry  *)p_rtm_fib_cmd)->hop_count == 1)) {
            t_fib_nh_msg_info  nh_msg_info;
            fib_form_nh_msg_info (af_index, p_rtm_fib_cmd, &nh_msg_info, 0);

            t_fib_nh *p_dup_nh = fib_get_nh (nh_msg_info.vrf_id, &nh_msg_info.ip_addr, nh_msg_info.if_index);
            if ((p_dup_nh != NULL) && (fib_get_dr_nh(p_dr, p_dup_nh))) {
                HAL_RT_LOG_INFO("HAL-RT-DUP", "vrf_id: %d, prefix: %s/%d dup route update ignored ",
                                p_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len);
                return STD_ERR_OK;
            } else if ((STD_IP_IS_ADDR_ZERO(&nh_msg_info.ip_addr)) && (FIB_IS_DR_WRITTEN(p_dr))) {
                /* Route replace case, increment the RIF here for new NH since the RIF wont be incremented
                 * in the HW route update flow. */
                if (hal_rif_index_get_or_create(0, nh_msg_info.vrf_id, nh_msg_info.if_index, &rif_id) == STD_ERR_OK) {
                    hal_rt_rif_ref_inc(nh_msg_info.vrf_id, nh_msg_info.if_index);
                }
            }

            /* On route replace from a connected route to a protocol route,
             * since the NH if-index for the connected route will be lost after
             * route entry update to NH-IP without decrementing the
             * route to RIF usage reference.
             * So before deleting dr nh, update RIF reference for NH if-index.
             */
            if (FIB_IS_DR_WRITTEN(p_dr)) {
                if(!hal_rt_rif_ref_dec(p_fh->vrf_id, p_fh->key.if_index))
                    hal_rif_index_remove(0, p_fh->vrf_id, p_fh->key.if_index);
            }
        }

        fib_delete_all_dr_nh (p_dr);
    } else if ((p_dr->num_nh == 1) && (!is_mgmt_route)) {
        /* @@TODO To overcome the CPS cfg and netlink events sequencing issue,
         * we can assume that there wont be any route with NH with just interface and NH with IP,
         * when the netlink events are ignored, remove this work-around. */
        t_fib_nh *p_flush_fh = FIB_GET_FIRST_NH_FROM_DR(p_dr, nh_holder);
        if (p_flush_fh && FIB_IS_NH_ZERO(p_flush_fh)) {
            t_fib_nh_msg_info  nh_msg_info;
            fib_form_nh_msg_info (af_index, p_rtm_fib_cmd, &nh_msg_info, 0);
            if ((((t_fib_route_entry  *)p_rtm_fib_cmd)->hop_count == 1) && (STD_IP_IS_ADDR_ZERO(&nh_msg_info.ip_addr))) {
                t_fib_nh *p_nh = fib_get_nh (nh_msg_info.vrf_id, &nh_msg_info.ip_addr, nh_msg_info.if_index);
                if ((p_nh != NULL) && (fib_get_dr_nh(p_dr, p_nh))) {
                    return STD_ERR_OK;
                } else if (FIB_IS_DR_WRITTEN(p_dr)) {
                    /* Route replace case, increment the RIF here for new NH since the RIF wont be incremented
                     * in the HW route update flow. */
                    if (hal_rif_index_get_or_create(0, nh_msg_info.vrf_id, nh_msg_info.if_index, &rif_id) == STD_ERR_OK) {
                        hal_rt_rif_ref_inc(nh_msg_info.vrf_id, nh_msg_info.if_index);
                    }
                }
            }
            /* If the route is currently connected route and may be the nexthop is via different VRF and
             * and the new route update with nexthop as intf via same VRF or nexthop as IP via same VRF,
             * flush the existing NHs */
            if (FIB_IS_DR_WRITTEN(p_dr)) {
                if(!hal_rt_rif_ref_dec(p_flush_fh->vrf_id, p_flush_fh->key.if_index))
                    hal_rif_index_remove(0, p_flush_fh->vrf_id, p_flush_fh->key.if_index);
            }
            fib_delete_all_dr_nh (p_dr);
        }
    } else if ((p_dr->num_nh != 1) && (!is_mgmt_route)) {
        /* @@TODO To overcome the CPS cfg and netlink events sequencing issue,
         * we can assume that there wont be any route with NH with just interface and NH with IP,
         * when the netlink events are ignored, remove this work-around. */
        /* ECMP route is getting replaced with connected route */
        t_fib_nh_msg_info  nh_msg_info;
        fib_form_nh_msg_info (af_index, p_rtm_fib_cmd, &nh_msg_info, 0);
        if ((((t_fib_route_entry  *)p_rtm_fib_cmd)->hop_count == 1) && (STD_IP_IS_ADDR_ZERO(&nh_msg_info.ip_addr))) {
            fib_delete_all_dr_nh (p_dr);
        }
    }

    if (fib_proc_dr_nh_add (p_dr, p_rtm_fib_cmd, p_nh_info_size) != STD_ERR_OK) {
        return STD_ERR_OK;
    }

    fib_updt_best_fit_dr_of_affected_nh (p_dr);

    if (FIB_IS_DR_DEFAULT (p_dr))
    {
        p_dr->default_dr_owner = FIB_DEFAULT_DR_OWNER_RTM;
    }

    /* Set ADD flag to trigger route download to walker only if,
     * this route has to be installed in hardware.
     * In cases, like port admin down when the ip-address is
     * assigned, then this route should only be cached and
     * not downloaded to walker thread.
     */
    if (is_skip_route_install != true) {
        p_dr->status_flag |= FIB_DR_STATUS_ADD;
    }
    if (is_mgmt_route) {
        nas_route_publish_route(p_dr, (is_rt_replace ? FIB_RT_MSG_UPD : FIB_RT_MSG_ADD));
    }
    fib_mark_dr_for_resolution (p_dr);

    if (is_neigh_flush_required) {
        t_fib_offload_msg *p_offload_msg = hal_rt_alloc_offload_msg ();

        if (!p_offload_msg) {
            HAL_RT_LOG_ERR ("HAL-RT", "Memory alloc failed for offload msg");
        } else {
            memcpy (p_offload_msg, &offload_msg, sizeof (t_fib_offload_msg));
            nas_rt_process_offload_msg (p_offload_msg);
        }
    }

    return STD_ERR_OK;
}

int fib_proc_dr_del_msg (uint8_t af_index, void *p_rtm_fib_cmd)
{
    t_fib_dr           *p_dr = NULL;
    t_fib_offload_msg   offload_msg;
    t_fib_nh           *p_fh = NULL;
    t_fib_nh_holder     nh_holder;
    t_fib_dr_msg_info   dr_msg_info;
    bool                is_neigh_flush_required = false;

    if (!p_rtm_fib_cmd)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_rtm_fib_cmd: %p",
                   __FUNCTION__, p_rtm_fib_cmd);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    memset (&dr_msg_info, 0, sizeof (dr_msg_info));

    fib_form_dr_msg_info (af_index, p_rtm_fib_cmd, &dr_msg_info);

    HAL_RT_LOG_DEBUG("HAL-RT-DR(RT-START)",
               "vrf_id: %d, prefix: %s, prefix_len: %d, proto: %d",
                dr_msg_info.vrf_id,
               FIB_IP_ADDR_TO_STR (&dr_msg_info.prefix), dr_msg_info.prefix_len,
               dr_msg_info.proto);

    if (!(FIB_IS_VRF_ID_VALID (dr_msg_info.vrf_id)))
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid vrf_id. vrf_id: %d",
                   __FUNCTION__, dr_msg_info.vrf_id);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    if (!(FIB_IS_PREFIX_LEN_VALID (af_index, dr_msg_info.prefix_len)))
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid prefix length. "
                   "prefix_len: %d", __FUNCTION__,
                   dr_msg_info.prefix_len);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }
    if (dr_msg_info.rt_type == RT_CACHE) {
        /* For IP address as route, always assume full prefix len (32 for ipv4 and 128 for ipv6)
         * since there would be a conflict with connected route if we dont use the full prefix len */
        dr_msg_info.prefix_len = FIB_AFINDEX_TO_PREFIX_LEN (af_index);
    }

    p_dr = fib_get_dr (dr_msg_info.vrf_id, &dr_msg_info.prefix, dr_msg_info.prefix_len);

    if (p_dr == NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                   "DR not found. vrf_id: %d, prefix: %s, "
                   "prefix_len: %d",
                   dr_msg_info.vrf_id,
                   FIB_IP_ADDR_TO_STR (&dr_msg_info.prefix),
                   dr_msg_info.prefix_len);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }
    if ((p_dr->rt_type != RT_UNREACHABLE) &&
        (STD_IP_IS_ADDR_LINK_LOCAL(&dr_msg_info.prefix))) {
        hal_ifindex_t if_index = ((t_fib_route_entry  *)p_rtm_fib_cmd)->nh_list[0].nh_if_index;

        t_fib_intf *p_intf = fib_get_intf (if_index, dr_msg_info.vrf_id, af_index);
        if (p_intf == NULL) {
            HAL_RT_LOG_ERR("HAL-RT-LLA", "Invalid intf vrf_id: %d, prefix: %s/%d, "
                           " proto: %d out-if:%d link-local-cnt:%d RIF-ref-cnt:%d", p_dr->vrf_id,
                           FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                           dr_msg_info.proto, if_index, p_dr->num_ipv6_link_local,
                           hal_rt_rif_ref_get(p_dr->vrf_id, if_index));
            return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
        }

        t_fib_link_node *p_ip_node = fib_get_intf_ip (p_intf, &dr_msg_info.prefix);
        if (p_ip_node) {
            fib_del_intf_ip(p_intf, p_ip_node);
        } else {
            HAL_RT_LOG_INFO("HAL-RT-LLA", "Invalid IP del vrf_id: %d, prefix: %s/%d, "
                           " proto: %d out-if:%d link-local-cnt:%d RIF-ref-cnt:%d", p_dr->vrf_id,
                           FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                           dr_msg_info.proto, if_index, p_dr->num_ipv6_link_local,
                           hal_rt_rif_ref_get(p_dr->vrf_id, if_index));
            return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
        }

        if (p_dr->num_ipv6_link_local > 0)
            p_dr->num_ipv6_link_local--;

        /* RIF ref count would have been decremented when the interface mode
         * changed from L3 to L2, but num_ipv6_link_local will still be intact
         * as it is tracking the kernel notification. So validation to be done
         * accordingly.
         */
        if ((p_dr->num_ipv6_link_local > 0) &&
            (FIB_IS_INTF_MODE_L3 (p_intf->mode)) &&
            (hal_rt_rif_ref_get(p_dr->vrf_id, if_index) == -1)) {
            /* Looks like duplicate link local route delete,
             * need to analyse further if the below error is seen in the journal */
            HAL_RT_LOG_INFO("HAL-RT-DR", "Reference count already 0 while deleting "
                            "the link local address from intf:%d", if_index);
            return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
        }

        HAL_RT_LOG_INFO("HAL-RT-LLA", "Route del vrf_id: %d, prefix: %s/%d, "
                       " proto: %d out-if:%d intf-mode:%s link-local-cnt:%d RIF-ref-cnt:%d", p_dr->vrf_id,
                       FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                       dr_msg_info.proto, if_index, hal_rt_intf_mode_to_str(p_intf->mode),
                       p_dr->num_ipv6_link_local, hal_rt_rif_ref_get(p_dr->vrf_id, if_index));

        /* RIF ref count would have been decremented when the interface mode
         * changed from L3 to L2 or when interface admin changed
         * from UP to down and RIF would have been deleted.
         * So check for L3 mode/admin status and remove RIF accordingly.
         */
        if (FIB_IS_INTF_MODE_L3(p_intf->mode) &&
            (p_intf->admin_status == RT_INTF_ADMIN_STATUS_UP)) {
            if (!hal_rt_rif_ref_dec(p_dr->vrf_id, if_index))
                hal_rif_index_remove(0, p_dr->vrf_id, if_index);
            p_dr->num_ipv6_rif_link_local--;
        }

        /* If there are other interfaces using the link local route,
         * dont delete the route */
        if (p_dr->num_ipv6_link_local > 0) {
            return STD_ERR_OK;
        }
    }

    /*
     * @@TODO - Temporary work-around to support IPv6 ECMP
     * Kernel is notifying the IPv6 route del with particular NH
     * even when there are NHs present in the route. so, the below workaround is added
     * to consider this route del as route add with remaining valid NH(s).
     * Note: This behavior is different in IPv4.
     */

    HAL_RT_LOG_DEBUG("HAL-RT-DR(RT-START)",
                 "vrf_id:%d, prefix:%s, prefix_len:%d, proto:%d curr-nh-cnt:%d nh-cnt:%lu",
                 dr_msg_info.vrf_id,
                 FIB_IP_ADDR_TO_STR (&dr_msg_info.prefix), dr_msg_info.prefix_len,
                 dr_msg_info.proto, p_dr->num_nh , ((t_fib_route_entry  *)p_rtm_fib_cmd)->hop_count);

    if ((((t_fib_route_entry  *)p_rtm_fib_cmd)->hop_count >= 1) &&
        (p_dr->num_nh > 1)) {

        p_dr->vrf_id = dr_msg_info.vrf_id;
        p_dr->proto = dr_msg_info.proto;

        p_dr->last_update_time = fib_tick_get ();

        fib_proc_dr_nh_del (p_dr, p_rtm_fib_cmd);
        fib_updt_best_fit_dr_of_affected_nh (p_dr);
        if (FIB_IS_DR_DEFAULT (p_dr))
        {
            p_dr->default_dr_owner = FIB_DEFAULT_DR_OWNER_RTM;
        }

        /* After DR-NH delete, if num_nh is 0, then delete this route and resume walker */
        if (p_dr->num_nh) {
            /* set ADD flag to trigger route download to walker */
            p_dr->status_flag |= FIB_DR_STATUS_ADD;
            fib_mark_dr_for_resolution (p_dr);

            return STD_ERR_OK;
        }
    } else if ((((t_fib_route_entry  *)p_rtm_fib_cmd)->hop_count == 1) &&
               (p_dr->num_nh == 1) && (!(STD_IP_IS_ADDR_LINK_LOCAL(&dr_msg_info.prefix)))) {
        /* If the NH is not present in the DR, return from here. */
        /* During interface admin down or delete scenarios,
         * Kernel will send route delete notifications for IPv6,
         * but not for IPv4. So in such cases, for IPv6 route delete
         * there might be duplicate events one from Kernel and one from
         * RTM event published locally from CPS config flow. Due to that
         * sometimes there is a possibility that this NH would have been
         * already deleted from this Route, but both NH and Route might
         * still exists. In such cases, DR will not be present in NH
         * dep_dr_tree and thus p_nh_dep_dr might be null.
         * So ignoring this failure here.
         */
        t_fib_nh_msg_info  nh_msg_info;
        fib_form_nh_msg_info (p_dr->key.prefix.af_index, p_rtm_fib_cmd, &nh_msg_info, 0);
        t_fib_nh *p_nh = fib_get_nh (nh_msg_info.vrf_id, &nh_msg_info.ip_addr, nh_msg_info.if_index);
        if ((p_nh == NULL) || (fib_get_nh_dep_dr(p_nh, p_dr) == NULL)) {
            return STD_ERR_OK;
        }
    } else {
        if ((((t_fib_route_entry  *)p_rtm_fib_cmd)->hop_count == 0) &&
            (p_dr->num_nh == 1) && (!(STD_IP_IS_ADDR_LINK_LOCAL(&dr_msg_info.prefix)))) {
            /* During route leak scenario, if the following sequence happens,
             * the RIF ref cnt is decremented for the wrong RIF.
             * Let's say, the same IP is configured on both parent and leaked VRFs on different intfs respectively,
             * and the host is reachable only via parent VRF,
             * so, the route is leaked from parent VRF to leaked VRF and the traffic is being sent via both the VRFs.
             * if the intf on which the IP is configured is shut in the leaked VRF, the leaked route will be effective and
             * if it is "no shut", the connected route will be effective for forwarding the traffic in the HW.
             * During "no shut" operation in leaked VRF, looks like due to sequencing issues between CPS and netlink events,
             * the connected route for leaked route is received first before receiving the leaked route del and
             * then connected route add from RTM i.e while processing RTM downloaded leaked route del,
             * the RIF is decremented for the connected route because netlink route add received first),
             * now the following change has been introduced,
             * if the NH present in route del msg is not matching the current NH present in the route, ignore route del msg. */
            t_fib_nh_msg_info  nh_msg_info;
            fib_form_nh_msg_info (p_dr->key.prefix.af_index, p_rtm_fib_cmd, &nh_msg_info, 0);
            t_fib_nh *p_nh = FIB_GET_FIRST_NH_FROM_DR(p_dr, nh_holder);
            if (p_nh && (p_nh->vrf_id != nh_msg_info.vrf_id) && FIB_IS_NH_ZERO(p_nh)) {
                return STD_ERR_OK;
            }
        }
        /* during interface admin down or delete scenarios,
         * Kernel will send route delete notifications for IPv6,
         * but not for IPv4. So in such cases, for IPv6 route delete
         * there might be duplicate events one from Kernel and one from
         * RTM event published locally from CPS config flow. Due to that
         * sometimes there is a possibility that this NH would have been
         * already deleted from this Route, but both NH and Route might
         * still exists. In such cases, DR nh count will be less than
         * the incoming hop_count. Ignore processing in such cases.
         */
        if ((((t_fib_route_entry  *)p_rtm_fib_cmd)->hop_count > 1) &&
            (p_dr->num_nh == 1)) {
            HAL_RT_LOG_DEBUG ("HAL-RT-DR-DEL",
                 "vrf_id:%d, prefix:%s, prefix_len:%d, proto:%d curr-nh-cnt:%d nh-cnt:%lu",
                 dr_msg_info.vrf_id,
                 FIB_IP_ADDR_TO_STR (&dr_msg_info.prefix), dr_msg_info.prefix_len,
                 dr_msg_info.proto, p_dr->num_nh , ((t_fib_route_entry  *)p_rtm_fib_cmd)->hop_count);

            return STD_ERR_OK;
        }
    }
    // TODO This needs to revisited to handle the DR del in the DR walker
    // fib_mark_dr_for_resolution (p_dr);
    p_dr->status_flag |= FIB_DR_STATUS_DEL;

    /* On route delete, trigger neighbor flush for the route prefix and interface.
     * This is done for following cases:
     * 1) Connected route delete,
     * 2) Route with exit interface.
     * Currently kernel wouldn't flush the neighbors learnt on that route
     * subnet whenever the route is deleted. Hence this work around is done
     * to ensure that the traffic forwarding ceases to those neighbors when
     * the route is deleted.
     */
    if (!(p_dr->is_mgmt_route)) {
        p_fh = FIB_GET_FIRST_NH_FROM_DR(p_dr, nh_holder);
        if (p_fh && FIB_IS_NH_ZERO(p_fh) && (p_dr->vrf_id == p_fh->vrf_id)) {
            is_neigh_flush_required = true;
            hal_rt_form_neigh_flush_msg (&offload_msg, p_dr, true, p_fh->key.if_index);
        }
    }

    fib_proc_dr_del (p_dr);

    /* When the local IP is no longer available, check if there is any neighbor still present,
     * if yes, program it in the HW */
    if (FIB_AFINDEX_TO_PREFIX_LEN (af_index) == dr_msg_info.prefix_len) {
        HAL_RT_LOG_INFO("HAL-RT-NH-ADD", "Local IP:%s",  FIB_IP_ADDR_TO_STR (&dr_msg_info.prefix));
        t_fib_nh *p_nh = fib_get_next_nh(dr_msg_info.vrf_id, &dr_msg_info.prefix, 0);
        if (p_nh && (!FIB_IS_NH_WRITTEN (p_nh)) && (memcmp(&p_nh->key.ip_addr,
                                                           &dr_msg_info.prefix, sizeof(t_fib_ip_addr)) == 0)) {
            HAL_RT_LOG_INFO("HAL-RT-NH-ADD", "NH:%s flags:0x%x found", FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                            p_nh->status_flag);
            if (!(p_nh->status_flag & (FIB_NH_STATUS_DEL | FIB_NH_STATUS_DEAD))) {
                p_nh->status_flag |= FIB_NH_STATUS_ADD;

                fib_mark_nh_for_resolution (p_nh);
            }
        }
    }

    fib_resume_nh_walker_thread(af_index);

    if (is_neigh_flush_required) {
        t_fib_offload_msg *p_offload_msg = hal_rt_alloc_offload_msg ();

        if (!p_offload_msg) {
            HAL_RT_LOG_ERR ("HAL-RT", "Memory alloc failed for offload msg");
        } else {
            memcpy (p_offload_msg, &offload_msg, sizeof (t_fib_offload_msg));
            nas_rt_process_offload_msg (p_offload_msg);
        }
    }

    return STD_ERR_OK;
}

int fib_proc_dr_del (t_fib_dr *p_dr)
{
    dn_hal_route_err  hal_err = DN_HAL_ROUTE_E_NONE;
    uint32_t      vrf_id = 0, nh_vrf_id = 0;
    uint8_t       af_index = 0;
    t_fib_nh     *p_nh;
    t_fib_nh_key  key;
    t_fib_nh_holder nh_holder;
    t_fib_nh     *p_fh = NULL;
    bool          rif_del = false;
    hal_ifindex_t if_index = 0;


    if (!p_dr)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_dr: %p",
                   __FUNCTION__, p_dr);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_INFO("HAL-RT-DR-DEL",
               "vrf_id: %d, prefix: %s, prefix_len: %d type:%d family:%d",
               p_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
               p_dr->rt_type, p_dr->key.prefix.af_index);

    p_fh = FIB_GET_FIRST_NH_FROM_DR(p_dr, nh_holder);
    if (p_fh && FIB_IS_NH_ZERO(p_fh)) {
        if_index = p_fh->key.if_index;
        nh_vrf_id = p_fh->vrf_id;
        nas_rt_handle_dest_change(p_dr, NULL, false);
        /* In case of IP address del, delete the routes that are reachable via
         * this IP address explicitly, since there is no non ECMP ipv4 route del event from OS */
        if (((p_dr->is_mgmt_route) ||
             ((p_dr->rt_type == RT_CACHE) && (p_dr->key.prefix.af_index == HAL_INET4_FAMILY))) &&
            (!(FIB_IS_DR_DEFAULT (p_dr)))) {
            /* The below function calls this function again,
             * please make sure this fib_proc_dr_del is re-entrant always */
            fib_process_route_del_on_ip_del_event(if_index, p_dr->vrf_id,
                                                  &p_dr->key.prefix, p_dr->rt_cfg_prefix_len);
        }
        /* Dont delete the RIF count for link route del here
         * since it's already done in the fib_proc_dr_del_msg() */
        if (FIB_IS_DR_WRITTEN(p_dr) &&
            !(STD_IP_IS_ADDR_LINK_LOCAL(&p_dr->key.prefix))) {
            if(!hal_rt_rif_ref_dec(nh_vrf_id, if_index))
                rif_del = true;
        }
    }

    if (p_dr->is_mgmt_route) {
        nas_route_publish_route(p_dr, FIB_RT_MSG_DEL);
    }
    if (p_dr->status_flag & FIB_DR_STATUS_DEL)
    {
        fib_mark_dr_dep_nh_for_resolution (p_dr);

        fib_delete_all_dr_nh (p_dr);

        fib_delete_all_dr_fh (p_dr);

        fib_delete_all_dr_dep_nh (p_dr);

        fib_del_dr_degen_fh (p_dr);
    }
    if (FIB_IS_DR_WRITTEN (p_dr))
    {
        hal_err = hal_fib_route_del (p_dr->vrf_id, p_dr);

        if (hal_err == DN_HAL_ROUTE_E_NONE)
        {
            if(rif_del)
                hal_rif_index_remove(0, nh_vrf_id, if_index);

            fib_check_threshold_for_all_cams (false);

            p_dr->status_flag &= ~FIB_DR_STATUS_WRITTEN;

            FIB_DECR_CNTRS_CAM_ROUTE_ENTRIES (p_dr->vrf_id,
                                              p_dr->key.prefix.af_index);

            if (p_dr->prefix_len == FIB_AFINDEX_TO_PREFIX_LEN(p_dr->key.prefix.af_index))
            {

                memset (&key, 0, sizeof (t_fib_nh_key));
                memcpy (&key.ip_addr, &(p_dr->key.prefix), sizeof (t_fib_ip_addr));

                p_nh = (t_fib_nh *)
                    std_radix_getexact (hal_rt_access_fib_vrf_nh_tree(p_dr->vrf_id, p_dr->key.prefix.af_index),
                            (uint8_t *)&key, FIB_RDX_NH_KEY_LEN);

                if (p_nh == NULL)
                {
                    p_nh = (t_fib_nh *)
                        std_radix_getnext (hal_rt_access_fib_vrf_nh_tree(p_dr->vrf_id, p_dr->key.prefix.af_index),
                                (uint8_t *)&key, FIB_RDX_NH_KEY_LEN);

                    while ((p_nh != NULL) && (!(memcmp (&(p_nh->key.ip_addr),
                                        &(p_dr->key.prefix),sizeof(t_fib_ip_addr)))))
                    {

                        if ((!(FIB_IS_NH_WRITTEN (p_nh))) && (FIB_IS_NH_OWNER_ARP (p_nh)))
                        {
                            HAL_RT_LOG_DEBUG("HAL-RT-DR", "Host with same prefix"
                                    "is available for resolution Vrf_id: %d, prefix %s/%d",
                                    p_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len);

                            fib_mark_nh_for_resolution (p_nh);

                        }

                        key.if_index = p_nh->key.if_index;

                        p_nh = (t_fib_nh *)
                            std_radix_getnext (hal_rt_access_fib_vrf_nh_tree(p_dr->vrf_id, p_dr->key.prefix.af_index),
                                    (uint8_t *)&key, FIB_RDX_NH_KEY_LEN);

                    }
                }
            }
        }
        else
        {
            HAL_RT_LOG_DEBUG("HAL-RT-DR",
                       "Error: hal_fib_route_del. "
                       "vrf_id: %d, prefix: %s, prefix_len: %d, "
                       "hal_err: %d (%s)",  p_dr->vrf_id,
                       FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                       hal_err, HAL_RT_GET_ERR_STR (hal_err));
        }
    }

    /* check if this is from route delete config or admin down event.
     * on admin down, local routes will only be deleted from NPU and
     * will be retained in nas. For those routes FIB_DR_STATUS_DEL
     * flag will not be set.
     */
    if (!(p_dr->status_flag & FIB_DR_STATUS_DEL))
    {
        HAL_RT_LOG_INFO ("HAL-RT-DR-SKIP",
                         "DR: vrf_id: %d, prefix: %s, prefix_len: %d, rt_type: %d ",
                         p_dr->vrf_id,
                         FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                         p_dr->prefix_len, p_dr->rt_type);
        return STD_ERR_OK;
    }
    p_dr->status_flag &= ~FIB_DR_STATUS_DEL;
    FIB_DECR_CNTRS_FIB_ROUTE_ENTRIES (p_dr->vrf_id, p_dr->key.prefix.af_index);

    fib_update_route_summary (p_dr->vrf_id, p_dr->key.prefix.af_index,
                           p_dr->prefix_len, false);

    if ((FIB_IS_DR_DEFAULT (p_dr)) &&
        (FIB_IS_DEFAULT_DR_OWNER_RTM (p_dr)))
    {
        vrf_id   = p_dr->vrf_id;
        af_index = p_dr->key.prefix.af_index;

        fib_del_dr (p_dr);

        if (FIB_GET_CNTRS_CATCH_ALL_ENTRIES(vrf_id, af_index))
            fib_add_default_dr (vrf_id, af_index);
    }
    else
    {
        fib_del_dr (p_dr);
    }

    return STD_ERR_OK;
}

int fib_proc_dr_nh_add (t_fib_dr *p_dr, void *p_rtm_fib_cmd, int *p_nh_info_size)
{
    t_fib_nh          *p_nh = NULL;
    t_fib_nh_dep_dr   *p_nh_dep_dr = NULL;
    t_fib_nh_msg_info  nh_msg_info;
    t_fib_dr_nh       *p_dr_nh = NULL;
    uint8_t            af_index = 0;
    uint32_t           nh_if_index = 0;
    uint32_t           vrf_id = 0;
    size_t i, nh_count;
    bool   is_dup = false, is_new_nh = false;

    if ((!p_dr) || (!p_rtm_fib_cmd) || (!p_nh_info_size)) {
        HAL_RT_LOG_ERR("HAL-RT-DR", "%s (): Invalid input param. p_dr: %p,"
                       "p_rtm_fib_cmd: %p, p_nh_info_size: %p", __FUNCTION__,
                       p_dr, p_rtm_fib_cmd, p_nh_info_size);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    af_index = p_dr->key.prefix.af_index;
    nh_count = ((t_fib_route_entry  *)p_rtm_fib_cmd)->hop_count;
    HAL_RT_LOG_DEBUG("HAL-RT-DR", "nh_count=%lu vrf_id: %d, prefix: %s, prefix_len: %d",
                     nh_count, p_dr->vrf_id,
                     FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len);

    /* for blackhole/unreachable/prohibit/cache routes,
     * simply return w/o adding NH for zero address.
     */
    if ((p_dr->rt_type != RT_CACHE) && (FIB_IS_RESERVED_RT_TYPE(p_dr->rt_type))) {
        return STD_ERR_OK;
    }

    /*
     *  Check all the nexthops (minimum is 1 NH) and if necessary form ECMP NH list
     */
    for (i=0 ; i < nh_count; i++) {

        fib_form_nh_msg_info (af_index, p_rtm_fib_cmd, &nh_msg_info, i);

        nh_if_index = nh_msg_info.if_index;
        if (nh_if_index == 0) {
            continue;
        }

        is_dup = false;
        /* Check if this NH is already created and also associated with IPv6 route,
         * if yes, continue to next NH. if we dont do the below check, fib_proc_nh_add will increment
         * the rtm_count uncessarily for NH and then RIF wont be deleted because rtm_count will never
         * become zero after route delete */
        p_nh = fib_get_nh (nh_msg_info.vrf_id, &nh_msg_info.ip_addr, nh_msg_info.if_index);
        if ((p_nh != NULL) && (fib_get_dr_nh(p_dr, p_nh)))
            continue;

        p_nh = fib_proc_nh_add (nh_msg_info.vrf_id, &nh_msg_info.ip_addr,
                                nh_msg_info.if_index, FIB_NH_OWNER_TYPE_RTM, 0, p_dr->is_mgmt_route,
                                nh_msg_info.vrf_id, nh_msg_info.flags);

        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                         "vrf_id: %d, ip_addr: %s, nh_loop_idx %lu if_index: %d",
                         vrf_id, FIB_IP_ADDR_TO_STR (&nh_msg_info.ip_addr), i, nh_if_index);

        p_dr_nh = fib_add_dr_nh (p_dr, p_nh, 0, 0, &is_dup);

        if (is_dup)
            continue;

        if (p_dr_nh == NULL)
        {
            HAL_RT_LOG_ERR("HAL-RT-DR", "DRNH Addition failed. "
                           "DR: vrfId: %d, prefix: %s, prefixLen: %d, "
                           "NH: vrfId: %d, ipAddr: %s, nhIndex: %lu nh_cnt:%lu ifIndex: %d",
                           p_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                           p_dr->prefix_len, p_nh->vrf_id,
                           FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), i, nh_count,
                           p_nh->key.if_index);
            continue;
        }
        p_nh_dep_dr = fib_add_nh_dep_dr (p_nh, p_dr);

        if (p_nh_dep_dr == NULL)
        {
            HAL_RT_LOG_ERR("HAL-RT-DR",
                           "%s (): NHDep_dr Addition failed. "
                           "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
                           "NH: vrf_id: %d, ip_addr: %s, nhIndex %lu if_index: 0x%x",
                           __FUNCTION__, p_dr->vrf_id,
                           FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                           p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                           nh_count, p_nh->key.if_index);
            continue;
        }
        is_new_nh = true;
        /* Check whether connected route's (Leaked VRF) NH is in different VRF (Parent VRF),
         * if yes, add the leaked VRF in the parent VRF and then add the ARPs/Neighbors
         * in the parent VRF matching this route into the leaked VRF.
         *
         * When the parent route is added, make sure to add the parent nbrs into the leaked VRFs
         * */
        if ((nh_count == 1) && (FIB_IS_NH_ZERO (p_nh))) {
            if (p_dr->vrf_id != p_nh->vrf_id) {
                t_fib_leaked_rt_key parent_rt_key;
                parent_rt_key.vrf_id = p_nh->vrf_id;
                memcpy(&(parent_rt_key.prefix), &p_dr->key.prefix, sizeof(hal_ip_addr_t));
                parent_rt_key.prefix_len = p_dr->prefix_len;
                hal_rt_add_dep_leaked_vrf(&parent_rt_key, p_dr->vrf_id);
                p_dr->parent_vrf_id = p_nh->vrf_id;

                /* If parent route exists, program all the available neighbors into leaked VRF */
                t_fib_dr *p_parent_dr = fib_get_dr (p_nh->vrf_id, &p_dr->key.prefix, p_dr->prefix_len);
                if (p_parent_dr) {
                    HAL_RT_LOG_INFO("HAL-RT-LEAK", "VRF-id:%d prefix:%s/%d leaked VRF:%d prefix:%s/%d",
                                    p_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                                    p_dr->prefix_len,
                                    p_parent_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_parent_dr->key.prefix),
                                    p_parent_dr->prefix_len);
                    fib_prg_leaked_nbrs_on_leaked_route_update(p_nh->key.if_index,
                                                               p_parent_dr, p_dr->vrf_id, true);
                }
            } else {
                /* Check if any leaked routes are waiting for parent route creation */
                fib_prg_leaked_nbrs_on_parent_route_update(p_dr, true);
            }
        }
    }
    if (is_new_nh == false) {
        HAL_RT_LOG_INFO("HAL-RT-DR", "Dup NH ignored for route: vrf_id:%d, prefix:%s/%d, "
                        "nh_cnt:%lu last NH: ip_addr:%s if_index:%d",
                        p_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                        p_dr->prefix_len, nh_count,
                        (p_nh ? FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr) : " "),
                        (p_nh ? p_nh->key.if_index : 0));

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }
    return STD_ERR_OK;
}

int fib_proc_dr_nh_del (t_fib_dr *p_dr, void *p_rtm_fib_cmd)
{
    t_fib_nh          *p_nh = NULL;
    t_fib_nh_dep_dr   *p_nh_dep_dr = NULL;
    t_fib_nh_msg_info  nh_msg_info;
    t_fib_dr_nh       *p_dr_nh = NULL;
    t_fib_dr_fh       *p_dr_fh = NULL;
    uint8_t            af_index = 0;
    uint32_t           nh_if_index = 0;
    uint32_t           vrf_id = 0;
    size_t i, nh_count;
    int rc = STD_ERR_OK;

    if ((!p_dr) || (!p_rtm_fib_cmd)) {
        HAL_RT_LOG_ERR("HAL-RT-DR", "%s (): Invalid input param. p_dr: %p,"
                   "p_rtm_fib_cmd: %p", __FUNCTION__,
                   p_dr, p_rtm_fib_cmd);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    af_index = p_dr->key.prefix.af_index;
    nh_count = ((t_fib_route_entry  *)p_rtm_fib_cmd)->hop_count;
    HAL_RT_LOG_DEBUG("HAL-RT-DR", "nh_count=%lu vrf_id: %d, prefix: %s, prefix_len: %d",
                    nh_count, p_dr->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len);

    /*
     *  Check all the nexthops (minimum is 1 NH) and if necessary form ECMP NH list
     */
    for (i=0 ; i < nh_count; i++) {

        fib_form_nh_msg_info (af_index, p_rtm_fib_cmd, &nh_msg_info, i);

        nh_if_index = nh_msg_info.if_index;

        if (nh_if_index == 0) {
            continue;
        }
        p_nh = fib_get_nh (nh_msg_info.vrf_id, &nh_msg_info.ip_addr, nh_msg_info.if_index);
        if (p_nh == NULL) {
            continue;
        }
        p_nh_dep_dr = fib_get_nh_dep_dr(p_nh, p_dr);

        if (p_nh_dep_dr == NULL)
        {
            /* during interface admin down or delete scenarios,
             * Kernel will send route delete notifications for IPv6,
             * but not for IPv4. So in such cases, for IPv6 route delete
             * there might be duplicate events one from Kernel and one from
             * RTM event published locally from CPS config flow. Due to that
             * sometimes there is a possibility that this NH would have been
             * already deleted from this Route, but both NH and Route might
             * still exists. In such cases, DR will not be present in NH
             * dep_dr_tree and thus p_nh_dep_dr might be null.
             * So ignoring this failure here.
             */
            HAL_RT_LOG_DEBUG ("HAL-RT-DR",
                              "%s (): NHDep_dr get failed. "
                              "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
                              "NH: vrf_id: %d, ip_addr: %s, nhIndex %lu if_index: 0x%x",
                              __FUNCTION__, p_dr->vrf_id,
                              FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                              p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                              nh_count, p_nh->key.if_index);
            continue;
        }

        fib_del_nh_dep_dr(p_nh, p_nh_dep_dr);

        fib_proc_nh_delete (p_nh, FIB_NH_OWNER_TYPE_RTM, 0);

        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                     "vrf_id: %d, ip_addr: %s, nh_loop_idx %lu if_index: %d",
                      vrf_id, FIB_IP_ADDR_TO_STR (&nh_msg_info.ip_addr), i, nh_if_index);
        p_dr_nh = fib_get_dr_nh(p_dr, p_nh);
        if (p_dr_nh) {
            rc = fib_del_dr_nh (p_dr, p_dr_nh);
            if (rc != STD_ERR_OK)
            {
                HAL_RT_LOG_ERR("HAL-RT-DR", "DRNH deletion failed "
                               "DR: vrfId: %d, prefix: %s/%d,"
                               "NH: vrfId: %d, ipAddr: %s, nhIndex: %lu nn_cnt:%lu ifIndex: %d",
                               p_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                               p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                               i, nh_count, p_nh->key.if_index);
                continue;
            }
        }
        p_dr_fh = fib_get_dr_fh (p_dr, p_nh);
        if (p_dr_fh != NULL)
        {
            fib_del_dr_fh (p_dr, p_dr_fh);
        }

    }
    return STD_ERR_OK;
}


int fib_form_dr_msg_info (uint8_t af_index, void *p_rtm_fib_cmd,
                      t_fib_dr_msg_info *p_fib_dr_msg_info)
{
    t_fib_route_entry  *p_rtm_v4_fib_cmd = NULL;
    t_fib_route_entry  *p_rtm_v6_fib_cmd = NULL;

    if ((!p_rtm_fib_cmd) || (!p_fib_dr_msg_info)) {
        HAL_RT_LOG_ERR("HAL-RT-DR", "%s (): Invalid input param. "
                   "p_rtm_fib_cmd: %p, p_fib_dr_msg_info: %p",
                   __FUNCTION__, p_rtm_fib_cmd, p_fib_dr_msg_info);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR", "af_index: %d",  af_index);

    memset (p_fib_dr_msg_info, 0, sizeof (t_fib_dr_msg_info));

    if (STD_IP_IS_AFINDEX_V4 (af_index)) {
        p_rtm_v4_fib_cmd = (t_fib_route_entry *)p_rtm_fib_cmd;

        memcpy (&p_fib_dr_msg_info->prefix.u.v4_addr,
                &p_rtm_v4_fib_cmd->prefix.u.v4_addr,
                HAL_RT_V4_ADDR_LEN);

        p_fib_dr_msg_info->prefix.af_index = af_index;

        p_fib_dr_msg_info->prefix_len = p_rtm_v4_fib_cmd->prefix_masklen;
        p_fib_dr_msg_info->vrf_id     = p_rtm_v4_fib_cmd->vrfid;
        p_fib_dr_msg_info->proto      = p_rtm_v4_fib_cmd->protocol;
        p_fib_dr_msg_info->rt_type    = p_rtm_v4_fib_cmd->rt_type;
    } else if (FIB_IS_AFINDEX_V6 (af_index)) {
        p_rtm_v6_fib_cmd = (t_fib_route_entry *)p_rtm_fib_cmd;

        memcpy (&p_fib_dr_msg_info->prefix.u.v6_addr,
                &p_rtm_v6_fib_cmd->prefix.u.v6_addr,
                HAL_RT_V6_ADDR_LEN);

        p_fib_dr_msg_info->prefix.af_index = af_index;

        p_fib_dr_msg_info->prefix_len = p_rtm_v6_fib_cmd->prefix_masklen;
        p_fib_dr_msg_info->vrf_id     = p_rtm_v6_fib_cmd->vrfid;
        p_fib_dr_msg_info->proto      = p_rtm_v6_fib_cmd->protocol;
        p_fib_dr_msg_info->rt_type    = p_rtm_v6_fib_cmd->rt_type;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR", "vrf_id: %d, prefix: %s, "
                "prefix_len: %d, proto: %d rt_type: %d",p_fib_dr_msg_info->vrf_id,
                FIB_IP_ADDR_TO_STR (&p_fib_dr_msg_info->prefix),
                p_fib_dr_msg_info->prefix_len, p_fib_dr_msg_info->proto,
                p_fib_dr_msg_info->rt_type);

    return STD_ERR_OK;
}

int fib_form_nh_msg_info (uint8_t af_index, void *p_rtm_nh_key, t_fib_nh_msg_info *p_fib_nh_msg_info, size_t nh_index)
{
    t_fib_route_entry     *p_rtm_v4NHKey = NULL;
    t_fib_route_entry     *p_rtm_v6NHKey = NULL;
    t_fib_dr       *p_best_fit_dr;
    t_fib_nh       *p_nh;
    t_fib_nh_holder nh_holder;

    if ((!p_rtm_nh_key) || (!p_fib_nh_msg_info)) {
        HAL_RT_LOG_ERR("HAL-RT-DR", "%s (): Invalid input param. "
                   "p_rtm_nh_key: %p, p_fib_nh_msg_info: %p",
                   __FUNCTION__, p_rtm_nh_key, p_fib_nh_msg_info);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR", "af_index: %d",  af_index);

    memset (p_fib_nh_msg_info, 0, sizeof (t_fib_nh_msg_info));

    if (STD_IP_IS_AFINDEX_V4 (af_index)) {
        p_rtm_v4NHKey = (t_fib_route_entry *) p_rtm_nh_key;
        p_fib_nh_msg_info->ip_addr.af_index = HAL_RT_V4_AFINDEX;

        p_fib_nh_msg_info->if_index = p_rtm_v4NHKey->nh_list[nh_index].nh_if_index;
        memcpy (&p_fib_nh_msg_info->ip_addr.u.v4_addr,
                &p_rtm_v4NHKey->nh_list[nh_index].nh_addr.u.v4_addr,
                HAL_RT_V4_ADDR_LEN);
        /*
         * @@TODO : NH vrfid to be obtained from nh_if_index for vrfs
         * implemented with Linux namespace or other vrf implementations
         */
        p_fib_nh_msg_info->vrf_id   = p_rtm_v4NHKey->nh_vrfid;
        p_fib_nh_msg_info->is_nh_vrf_present = p_rtm_v4NHKey->is_nh_vrf_present;
        p_fib_nh_msg_info->flags = p_rtm_v4NHKey->nh_list[nh_index].nh_flags;
    }
    else if (FIB_IS_AFINDEX_V6 (af_index))
    {
        p_rtm_v6NHKey = (t_fib_route_entry *)p_rtm_nh_key;

        memcpy (&p_fib_nh_msg_info->ip_addr.u.v6_addr,
                &p_rtm_v6NHKey->nh_list[nh_index].nh_addr.u.v6_addr,
                HAL_RT_V6_ADDR_LEN);
        p_fib_nh_msg_info->if_index = p_rtm_v6NHKey->nh_list[nh_index].nh_if_index;

        p_fib_nh_msg_info->ip_addr.af_index = HAL_RT_V6_AFINDEX;


        /*
         * @@TODO : NH vrfid to be obtained from nh_if_index for vrfs
         * implemented with Linux namespace or other vrf implementations
         */
        p_fib_nh_msg_info->vrf_id   = p_rtm_v6NHKey->nh_vrfid;
        p_fib_nh_msg_info->is_nh_vrf_present = p_rtm_v6NHKey->is_nh_vrf_present;
        p_fib_nh_msg_info->flags = p_rtm_v6NHKey->nh_list[nh_index].nh_flags;
    }

    if (p_fib_nh_msg_info->if_index == 0)
    {
        p_best_fit_dr = fib_get_best_fit_dr (p_fib_nh_msg_info->vrf_id,
                                             &p_fib_nh_msg_info->ip_addr);

        if (p_best_fit_dr != NULL)
        {
            p_nh = FIB_GET_FIRST_NH_FROM_DR (p_best_fit_dr, nh_holder);

            if (p_nh != NULL)
            {
                if ((FIB_IS_NH_ZERO (p_nh)))
                {
                    p_fib_nh_msg_info->if_index = p_nh->key.if_index;
                }
            }
        }
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "vrf_id: %d, ip_addr: %s, nh_index %lu if_index: 0x%x",
                p_fib_nh_msg_info->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_fib_nh_msg_info->ip_addr),
               nh_index, p_fib_nh_msg_info->if_index);

    return STD_ERR_OK;
}

int fib_form_tnl_nh_msg_info (t_fib_tnl_dest *p_tnl_dest,
                         t_fib_nh_msg_info *p_fib_nh_msg_info)
{
    uint8_t af_index;

    if ((!p_tnl_dest))
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_tnl_dest : %p",
                   __FUNCTION__, p_tnl_dest);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    af_index = p_tnl_dest->dest_addr.af_index;

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "af_index: %d",  af_index);

    memset (p_fib_nh_msg_info, 0, sizeof (t_fib_nh_msg_info));

    if (STD_IP_IS_AFINDEX_V4 (af_index))
    {
        p_fib_nh_msg_info->ip_addr.af_index = HAL_RT_V4_AFINDEX;

        memcpy (&p_fib_nh_msg_info->ip_addr.u.v4_addr,
                &p_tnl_dest->dest_addr.u.v4_addr,
                HAL_RT_V4_ADDR_LEN);
    }
    else
    {
        p_fib_nh_msg_info->ip_addr.af_index = HAL_RT_V6_AFINDEX;

        memcpy (&p_fib_nh_msg_info->ip_addr.u.v6_addr,
                &p_tnl_dest->dest_addr.u.v6_addr,
                HAL_RT_V6_ADDR_LEN);
    }

    p_fib_nh_msg_info->if_index = p_tnl_dest->key.if_index;
    p_fib_nh_msg_info->vrf_id   = p_tnl_dest->key.vrf_id;

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "vrf_id: %d, ip_addr: %s, if_index: 0x%x",
                p_fib_nh_msg_info->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_fib_nh_msg_info->ip_addr),
               p_fib_nh_msg_info->if_index);

    return STD_ERR_OK;
}

int fib_add_default_dr (uint32_t vrf_id, uint8_t af_index)
{
    t_fib_dr        *p_dr = NULL;
    t_fib_ip_addr    ip_addr;

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "vrf_id: %d, af_index: %d",
                vrf_id, af_index);

    if (!(FIB_IS_VRF_ID_VALID (vrf_id)))
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid vrf_id. vrf_id: %d",
                   __FUNCTION__, vrf_id);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    memset (&ip_addr, 0, sizeof (t_fib_ip_addr));
    ip_addr.af_index = af_index;

    p_dr = fib_get_dr (vrf_id, &ip_addr, 0);

    if (p_dr != NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                         "Duplicate default DR addition. "
                         "vrf_id: %d, af_index: %d",
                         vrf_id, af_index);

        p_dr->rt_type = RT_UNREACHABLE;

        p_dr->default_dr_owner = FIB_DEFAULT_DR_OWNER_FIB;

        /* set ADD flag to trigger route download to walker */
        p_dr->status_flag |= FIB_DR_STATUS_ADD;
        fib_mark_dr_for_resolution (p_dr);

        fib_resume_dr_walker_thread (af_index);

        return STD_ERR_OK;
    }

    p_dr = fib_add_dr (vrf_id, &ip_addr, 0);

    if (p_dr == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): DR addition failed. "
                   "vrf_id: %d, af_index: %d",
                   __FUNCTION__, vrf_id, af_index);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    std_dll_init (&p_dr->nh_list);
    std_dll_init (&p_dr->fh_list);
    std_dll_init (&p_dr->dep_nh_list);
    std_dll_init (&p_dr->degen_dr_fh.tunnel_fh_list);

    p_dr->vrf_id = vrf_id;
    p_dr->parent_vrf_id = vrf_id;

    p_dr->rt_type = RT_UNREACHABLE;

    p_dr->default_dr_owner = FIB_DEFAULT_DR_OWNER_FIB;

    FIB_INCR_CNTRS_FIB_ROUTE_ENTRIES (vrf_id, af_index);

    fib_update_route_summary (vrf_id, af_index, p_dr->prefix_len, true);

    /* set ADD flag to trigger route download to walker */
    p_dr->status_flag |= FIB_DR_STATUS_ADD;
    fib_mark_dr_for_resolution (p_dr);

    fib_resume_dr_walker_thread (af_index);

    return STD_ERR_OK;
}

int fib_handle_default_link_local_route (uint32_t vrf_id, bool is_add)
{
    t_fib_dr        *p_dr = NULL;
    t_fib_ip_addr    ip_addr;
    uint8_t          af_index = HAL_RT_V6_AFINDEX;
    /* using link local route prefix length to match first 10 bits of fe80 */
    uint8_t          prefix_len = 10;
    /* link local address prefix */
    char addr[HAL_RT_V6_ADDR_LEN] = {0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
                     "vrf_id: %d, af_index: %d", vrf_id, af_index);

    if (!(FIB_IS_VRF_ID_VALID (vrf_id)))
    {
        HAL_RT_LOG_ERR("HAL-RT-DR", "Invalid vrf_id:%d", vrf_id);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    memset (&ip_addr, 0, sizeof (t_fib_ip_addr));
    ip_addr.af_index = af_index;
    memcpy (&ip_addr.u.v6_addr, addr, HAL_RT_V6_ADDR_LEN);

    p_dr = fib_get_dr (vrf_id, &ip_addr, prefix_len);

    if (p_dr == NULL)
    {
        if (is_add == false) {
            HAL_RT_LOG_INFO("HAL-RT-DR", "Link local Route does not exist for vrf_id:%d", vrf_id);
            return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
        }
        p_dr = fib_add_dr (vrf_id, &ip_addr, prefix_len);

        if (p_dr == NULL)
        {
            HAL_RT_LOG_ERR("HAL-RT-DR", "DR addition failed. "
                           "vrf_id: %d, af_index: %d", vrf_id, af_index);

            return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
        }

        std_dll_init (&p_dr->nh_list);
        std_dll_init (&p_dr->fh_list);
        std_dll_init (&p_dr->dep_nh_list);
        std_dll_init (&p_dr->degen_dr_fh.tunnel_fh_list);

        p_dr->vrf_id = vrf_id;
        p_dr->parent_vrf_id = vrf_id;

        FIB_INCR_CNTRS_FIB_ROUTE_ENTRIES (vrf_id, af_index);

        fib_update_route_summary (vrf_id, af_index, p_dr->prefix_len, true);
    }
    HAL_RT_LOG_DEBUG("HAL-RT-DR",
                     "Default link local route addition. "
                     "vrf_id: %d, af_index: %d",
                     vrf_id, af_index);

    if (is_add) {
        p_dr->rt_type = RT_BLACKHOLE;
        p_dr->default_dr_owner = FIB_DEFAULT_DR_OWNER_FIB;
        p_dr->status_flag |= FIB_DR_STATUS_ADD;
        fib_mark_dr_for_resolution (p_dr);

        fib_resume_dr_walker_thread (af_index);
    } else {
        p_dr->status_flag |= FIB_DR_STATUS_DEL;
        fib_proc_dr_del (p_dr);
    }
    return STD_ERR_OK;
}

t_fib_dr *fib_add_dr (uint32_t vrf_id, t_fib_ip_addr *p_prefix,
                  uint8_t prefix_len)
{
    t_fib_dr    *p_dr = NULL;
    std_rt_head *p_radix_head = NULL;
    uint8_t      af_index = 0;

    if (!p_prefix)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_prefix: %p",
                   __FUNCTION__, p_prefix);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "vrf_id: %d, prefix: %s, prefix_len: %d",
               vrf_id, FIB_IP_ADDR_TO_STR (p_prefix),
               prefix_len);

    p_dr = fib_alloc_dr_node ();

    if (p_dr == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Memory alloc failed. "
                   "vrf_id: %d, prefix: %s, prefix_len: %d",
                   __FUNCTION__, vrf_id, FIB_IP_ADDR_TO_STR (p_prefix),
                   prefix_len);

        return NULL;
    }

    af_index = p_prefix->af_index;

    memcpy (&p_dr->key.prefix, p_prefix, sizeof (t_fib_ip_addr));

    p_dr->prefix_len = prefix_len;

    p_dr->radical.rth_addr = (uint8_t *) (&(p_dr->key));

    p_radix_head = std_radix_insert (hal_rt_access_fib_vrf_dr_tree(vrf_id, af_index),
                                 (std_rt_head *)(&p_dr->radical),
                                 FIB_GET_RDX_DR_KEY_LEN (p_prefix, prefix_len));

    if (p_radix_head == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Radix insertion failed. "
                   "vrf_id: %d, prefix: %s, prefix_len: %d",
                   __FUNCTION__, vrf_id, FIB_IP_ADDR_TO_STR (p_prefix),
                   prefix_len);

        fib_free_dr_node (p_dr);
        return NULL;
    }

    if (p_radix_head != ((std_rt_head *)p_dr))
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                   "Duplicate radix insertion. "
                   "vrf_id: %d, prefix: %s, prefix_len: %d",
                   vrf_id, FIB_IP_ADDR_TO_STR (p_prefix),
                   prefix_len);

        fib_free_dr_node (p_dr);

        p_dr = (t_fib_dr *)p_radix_head;
    }

    return p_dr;
}

t_fib_dr *fib_get_dr (uint32_t vrf_id, t_fib_ip_addr *p_prefix, uint8_t prefix_len)
{
    t_fib_dr      *p_dr = NULL;
    t_fib_dr_key   key;
    uint8_t        af_index = 0;

    if (!p_prefix)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_prefix: %p",
                   __FUNCTION__, p_prefix);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "vrf_id: %d, prefix: %s, prefix_len: %d",
               vrf_id, FIB_IP_ADDR_TO_STR (p_prefix),
               prefix_len);

    af_index = p_prefix->af_index;

    memset (&key, 0, sizeof (t_fib_dr_key));

    memcpy (&key.prefix, p_prefix, sizeof (t_fib_ip_addr));

    p_dr = (t_fib_dr *)
        std_radix_getexact (hal_rt_access_fib_vrf_dr_tree(vrf_id, af_index),
                          (uint8_t *)&key, FIB_GET_RDX_DR_KEY_LEN (p_prefix, prefix_len));

    if (p_dr != NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR", "vrf_id: %d, prefix: %s/%d, p_dr: %p",
                   vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                   p_dr->prefix_len, p_dr);
    }

    return p_dr;
}

t_fib_dr *fib_get_first_dr (uint32_t vrf_id, uint8_t af_index)
{
    t_fib_dr     *p_dr = NULL;
    t_fib_dr_key  key;

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "vrf_id: %d, af_index: %d",
               vrf_id, af_index);

    memset (&key, 0, sizeof (t_fib_dr_key));

    key.prefix.af_index = af_index;

    p_dr = (t_fib_dr *)
        std_radix_getexact (hal_rt_access_fib_vrf_dr_tree(vrf_id, af_index),
                           (uint8_t *)&key, FIB_GET_RDX_DR_KEY_LEN (&key.prefix, 0));

    if (p_dr == NULL)
    {
        p_dr = (t_fib_dr *)
            std_radix_getnext (hal_rt_access_fib_vrf_dr_tree(vrf_id, af_index),
                             (uint8_t *)&key, FIB_GET_RDX_DR_KEY_LEN (&key.prefix, 0));
    }

    if (p_dr != NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR", "vrf_id: %d, prefix: %s/%d",
                   vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                   p_dr->prefix_len);
    }

    return p_dr;
}

t_fib_dr *fib_get_next_dr (uint32_t vrf_id, t_fib_ip_addr *p_prefix,
                      uint8_t prefix_len)
{
    t_fib_dr     *p_dr = NULL;
    t_fib_dr_key  key;
    uint8_t       af_index = 0;

    if (!p_prefix)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_prefix: %p",
                   __FUNCTION__, p_prefix);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "vrf_id: %d, prefix: %s, prefix_len: %d",
               vrf_id, FIB_IP_ADDR_TO_STR (p_prefix),
               prefix_len);

    af_index = p_prefix->af_index;

    memset (&key, 0, sizeof (t_fib_dr_key));

    memcpy (&key.prefix, p_prefix, sizeof (t_fib_ip_addr));

    p_dr = (t_fib_dr *)
        std_radix_getnext (hal_rt_access_fib_vrf_dr_tree(vrf_id, af_index),
                         (uint8_t *) &key, FIB_GET_RDX_DR_KEY_LEN (p_prefix, prefix_len));

    if (p_dr != NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR", "vrf_id: %d, prefix: %s/%d",
                   vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                   p_dr->prefix_len);
    }

    return p_dr;
}

int fib_del_dr (t_fib_dr *p_dr)
{
    uint32_t  vrf_id = 0;
    uint8_t   af_index = 0;

    if (p_dr == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_dr: %p",
                   __FUNCTION__, p_dr);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "vrf_id: %d, prefix: %s, prefix_len: %d",
               p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
               p_dr->prefix_len);

    vrf_id   = p_dr->vrf_id;
    af_index = p_dr->key.prefix.af_index;

    std_radix_remove (hal_rt_access_fib_vrf_dr_tree(vrf_id, af_index), (std_rt_head *)(&p_dr->radical));

    fib_free_dr_node (p_dr);

    return STD_ERR_OK;
}

t_fib_dr_nh *fib_add_dr_nh (t_fib_dr *p_dr, t_fib_nh *p_nh, uint8_t *p_cur_nh_tlv,
                      uint32_t nh_tlv_len, bool *p_is_dup)
{
    t_fib_dr_nh  *p_dr_nh = NULL;

    if ((!p_dr) ||
        (!p_nh))
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_dr: %p, p_nh: %p",
                   __FUNCTION__, p_dr, p_nh);

        return NULL;
    }
    if (fib_get_dr_nh(p_dr, p_nh))
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                     "Duplicate Add - DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
                     "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                     "p_cur_nh_tlv: %p, nh_tlv_len: %d",
                     p_dr->vrf_id,
                     FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                     p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                     p_nh->key.if_index, p_cur_nh_tlv, nh_tlv_len);
        *p_is_dup = true;
        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "p_cur_nh_tlv: %p, nh_tlv_len: %d",
               p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
               p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
               p_nh->key.if_index, p_cur_nh_tlv, nh_tlv_len);

    if (nh_tlv_len > RT_PER_TLV_MAX_LEN)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid nh_tlv_len. nh_tlv_len: %d",
                   __FUNCTION__, nh_tlv_len);

        return NULL;
    }

    if (nh_tlv_len > 0)
    {
        p_dr_nh = (t_fib_dr_nh *) FIB_DR_NH_TLV_MEM_MALLOC ();
    }
    else
    {
        p_dr_nh = (t_fib_dr_nh *) FIB_DR_NH_MEM_MALLOC ();
    }

    if (p_dr_nh == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Memory alloc failed", __FUNCTION__);

        return NULL;
    }

    /* NOTE: p_cur_nh_tlv is non NULL only when nh_tlv_len > 0 */

    if (nh_tlv_len > 0)
    {
        memset (p_dr_nh, 0, ((sizeof (t_fib_dr_nh)) + RT_PER_TLV_MAX_LEN));

        p_dr_nh->link_node.self = p_nh;

        p_dr_nh->tlv_info_len = nh_tlv_len;

        if (p_cur_nh_tlv != NULL)
        {
            memcpy (p_dr_nh->tlv_info, p_cur_nh_tlv, nh_tlv_len);
        }
    }
    else
    {
        memset (p_dr_nh, 0, sizeof (t_fib_dr_nh));

        p_dr_nh->link_node.self = p_nh;

        p_dr_nh->tlv_info_len = 0;
    }

    std_dll_insertatback (&p_dr->nh_list, &p_dr_nh->link_node.glue);

    p_dr->num_nh++;

    p_nh->dr_ref_count++;

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "nh_count: %d dr_ref_count: %d", p_nh->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
               p_dr->num_nh, p_nh->dr_ref_count);

    return p_dr_nh;
}

t_fib_dr_nh *fib_get_dr_nh (t_fib_dr *p_dr, t_fib_nh *p_nh)
{
    t_fib_dr_nh   *p_dr_nh = NULL;
    t_fib_nh     *p_temp_nh = NULL;
    t_fib_nh_holder   nh_holder;

    if ((!p_dr) ||
        (!p_nh))
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_dr: %p, p_nh: %p",
                   __FUNCTION__, p_dr, p_nh);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x",
               p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
               p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
               p_nh->key.if_index);

    FIB_FOR_EACH_NH_FROM_DR (p_dr, p_temp_nh, nh_holder)
    {
        if ((p_nh->vrf_id == p_temp_nh->vrf_id) &&
            ((memcmp (&p_nh->key, &p_temp_nh->key, sizeof (t_fib_nh_key))) == 0))
        {
            p_dr_nh = FIB_GET_DRNH_NODE_FROM_NH_HOLDER (nh_holder);

            return p_dr_nh;
        }
    }

    return NULL;
}

int fib_del_dr_nh (t_fib_dr *p_dr, t_fib_dr_nh *p_dr_nh)
{
    t_fib_nh  *p_nh = NULL;

    if ((!p_dr) ||
        (!p_dr_nh))
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_dr: %p, p_dr_nh: %p",
                   __FUNCTION__, p_dr, p_dr_nh);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d",
               p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len);

    p_nh = p_dr_nh->link_node.self;

    if (p_nh != NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                   "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                   "dr_ref_count: %d", p_nh->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
                   p_nh->dr_ref_count);

        if (p_nh->dr_ref_count > 0)
        {
            p_nh->dr_ref_count--;
        }
    }

    std_dll_remove (&p_dr->nh_list, &p_dr_nh->link_node.glue);

    if (p_dr_nh->tlv_info_len != 0)
    {
        memset (p_dr_nh, 0, ((sizeof (t_fib_dr_nh)) + RT_PER_TLV_MAX_LEN));

        FIB_DR_NH_TLV_MEM_FREE (p_dr_nh);
    }
    else
    {
        memset (p_dr_nh, 0, sizeof (t_fib_dr_nh));

        FIB_DR_NH_MEM_FREE (p_dr_nh);
    }

    p_dr->num_nh--;

    return STD_ERR_OK;
}

int fib_delete_all_dr_nh (t_fib_dr *p_dr)
{
    t_fib_dr_nh      *p_dr_nh = NULL;
    t_fib_nh        *p_nh = NULL;
    t_fib_nh_dep_dr   *p_nh_dep_dr = NULL;
    t_fib_nh_holder  nh_holder;

    if (!p_dr)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_dr: %p",
                   __FUNCTION__, p_dr);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d",
               p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len);

    FIB_FOR_EACH_NH_FROM_DR (p_dr, p_nh, nh_holder)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                   "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x",
                   p_nh->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index);

        /* Check whether connected route's (Leaked VRF) NH is in different VRF (Parent VRF),
         * if yes, del the leaked VRF in the parent VRF and then remove the ARPs/Neighbors
         * in the parent VRF matching this route from the leaked VRF.
         *
         * When the parent route is deleted, make sure to delete the parent nbrs from the leaked VRFs */
        if ((p_dr->num_nh == 1) && (FIB_IS_NH_ZERO (p_nh))) {
            if (p_dr->vrf_id != p_nh->vrf_id) {
                t_fib_leaked_rt_key parent_rt_key;
                parent_rt_key.vrf_id = p_nh->vrf_id;
                memcpy(&(parent_rt_key.prefix), &p_dr->key.prefix, sizeof(hal_ip_addr_t));
                parent_rt_key.prefix_len = p_dr->prefix_len;
                hal_rt_del_dep_leaked_vrf(&parent_rt_key, p_dr->vrf_id);

                t_fib_dr *p_parent_dr = fib_get_dr (p_nh->vrf_id, &p_dr->key.prefix, p_dr->prefix_len);
                if (p_parent_dr) {
                    HAL_RT_LOG_INFO("HAL-RT-LEAK", "Rt del VRF-id:%d prefix:%s/%d leaked VRF:%d prefix:%s/%d",
                                    p_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                                    p_dr->prefix_len,
                                    p_parent_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_parent_dr->key.prefix),
                                    p_parent_dr->prefix_len);
                    fib_prg_leaked_nbrs_on_leaked_route_update(p_nh->key.if_index, p_parent_dr, p_dr->vrf_id, false);
                }
            } else {
                /* If route in parent VRF is deleted, delete all the nbrs from leaked VRF. */
                fib_prg_leaked_nbrs_on_parent_route_update(p_dr, false);
            }
        }

        p_nh_dep_dr = fib_get_nh_dep_dr (p_nh, p_dr);

        if (p_nh_dep_dr != NULL)
        {
            fib_del_nh_dep_dr (p_nh, p_nh_dep_dr);
        }

        fib_proc_nh_delete (p_nh, FIB_NH_OWNER_TYPE_RTM, 0);

        p_dr_nh = FIB_GET_DRNH_NODE_FROM_NH_HOLDER (nh_holder);

        fib_del_dr_nh (p_dr, p_dr_nh);
        fib_check_and_delete_nh (p_nh, false);
    }

    return STD_ERR_OK;
}

t_fib_dr_fh *fib_add_dr_fh (t_fib_dr *p_dr, t_fib_nh *p_fh)
{
    t_fib_dr_fh  *p_dr_fh = NULL;

    if ((!p_dr) ||
        (!p_fh))
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_dr: %p, p_fh: %p",
                   __FUNCTION__, p_dr, p_fh);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
               "FH: vrf_id: %d, ip_addr: %s, if_index: %d",
               p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
               p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
               p_fh->key.if_index);

    p_dr_fh = (t_fib_dr_fh *) FIB_DR_FH_MEM_MALLOC ();

    if (p_dr_fh == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Memory alloc failed", __FUNCTION__);

        return NULL;
    }

    memset (p_dr_fh, 0, sizeof (t_fib_dr_fh));

    std_dll_init (&p_dr_fh->tunnel_fh_list);

    p_dr_fh->link_node.self = p_fh;

    std_dll_insertatback (&p_dr->fh_list, &p_dr_fh->link_node.glue);

    /*
     * Increment num_fh to ensure we check for ECMP case
     */
    p_dr->num_fh++;
    p_fh->dr_ref_count++;

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: num_fh: %d, FH: dr_ref_count: %d",
               p_dr->num_fh, p_fh->dr_ref_count);

    return p_dr_fh;
}

t_fib_dr_fh *fib_get_dr_fh (t_fib_dr *p_dr, t_fib_nh *p_fh)
{
    t_fib_dr_fh   *p_dr_fh = NULL;
    t_fib_nh     *p_temp_fh = NULL;
    t_fib_nh_holder   nh_holder;

    if ((!p_dr) ||
        (!p_fh))
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_dr: %p, p_fh: %p",
                   __FUNCTION__, p_dr, p_fh);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
               "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x",
               p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
               p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
               p_fh->key.if_index);

    FIB_FOR_EACH_FH_FROM_DR (p_dr, p_temp_fh, nh_holder)
    {
        if ((p_fh->vrf_id == p_temp_fh->vrf_id) &&
            ((memcmp (&p_fh->key, &p_temp_fh->key, sizeof (t_fib_nh_key))) == 0))
        {
            p_dr_fh = FIB_GET_DRFH_NODE_FROM_NH_HOLDER (nh_holder);

            return p_dr_fh;
        }
    }

    return NULL;
}

int fib_del_dr_fh (t_fib_dr *p_dr, t_fib_dr_fh *p_dr_fh)
{
    t_fib_nh  *p_fh = NULL;

    if ((!p_dr) ||
        (!p_dr_fh))
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_dr: %p, p_fh: %p",
                   __FUNCTION__, p_dr, p_fh);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
               "num_fh: %d", p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
               p_dr->num_fh);

    p_fh = p_dr_fh->link_node.self;

    if (p_fh != NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                   "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                   "dr_ref_count: %d",
                   p_fh->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                   p_fh->key.if_index, p_fh->dr_ref_count);

        /*
         * Decrement num_fh to ensure we check for ECMP case
         */
        if (p_dr->num_fh > 0) {
            p_dr->num_fh--;
        }


        if (p_fh->dr_ref_count > 0)
        {
            p_fh->dr_ref_count--;

            /* if FH reference count has become zero,
             * then mark the NH for resolution to clean-up nexthop.
             */
            if (FIB_IS_NH_REF_COUNT_ZERO (p_fh))
                fib_mark_nh_for_resolution(p_fh);
        }
    }

    std_dll_remove (&p_dr->fh_list, &p_dr_fh->link_node.glue);

    memset (p_dr_fh, 0, sizeof (t_fib_dr_fh));

    FIB_DR_FH_MEM_FREE (p_dr_fh);

    return STD_ERR_OK;
}

int fib_delete_all_dr_fh (t_fib_dr *p_dr)
{
    t_fib_dr_fh    *p_dr_fh = NULL;
    t_fib_nh       *p_fh = NULL;
    t_fib_nh_holder nh_holder;

    if (!p_dr)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_dr: %p",
                   __FUNCTION__, p_dr);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d",
               p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len);

    FIB_FOR_EACH_FH_FROM_DR (p_dr, p_fh, nh_holder)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                   "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x",
                   p_fh->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                   p_fh->key.if_index);

        p_dr_fh = FIB_GET_DRFH_NODE_FROM_NH_HOLDER (nh_holder);

        fib_del_dr_fh (p_dr, p_dr_fh);
    }

    return STD_ERR_OK;
}

t_fib_link_node *fib_add_dr_dep_nh (t_fib_dr *p_dr, t_fib_nh *p_nh)
{
    t_fib_link_node  *p_link_node = NULL;

    if ((!p_dr) ||
        (!p_nh))
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_dr: %p, p_nh: %p",
                   __FUNCTION__, p_dr, p_nh);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x",
               p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
               p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
               p_nh->key.if_index);

    p_link_node = (t_fib_link_node *) FIB_LINK_NODE_MEM_MALLOC ();

    if (p_link_node == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Memory alloc failed", __FUNCTION__);

        return NULL;
    }

    memset (p_link_node, 0, sizeof (t_fib_link_node));

    p_link_node->self = p_nh;

    std_dll_insertatback (&p_dr->dep_nh_list, &p_link_node->glue);

    return p_link_node;
}

t_fib_link_node *fib_get_dr_dep_nh (t_fib_dr *p_dr, t_fib_nh *p_nh)
{
    t_fib_link_node  *p_link_node = NULL;
    t_fib_nh        *p_temp_nh = NULL;
    t_fib_nh_holder  nh_holder;

    if ((!p_dr) ||
        (!p_nh))
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_dr: %p, p_nh: %p",
                   __FUNCTION__, p_dr, p_nh);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x",
               p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
               p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
               p_nh->key.if_index);

    FIB_FOR_EACH_DEP_NH_FROM_DR (p_dr, p_temp_nh, nh_holder)
    {
        if ((p_nh->vrf_id == p_temp_nh->vrf_id) &&
            ((memcmp (&p_nh->key, &p_temp_nh->key, sizeof (t_fib_nh_key))) == 0))
        {
            p_link_node = FIB_GET_LINK_NODE_FROM_NH_HOLDER (nh_holder);

            return p_link_node;
        }
    }

    return NULL;
}

int fib_del_dr_dep_nh (t_fib_dr *p_dr, t_fib_link_node *p_link_node)
{
    if ((!p_dr) ||
        (!p_link_node))
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_dr: %p, p_link_node: %p",
                   __FUNCTION__, p_dr, p_link_node);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d",
               p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len);

    std_dll_remove (&p_dr->dep_nh_list, &p_link_node->glue);

    memset (p_link_node, 0, sizeof (t_fib_link_node));

    FIB_LINK_NODE_MEM_FREE (p_link_node);

    return STD_ERR_OK;
}

int fib_delete_all_dr_dep_nh (t_fib_dr *p_dr)
{
    t_fib_link_node  *p_link_node = NULL;
    t_fib_nh        *p_nh = NULL;
    t_fib_nh_holder  nh_holder;

    if (!p_dr)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_dr: %p",
                   __FUNCTION__, p_dr);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d",
               p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len);

    FIB_FOR_EACH_DEP_NH_FROM_DR (p_dr, p_nh, nh_holder)
    {
        p_nh->p_best_fit_dr = NULL;

        p_link_node = FIB_GET_LINK_NODE_FROM_NH_HOLDER (nh_holder);

        fib_del_dr_dep_nh (p_dr, p_link_node);
    }

    return STD_ERR_OK;
}

int fib_add_dr_degen_fh (t_fib_dr *p_dr, t_fib_nh *p_fh, t_fib_tunnel_fh *p_tunnel_fh)
{
    t_fib_tunnel_dr_fh *p_tunnel_dr_fh_node = NULL;

    if ((!p_dr))
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_dr: %p",
                   __FUNCTION__, p_dr);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    if (p_fh != NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                   "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
                   "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x",
                   p_dr->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                   p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                   p_fh->key.if_index);
    }

    p_dr->degen_dr_fh.link_node.self = p_fh;

    if (p_tunnel_fh != NULL)
    {
        p_tunnel_dr_fh_node = fib_alloc_tunnel_dr_fh_node ();

        p_tunnel_dr_fh_node->link_node.self = p_tunnel_fh;

        std_dll_insertatback (&(p_dr->degen_dr_fh.tunnel_fh_list),
                            &p_tunnel_dr_fh_node->link_node.glue);
    }

    return STD_ERR_OK;
}

t_fib_nh *fib_get_dr_degen_fh (t_fib_dr *p_dr)
{
    if (!p_dr)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_dr: %p",
                   __FUNCTION__, p_dr);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d",
               p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len);

    return (p_dr->degen_dr_fh.link_node.self);
}

int fib_del_dr_degen_fh (t_fib_dr *p_dr)
{
    t_fib_tunnel_dr_fh *p_tunnel_dr_fh_node = NULL;
    t_fib_nh_holder   nh_holder;

    if (!p_dr)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_dr: %p",
                   __FUNCTION__, p_dr);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d",
               p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len);

    p_dr->degen_dr_fh.link_node.self = NULL;

    FIB_GET_FIRST_TUNNEL_FH_FROM_DRFH (&p_dr->degen_dr_fh, nh_holder);
    p_tunnel_dr_fh_node = FIB_GET_TUNNEL_DRFH_NODE_FROM_NH_HOLDER (nh_holder);

    if (p_tunnel_dr_fh_node != NULL)
    {
        std_dll_remove (&p_dr->degen_dr_fh.tunnel_fh_list,
                      &p_tunnel_dr_fh_node->link_node.glue);

        memset (p_tunnel_dr_fh_node, 0, sizeof (t_fib_tunnel_dr_fh));

        fib_free_tunnel_dr_fh_node (p_tunnel_dr_fh_node);
    }

    return STD_ERR_OK;
}

t_fib_dr *fib_get_best_fit_dr (uint32_t vrf_id, t_fib_ip_addr *p_ip_addr)
{
    t_fib_dr       *p_best_fit_dr = NULL;
    uint8_t     af_index = 0;

    if (!p_ip_addr)
    {
        return NULL;
    }

    af_index = p_ip_addr->af_index;

    p_best_fit_dr = (t_fib_dr *)
        std_radix_getbest (hal_rt_access_fib_vrf_dr_tree(vrf_id, af_index),
                         (uint8_t *)p_ip_addr,
                         FIB_GET_RDX_DR_KEY_LEN (p_ip_addr,
                         FIB_AFINDEX_TO_PREFIX_LEN (af_index)));

    return p_best_fit_dr;
}

/* get Next best DR for the given route prefix. when a NH for a DR goes down,
 * for which tracking is on, then we need to find out
 * next best DR (with different route prefix length) and use that for NHT
 */
t_fib_dr *fib_get_next_best_fit_dr (uint32_t vrf_id, t_fib_ip_addr *p_ip_addr, uint8_t prefix_len)
{
    t_fib_dr       *p_best_fit_dr = NULL;
    uint8_t     af_index = 0;

    if (!p_ip_addr)
    {
        return NULL;
    }

    af_index = p_ip_addr->af_index;

    p_best_fit_dr = (t_fib_dr *)
        std_radix_getnextbest (hal_rt_access_fib_vrf_dr_tree(vrf_id, af_index),
                         (uint8_t *)p_ip_addr,
                         FIB_GET_RDX_DR_KEY_LEN (p_ip_addr, prefix_len));

    return p_best_fit_dr;
}

int fib_dr_walker_init (void)
{
    pthread_mutex_init(&fib_dr_mutex, NULL);
    pthread_cond_init (&fib_dr_cond, NULL);

    return STD_ERR_OK;
}

int fib_dr_walker_main (void)
{
    t_fib_vrf_info         *p_vrf_info = NULL;
    std_radix_version_t  marker_version = 0;
    std_radix_version_t  max_version = 0;
    std_radix_version_t  max_walker_version = 0;
    uint32_t             tot_dr_processed = 0;
    uint32_t             num_active_vrfs = 0;
    uint32_t             vrf_id = 0, next_vrf_id = 0;
    int                  af_index = 0;
    int                  rc = STD_ERR_OK;
    uint8_t              af_itr = 0;
    t_std_error          vrf_rc = STD_ERR_OK;

    for ( ; ;)
    {
        pthread_mutex_lock( &fib_dr_mutex );
        while (is_dr_pending_for_processing == 0) // check predicate for signal before wait
        {
            pthread_cond_wait( &fib_dr_cond, &fib_dr_mutex );
        }
        is_dr_pending_for_processing = 0; //reset the predicate for signal
        pthread_mutex_unlock( &fib_dr_mutex );

        tot_dr_processed = 0;
        num_active_vrfs  = 0;

        next_vrf_id = 0;
        vrf_rc = hal_rt_get_first_vrf_id(&next_vrf_id);
        /* VRF-ids loop */
        while(vrf_rc == STD_ERR_OK) {
            vrf_id = next_vrf_id;
            vrf_rc = hal_rt_get_next_vrf_id(vrf_id, &next_vrf_id);
            /* Address family loop */
            for (af_itr = 0, af_index = HAL_RT_V4_AFINDEX; af_itr < HAL_RT_MAX_VALID_AF_CNT;
                 af_index = HAL_RT_V6_AFINDEX, af_itr++) {
                nas_l3_lock();
                if (hal_rt_access_fib_vrf(vrf_id) == NULL) {
                    nas_l3_unlock();
                    break;
                }

                p_vrf_info = FIB_GET_VRF_INFO (vrf_id, af_index);
                if (p_vrf_info == NULL){
                    HAL_RT_LOG_DEBUG("HAL-RT-DR", "Vrf info NULL. "
                                     "vrf_id: %d, af_index: %d", vrf_id, af_index);

                    nas_l3_unlock();
                    continue;
                }

                p_vrf_info->num_dr_processed_by_walker = 0;

                if (p_vrf_info->dr_clear_on == true) {
                    max_walker_version = p_vrf_info->dr_clear_max_radix_ver;
                }
                else if (p_vrf_info->dr_ha_on == true) {
                    max_walker_version = p_vrf_info->dr_ha_max_radix_ver;
                }
                else {
                    max_walker_version = std_radix_getversion (p_vrf_info->dr_tree);
                }

                /* Process a maximum of FIB_DR_WALKER_COUNT nodes per vrf */

                std_radical_walkchangelist (p_vrf_info->dr_tree,
                                            &p_vrf_info->dr_radical_marker,
                                            fib_dr_walker_call_back,
                                            0,
                                            FIB_DR_WALKER_COUNT,
                                            max_walker_version,
                                            &rc);

                /* @TODO: Need to handle version wrap */
                max_version    = std_radix_getversion (p_vrf_info->dr_tree);
                marker_version = p_vrf_info->dr_radical_marker.rth_version;

                if (marker_version != max_version) {
                    num_active_vrfs++;
                }

                /*
                 * 'p_vrf_info->num_dr_processed_by_walker' is updated in
                 * fib_dr_walker_call_back ().
                 */
                if (p_vrf_info->num_dr_processed_by_walker == FIB_DR_WALKER_COUNT) {
                    HAL_RT_LOG_DEBUG("HAL-RT-DR", "Max DR processed %d per walk, relinquish now",
                                     tot_dr_processed);
                    is_dr_pending_for_processing = true;
                }
                tot_dr_processed += p_vrf_info->num_dr_processed_by_walker;
                nas_l3_unlock();
            }
        }  /* End of vrf loop */

        HAL_RT_LOG_DEBUG("HAL-RT-DR", "Total DR processed %d",  tot_dr_processed);

        if(tot_dr_processed) {
            fib_resume_nh_walker_thread(af_index);
        }
    }      /* End of infinite loop */
    return STD_ERR_OK;
}

int fib_dr_walker_call_back (std_radical_head_t *p_rt_head, va_list ap)
{
    t_fib_vrf_info   *p_vrf_info = NULL;
    t_fib_dr        *p_dr = NULL;

    if (!p_rt_head)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_rt_head: %p",
                   __FUNCTION__, p_rt_head);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    p_dr = (t_fib_dr *) p_rt_head;

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
               "status_flag: 0x%x", p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
               p_dr->status_flag);

    p_vrf_info = FIB_GET_VRF_INFO (p_dr->vrf_id,
                                 p_dr->key.prefix.af_index);

    if (p_vrf_info == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Vrf info NULL. vrf_id: %d, af_index: %d",
                   __FUNCTION__, p_dr->vrf_id, p_dr->key.prefix.af_index);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "num_dr_processed_by_walker: %d, clear_ip_fib_on: %d, "
               "clear_ip_route_on: %d, dr_ha_on: %d, last_update_time: %lu, "
               "default_dr_owner: %d",
               p_vrf_info->num_dr_processed_by_walker, p_vrf_info->clear_ip_fib_on,
               p_vrf_info->clear_ip_route_on, p_vrf_info->dr_ha_on,
               p_dr->last_update_time, p_dr->default_dr_owner);

    p_vrf_info->num_dr_processed_by_walker++;

    if (p_vrf_info->dr_clear_on == true)
    {
        if ((FIB_IS_DR_DEFAULT (p_dr)) &&
            (FIB_IS_DEFAULT_DR_OWNER_FIB (p_dr)) &&
            (FIB_IS_VRF_CREATED (p_dr->vrf_id, p_dr->key.prefix.af_index)))
        {
            /*
             * Default DR is owned by FIB and the VRF is created.
             * So need not clear the default DR.
             */
        } else {
            p_dr->status_flag |= FIB_DR_STATUS_DEL;
            fib_proc_dr_del (p_dr);
        }

        return STD_ERR_OK;
    }

    if (p_dr->status_flag & FIB_DR_STATUS_DEL) {
        fib_proc_dr_del (p_dr);
    } else {
        fib_resolve_dr (p_dr);

        fib_mark_dr_dep_nh_for_resolution (p_dr);

        p_dr->status_flag &= ~FIB_DR_STATUS_REQ_RESOLVE;

        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                     "End of processing. "
                     "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
                     "status_flag: 0x%x", p_dr->vrf_id,
                     FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                     p_dr->prefix_len, p_dr->status_flag);
    }

    return STD_ERR_OK;
}

int fib_resolve_dr (t_fib_dr *p_dr)
{
    t_fib_dr_fh    *p_dr_fh = NULL;
    t_fib_nh       *p_nh = NULL;
    t_fib_nh       *p_fh = NULL;
    t_fib_nh_holder nh_holder1;
    t_fib_nh_holder nh_holder2;
    dn_hal_route_err   hal_err = DN_HAL_ROUTE_E_NONE;
    const           t_fib_config *p_config = NULL;

    if (!p_dr)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_dr: %p",
                   __FUNCTION__, p_dr);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }


    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d",
               p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len);


    fib_delete_all_dr_fh (p_dr);

    fib_del_dr_degen_fh (p_dr);

    p_dr->status_flag &= ~FIB_DR_STATUS_DEGENERATED;

    FIB_FOR_EACH_NH_FROM_DR (p_dr, p_nh, nh_holder1)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                   "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x",
                   p_nh->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index);

        /* Dont add the NH into FH list, if the NH is marked for dead */
        if (p_nh->status_flag & FIB_NH_STATUS_DEAD) {
            HAL_RT_LOG_DEBUG("HAL-RT-DR",
                             "NH in dead state. "
                             "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x",
                             p_nh->vrf_id,
                             FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index);
            continue;
        }
        if (FIB_IS_NH_REQ_RESOLVE (p_nh))
        {
            HAL_RT_LOG_DEBUG("HAL-RT-DR",
                       "NH in request resolve state. "
                       "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x",
                       p_nh->vrf_id,
                       FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index);

            continue;
        }

        /* First Hop */
        if (FIB_IS_NH_FH (p_nh))
        {
            p_dr_fh = fib_get_dr_fh (p_dr, p_nh);

            if (p_dr_fh != NULL)
            {
                HAL_RT_LOG_DEBUG("HAL-RT-DR",
                           "Duplicate DRFH. "
                           "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
                           "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x",
                           p_dr->vrf_id,
                           FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                           p_dr->prefix_len, p_nh->vrf_id,
                           FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                           p_nh->key.if_index);

                continue;
            }

            p_dr_fh = fib_add_dr_fh (p_dr, p_nh);

            if (p_dr_fh == NULL)
            {
                HAL_RT_LOG_DEBUG("HAL-RT-DR",
                           "DRFH addition failed. "
                           "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
                           "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x",
                           p_dr->vrf_id,
                           FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                           p_dr->prefix_len, p_nh->vrf_id,
                           FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                           p_nh->key.if_index);

                continue;
            }
        }
        else /* Next Hop */
        {
            FIB_FOR_EACH_FH_FROM_NH (p_nh, p_fh, nh_holder2)
            {
                HAL_RT_LOG_DEBUG("HAL-RT-DR",
                           "FH: vrf_id: %d, ip_addr: %s, "
                           "if_index: 0x%x",
                           p_fh->vrf_id,
                           FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                           p_fh->key.if_index);

                if (FIB_IS_NH_REQ_RESOLVE (p_fh))
                {
                    HAL_RT_LOG_DEBUG("HAL-RT-DR",
                               "FH in request resolve state. "
                               "FH: vrf_id: %d, ip_addr: %s, "
                               "if_index: 0x%x",
                               p_fh->vrf_id,
                               FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                               p_fh->key.if_index);

                    continue;
                }

                if (FIB_IS_NH_FH (p_fh))
                {
                    p_dr_fh = fib_get_dr_fh (p_dr, p_fh);

                    if (p_dr_fh != NULL)
                    {
                        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                                   "Duplicate DRFH. "
                                   "DR: vrf_id: %d, prefix: %s, "
                                   "prefix_len: %d, "
                                   "FH: vrf_id: %d, ip_addr: %s, "
                                   "if_index: 0x%x",
                                   p_dr->vrf_id,
                                   FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                                   p_dr->prefix_len, p_fh->vrf_id,
                                   FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                                   p_fh->key.if_index);

                        continue;
                    }

                    p_dr_fh = fib_add_dr_fh (p_dr, p_fh);

                    if (p_dr_fh == NULL)
                    {
                        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                                   "DRFH addition failed. "
                                   "DR: vrf_id: %d, prefix: %s, "
                                   "prefix_len: %d, "
                                   "FH: vrf_id: %d, ip_addr: %s, "
                                   "if_index: 0x%x",
                                   p_dr->vrf_id,
                                   FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                                   p_dr->prefix_len, p_fh->vrf_id,
                                   FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                                   p_fh->key.if_index);

                        continue;
                    }
                }
            }
        }
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
               "status_flag: 0x%x",
               p_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
               p_dr->prefix_len, p_dr->status_flag);

    if (FIB_IS_DR_DEFAULT (p_dr))
    {
        t_fib_nh_holder nh_holder;
        if ((!(FIB_IS_VRF_CREATED (p_dr->vrf_id, p_dr->key.prefix.af_index))) ||
            ((FIB_IS_DEFAULT_DR_OWNER_FIB (p_dr)) &&
             (FIB_IS_CATCH_ALL_ROUTE_DISABLED (p_dr->vrf_id,
                                               p_dr->key.prefix.af_index))) ||
            (!(FIB_IS_RESERVED_RT_TYPE(p_dr->rt_type)) &&
             (FIB_GET_FIRST_NH_FROM_DR(p_dr, nh_holder) == NULL)))
        {
            return STD_ERR_OK;
        }
    }

    if (FIB_IS_MGMT_ROUTE(p_dr->vrf_id, p_dr) || (p_dr->rt_type == RT_CACHE)) {
        /* Dont go for NPU programming for out of band routes,
         * once the in band mgmt is needed, make sure to program the route into the NPU */
        return STD_ERR_OK;
    }

    hal_err = hal_fib_route_add (p_dr->vrf_id, p_dr);

    if (hal_err == DN_HAL_ROUTE_E_NONE)
    {
        if (!(FIB_IS_DR_WRITTEN (p_dr)))
        {
            fib_check_threshold_for_all_cams (true);

            p_dr->status_flag |= FIB_DR_STATUS_WRITTEN;

            FIB_INCR_CNTRS_CAM_ROUTE_ENTRIES (p_dr->vrf_id,
                                              p_dr->key.prefix.af_index);
        }
    }
    else
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "Error: hal_fib_route_add. "
                   "vrf_id: %d, prefix: %s, prefix_len: %d, "
                   "hal_err: %d (%s)", p_dr->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                   hal_err, HAL_RT_GET_ERR_STR (hal_err));

        if (hal_err == DN_HAL_ROUTE_E_DEGEN)
        {
            p_config = hal_rt_access_fib_config();
            if (p_config && p_config->ecmp_path_fall_back == true)
            {
                fib_proc_dr_degeneration (p_dr);
            }
            else
            {
                /*
                 *There could have been a non-ecmp route in cam and
                 *when multipath table full is detected, the route would
                 *have been deleted from the table. So status and counter
                 *should be handled accordingly.
                 */
                if (FIB_IS_DR_WRITTEN (p_dr))
                {
                    p_dr->status_flag &= ~FIB_DR_STATUS_WRITTEN;

                    FIB_DECR_CNTRS_CAM_ROUTE_ENTRIES (p_dr->vrf_id,
                                                      p_dr->key.prefix.af_index);
                }
            }
        }
        else
        {
            if (FIB_IS_DR_WRITTEN (p_dr))
            {
                p_dr->status_flag &= ~FIB_DR_STATUS_WRITTEN;

                FIB_DECR_CNTRS_CAM_ROUTE_ENTRIES (p_dr->vrf_id,
                                                  p_dr->key.prefix.af_index);
            }
        }
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "End of processing. "
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
               "status_flag: 0x%x",
               p_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
               p_dr->prefix_len, p_dr->status_flag);

    return STD_ERR_OK;
}

int fib_updt_best_fit_dr_of_affected_nh (t_fib_dr *p_dr)
{
    t_fib_dr        *p_less_specific_dr = NULL;
    t_fib_nh        *p_nh = NULL;
    t_fib_link_node  *p_link_node = NULL;
    t_fib_nh_holder  nh_holder;
    t_fib_ip_addr     mask;
    uint32_t     vrf_id = 0;
    uint8_t      af_index = 0;

    if (!p_dr)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_dr: %p",
                   __FUNCTION__, p_dr);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d",
               p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len);

    vrf_id   = p_dr->vrf_id;
    af_index = p_dr->key.prefix.af_index;

    p_less_specific_dr = (t_fib_dr *)
        std_radix_getlessspecific (hal_rt_access_fib_vrf_dr_tree(vrf_id, af_index),
                                  (std_rt_head *)(&p_dr->radical));

    while (p_less_specific_dr)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                   "Less specific DR: vrf_id: %d, prefix: %s, "
                   "prefix_len: %d",p_less_specific_dr->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_less_specific_dr->key.prefix),
                   p_less_specific_dr->prefix_len);

        FIB_FOR_EACH_DEP_NH_FROM_DR (p_less_specific_dr, p_nh, nh_holder)
        {
            HAL_RT_LOG_DEBUG("HAL-RT-DR",
                       "Dep NH: vrf_id: %d, ip_addr: %s, "
                       "if_index: 0x%x",
                       p_nh->vrf_id,
                       FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                       p_nh->key.if_index);

            memset (&mask, 0, sizeof (t_fib_ip_addr));

            std_ip_get_mask_from_prefix_len (af_index, p_dr->prefix_len, &mask);

            if (FIB_IS_IP_ADDR_IN_PREFIX (&p_dr->key.prefix, &mask,
                                          &p_nh->key.ip_addr))
            {
                HAL_RT_LOG_DEBUG("HAL-RT-DR",
                           "Re-resolving NH. "
                           "vrf_id: %d, ip_addr: %s, if_index: 0x%x",
                           p_nh->vrf_id,
                           FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                           p_nh->key.if_index);

                p_nh->p_best_fit_dr = NULL;

                p_link_node = FIB_GET_LINK_NODE_FROM_NH_HOLDER (nh_holder);

                fib_del_dr_dep_nh (p_less_specific_dr, p_link_node);

                fib_mark_nh_for_resolution (p_nh);
            }
        }

        p_less_specific_dr = (t_fib_dr *)
            std_radix_getlessspecific (hal_rt_access_fib_vrf_dr_tree(vrf_id, af_index),
                                     (std_rt_head *)(&p_less_specific_dr->radical));
    }

    return STD_ERR_OK;
}

int fib_proc_dr_degeneration (t_fib_dr *p_dr)
{
    t_fib_nh        *p_fh = NULL;
    t_fib_nh_holder  nh_holder;
    bool             is_route_added = false;
    dn_hal_route_err    hal_err = DN_HAL_ROUTE_E_NONE;
    t_fib_tunnel_fh *p_tunnel_fh = NULL;
    bool             is_tunnel_fh = false;

    if (!p_dr)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_dr: %p",
                   __FUNCTION__, p_dr);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
               "status_flag: 0x%x", p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
               p_dr->prefix_len, p_dr->status_flag);

    p_dr->status_flag |= FIB_DR_STATUS_DEGENERATED;

    FIB_FOR_EACH_FH_FROM_DR (p_dr, p_fh, nh_holder)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                   "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
                   "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x",
                   p_dr->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                   p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                   p_fh->key.if_index);


        if (((FIB_IS_NH_WRITTEN (p_fh)) &&
             (p_fh->p_arp_info->state == FIB_ARP_RESOLVED)) ||
            (is_tunnel_fh == true))
        {
            fib_add_dr_degen_fh (p_dr, p_fh, p_tunnel_fh);

            hal_err = hal_fib_route_add (p_dr->vrf_id, p_dr);

            if (hal_err == DN_HAL_ROUTE_E_NONE)
            {
                if (!(FIB_IS_DR_WRITTEN (p_dr)))
                {
                    fib_check_threshold_for_all_cams (true);

                    p_dr->status_flag |= FIB_DR_STATUS_WRITTEN;

                    FIB_INCR_CNTRS_CAM_ROUTE_ENTRIES (p_dr->vrf_id,
                                                      p_dr->key.prefix.af_index);
                }

                is_route_added = true;

                break;
            }
            else
            {
                HAL_RT_LOG_DEBUG("HAL-RT-DR",
                           "Error: hal_fib_route_add. "
                           "vrf_id: %d, prefix: %s, prefix_len: %d, "
                           "hal_err: %d (%s)", p_dr->vrf_id,
                           FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                           p_dr->prefix_len, hal_err,
                           HAL_RT_GET_ERR_STR (hal_err));

                fib_del_dr_degen_fh (p_dr);
            }
        }
    }

    /*
     * If none of the FHs were written, then point the route
     * to the CPU.
     */
    if (is_route_added == false)
    {
        /*
         * If FIB_DR_STATUS_DEGENERATED flag is set and 'degen_dr_fh' in
         * DR node is NULL, then the HAL layer would point the route
         * to the CPU.
         */
        fib_add_dr_degen_fh (p_dr, NULL, NULL);

        hal_err = hal_fib_route_add (p_dr->vrf_id, p_dr);

        if (hal_err == DN_HAL_ROUTE_E_NONE)
        {
            if (!(FIB_IS_DR_WRITTEN (p_dr)))
            {
                fib_check_threshold_for_all_cams (true);

                p_dr->status_flag |= FIB_DR_STATUS_WRITTEN;

                FIB_INCR_CNTRS_CAM_ROUTE_ENTRIES (p_dr->vrf_id,
                                                  p_dr->key.prefix.af_index);
            }
        }
        else
        {
            HAL_RT_LOG_DEBUG("HAL-RT-DR",
                       "Error: hal_fib_route_add. "
                       "vrf_id: %d, prefix: %s, prefix_len: %d, "
                       "hal_err: %d (%s)", p_dr->vrf_id,
                       FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                       hal_err, HAL_RT_GET_ERR_STR (hal_err));

            if (FIB_IS_DR_WRITTEN (p_dr))
            {
                p_dr->status_flag &= ~FIB_DR_STATUS_WRITTEN;

                FIB_DECR_CNTRS_CAM_ROUTE_ENTRIES (p_dr->vrf_id,
                                                  p_dr->key.prefix.af_index);
            }
        }
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
               "status_flag: 0x%x",
               p_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
               p_dr->prefix_len, p_dr->status_flag);

    return STD_ERR_OK;
}

int fib_mark_dr_for_resolution (t_fib_dr *p_dr)
{
    uint8_t   af_index = 0;
    uint32_t  vrf_id = 0;

    if (!p_dr)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                   "Invalid input param. p_dr: %p",
                   p_dr);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    if (!(p_dr->status_flag & FIB_DR_STATUS_ADD)) {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                   "DR: Skipping route programming to walker. "
                   "vrf_id: %d, prefix: %s, prefix_len: %d, "
                   "status_flag: 0x%x", p_dr->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                   p_dr->prefix_len, p_dr->status_flag);

        return STD_ERR_OK;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
               "status_flag: 0x%x", p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
               p_dr->prefix_len, p_dr->status_flag);

    p_dr->status_flag |= FIB_DR_STATUS_REQ_RESOLVE;

    af_index = p_dr->key.prefix.af_index;
    vrf_id   = p_dr->vrf_id;

    std_radical_appendtochangelist (hal_rt_access_fib_vrf_dr_tree(vrf_id, af_index),
                                  (std_radical_head_t *)&(p_dr->radical));


    //fib_resume_dr_walker_thread (af_index);

    return STD_ERR_OK;
}

int fib_mark_dr_dep_nh_for_resolution (t_fib_dr *p_dr)
{
    t_fib_nh       *p_nh = NULL;
    t_fib_nh_holder nh_holder;

    if (!p_dr)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_dr: %p",
                   __FUNCTION__, p_dr);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
               "status_flag: 0x%x", p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
               p_dr->prefix_len, p_dr->status_flag);

    FIB_FOR_EACH_DEP_NH_FROM_DR (p_dr, p_nh, nh_holder)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                   "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
                   "Dep NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x",
                   p_dr->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                   p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                   p_nh->key.if_index);


        fib_mark_nh_for_resolution (p_nh);
    }

    return STD_ERR_OK;
}

int fib_resume_dr_walker_thread (uint8_t af_index)
{
    int retval;

    pthread_mutex_lock( &fib_dr_mutex );
    is_dr_pending_for_processing = 1; //set the predicate for signal
    if((retval = pthread_cond_signal( &fib_dr_cond )) != 0) {
        HAL_RT_LOG_DEBUG("HAL-RT-DR", "pthread cond signal failed %d", retval);
    }
    pthread_mutex_unlock( &fib_dr_mutex );
    return STD_ERR_OK;
}

int fib_update_route_summary (uint32_t vrf_id, uint8_t af_index,
                           uint8_t prefix_len, bool action)
{
    t_fib_route_summary   *p_route_summary = NULL;

    p_route_summary = FIB_GET_ROUTE_SUMMARY (vrf_id, af_index);

    if (p_route_summary == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): action:%d Route summary NULL. "
                   "vrf_id: %d, af_index: %d",
                   __FUNCTION__, action, vrf_id, af_index);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    if (action == true)
    {
        p_route_summary->a_curr_count [prefix_len] ++;
    }
    else
    {
        if ((p_route_summary->a_curr_count [prefix_len]) > 0)
        {
            p_route_summary->a_curr_count [prefix_len] --;
        }
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "vrf_id: %d, af_index: %d, prefix_len: %d, "
               "a_curr_count: %d", vrf_id, af_index,
               prefix_len, p_route_summary->a_curr_count [prefix_len]);
    return STD_ERR_OK;
}

bool hal_rt_handle_ip_unreachable_config (t_fib_intf_ip_unreach_config *p_cfg, bool *p_os_gbl_cfg_req) {
    uint32_t vrf_id = FIB_DEFAULT_VRF;
    bool is_intf_present = false;
    t_fib_intf *p_db_intf = NULL;

    *p_os_gbl_cfg_req = false;
    HAL_RT_LOG_INFO("HAL-RT-CATCH_ALL", "IP unreachable VRF:%s is_del:%d if-index:%d af:%d vrf:%d",
                    (p_cfg->vrf_name ? p_cfg->vrf_name : ""),
                    p_cfg->is_op_del, p_cfg->if_index, p_cfg->af_index, vrf_id);

    if (hal_rt_get_vrf_id(p_cfg->vrf_name, &vrf_id) == false) {
        HAL_RT_LOG_ERR("HAL-RT-CATCH_ALL", "IP unreachable VRF-id get failed from name:%s if-index:%d af:%d ",
                       (p_cfg->vrf_name ? p_cfg->vrf_name : ""),
                       p_cfg->if_index, p_cfg->af_index);
        return false;
    }
    p_db_intf = fib_get_or_create_intf(p_cfg->if_index, vrf_id,
                                       p_cfg->af_index, &is_intf_present);
    if (!p_db_intf) {
        HAL_RT_LOG_ERR("HAL-RT-CATCH_ALL", "IP unreachable if-index:%d af:%d vrf:%d update failed!",
                       p_cfg->if_index, p_cfg->af_index, vrf_id);
        return false;
    }

    if (p_cfg->is_op_del == true) {
        if (((p_cfg->af_index == HAL_RT_V4_AFINDEX) && (!(p_db_intf->is_ipv4_unreachables_set))) ||
            ((p_cfg->af_index == HAL_RT_V6_AFINDEX) && (!(p_db_intf->is_ipv6_unreachables_set)))) {
            HAL_RT_LOG_ERR("HAL-RT-CATCH_ALL", "Duplicate IP unreachable if-index:%d af:%d vrf:%d "
                           "is_del:%d ipv4_unre_set:%d ipv6_unre_set:%d",
                           p_cfg->if_index, p_cfg->af_index, vrf_id, p_cfg->is_op_del,
                           p_db_intf->is_ipv4_unreachables_set, p_db_intf->is_ipv6_unreachables_set);
            return false;
        }
    } else {
        if (((p_cfg->af_index == HAL_RT_V4_AFINDEX) && (p_db_intf->is_ipv4_unreachables_set)) ||
            ((p_cfg->af_index == HAL_RT_V6_AFINDEX) && (p_db_intf->is_ipv6_unreachables_set))) {
            HAL_RT_LOG_ERR("HAL-RT-CATCH_ALL", "Duplicate IP unreachable if-index:%d af:%d vrf:%d "
                           "is_del:%d ipv4_unre_set:%d ipv6_unre_set:%d",
                           p_cfg->if_index, p_cfg->af_index, vrf_id, p_cfg->is_op_del,
                           p_db_intf->is_ipv4_unreachables_set, p_db_intf->is_ipv6_unreachables_set);
            return false;
        }
    }

    if (p_cfg->af_index == HAL_RT_V4_AFINDEX)
        p_db_intf->is_ipv4_unreachables_set = ((p_cfg->is_op_del) ? false : true);
    else if (p_cfg->af_index == HAL_RT_V6_AFINDEX)
        p_db_intf->is_ipv6_unreachables_set = ((p_cfg->is_op_del) ? false : true);

    if (p_cfg->is_op_del) {
        HAL_RT_LOG_INFO("HAL-RT-CATCH_ALL", "IP unreachable del if-index:%d af:%d "
                        "vrf:%d catch-all-cnt:%d",
                        p_cfg->if_index, p_cfg->af_index,
                        vrf_id, FIB_GET_CNTRS_CATCH_ALL_ENTRIES(vrf_id, p_cfg->af_index));
        FIB_DECR_CNTRS_CATCH_ALL_ENTRIES(vrf_id, p_cfg->af_index);
        if (FIB_GET_CNTRS_CATCH_ALL_ENTRIES(vrf_id, p_cfg->af_index) != 0) {
            return true;
        }
        *p_os_gbl_cfg_req = true;
        /* If all ip-unreachable interfaces deleted from the VRF and address family i.e
         * last interface delete configuration from the user,
         * delete the FIB default route if present. */
    } else {
        HAL_RT_LOG_INFO("HAL-RT-CATCH_ALL", "IP unreachable add if-index:%d af:%d "
                        "vrf:%d catch-all-cnt:%d",
                        p_cfg->if_index, p_cfg->af_index,
                        vrf_id, FIB_GET_CNTRS_CATCH_ALL_ENTRIES(vrf_id, p_cfg->af_index));
        FIB_INCR_CNTRS_CATCH_ALL_ENTRIES(vrf_id, p_cfg->af_index);
        if (FIB_GET_CNTRS_CATCH_ALL_ENTRIES(vrf_id, p_cfg->af_index) != 1) {
            return true;
        }
        *p_os_gbl_cfg_req = true;
        /* First ip-unreachable with interface configuration from the user,
         * install the default route (catch all) FIB into the NPU to lift
         * all the non-routable packets to CPU to generate the ICMP unreachable messages
         * on the configured interface if RTM default route is not present. */
    }

    t_fib_ip_addr ip_addr;
    memset (&ip_addr, 0, sizeof (t_fib_ip_addr));
    ip_addr.af_index = p_cfg->af_index;

    t_fib_dr *p_dr = fib_get_dr (vrf_id, &ip_addr, 0);
    if (p_dr != NULL) {
        if (FIB_IS_DEFAULT_DR_OWNER_RTM (p_dr)) {
            /* There is a default route installed by RTM, dont add/del the catchall entry */
            HAL_RT_LOG_INFO("HAL-RT-CATCH_ALL", "RTM default route already exists! "
                            "if-index:%d af:%d vrf:%d", p_cfg->if_index, p_cfg->af_index, vrf_id);
            return true;
        } else if ((p_cfg->is_op_del) && (FIB_IS_DEFAULT_DR_OWNER_FIB (p_dr))) {
            HAL_RT_LOG_INFO("HAL-RT-CATCH_ALL", "IP unreachable default route del "
                           "if-index:%d af:%d vrf:%d",
                           p_cfg->if_index, p_cfg->af_index, vrf_id);
            p_dr->status_flag |= FIB_DR_STATUS_DEL;
            fib_proc_dr_del(p_dr);
        }
    } else if (!(p_cfg->is_op_del)) {
        HAL_RT_LOG_INFO("HAL-RT-CATCH_ALL", "IP unreachable adding defaut route "
                        "if-index:%d af:%d vrf:%d", p_cfg->if_index,
                        p_cfg->af_index, vrf_id);
        fib_add_default_dr (vrf_id, p_cfg->af_index);
    }

    if (p_cfg->is_op_del) {
        /* Check if the interface delete is waiting
         * for the IP unreachable config reset */
        fib_check_and_delete_intf(p_db_intf);
    }
    return true;
}


bool hal_rt_form_neigh_flush_msg (t_fib_offload_msg *p_offload_msg, t_fib_dr *p_dr, bool is_neigh_flush_with_intf, hal_ifindex_t if_index)
{
    t_fib_offload_msg_neigh_flush *flush_msg = &(p_offload_msg->neigh_flush_msg);

    memset (p_offload_msg, 0, sizeof (t_fib_offload_msg));
    p_offload_msg->type = FIB_OFFLOAD_MSG_TYPE_NEIGH_FLUSH;

    flush_msg->vrf_id = p_dr->vrf_id;
    memcpy (&flush_msg->prefix, &p_dr->key.prefix, sizeof (p_dr->key.prefix));
    flush_msg->prefix_len = p_dr->prefix_len;
    flush_msg->is_neigh_flush_with_intf = is_neigh_flush_with_intf;
    if (is_neigh_flush_with_intf)
        flush_msg->if_index = if_index;

    safestrncpy(flush_msg->vrf_name,
                (const char *)FIB_GET_VRF_NAME (p_dr->vrf_id, p_dr->key.prefix.af_index),
                sizeof(flush_msg->vrf_name));

    HAL_RT_LOG_DEBUG("HAL-RT-OFF", " Neigh flush message for "
                     "vrf: %s(%d), prefix: %s, prefix_len: %d "
                     "flush_with_intf: %s, if_index: %d", flush_msg->vrf_name, flush_msg->vrf_id,
                     FIB_IP_ADDR_TO_STR (&flush_msg->prefix), flush_msg->prefix_len,
                     (flush_msg->is_neigh_flush_with_intf ? "true":"false"), flush_msg->if_index);

    return true;
}
