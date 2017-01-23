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
 * \file   hal_rt_dr.c
 * \brief  Hal Routing DR functionality
 * \date   05-2014
 * \author Prince Sunny & Satish Mynam
 */

#include "hal_rt_main.h"
#include "hal_rt_mem.h"
#include "hal_rt_route.h"
#include "hal_rt_util.h"
#include "hal_rt_api.h"
#include "hal_rt_debug.h"
#include "hal_rt_mem.h"

#include "event_log.h"
#include "std_ip_utils.h"

#include "cps_api_interface_types.h"
#include "cps_api_events.h"
#include "cps_api_route.h"

#include <string.h>
#include <stdio.h>
#include <pthread.h>

pthread_mutex_t fib_dr_mutex;
pthread_cond_t  fib_dr_cond;
static bool     is_dr_pending_for_processing = 0; //initialize the predicate for signal

#define ROUTE_NEXT_HOP_DEF_WEIGHT (10)

void hal_rt_cps_obj_to_route(cps_api_object_t obj, t_fib_route_entry *r) {
    memset(r,0,sizeof(*r));
    cps_api_object_attr_t list[cps_api_if_ROUTE_A_MAX];
    char buff[1000], buff1[1000];

    cps_api_object_attr_fill_list(obj,0,list,sizeof(list)/sizeof(*list));

    if (list[cps_api_if_ROUTE_A_MSG_TYPE]!=NULL)
        r->msg_type = cps_api_object_attr_data_u32(list[cps_api_if_ROUTE_A_MSG_TYPE]);
    if (list[cps_api_if_ROUTE_A_DISTANCE]!=NULL)
        r->distance = cps_api_object_attr_data_u32(list[cps_api_if_ROUTE_A_DISTANCE]);
    if (list[cps_api_if_ROUTE_A_PROTOCOL]!=NULL)
        r->protocol = cps_api_object_attr_data_u32(list[cps_api_if_ROUTE_A_PROTOCOL]);
    if (list[cps_api_if_ROUTE_A_VRF]!=NULL)
        r->vrfid = cps_api_object_attr_data_u32(list[cps_api_if_ROUTE_A_VRF]);

    if (list[cps_api_if_ROUTE_A_PREFIX]!=NULL) {
        r->prefix = *(hal_ip_addr_t*)cps_api_object_attr_data_bin(list[cps_api_if_ROUTE_A_PREFIX]);
    } else if (list[cps_api_if_ROUTE_A_FAMILY]!=NULL) {
        r->prefix.af_index = cps_api_object_attr_data_u32(list[cps_api_if_ROUTE_A_FAMILY]);
    }
    if (list[cps_api_if_ROUTE_A_PREFIX_LEN]!=NULL)
        r->prefix_masklen = cps_api_object_attr_data_u32(list[cps_api_if_ROUTE_A_PREFIX_LEN]);
   if (list[cps_api_if_ROUTE_A_NH_IFINDEX]!=NULL)
        r->nh_if_index = cps_api_object_attr_data_u32(list[cps_api_if_ROUTE_A_NH_IFINDEX]);
    if (list[cps_api_if_ROUTE_A_NEXT_HOP_VRF]!=NULL)
        r->nh_vrfid = cps_api_object_attr_data_u32(list[cps_api_if_ROUTE_A_NEXT_HOP_VRF]);
    if (list[cps_api_if_ROUTE_A_NEXT_HOP_ADDR]!=NULL)
        r->nh_addr = *(hal_ip_addr_t*)cps_api_object_attr_data_bin(list[cps_api_if_ROUTE_A_NEXT_HOP_ADDR]);

    if (list[cps_api_if_ROUTE_A_HOP_COUNT]!=NULL)
           r->hop_count = cps_api_object_attr_data_u32(list[cps_api_if_ROUTE_A_HOP_COUNT]);

    /*
     * If multiple NHs are present, check cps_api_if_ROUTE_A_NH attribute
     */
    if (list[cps_api_if_ROUTE_A_NH]) {
       cps_api_object_it_t nhit;
       cps_api_object_it_from_attr(list[cps_api_if_ROUTE_A_NH],&nhit);
       cps_api_object_it_inside(&nhit);
       size_t hop = 0;
       for ( ; cps_api_object_it_valid(&nhit) ;
               cps_api_object_it_next(&nhit), ++hop) {
           cps_api_object_it_t node = nhit;
           cps_api_object_it_inside(&node);
           r->nh_list[hop].nh_weight = ROUTE_NEXT_HOP_DEF_WEIGHT;
           for ( ; cps_api_object_it_valid(&node) ;
                   cps_api_object_it_next(&node)) {

               switch(cps_api_object_attr_id(node.attr)) {
               case cps_api_if_ROUTE_A_NH_IFINDEX:
                   r->nh_list[hop].nh_if_index = cps_api_object_attr_data_u32(node.attr);
                   break;
               case cps_api_if_ROUTE_A_NEXT_HOP_ADDR:
                   r->nh_list[hop].nh_addr = *(hal_ip_addr_t*)cps_api_object_attr_data_bin(node.attr);

                   HAL_RT_LOG_DEBUG("HAL-RT-DR(CPS): ",
                           "Prefix:%s NH(%d): %s, nhIndex %d \r\n",
                           std_ip_to_string(&r->prefix,buff,sizeof(buff)), hop,
                           std_ip_to_string(&r->nh_list[hop].nh_addr, buff1,
                           sizeof(buff1)), hop);

                   break;
               case cps_api_if_ROUTE_A_NEXT_HOP_WEIGHT:
                   r->nh_list[hop].nh_weight = cps_api_object_attr_data_u32(node.attr);
                   break;
               default:
                   break;
               }

           }
        }
    }
}

int fib_create_dr_tree (t_fib_vrf_info *p_vrf_info)
{
    char tree_name_str [FIB_RDX_MAX_NAME_LEN];

    if (!p_vrf_info)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR", "%s (): Invalid input param. p_vrf_info: %p\r\n",
                   __FUNCTION__, p_vrf_info);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR", "Vrf_id: %d, af_index: %s\r\n",
                p_vrf_info->vrf_id,
               STD_IP_AFINDEX_TO_STR (p_vrf_info->af_index));

    if (p_vrf_info->dr_tree != NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR", "DR tree already created. "
                   "vrf_id: %d, af_index: %d\r\n",
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
                   "af_index: %s\r\n", __FUNCTION__, p_vrf_info->vrf_id,
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
                   "%s (): Invalid input param. p_vrf_info: %p\r\n",
                   __FUNCTION__, p_vrf_info);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    if (p_vrf_info->dr_tree == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): DR tree not present. "
                   "vrf_id: %d, af_index: %d\r\n",
                   __FUNCTION__, p_vrf_info->vrf_id, p_vrf_info->af_index);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    std_radix_destroy (p_vrf_info->dr_tree);

    p_vrf_info->dr_tree = NULL;

    return STD_ERR_OK;
}

int fib_proc_dr_download (t_fib_route_entry *p_rt_entry)
{
    int           ix,nh_info_size = 0;
    uint32_t      vrf_id = 0;
    uint8_t       af_index = 0;
    bool          rt_change = false, is_rt_replace = false;
    hal_ifindex_t nh_if_index = 0;

    vrf_id   = p_rt_entry->vrfid;
    af_index = HAL_RT_ADDR_FAM_TO_AFINDEX(p_rt_entry->prefix.af_index);

    HAL_RT_LOG_INFO("HAL-RT", "Route %s vrf_id %d, af-index %d"
                    " prefix %s/%d distance %d\r\n",
                    ((p_rt_entry->msg_type == ROUTE_ADD) ? "Add" :
                     ((p_rt_entry->msg_type == ROUTE_DEL) ? "Del" : "Update")),
                    vrf_id, af_index, FIB_IP_ADDR_TO_STR(&p_rt_entry->prefix),
                    p_rt_entry->prefix_masklen, p_rt_entry->hop_count, p_rt_entry->distance);

    /*
     * Check for ECMP NHs and check for nh_if_index appropriately
     * either single NH case or multiple NH  case got from nh_list
     * (currently the cps_linux_api sends single NH and nhlist[] separately)
     */

    for (ix=0; ix<p_rt_entry->hop_count; ix++) {
        nh_if_index = p_rt_entry->nh_list[ix].nh_if_index;
        if(hal_rt_validate_intf(nh_if_index) != STD_ERR_OK) {

            HAL_RT_LOG_INFO("HAL-RT", "Invalid interface, so skipping route add. msg_type: %d vrf_id %d, af-index %d"
                        " nh_count %d addr:%s on if_index %d\r\n",
                        p_rt_entry->msg_type, vrf_id, af_index, p_rt_entry->hop_count,
                        FIB_IP_ADDR_TO_STR(&p_rt_entry->prefix), nh_if_index);
            return STD_ERR_OK;
        }
    }

    HAL_RT_LOG_DEBUG("HAL-RT", "type: %d vrf_id %d, af-index %d"
            " route count %d, nh_count %d distance %d\r\n", p_rt_entry->msg_type,
            vrf_id, af_index, 1, p_rt_entry->hop_count, p_rt_entry->distance);

    if (!(FIB_IS_VRF_ID_VALID (vrf_id))) {
        HAL_RT_LOG_ERR("HAL-RT-DR", "%s (): Invalid vrf_id. vrf_id: %d\r\n",
                   __FUNCTION__, vrf_id);
        return STD_ERR_OK;
    }

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
        case ROUTE_UPD:
            is_rt_replace = true;
        case ROUTE_ADD:
            FIB_INCR_CNTRS_ROUTE_ADD (vrf_id, af_index);
            fib_proc_dr_add_msg (af_index, p_rt_entry, &nh_info_size, is_rt_replace);
            rt_change = true;
            break;

        case ROUTE_DEL:
            FIB_INCR_CNTRS_ROUTE_DEL (vrf_id, af_index);
            fib_proc_dr_del_msg (af_index, p_rt_entry);
            rt_change = true;
            break;
        default:
            HAL_RT_LOG_ERR("HAL-RT-DR", "%s (): Invalid case. \r\n", __FUNCTION__);
            break;
    }
    if(rt_change) {
        fib_resume_dr_walker_thread (af_index);
    }

    return STD_ERR_OK;
}

int fib_proc_dr_add_msg (uint8_t af_index, void *p_rtm_fib_cmd, int *p_nh_info_size, bool is_rt_replace)
{
    t_fib_dr           *p_dr = NULL;
    t_fib_dr_msg_info   dr_msg_info;

    if (!p_rtm_fib_cmd) {
        HAL_RT_LOG_ERR("HAL-RT-DR", "%s (): Invalid input param. p_rtm_fib_cmd: %p\r\n",
                   __FUNCTION__, p_rtm_fib_cmd);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    memset (&dr_msg_info, 0, sizeof (dr_msg_info));

    fib_form_dr_msg_info (af_index, p_rtm_fib_cmd, &dr_msg_info);

    HAL_RT_LOG_DEBUG("HAL-RT-DR(RT-START)",
               "vrf_id: %d, prefix: %s, prefix_len: %d, proto: %d\r\n",
                dr_msg_info.vrf_id,
               FIB_IP_ADDR_TO_STR (&dr_msg_info.prefix), dr_msg_info.prefix_len,
               dr_msg_info.proto);

    if (!(FIB_IS_VRF_ID_VALID (dr_msg_info.vrf_id)))
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid vrf_id. vrf_id: %d\r\n",
                   __FUNCTION__, dr_msg_info.vrf_id);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    if (!(FIB_IS_PREFIX_LEN_VALID (af_index, dr_msg_info.prefix_len)))
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid prefix length. "
                   "prefix_len: %d\r\n", __FUNCTION__,
                   dr_msg_info.prefix_len);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    nas_l3_lock();

    p_dr = fib_get_dr (dr_msg_info.vrf_id, &dr_msg_info.prefix, dr_msg_info.prefix_len);

    if (p_dr == NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                   "Adding DR. vrf_id: %d, prefix: %s, "
                   "prefix_len: %d\r\n",
                   dr_msg_info.vrf_id,
                   FIB_IP_ADDR_TO_STR (&dr_msg_info.prefix),
                   dr_msg_info.prefix_len);

        p_dr = fib_add_dr (dr_msg_info.vrf_id, &dr_msg_info.prefix,
                        dr_msg_info.prefix_len);

        if (p_dr == NULL)
        {
            HAL_RT_LOG_ERR("HAL-RT-DR",
                       "%s (): DR addition failed. vrf_id: %d, prefix: %s, "
                       "prefix_len: %d\r\n", __FUNCTION__,
                       dr_msg_info.vrf_id,
                       FIB_IP_ADDR_TO_STR (&dr_msg_info.prefix),
                       dr_msg_info.prefix_len);

            nas_l3_unlock();
            return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
        }

        std_dll_init (&p_dr->nh_list);
        std_dll_init (&p_dr->fh_list);
        std_dll_init (&p_dr->dep_nh_list);
        std_dll_init (&p_dr->degen_dr_fh.tunnel_fh_list);

        FIB_INCR_CNTRS_FIB_ROUTE_ENTRIES (dr_msg_info.vrf_id, af_index);

        fib_update_route_summary (dr_msg_info.vrf_id, af_index,
                               dr_msg_info.prefix_len, true);
    }

    p_dr->vrf_id = dr_msg_info.vrf_id;
    p_dr->proto = dr_msg_info.proto;

    p_dr->last_update_time = fib_tick_get ();

    /*
     * @Todo - Temporary work-around to support IPv6 ECMP
     * Multiple Add requests for the same IPv6 routes are treated as ECMP
     * The following command triggered route replace is handled in the ROUTE_UPD route type
     * "ip -6 route change", "ip -6 route replace"
     */
    if(is_rt_replace || (STD_IP_IS_AFINDEX_V4 (af_index))) {
        fib_delete_all_dr_nh (p_dr);
        fib_delete_all_dr_fh (p_dr);
    }

    fib_proc_dr_nh_add (p_dr, p_rtm_fib_cmd, p_nh_info_size);

    fib_updt_best_fit_dr_of_affected_nh (p_dr);

    if (FIB_IS_DR_DEFAULT (p_dr))
    {
        p_dr->default_dr_owner = FIB_DEFAULT_DR_OWNER_RTM;
    }
    fib_mark_dr_for_resolution (p_dr);

    nas_l3_unlock();

    return STD_ERR_OK;
}

int fib_proc_dr_del_msg (uint8_t af_index, void *p_rtm_fib_cmd)
{
    t_fib_dr           *p_dr = NULL;
    t_fib_dr_msg_info   dr_msg_info;

    if (!p_rtm_fib_cmd)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_rtm_fib_cmd: %p\r\n",
                   __FUNCTION__, p_rtm_fib_cmd);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    memset (&dr_msg_info, 0, sizeof (dr_msg_info));

    fib_form_dr_msg_info (af_index, p_rtm_fib_cmd, &dr_msg_info);

    HAL_RT_LOG_DEBUG("HAL-RT-DR(RT-START)",
               "vrf_id: %d, prefix: %s, prefix_len: %d, proto: %d\r\n",
                dr_msg_info.vrf_id,
               FIB_IP_ADDR_TO_STR (&dr_msg_info.prefix), dr_msg_info.prefix_len,
               dr_msg_info.proto);

    if (!(FIB_IS_VRF_ID_VALID (dr_msg_info.vrf_id)))
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid vrf_id. vrf_id: %d\r\n",
                   __FUNCTION__, dr_msg_info.vrf_id);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    if (!(FIB_IS_PREFIX_LEN_VALID (af_index, dr_msg_info.prefix_len)))
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid prefix length. "
                   "prefix_len: %d\r\n", __FUNCTION__,
                   dr_msg_info.prefix_len);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    nas_l3_lock();

    p_dr = fib_get_dr (dr_msg_info.vrf_id, &dr_msg_info.prefix, dr_msg_info.prefix_len);

    if (p_dr == NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                   "DR not found. vrf_id: %d, prefix: %s, "
                   "prefix_len: %d\r\n",
                   dr_msg_info.vrf_id,
                   FIB_IP_ADDR_TO_STR (&dr_msg_info.prefix),
                   dr_msg_info.prefix_len);

        nas_l3_unlock();
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    /*
     * @@TODO - Temporary work-around to support IPv6 ECMP
     * Kernel is notifying the IPv6 route del with particular NH
     * even when there are NHs present in the route. so, the below workaround is added
     * to consider this route del as route add with remaining valid NH(s).
     * Note: This behavior is different in IPv4.
     */

    HAL_RT_LOG_DEBUG("HAL-RT-DR(RT-START)",
                 "vrf_id:%d, prefix:%s, prefix_len:%d, proto:%d curr-nh-cnt:%d nh-cnt:%d\r\n",
                 dr_msg_info.vrf_id,
                 FIB_IP_ADDR_TO_STR (&dr_msg_info.prefix), dr_msg_info.prefix_len,
                 dr_msg_info.proto, p_dr->num_nh , ((t_fib_route_entry  *)p_rtm_fib_cmd)->hop_count);

    if (FIB_IS_AFINDEX_V6 (af_index) &&  (((t_fib_route_entry  *)p_rtm_fib_cmd)->hop_count == 1) &&
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

        fib_mark_dr_for_resolution (p_dr);

        nas_l3_unlock();

        return STD_ERR_OK;
    }
    // TODO This needs to revisited to handle the DR del in the DR walker
    // p_dr->status_flag |= FIB_DR_STATUS_DEL;
    // fib_mark_dr_for_resolution (p_dr);
    fib_proc_dr_del (p_dr);

    nas_l3_unlock();

    fib_resume_nh_walker_thread(af_index);

    return STD_ERR_OK;
}

int fib_proc_dr_del (t_fib_dr *p_dr)
{
    dn_hal_route_err  hal_err = DN_HAL_ROUTE_E_NONE;
    uint32_t      vrf_id = 0;
    uint8_t       af_index = 0;
    t_fib_nh     *p_nh;
    t_fib_nh_key  key;
    t_fib_nh_holder nh_holder;
    t_fib_nh     *p_fh = NULL;
    bool          rif_del = false;
    hal_ifindex_t if_index;

    if (!p_dr)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_dr: %p\r\n",
                   __FUNCTION__, p_dr);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
               p_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len);

    p_fh = FIB_GET_FIRST_NH_FROM_DR(p_dr, nh_holder);
    if (p_fh && FIB_IS_NH_ZERO(p_fh)) {
        if_index = p_fh->key.if_index;
        if(!hal_rt_rif_ref_dec(if_index))
            rif_del = true;
    }

    fib_mark_dr_dep_nh_for_resolution (p_dr);

    fib_delete_all_dr_nh (p_dr);

    fib_delete_all_dr_fh (p_dr);

    fib_delete_all_dr_dep_nh (p_dr);

    fib_del_dr_degen_fh (p_dr);

    if (FIB_IS_DR_WRITTEN (p_dr))
    {
        hal_err = hal_fib_route_del (p_dr->vrf_id, p_dr);

        if (hal_err == DN_HAL_ROUTE_E_NONE)
        {
            if(rif_del)
                hal_rif_index_remove(0, p_dr->vrf_id, if_index);

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
                                    "is available for resolution Vrf_id: %d, prefix %s/%d\r\n",
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
                       "hal_err: %d (%s)\r\n",  p_dr->vrf_id,
                       FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                       hal_err, HAL_RT_GET_ERR_STR (hal_err));
        }
    }

    FIB_DECR_CNTRS_FIB_ROUTE_ENTRIES (p_dr->vrf_id, p_dr->key.prefix.af_index);

    fib_update_route_summary (p_dr->vrf_id, p_dr->key.prefix.af_index,
                           p_dr->prefix_len, false);

    if ((FIB_IS_DR_DEFAULT (p_dr)) &&
        (FIB_IS_DEFAULT_DR_OWNER_RTM (p_dr)))
    {
        vrf_id   = p_dr->vrf_id;
        af_index = p_dr->key.prefix.af_index;

        fib_del_dr (p_dr);

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

    if ((!p_dr) || (!p_rtm_fib_cmd) || (!p_nh_info_size)) {
        HAL_RT_LOG_ERR("HAL-RT-DR", "%s (): Invalid input param. p_dr: %p,"
                   "p_rtm_fib_cmd: %p, p_nh_info_size: %p\r\n", __FUNCTION__,
                   p_dr, p_rtm_fib_cmd, p_nh_info_size);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    af_index = p_dr->key.prefix.af_index;
    nh_count = ((t_fib_route_entry  *)p_rtm_fib_cmd)->hop_count;
    HAL_RT_LOG_DEBUG("HAL-RT-DR", "nh_count=%d vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
                    nh_count, p_dr->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len);

    /*
     *  Check all the nexthops (minimum is 1 NH) and if necessary form ECMP NH list
     */
    for (i=0 ; i < nh_count; i++) {

        fib_form_nh_msg_info (af_index, p_rtm_fib_cmd, &nh_msg_info, i);

        nh_if_index = nh_msg_info.if_index;

        p_nh = fib_proc_nh_add (nh_msg_info.vrf_id, &nh_msg_info.ip_addr,
                nh_msg_info.if_index, FIB_NH_OWNER_TYPE_RTM, 0);

        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                     "vrf_id: %d, ip_addr: %s, nh_loop_idx %d if_index: %d",
                      vrf_id, FIB_IP_ADDR_TO_STR (&nh_msg_info.ip_addr), i, nh_if_index);

        p_dr_nh = fib_add_dr_nh (p_dr, p_nh, 0, 0);

        if (p_dr_nh == NULL)
        {
            HAL_RT_LOG_ERR("HAL-RT-DR",
                    "%s (): DRNH Addition failed. "
                    "DR: vrfId: %ld, prefix: %s, prefixLen: %d, "
                    "NH: vrfId: %ld, ipAddr: %s, nhIndex %d ifIndex: 0x%lx\r\n",
                    __FUNCTION__, p_dr->vrf_id,
                    FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                    p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                    nh_count, p_nh->key.if_index);
            continue;

        }
        p_nh_dep_dr = fib_add_nh_dep_dr (p_nh, p_dr);

        if (p_nh_dep_dr == NULL)
        {
            HAL_RT_LOG_ERR("HAL-RT-DR",
                    "%s (): NHDep_dr Addition failed. "
                    "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
                    "NH: vrf_id: %d, ip_addr: %s, nhIndex %d if_index: 0x%x\r\n",
                    __FUNCTION__, p_dr->vrf_id,
                    FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                    p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                    nh_count, p_nh->key.if_index);
            continue;
        }
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
                   "p_rtm_fib_cmd: %p\r\n", __FUNCTION__,
                   p_dr, p_rtm_fib_cmd);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    af_index = p_dr->key.prefix.af_index;
    nh_count = ((t_fib_route_entry  *)p_rtm_fib_cmd)->hop_count;
    HAL_RT_LOG_DEBUG("HAL-RT-DR", "nh_count=%d vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
                    nh_count, p_dr->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len);

    /*
     *  Check all the nexthops (minimum is 1 NH) and if necessary form ECMP NH list
     */
    for (i=0 ; i < nh_count; i++) {

        fib_form_nh_msg_info (af_index, p_rtm_fib_cmd, &nh_msg_info, i);

        nh_if_index = nh_msg_info.if_index;
        p_nh = fib_get_nh (nh_msg_info.vrf_id, &nh_msg_info.ip_addr, nh_msg_info.if_index);
        if (p_nh == NULL) {
            continue;
        }

        fib_proc_nh_delete (p_nh, FIB_NH_OWNER_TYPE_RTM, 0);

        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                     "vrf_id: %d, ip_addr: %s, nh_loop_idx %d if_index: %d",
                      vrf_id, FIB_IP_ADDR_TO_STR (&nh_msg_info.ip_addr), i, nh_if_index);
        p_dr_nh = fib_get_dr_nh(p_dr, p_nh);
        if (p_dr_nh) {
            rc = fib_del_dr_nh (p_dr, p_dr_nh);
            if (rc != STD_ERR_OK)
            {
                HAL_RT_LOG_ERR("HAL-RT-DR",
                           "%s (): DRNH deletion failed. "
                           "DR: vrfId: %ld, prefix: %s, prefixLen: %d, "
                           "NH: vrfId: %ld, ipAddr: %s, nhIndex %d ifIndex: 0x%lx\r\n",
                           __FUNCTION__, p_dr->vrf_id,
                           FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                           p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                           nh_count, p_nh->key.if_index);
                continue;
            }
        }
        p_dr_fh = fib_get_dr_fh (p_dr, p_nh);
        if (p_dr_fh != NULL)
        {
            fib_del_dr_fh (p_dr, p_dr_fh);
        }

        p_nh_dep_dr = fib_get_nh_dep_dr(p_nh, p_dr);

        if (p_nh_dep_dr == NULL)
        {
            HAL_RT_LOG_ERR("HAL-RT-DR",
                    "%s (): NHDep_dr get failed. "
                    "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
                    "NH: vrf_id: %d, ip_addr: %s, nhIndex %d if_index: 0x%x\r\n",
                    __FUNCTION__, p_dr->vrf_id,
                    FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                    p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                    nh_count, p_nh->key.if_index);
            continue;
        }
        fib_del_nh_dep_dr(p_nh, p_nh_dep_dr);
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
                   "p_rtm_fib_cmd: %p, p_fib_dr_msg_info: %p\r\n",
                   __FUNCTION__, p_rtm_fib_cmd, p_fib_dr_msg_info);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR", "af_index: %d\r\n",  af_index);

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
    } else if (FIB_IS_AFINDEX_V6 (af_index)) {
        p_rtm_v6_fib_cmd = (t_fib_route_entry *)p_rtm_fib_cmd;

        memcpy (&p_fib_dr_msg_info->prefix.u.v6_addr,
                &p_rtm_v6_fib_cmd->prefix.u.v6_addr,
                HAL_RT_V6_ADDR_LEN);

        p_fib_dr_msg_info->prefix.af_index = af_index;

        p_fib_dr_msg_info->prefix_len = p_rtm_v6_fib_cmd->prefix_masklen;
        p_fib_dr_msg_info->vrf_id     = FIB_DEFAULT_VRF;
        p_fib_dr_msg_info->proto      = p_rtm_v6_fib_cmd->protocol;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR", "vrf_id: %d, prefix: %s, "
                "prefix_len: %d, proto: %d\r\n",p_fib_dr_msg_info->vrf_id,
                FIB_IP_ADDR_TO_STR (&p_fib_dr_msg_info->prefix),
                p_fib_dr_msg_info->prefix_len, p_fib_dr_msg_info->proto);

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
                   "p_rtm_nh_key: %p, p_fib_nh_msg_info: %p\r\n",
                   __FUNCTION__, p_rtm_nh_key, p_fib_nh_msg_info);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR", "af_index: %d\r\n",  af_index);

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
        p_fib_nh_msg_info->vrf_id   = p_rtm_v4NHKey->vrfid;
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
        p_fib_nh_msg_info->vrf_id   = p_rtm_v6NHKey->vrfid;
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
               "vrf_id: %d, ip_addr: %s, nh_index %d if_index: 0x%x\r\n",
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
                   "%s (): Invalid input param. p_tnl_dest : %p\r\n",
                   __FUNCTION__, p_tnl_dest);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    af_index = p_tnl_dest->dest_addr.af_index;

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "af_index: %d\r\n",  af_index);

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
               "vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
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
               "vrf_id: %d, af_index: %d\r\n",
                vrf_id, af_index);

    if (!(FIB_IS_VRF_ID_VALID (vrf_id)))
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid vrf_id. vrf_id: %d\r\n",
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
                   "vrf_id: %d, af_index: %d\r\n",
                   vrf_id, af_index);

        p_dr->default_dr_owner = FIB_DEFAULT_DR_OWNER_FIB;

        fib_mark_dr_for_resolution (p_dr);

        fib_resume_dr_walker_thread (af_index);

        return STD_ERR_OK;
    }

    p_dr = fib_add_dr (vrf_id, &ip_addr, 0);

    if (p_dr == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): DR addition failed. "
                   "vrf_id: %d, af_index: %d\r\n",
                   __FUNCTION__, vrf_id, af_index);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    std_dll_init (&p_dr->nh_list);
    std_dll_init (&p_dr->fh_list);
    std_dll_init (&p_dr->dep_nh_list);
    std_dll_init (&p_dr->degen_dr_fh.tunnel_fh_list);

    p_dr->vrf_id = vrf_id;

    p_dr->default_dr_owner = FIB_DEFAULT_DR_OWNER_FIB;

    FIB_INCR_CNTRS_FIB_ROUTE_ENTRIES (vrf_id, af_index);

    fib_update_route_summary (vrf_id, af_index, p_dr->prefix_len, true);

    fib_mark_dr_for_resolution (p_dr);

    fib_resume_dr_walker_thread (af_index);

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
                   "%s (): Invalid input param. p_prefix: %p\r\n",
                   __FUNCTION__, p_prefix);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
               vrf_id, FIB_IP_ADDR_TO_STR (p_prefix),
               prefix_len);

    p_dr = fib_alloc_dr_node ();

    if (p_dr == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Memory alloc failed. "
                   "vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
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
                   "vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
                   __FUNCTION__, vrf_id, FIB_IP_ADDR_TO_STR (p_prefix),
                   prefix_len);

        fib_free_dr_node (p_dr);
        return NULL;
    }

    if (p_radix_head != ((std_rt_head *)p_dr))
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                   "Duplicate radix insertion. "
                   "vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
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
                   "%s (): Invalid input param. p_prefix: %p\r\n",
                   __FUNCTION__, p_prefix);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
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
        HAL_RT_LOG_DEBUG("HAL-RT-DR", "vrf_id: %d, prefix: %s/%d, p_dr: %p\r\n",
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
               "vrf_id: %d, af_index: %d\r\n",
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
        HAL_RT_LOG_DEBUG("HAL-RT-DR", "vrf_id: %d, prefix: %s/%d\r\n",
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
                   "%s (): Invalid input param. p_prefix: %p\r\n",
                   __FUNCTION__, p_prefix);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
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
        HAL_RT_LOG_DEBUG("HAL-RT-DR", "vrf_id: %d, prefix: %s/%d\r\n",
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
                   "%s (): Invalid input param. p_dr: %p\r\n",
                   __FUNCTION__, p_dr);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
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
                      uint32_t nh_tlv_len)
{
    t_fib_dr_nh  *p_dr_nh = NULL;

    if ((!p_dr) ||
        (!p_nh))
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid input param. p_dr: %p, p_nh: %p\r\n",
                   __FUNCTION__, p_dr, p_nh);

        return NULL;
    }
    if (fib_get_dr_nh(p_dr, p_nh))
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                     "Duplicate Add - DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
                     "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                     "p_cur_nh_tlv: %p, nh_tlv_len: %d\r\n",
                     p_dr->vrf_id,
                     FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                     p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                     p_nh->key.if_index, p_cur_nh_tlv, nh_tlv_len);
        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "p_cur_nh_tlv: %p, nh_tlv_len: %d\r\n",
               p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
               p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
               p_nh->key.if_index, p_cur_nh_tlv, nh_tlv_len);

    if (nh_tlv_len > RT_PER_TLV_MAX_LEN)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Invalid nh_tlv_len. nh_tlv_len: %d\r\n",
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
                   "%s (): Memory alloc failed\r\n", __FUNCTION__);

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
               "nh_count: %d dr_ref_count: %d\r\n", p_nh->vrf_id,
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
                   "%s (): Invalid input param. p_dr: %p, p_nh: %p\r\n",
                   __FUNCTION__, p_dr, p_nh);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
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
                   "%s (): Invalid input param. p_dr: %p, p_dr_nh: %p\r\n",
                   __FUNCTION__, p_dr, p_dr_nh);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
               p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len);

    p_nh = p_dr_nh->link_node.self;

    if (p_nh != NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                   "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                   "dr_ref_count: %d\r\n", p_nh->vrf_id,
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
                   "%s (): Invalid input param. p_dr: %p\r\n",
                   __FUNCTION__, p_dr);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
               p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len);

    FIB_FOR_EACH_NH_FROM_DR (p_dr, p_nh, nh_holder)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                   "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
                   p_nh->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index);

        p_nh_dep_dr = fib_get_nh_dep_dr (p_nh, p_dr);

        if (p_nh_dep_dr != NULL)
        {
            fib_del_nh_dep_dr (p_nh, p_nh_dep_dr);
        }

        fib_proc_nh_delete (p_nh, FIB_NH_OWNER_TYPE_RTM, 0);

        p_dr_nh = FIB_GET_DRNH_NODE_FROM_NH_HOLDER (nh_holder);

        fib_del_dr_nh (p_dr, p_dr_nh);
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
                   "%s (): Invalid input param. p_dr: %p, p_fh: %p\r\n",
                   __FUNCTION__, p_dr, p_fh);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
               "FH: vrf_id: %d, ip_addr: %s, if_index: %d\r\n",
               p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
               p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
               p_fh->key.if_index);

    p_dr_fh = (t_fib_dr_fh *) FIB_DR_FH_MEM_MALLOC ();

    if (p_dr_fh == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Memory alloc failed\r\n", __FUNCTION__);

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
               "DR: num_fh: %d, FH: dr_ref_count: %d\r\n",
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
                   "%s (): Invalid input param. p_dr: %p, p_fh: %p\r\n",
                   __FUNCTION__, p_dr, p_fh);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
               "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
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
                   "%s (): Invalid input param. p_dr: %p, p_fh: %p\r\n",
                   __FUNCTION__, p_dr, p_fh);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
               "num_fh: %d\r\n", p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
               p_dr->num_fh);

    p_fh = p_dr_fh->link_node.self;

    if (p_fh != NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                   "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                   "dr_ref_count: %d\r\n",
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

            fib_check_and_delete_nh (p_fh);
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
                   "%s (): Invalid input param. p_dr: %p\r\n",
                   __FUNCTION__, p_dr);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
               p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len);

    FIB_FOR_EACH_FH_FROM_DR (p_dr, p_fh, nh_holder)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                   "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
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
                   "%s (): Invalid input param. p_dr: %p, p_nh: %p\r\n",
                   __FUNCTION__, p_dr, p_nh);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
               p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
               p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
               p_nh->key.if_index);

    p_link_node = (t_fib_link_node *) FIB_LINK_NODE_MEM_MALLOC ();

    if (p_link_node == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Memory alloc failed\r\n", __FUNCTION__);

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
                   "%s (): Invalid input param. p_dr: %p, p_nh: %p\r\n",
                   __FUNCTION__, p_dr, p_nh);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
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
                   "%s (): Invalid input param. p_dr: %p, p_link_node: %p\r\n",
                   __FUNCTION__, p_dr, p_link_node);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
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
                   "%s (): Invalid input param. p_dr: %p\r\n",
                   __FUNCTION__, p_dr);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
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
                   "%s (): Invalid input param. p_dr: %p\r\n",
                   __FUNCTION__, p_dr);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    if (p_fh != NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                   "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
                   "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
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
                   "%s (): Invalid input param. p_dr: %p\r\n",
                   __FUNCTION__, p_dr);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
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
                   "%s (): Invalid input param. p_dr: %p\r\n",
                   __FUNCTION__, p_dr);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
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
t_fib_dr *fib_get_next_best_fit_dr (uint32_t vrf_id, t_fib_ip_addr *p_ip_addr)
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
                         FIB_GET_RDX_DR_KEY_LEN (p_ip_addr,
                         FIB_AFINDEX_TO_PREFIX_LEN (af_index)));

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
    uint32_t             vrf_id = 0;
    int                  af_index = 0;
    int                  rc = STD_ERR_OK;

    HAL_RT_LOG_DEBUG("HAL-RT-DR", "af_index: %d\r\n", af_index);

    for (vrf_id = FIB_MIN_VRF; vrf_id < FIB_MAX_VRF; vrf_id++) {
        for (af_index = FIB_MIN_AFINDEX; af_index < FIB_MAX_AFINDEX; af_index++) {
            p_vrf_info = FIB_GET_VRF_INFO (vrf_id, af_index);
            if (p_vrf_info == NULL)
            {
                HAL_RT_LOG_DEBUG("HAL-RT-DR", "Vrf info NULL. "
                          "vrf_id: %d, af_index: %d\r\n",
                           vrf_id, af_index);
                continue;
            }
            memset (&p_vrf_info->dr_radical_marker, 0, sizeof (std_radical_ref_t));
            std_radical_walkconstructor (p_vrf_info->dr_tree,
                                       &p_vrf_info->dr_radical_marker);
        }
    }

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

        for (vrf_id = FIB_MIN_VRF; vrf_id < FIB_MAX_VRF; vrf_id++) {
            for (af_index = FIB_MIN_AFINDEX; af_index < FIB_MAX_AFINDEX; af_index++) {
                p_vrf_info = FIB_GET_VRF_INFO (vrf_id, af_index);

                if (p_vrf_info == NULL){
                    HAL_RT_LOG_DEBUG("HAL-RT-DR", "Vrf info NULL. "
                               "vrf_id: %d, af_index: %d\r\n", vrf_id, af_index);

                    continue;
                }

                nas_l3_lock();

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
                    HAL_RT_LOG_DEBUG("HAL-RT-DR", "Max DR processed per walk, relinquish now",
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
                   "%s (): Invalid input param. p_rt_head: %p\r\n",
                   __FUNCTION__, p_rt_head);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    p_dr = (t_fib_dr *) p_rt_head;

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
               "status_flag: 0x%x\r\n", p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
               p_dr->status_flag);

    p_vrf_info = FIB_GET_VRF_INFO (p_dr->vrf_id,
                                 p_dr->key.prefix.af_index);

    if (p_vrf_info == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR",
                   "%s (): Vrf info NULL. vrf_id: %d, af_index: %d\r\n",
                   __FUNCTION__, p_dr->vrf_id, p_dr->key.prefix.af_index);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "num_dr_processed_by_walker: %d, clear_ip_fib_on: %d, "
               "clear_ip_route_on: %d, dr_ha_on: %d, last_update_time: %lld, "
               "default_dr_owner: %d\r\n",
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
            fib_proc_dr_del (p_dr);
        }

        return STD_ERR_OK;
    }

    if (p_dr->status_flag & FIB_DR_STATUS_DEL) {
        p_dr->status_flag &= ~FIB_DR_STATUS_DEL;
        fib_proc_dr_del (p_dr);
    } else {
        fib_resolve_dr (p_dr);

        fib_mark_dr_dep_nh_for_resolution (p_dr);

        p_dr->status_flag &= ~FIB_DR_STATUS_REQ_RESOLVE;

        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                     "End of processing. "
                     "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
                     "status_flag: 0x%x\r\n", p_dr->vrf_id,
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
                   "%s (): Invalid input param. p_dr: %p\r\n",
                   __FUNCTION__, p_dr);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }


    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
               p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len);


    fib_delete_all_dr_fh (p_dr);

    fib_del_dr_degen_fh (p_dr);

    p_dr->status_flag &= ~FIB_DR_STATUS_DEGENERATED;

    FIB_FOR_EACH_NH_FROM_DR (p_dr, p_nh, nh_holder1)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                   "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
                   p_nh->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index);

        if (FIB_IS_NH_REQ_RESOLVE (p_nh))
        {
            HAL_RT_LOG_DEBUG("HAL-RT-DR",
                       "NH in request resolve state. "
                       "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
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
                           "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
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
                           "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
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
                           "if_index: 0x%x\r\n",
                           p_fh->vrf_id,
                           FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                           p_fh->key.if_index);

                if (FIB_IS_NH_REQ_RESOLVE (p_fh))
                {
                    HAL_RT_LOG_DEBUG("HAL-RT-DR",
                               "FH in request resolve state. "
                               "FH: vrf_id: %d, ip_addr: %s, "
                               "if_index: 0x%x\r\n",
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
                                   "if_index: 0x%x\r\n",
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
                                   "if_index: 0x%x\r\n",
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
               "status_flag: 0x%x\r\n",
               p_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
               p_dr->prefix_len, p_dr->status_flag);

    if (FIB_IS_DR_DEFAULT (p_dr))
    {
        t_fib_nh_holder nh_holder;
        if ((!(FIB_IS_VRF_CREATED (p_dr->vrf_id, p_dr->key.prefix.af_index))) ||
            ((FIB_IS_DEFAULT_DR_OWNER_FIB (p_dr)) &&
             (FIB_IS_CATCH_ALL_ROUTE_DISABLED (p_dr->vrf_id,
                                               p_dr->key.prefix.af_index))) ||
            (FIB_GET_FIRST_NH_FROM_DR(p_dr, nh_holder) == NULL))
        {
            return STD_ERR_OK;
        }
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
                   "hal_err: %d (%s)\r\n", p_dr->vrf_id,
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
               "status_flag: 0x%x\r\n",
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
                   "%s (): Invalid input param. p_dr: %p\r\n",
                   __FUNCTION__, p_dr);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
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
                   "prefix_len: %d\r\n",p_less_specific_dr->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_less_specific_dr->key.prefix),
                   p_less_specific_dr->prefix_len);

        FIB_FOR_EACH_DEP_NH_FROM_DR (p_less_specific_dr, p_nh, nh_holder)
        {
            HAL_RT_LOG_DEBUG("HAL-RT-DR",
                       "Dep NH: vrf_id: %d, ip_addr: %s, "
                       "if_index: 0x%x\r\n",
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
                           "vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
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
                   "%s (): Invalid input param. p_dr: %p\r\n",
                   __FUNCTION__, p_dr);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
               "status_flag: 0x%x\r\n", p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
               p_dr->prefix_len, p_dr->status_flag);

    p_dr->status_flag |= FIB_DR_STATUS_DEGENERATED;

    FIB_FOR_EACH_FH_FROM_DR (p_dr, p_fh, nh_holder)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                   "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
                   "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
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
                           "hal_err: %d (%s)\r\n", p_dr->vrf_id,
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
                       "hal_err: %d (%s)\r\n", p_dr->vrf_id,
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
               "status_flag: 0x%x\r\n",
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
                   "Invalid input param. p_dr: %p\r\n",
                   p_dr);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
               "status_flag: 0x%x\r\n", p_dr->vrf_id,
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
                   "%s (): Invalid input param. p_dr: %p\r\n",
                   __FUNCTION__, p_dr);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-DR",
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
               "status_flag: 0x%x\r\n", p_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
               p_dr->prefix_len, p_dr->status_flag);

    FIB_FOR_EACH_DEP_NH_FROM_DR (p_dr, p_nh, nh_holder)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR",
                   "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
                   "Dep NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
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

    HAL_RT_LOG_DEBUG("HAL-RT-DR", "af_index: %d\r\n",  af_index);
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
                   "vrf_id: %d, af_index: %d\r\n",
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
               "a_curr_count: %d\r\n", vrf_id, af_index,
               prefix_len, p_route_summary->a_curr_count [prefix_len]);
    return STD_ERR_OK;
}

int fib_nbr_and_route_del_on_intf_down (t_fib_intf *p_intf) {
    t_fib_nh       *p_fh = NULL, *p_nh = NULL;
    t_fib_nh_holder nh_holder, nh_holder1;
    t_fib_nh_dep_dr   *p_nh_dep_dr = NULL;
    t_fib_dr *p_del_dr = NULL;
    bool is_fib_route_del = true;

    /* Loop for all the FH and associated routes for deletion */
    FIB_FOR_EACH_FH_FROM_INTF (p_intf, p_fh, nh_holder) {
        p_fh->status_flag |= FIB_NH_STATUS_DEAD;
        fib_proc_nh_delete (p_fh, FIB_NH_OWNER_TYPE_ARP, 0);
        p_nh_dep_dr = fib_get_first_nh_dep_dr (p_fh);
        while (p_nh_dep_dr != NULL) {
            if (p_nh_dep_dr->p_dr == NULL) {
                p_nh_dep_dr = fib_get_next_nh_dep_dr (p_fh, p_nh_dep_dr->key.vrf_id,
                                                      &p_nh_dep_dr->key.dr_key.prefix,
                                                      p_nh_dep_dr->prefix_len);
                continue;
            }
            /* Init the FIB route del to true first, if any valid path found in the ECMP, dont delete the FIB route */
            is_fib_route_del = true;
            HAL_RT_LOG_DEBUG("HAL-RT-DR",
                             "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
                             "Dep NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x status:0x%x\r\n",
                             p_nh_dep_dr->p_dr->vrf_id,
                             FIB_IP_ADDR_TO_STR (&p_nh_dep_dr->p_dr->key.prefix),
                             p_nh_dep_dr->p_dr->prefix_len, p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                             p_fh->key.if_index, p_fh->status_flag);
            /* If all the multipaths are dead for the ECMP route, delete the route, otherwise continue for next route */
            if (p_nh_dep_dr->p_dr->num_nh > 1) {
                FIB_FOR_EACH_NH_FROM_DR (p_nh_dep_dr->p_dr, p_nh, nh_holder1)
                {
                    HAL_RT_LOG_DEBUG("HAL-RT-DR",
                                     "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
                                     "Dep NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x status:0x%x is_nh_dead:%s\r\n",
                                     p_nh_dep_dr->p_dr->vrf_id,
                                     FIB_IP_ADDR_TO_STR (&p_nh_dep_dr->p_dr->key.prefix),
                                     p_nh_dep_dr->p_dr->prefix_len, p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                                     p_nh->key.if_index, p_nh->status_flag,
                                     ((p_nh->status_flag & FIB_NH_STATUS_DEAD) ? "yes": "no"));
                    if (p_nh->status_flag & FIB_NH_STATUS_DEAD) {
                        continue;
                    }
                    /* Valid NH is found, dont delete the ECMP route */
                    is_fib_route_del = false;
                    break;
                }
            }
            /* copy the route to be deleted and then get the next dependent dr,
             * to avoid accessing the invalid dep-dr after route deletion */
            p_del_dr = p_nh_dep_dr->p_dr;
            p_nh_dep_dr = fib_get_next_nh_dep_dr (p_fh, p_nh_dep_dr->key.vrf_id,
                                                  &p_nh_dep_dr->key.dr_key.prefix,
                                                  p_nh_dep_dr->prefix_len);
            if (is_fib_route_del && p_del_dr) {
                /* Delete the route since the NH(s) is dead */
                // TODO This needs to revisited to handle the DR del in the DR walker
                //p_del_dr->status_flag |= FIB_DR_STATUS_DEL;
                //         fib_mark_dr_for_resolution (p_del_dr);
                fib_proc_dr_del (p_del_dr);
            }
        }
    }
    return STD_ERR_OK;
}

int fib_handle_intf_admin_status_change(int if_index, int vrf_id, int af_index, bool is_admin_up) {

    t_fib_intf  *p_intf = NULL;
    t_fib_nh    *p_fh = NULL;
    t_fib_nh_holder nh_holder;

    /* Get the L3 interface and delete all the associated routes*/
    p_intf = fib_get_intf (if_index, vrf_id, af_index);
    HAL_RT_LOG_INFO ("HAL-RT-DR", "Admin status if_index: %d, vrf_id: %d, af_index: %d admin_up:%d\r\n",
                    if_index, vrf_id, af_index, is_admin_up);

    /* if interface notification is received for the first time,
     * just update the admin status from kernel.
     */
    if (p_intf == NULL)
    {
        if ((p_intf = fib_add_intf (if_index, vrf_id, af_index)) == NULL)
        {
            HAL_RT_LOG_ERR ("HAL-RT-DR",
                            "%s (): Intf addition failed. "
                            "if_index: 0x%x, vrf_id: %d, af_index: %d\r\n",
                            __FUNCTION__, if_index, vrf_id, af_index);

            return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
        }

        std_dll_init (&p_intf->fh_list);
        std_dll_init (&p_intf->pending_fh_list);

        p_intf->admin_status = is_admin_up;
        return STD_ERR_OK;
    }

    /* simply return, if we are receiving duplicate status notification */
    /* On bootup, admin down event for master interface on interface create
     * from kernel might be processed after processing connected route add.
     * in this scenario we may end up in a state where
     * where connected route will never get installed after that.
     * To avoid this issue, skip out of order duplicate state notifications.
     */
    if (p_intf->admin_status == is_admin_up)
    {
        HAL_RT_LOG_DEBUG ("HAL-RT-DR",
                        "Duplicate admin notification for "
                        "vrf_id: %d, if_index: 0x%x, af: %d, is_admin_up: %d\r\n",
                        vrf_id, if_index, af_index, is_admin_up);

        return STD_ERR_OK;
    }

    p_intf->admin_status = is_admin_up;

    if (is_admin_up) {
        /* If admin is up, clear the NH dead status flag */
        FIB_FOR_EACH_FH_FROM_INTF (p_intf, p_fh, nh_holder) {
            HAL_RT_LOG_DEBUG("HAL-RT-DR",
                             "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x status:0x%x is_nh_dead:%s\r\n",
                             p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                             p_fh->key.if_index, p_fh->status_flag,
                             ((p_fh->status_flag & FIB_NH_STATUS_DEAD) ? "yes" : "no"));
            p_fh->status_flag &= ~FIB_NH_STATUS_DEAD;
        }
    } else {
        fib_nbr_and_route_del_on_intf_down(p_intf);
    }
    fib_resume_nh_walker_thread(af_index);
    fib_resume_dr_walker_thread(af_index);
    return STD_ERR_OK;
}

