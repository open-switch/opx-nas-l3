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
 * \file   hal_rt_nh.c
 * \brief  Hal Routing Next Hop functionality
 * \date   05-2014
 * \author Prince Sunny & Satish Mynam
 */

#include "hal_rt_main.h"
#include "hal_rt_mem.h"
#include "hal_rt_route.h"
#include "hal_rt_api.h"
#include "hal_rt_util.h"
#include "hal_rt_debug.h"
#include "nas_rt_api.h"

#include "event_log.h"
#include "std_ip_utils.h"

#include <pthread.h>
#include <string.h>
#include <stdio.h>

/**************************************************************************
 *                            GLOBALS
 **************************************************************************/
pthread_mutex_t fib_nh_mutex;
pthread_cond_t  fib_nh_cond;
static bool     is_nh_pending_for_processing = 0; //initialize the predicate for signal
std_rt_table   *rt_intf_tree = NULL;

std_rt_table * hal_rt_access_intf_tree(void)
{
    return (rt_intf_tree);
}

int fib_create_nh_tree (t_fib_vrf_info *p_vrf_info)
{
    char tree_name_str [FIB_RDX_MAX_NAME_LEN];

    if (!p_vrf_info)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH", "Invalid input param. p_vrf_info: %p\r\n", p_vrf_info);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH", "Vrf_id: %d, af_index: %s\r\n",
                 p_vrf_info->vrf_id, STD_IP_AFINDEX_TO_STR (p_vrf_info->af_index));

    if (p_vrf_info->nh_tree != NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                   "NH tree already created. vrf_id: %d, af_index: %d\r\n",
                   p_vrf_info->vrf_id, p_vrf_info->af_index);

        return STD_ERR_OK;
    }

    memset (tree_name_str, 0, FIB_RDX_MAX_NAME_LEN);

    snprintf (tree_name_str, FIB_RDX_MAX_NAME_LEN, "Fib%s_nh_tree_vrf%d",
             STD_IP_AFINDEX_TO_STR (p_vrf_info->af_index), p_vrf_info->vrf_id);

    p_vrf_info->nh_tree = std_radix_create (tree_name_str, FIB_RDX_NH_KEY_LEN,
                                       NULL, NULL, 0);

    if (p_vrf_info->nh_tree == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): std_radix_create failed. Vrf_id: %d, "
                   "af_index: %s\r\n", __FUNCTION__, p_vrf_info->vrf_id,
                   STD_IP_AFINDEX_TO_STR (p_vrf_info->af_index));

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    std_radix_enable_radical (p_vrf_info->nh_tree);

    return STD_ERR_OK;
}

int fib_destroy_nh_tree (t_fib_vrf_info *p_vrf_info)
{
    if (!p_vrf_info)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_vrf_info: %p\r\n",
                   __FUNCTION__, p_vrf_info);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
                 "Vrf_id: %d, af_index: %s\r\n", p_vrf_info->vrf_id,
                 STD_IP_AFINDEX_TO_STR (p_vrf_info->af_index));

    if (p_vrf_info->nh_tree == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): NH tree not present. "
                   "vrf_id: %d, af_index: %d\r\n",
                   __FUNCTION__, p_vrf_info->vrf_id, p_vrf_info->af_index);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    std_radix_destroy (p_vrf_info->nh_tree);

    p_vrf_info->nh_tree = NULL;

    return STD_ERR_OK;
}

int fib_create_nh_dep_dr_tree (t_fib_nh *p_nh)
{
    if (!p_nh)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_nh: %p\r\n",
                   __FUNCTION__, p_nh);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
                 "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
                  p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index);

    if (p_nh->dep_dr_tree != NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                     "Dep DR tree already created. NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
                     p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index);

        return STD_ERR_OK;
    }

    p_nh->dep_dr_tree = std_radix_create ("Fib_nh_dep_dr_tree", FIB_RDX_NH_DEP_DR_KEY_LEN,
                                        NULL, NULL, 0);

    if (p_nh->dep_dr_tree == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "std_radix_create failed.NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
                   p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    return STD_ERR_OK;
}

int fib_destroy_nh_dep_dr_tree (t_fib_nh *p_nh)
{
    if (!p_nh)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_nh: %p\r\n", __FUNCTION__, p_nh);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
                 "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
                 p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index);

    if (p_nh->dep_dr_tree == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Dep DR tree not present. "
                   "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
                   __FUNCTION__, p_nh->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    std_radix_destroy (p_nh->dep_dr_tree);

    p_nh->dep_dr_tree = NULL;

    return STD_ERR_OK;
}

int fib_create_intf_tree (void)
{
    if (rt_intf_tree != NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                   " Intf tree already created\r\n", __FUNCTION__);

        return STD_ERR_OK;
    }

    rt_intf_tree = std_radix_create ("rt_intf_tree", FIB_RDX_INTF_KEY_LEN, NULL, NULL, 0);

    if (rt_intf_tree == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): std_radix_create failed\r\n", __FUNCTION__);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    return STD_ERR_OK;
}

int fib_destroy_intf_tree (void)
{
    if (rt_intf_tree == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Intf tree not present\r\n", __FUNCTION__);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    std_radix_destroy (rt_intf_tree);

    rt_intf_tree = NULL;

    return STD_ERR_OK;
}

t_fib_nh *fib_proc_nh_add (uint32_t vrf_id, t_fib_ip_addr *p_ip_addr,
                      uint32_t if_index, t_fib_nh_owner_type owner_type, uint32_t owner_value)
{
    t_fib_nh    *p_nh = NULL;
    bool   resolve_nh = false;

    if (!p_ip_addr)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_ip_addr: %p\r\n", __FUNCTION__, p_ip_addr);
        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
                 "vrf_id: %d, ip_addr: %s, if_index: 0x%x,owner_type: %d, owner_value: %d\r\n",
                 vrf_id, FIB_IP_ADDR_TO_STR (p_ip_addr), if_index, owner_type, owner_value);

    resolve_nh = true;

    p_nh = fib_get_nh (vrf_id, p_ip_addr, if_index);

    if (p_nh == NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                     "NH not found. vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
                     vrf_id, FIB_IP_ADDR_TO_STR (p_ip_addr), if_index);

        p_nh = fib_add_nh (vrf_id, p_ip_addr, if_index);

        if (p_nh == NULL)
        {
            HAL_RT_LOG_ERR("HAL-RT-NH",
                       "%s (): NH addition failed. "
                       "vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
                       __FUNCTION__, vrf_id, FIB_IP_ADDR_TO_STR (p_ip_addr),
                       if_index);

            return NULL;
        }

        p_nh->vrf_id = vrf_id;

        fib_create_nh_dep_dr_tree (p_nh);

        /* First Hop */
        if (((p_nh->key.if_index != 0) || (FIB_IS_NH_LOOP_BACK (p_nh))) &&
            (p_nh->p_arp_info == NULL))
        {
            p_nh->p_arp_info = FIB_ARP_INFO_MEM_MALLOC ();

            if (p_nh->p_arp_info != NULL)
            {
                memset (p_nh->p_arp_info, 0, sizeof (t_fib_arp_info));

                p_nh->p_arp_info->state = FIB_ARP_UNRESOLVED;

                fib_proc_add_intf_fh (p_nh, false);
            }
            else
            {
                HAL_RT_LOG_ERR("HAL-RT-NH",
                           "%s (): Arp info memory alloc failed\r\n", __FUNCTION__);
            }
        }

        std_dll_init (&p_nh->fh_list);
        std_dll_init (&p_nh->tunnel_fh_list);
    }
    else
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                     "Duplicate NH add. vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
                     vrf_id, FIB_IP_ADDR_TO_STR (p_ip_addr), if_index);

        /*
         * If RTM or ARP is already an owner of the NH and the incoming
         * owner type is RTM or any client, then the NH need not be
         * marked for resolution.
         */
        if (((FIB_IS_NH_OWNER_RTM (p_nh)) ||
             (FIB_IS_NH_OWNER_ARP (p_nh))) &&
            ((owner_type == FIB_NH_OWNER_TYPE_RTM) ||
             (owner_type == FIB_NH_OWNER_TYPE_CLIENT)))
        {
            resolve_nh = false;
        }
    }

    if ((owner_type == FIB_NH_OWNER_TYPE_ARP) &&
        (!(FIB_IS_NH_OWNER_ARP (p_nh))))
    {
        /*
         * This case happens when the NH is marked for deletion in which
         * arp_info is cleared. But before the NH thread resumes and delete
         * the NH, if a new request comes to add the ARP, we've to recreate
         * the arp_info structure.
         */
        if (((p_nh->key.if_index != 0) || (FIB_IS_NH_LOOP_BACK (p_nh))) &&
            (p_nh->p_arp_info == NULL))
        {
            p_nh->p_arp_info = FIB_ARP_INFO_MEM_MALLOC ();

            if (p_nh->p_arp_info != NULL)
            {
                memset (p_nh->p_arp_info, 0, sizeof (t_fib_arp_info));

                p_nh->p_arp_info->state = FIB_ARP_UNRESOLVED;

                fib_proc_add_intf_fh (p_nh, false);
            }
            else
            {
                HAL_RT_LOG_ERR("HAL-RT-NH",
                           "%s (): Arp info memory alloc failed\r\n", __FUNCTION__);
            }
        }

        FIB_INCR_CNTRS_FIB_HOST_ENTRIES (vrf_id, p_ip_addr->af_index);

        fib_update_route_summary (vrf_id, p_ip_addr->af_index,
                               FIB_AFINDEX_TO_PREFIX_LEN (p_ip_addr->af_index),
                               true);
    }

    FIB_SET_NH_OWNER (p_nh, owner_type, owner_value);

    if (owner_type == FIB_NH_OWNER_TYPE_RTM)
    {
        p_nh->rtm_ref_count++;
    }

    if (owner_type == FIB_NH_OWNER_TYPE_ARP)
    {
        p_nh->arp_last_update_time = fib_tick_get ();

        /* Resolve the directly-connected Tunnel NH nodes for this FH
         * during host-add and host-update notifications */
        fib_resolve_connected_tunnel_nh (vrf_id, p_nh);
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
                "BEFORE vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                "owner_flag: 0x%x, status_flag: 0x%x, rtm_ref_count: %d, resolve_nh: %d\r\n",
                vrf_id, FIB_IP_ADDR_TO_STR (p_ip_addr), if_index, p_nh->owner_flag, p_nh->status_flag,
                p_nh->rtm_ref_count, resolve_nh);

    p_nh->status_flag &= ~FIB_NH_STATUS_DEL;

    if (resolve_nh == true)
    {
        p_nh->status_flag |= FIB_NH_STATUS_ADD;

        fib_mark_nh_for_resolution (p_nh);
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
                 "AFTER vrf_id: %d, ip_addr: %s, if_index: %d, "
                 "owner_flag: 0x%x, status_flag: 0x%x, rtm_ref_count: %d, resolve_nh: %d\r\n",
                  vrf_id, FIB_IP_ADDR_TO_STR (p_ip_addr), if_index, p_nh->owner_flag, p_nh->status_flag,
                  p_nh->rtm_ref_count, resolve_nh);

    return p_nh;
}

int fib_proc_nh_delete (t_fib_nh *p_nh, t_fib_nh_owner_type owner_type,
                     uint32_t owner_value)
{
    bool      resolve_nh = false;

    if (!p_nh)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_nh: %p\r\n", __FUNCTION__, p_nh);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
                 "vrf_id: %d, ip_addr: %s, if_index: 0x%x, owner_type: %d, owner_value: %d"
                 "owner_flag: 0x%x, status_flag: 0x%x\r\n",
                 p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                 p_nh->key.if_index, owner_type, owner_value, p_nh->owner_flag, p_nh->status_flag);

    if (!(FIB_IS_NH_OWNER (p_nh, owner_type, owner_value)))
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                     "Ownership not present. vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                     "owner_flag: 0x%x, owner_type: %d, owner_value: %d\r\n",
                     p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                     p_nh->key.if_index, p_nh->owner_flag, owner_type, owner_value);
        return STD_ERR_OK;
    }

    if (owner_type == FIB_NH_OWNER_TYPE_RTM)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                     "vrf_id: %d, ip_addr: %s, if_index: 0x%x,rtm_ref_count: %d\r\n",
                      p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index, p_nh->rtm_ref_count);

        if (p_nh->rtm_ref_count > 0)
        {
            p_nh->rtm_ref_count--;
        }

        if (p_nh->rtm_ref_count == 0)
        {
            FIB_RESET_NH_OWNER (p_nh, owner_type, owner_value);
        }
    }
    else
    {
        FIB_RESET_NH_OWNER (p_nh, owner_type, owner_value);
    }

    if (owner_type == FIB_NH_OWNER_TYPE_ARP)
    {
        if (p_nh->p_arp_info != NULL)
        {
            /*
             * For Arp learnt on Vlan interface, the node added for
             * physical If_index is deleted here
             */
            memset (p_nh->p_arp_info, 0, sizeof (t_fib_arp_info));

            p_nh->p_arp_info->state = FIB_ARP_UNRESOLVED;
        }

        FIB_DECR_CNTRS_FIB_HOST_ENTRIES (p_nh->vrf_id, p_nh->key.ip_addr.af_index);

        fib_update_route_summary (p_nh->vrf_id, p_nh->key.ip_addr.af_index,
                           FIB_AFINDEX_TO_PREFIX_LEN (p_nh->key.ip_addr.af_index),
                           false);

        /* Resolve the directly-connected Tunnel NH nodes for this FH */
        fib_resolve_connected_tunnel_nh (p_nh->vrf_id, p_nh);
    }

    if ((owner_type != FIB_NH_OWNER_TYPE_RTM) &&
        (owner_type != FIB_NH_OWNER_TYPE_ARP))
    {
        return STD_ERR_OK;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
                 "vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                 "owner_flag: 0x%x, status_flag: 0x%x\r\n",
                 p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                 p_nh->key.if_index, p_nh->owner_flag, p_nh->status_flag);

    resolve_nh = false;

    /*
     * If both RTM and ARP are not owner of the NH, then mark the
     * NH for deletion.
     */
    if ((!(FIB_IS_NH_OWNER_RTM (p_nh))) &&
        (!(FIB_IS_NH_OWNER_ARP (p_nh))))
    {
        p_nh->status_flag |= FIB_NH_STATUS_DEL;
        p_nh->status_flag &= ~FIB_NH_STATUS_ADD;

        resolve_nh = true;
    }
    else if ((FIB_IS_NH_OWNER_RTM (p_nh)) &&
             (owner_type == FIB_NH_OWNER_TYPE_ARP))
    {
        /*
         * If RTM is an owner of the NH and the incoming owner type is ARP,
         * then the NH should be marked for resolution.
         */
        p_nh->status_flag |= FIB_NH_STATUS_ADD;
        p_nh->status_flag &= ~FIB_NH_STATUS_DEL;

        resolve_nh = true;
    }

    /*
     * NOTE: If ARP is an owner of the NH and the incoming
     * owner type is RTM, then the NH need not be marked for resolution.
     */

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
                 " vrf_id: %d, ip_addr: %s, if_index: %d, "
                 "owner_flag: 0x%x, status_flag: 0x%x, resolve_nh: %d \r\n",
                 p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                 p_nh->key.if_index, p_nh->owner_flag, p_nh->status_flag, resolve_nh);

    if ((resolve_nh == true))
    {
        fib_mark_nh_for_resolution (p_nh);
        /*
         * NH thread need not be resumed here. Let the DR thread continue the execution
         * and once DRs are updated with the new NHs, the NH thread can be resumed to continue
         * with the deletion of old NH.
         */
        //fib_resume_nh_walker_thread(af_index);
    }

    return STD_ERR_OK;
}

int fib_proc_add_intf_fh (t_fib_nh *p_fh, bool add_phy_if_index)
{
    t_fib_intf     *p_intf     = NULL;
    t_fib_link_node *p_link_node = NULL;
    uint32_t    if_index   = 0;

    if (!p_fh)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                "%s (): Invalid input param. p_fh: %p\r\n", __FUNCTION__, p_fh);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    if (add_phy_if_index)
    {
        if (!(p_fh->p_arp_info))
        {
            HAL_RT_LOG_ERR("HAL-RT-NH",
                    "%s (): Invalid param. p_arp_info: %p\r\n", __FUNCTION__, p_fh->p_arp_info);
            return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
        }

        if_index = p_fh->p_arp_info->if_index;
    }
    else
    {
        if_index = p_fh->key.if_index;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
                 "vrf_id: %d, ip_addr: %s, if_index: 0x%x,"
                 "owner_flag: 0x%x, status_flag: 0x%x\r\n",
                 p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                 if_index, p_fh->owner_flag, p_fh->status_flag);


    p_intf = fib_get_intf (if_index, p_fh->vrf_id, p_fh->key.ip_addr.af_index);

    if (p_intf == NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                     "Intf not found. if_index: 0x%x, vrf_id: %d, af_index: %d\r\n",
                     if_index, p_fh->vrf_id, p_fh->key.ip_addr.af_index);

        p_intf = fib_add_intf (if_index, p_fh->vrf_id, p_fh->key.ip_addr.af_index);

        if (p_intf == NULL)
        {
            HAL_RT_LOG_ERR("HAL-RT-NH",
                    "%s (): Intf addition failed. "
                    "if_index: 0x%x, vrf_id: %d, af_index: %d\r\n",
                    __FUNCTION__, if_index, p_fh->vrf_id,
                    p_fh->key.ip_addr.af_index);

            return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
        }

        std_dll_init (&p_intf->fh_list);
        std_dll_init (&p_intf->pending_fh_list);
    }

    p_link_node = fib_add_intf_fh (p_intf, p_fh);

    if (p_link_node == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                  "%s (): Intf FH addition failed. if_index: 0x%x, vrf_id: %d, ip_addr: %s\r\n",
                  __FUNCTION__, if_index, p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr));
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    return STD_ERR_OK;
}

int fib_proc_del_intf_fh (t_fib_nh *p_fh, bool del_phy_if_index)
{
    t_fib_intf     *p_intf     = NULL;
    t_fib_link_node *p_link_node = NULL;
    uint32_t    if_index   = 0;

    if (!p_fh)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_fh: %p\r\n", __FUNCTION__, p_fh);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    if (del_phy_if_index)
    {
        if (!(p_fh->p_arp_info))
        {
            HAL_RT_LOG_ERR("HAL-RT-NH",
                       "%s (): Invalid param. p_arp_info: %p\r\n", __FUNCTION__, p_fh->p_arp_info);
            return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
        }

        if_index = p_fh->p_arp_info->if_index;
    }
    else
    {
        if_index = p_fh->key.if_index;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
                 "vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                 "owner_flag: 0x%x, status_flag: 0x%x\r\n",
                 p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr), if_index,
                 p_fh->owner_flag, p_fh->status_flag);

    p_intf = fib_get_intf (if_index, p_fh->vrf_id, p_fh->key.ip_addr.af_index);

    if (p_intf == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                "%s (): Intf not found. "
                "if_index: 0x%x, vrf_id: %d, af_index: %d\r\n",
                __FUNCTION__, if_index, p_fh->vrf_id,
                p_fh->key.ip_addr.af_index);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    p_link_node = fib_get_intf_fh (p_intf, p_fh);

    if (p_link_node == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                "%s (): Intf FH not found. "
                "if_index: 0x%x, vrf_id: %d, ip_addr: %s\r\n",
                __FUNCTION__, if_index, p_fh->vrf_id,
                FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr));

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    fib_del_intf_fh (p_intf, p_link_node);

    fib_check_and_delete_intf (p_intf);

    return STD_ERR_OK;
}

int fib_proc_pending_fh_add (t_fib_nh *p_fh)
{
    t_fib_intf       *p_intf = NULL;
    t_fib_link_node   *p_link_node = NULL;

    if (!p_fh)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_fh: %p\r\n",
                   __FUNCTION__, p_fh);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "owner_flag: 0x%x, status_flag: 0x%x\r\n",
               p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
               p_fh->key.if_index, p_fh->owner_flag, p_fh->status_flag);

    if (FIB_IS_FH_PENDING (p_fh))
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                   "Duplicate pending FH add. "
                   "vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                   "owner_flag: 0x%x, status_flag: 0x%x\r\n",
                   p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                   p_fh->key.if_index, p_fh->owner_flag, p_fh->status_flag);

        return STD_ERR_OK;
    }

    p_fh->status_flag |= FIB_NH_STATUS_PENDING;

    p_intf = fib_get_intf (p_fh->key.if_index, p_fh->vrf_id,
                        p_fh->key.ip_addr.af_index);

    if (p_intf == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Intf not found. "
                   "if_index: 0x%x, vrf_id: %d, af_index: %d\r\n",
                   __FUNCTION__, p_fh->key.if_index, p_fh->vrf_id,
                   p_fh->key.ip_addr.af_index);

        p_intf = fib_add_intf (p_fh->key.if_index, p_fh->vrf_id,
                            p_fh->key.ip_addr.af_index);

        if (p_intf == NULL)
        {
            HAL_RT_LOG_ERR("HAL-RT-NH",
                       "%s (): Intf addition failed. "
                       "if_index: 0x%x, vrf_id: %d, af_index: %d\r\n",
                       __FUNCTION__, p_fh->key.if_index, p_fh->vrf_id,
                       p_fh->key.ip_addr.af_index);

            return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
        }

        std_dll_init (&p_intf->fh_list);
        std_dll_init (&p_intf->pending_fh_list);
    }

    p_link_node = fib_add_intf_pending_fh (p_intf, p_fh);

    if (p_link_node == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Intf pending FH addition failed. "
                   "if_index: 0x%x, vrf_id: %d, ip_addr: %s\r\n",
                   __FUNCTION__, p_fh->key.if_index, p_fh->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr));

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    return STD_ERR_OK;
}

int fib_proc_pending_fh_del (t_fib_nh *p_fh)
{
    t_fib_intf       *p_intf = NULL;
    t_fib_link_node   *p_link_node = NULL;

    if (!p_fh)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_fh: %p\r\n",
                   __FUNCTION__, p_fh);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "owner_flag: 0x%x, status_flag: 0x%x\r\n",
               p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
               p_fh->key.if_index, p_fh->owner_flag, p_fh->status_flag);

    if (!(FIB_IS_FH_PENDING (p_fh)))
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                   "FH not pending. "
                   "vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                   "owner_flag: 0x%x, status_flag: 0x%x\r\n",
                   p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                   p_fh->key.if_index, p_fh->owner_flag, p_fh->status_flag);

        return STD_ERR_OK;
    }

    p_fh->status_flag &= ~FIB_NH_STATUS_PENDING;

    p_intf = fib_get_intf (p_fh->key.if_index, p_fh->vrf_id,
                        p_fh->key.ip_addr.af_index);

    if (p_intf == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Intf not found. "
                   "if_index: 0x%x, vrf_id: %d, af_index: %d\r\n",
                   __FUNCTION__, p_fh->key.if_index, p_fh->vrf_id,
                   p_fh->key.ip_addr.af_index);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    p_link_node = fib_get_intf_pending_fh (p_intf, p_fh);

    if (p_link_node == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Intf pending FH not found. "
                   "if_index: 0x%x, vrf_id: %d, ip_addr: %s\r\n",
                   __FUNCTION__, p_fh->key.if_index, p_fh->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr));

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    fib_del_intf_pending_fh (p_intf, p_link_node);

    fib_check_and_delete_intf (p_intf);

    return STD_ERR_OK;
}

int fib_pending_intf_call_back (uint32_t if_index, bool action)
{
    t_fib_intf     *p_intf = NULL;
    t_fib_intf_key  key;
    t_fib_nh       *p_fh = NULL;
    t_fib_nh_holder nh_holder;
    uint8_t         af_index = 0;

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "if_index: 0x%x, action: %d\r\n", if_index, action);

    memset (&key, 0, sizeof (t_fib_intf_key));

    key.if_index = if_index;

    p_intf = (t_fib_intf *)std_radix_getexact (rt_intf_tree,(uint8_t *)&key, FIB_RDX_INTF_KEY_LEN);

    if (p_intf == NULL)
    {
        p_intf = (t_fib_intf *)
                  std_radix_getnext (rt_intf_tree, (uint8_t *)&key, FIB_RDX_INTF_KEY_LEN);
    }

    while (p_intf != NULL)
    {
        if (p_intf->key.if_index > if_index)
        {
            break;
        }

        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                   "Intf: if_index: 0x%x, vrf_id: %d, "
                   "af_index: %d\r\n",  p_intf->key.if_index, p_intf->key.vrf_id,
                   p_intf->key.af_index);

        FIB_FOR_EACH_PENDING_FH_FROM_INTF (p_intf, p_fh, nh_holder)
        {
            HAL_RT_LOG_DEBUG("HAL-RT-NH",
                       "Intf: if_index: 0x%x, vrf_id: %d, "
                       "af_index: %d, FH: ip_addr: %s, if_index: 0x%x, "
                       "vrf_id: %d, status_flag: 0x%x\r\n",
                       p_intf->key.if_index, p_intf->key.vrf_id,
                       p_intf->key.af_index,
                       FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                       p_fh->key.if_index, p_fh->vrf_id, p_fh->status_flag);

            if (FIB_IS_NH_REQ_RESOLVE (p_fh))
            {
                HAL_RT_LOG_DEBUG("HAL-RT-NH",
                           "FH in request resolving state. "
                           "ip_addr: %s, if_index: 0x%x, vrf_id: %d\r\n",
                           FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                           p_fh->key.if_index, p_fh->vrf_id);

                continue;
            }

            /*
             * fib_nh_walker_call_back () would handle both the scenarios
             * action = true and action = false.
             */

            p_fh->status_flag |= FIB_NH_STATUS_ADD;

            fib_mark_nh_for_resolution (p_fh);
            fib_resume_nh_walker_thread(af_index);
        }

        p_intf = (t_fib_intf *)
                  std_radix_getnext (rt_intf_tree, (uint8_t *)&p_intf->key, FIB_RDX_INTF_KEY_LEN);
    }

    return STD_ERR_OK;
}

t_fib_nh *fib_add_nh (uint32_t vrf_id, t_fib_ip_addr *p_ip_addr, uint32_t if_index)
{
    t_fib_nh     *p_nh = NULL;
    std_rt_head    *p_radix_head = NULL;
    uint8_t   af_index = 0;

    if (!p_ip_addr)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_ip_addr: %p\r\n",
                   __FUNCTION__, p_ip_addr);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n", vrf_id, FIB_IP_ADDR_TO_STR (p_ip_addr),
               if_index);

    p_nh = fib_alloc_nh_node ();

    if (p_nh == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH", "%s (): Memory alloc failed\r\n", __FUNCTION__);

        return NULL;
    }

    af_index = p_ip_addr->af_index;

    memcpy (&p_nh->key.ip_addr, p_ip_addr, sizeof (t_fib_ip_addr));

    p_nh->key.if_index = if_index;

    p_nh->radical.rth_addr = (uint8_t *) (&(p_nh->key));

    p_radix_head = std_radix_insert (hal_rt_access_fib_vrf_nh_tree(vrf_id, af_index),
                                 (std_rt_head *)(&p_nh->radical),
                                 FIB_RDX_NH_KEY_LEN);

    if (p_radix_head == NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                   "Radix insertion failed. "
                   "vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
                   vrf_id, FIB_IP_ADDR_TO_STR (p_ip_addr), if_index);

        fib_free_nh_node (p_nh);
        return NULL;
    }

    if (p_radix_head != ((std_rt_head *)p_nh))
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                   "Duplicate radix insertion. "
                   "vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
                   vrf_id, FIB_IP_ADDR_TO_STR (p_ip_addr), if_index);

        fib_free_nh_node (p_nh);

        p_nh = (t_fib_nh *)p_radix_head;
    }

    return p_nh;
}

t_fib_nh *fib_get_nh (uint32_t vrf_id, t_fib_ip_addr *p_ip_addr, uint32_t if_index)
{
    t_fib_nh    *p_nh = NULL;
    t_fib_nh_key  key;
    uint8_t  af_index = 0;

    if (!p_ip_addr)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_ip_addr: %p\r\n",
                   __FUNCTION__, p_ip_addr);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
               vrf_id, FIB_IP_ADDR_TO_STR (p_ip_addr), if_index);

    af_index = p_ip_addr->af_index;

    memset (&key, 0, sizeof (key));
    memcpy (&key.ip_addr, p_ip_addr, sizeof (t_fib_ip_addr));

    key.if_index = if_index;

    p_nh = (t_fib_nh *) std_radix_getexact (hal_rt_access_fib_vrf_nh_tree(vrf_id, af_index),
                          (uint8_t *) &key, FIB_RDX_NH_KEY_LEN);

    return p_nh;
}

t_fib_nh *fib_get_first_nh (uint32_t vrf_id, uint8_t af_index)
{
    t_fib_nh    *p_nh = NULL;
    t_fib_nh_key  key;

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               " vrf_id: %d, af_index: %d\r\n", vrf_id, af_index);

    memset (&key, 0, sizeof (t_fib_nh_key));

    p_nh = (t_fib_nh *) std_radix_getexact (hal_rt_access_fib_vrf_nh_tree(vrf_id, af_index),
                          (uint8_t *)&key, FIB_RDX_NH_KEY_LEN);

    if (p_nh == NULL)
    {
        p_nh = (t_fib_nh *) std_radix_getnext (hal_rt_access_fib_vrf_nh_tree(vrf_id, af_index),
                             (uint8_t *)&key, FIB_RDX_NH_KEY_LEN);
    }

    return p_nh;
}

t_fib_nh *fib_get_next_nh (uint32_t vrf_id, t_fib_ip_addr *p_ip_addr,
                      uint32_t if_index)
{
    t_fib_nh    *p_nh = NULL;
    t_fib_nh_key  key;
    uint8_t  af_index;

    if (!p_ip_addr)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_ip_addr: %p\r\n",
                   __FUNCTION__, p_ip_addr);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
               vrf_id, FIB_IP_ADDR_TO_STR (p_ip_addr),
               if_index);

    af_index = p_ip_addr->af_index;

    memset (&key, 0, sizeof (key));
    memcpy (&key.ip_addr, p_ip_addr, sizeof (t_fib_ip_addr));

    key.if_index = if_index;

    p_nh = (t_fib_nh *)
        std_radix_getnext (hal_rt_access_fib_vrf_nh_tree(vrf_id, af_index),
                         (uint8_t *) &key, FIB_RDX_NH_KEY_LEN);

    return p_nh;
}

t_fib_nh *fib_get_nh_for_host (uint32_t vrf_id, t_fib_ip_addr *p_ip_addr)
{
    t_fib_nh *p_nh;

    if (!p_ip_addr)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_ip_addr: %p\r\n",
                   __FUNCTION__, p_ip_addr);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "vrf_id: %d, ip_addr: %s\r\n",
               vrf_id, FIB_IP_ADDR_TO_STR (p_ip_addr));

    p_nh = fib_get_nh (vrf_id, p_ip_addr, 0);

    if (p_nh == NULL)
    {
        p_nh = fib_get_next_nh (vrf_id, p_ip_addr, 0);

        if ((p_nh != NULL) && (FIB_IS_NH_OWNER_ARP (p_nh)))
        {
            if ((p_nh->key.ip_addr.af_index == p_ip_addr->af_index) &&
                (memcmp (p_nh->key.ip_addr.u.v6_addr, p_ip_addr->u.v6_addr,
                         STD_IP_AFINDEX_TO_ADDR_LEN (p_ip_addr->af_index)) == 0))
            {
                return p_nh;
            }
        }
    }

    return NULL;
}

int fib_del_nh (t_fib_nh *p_nh)
{
    uint32_t  vrf_id = 0;
    uint8_t   af_index = 0;

    if (p_nh == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_nh: %p\r\n",
                   __FUNCTION__, p_nh);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
                p_nh->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
               p_nh->key.if_index);

    vrf_id = p_nh->vrf_id;

    af_index = p_nh->key.ip_addr.af_index;

    std_radix_remove (hal_rt_access_fib_vrf_nh_tree(vrf_id, af_index),
                    (std_rt_head *)(&p_nh->radical));

    fib_free_nh_node (p_nh);

    return STD_ERR_OK;
}

t_fib_link_node *fib_add_nh_fh (t_fib_nh *p_nh, t_fib_nh *p_fh)
{
    t_fib_link_node  *p_link_node = NULL;

    if ((!p_nh) ||
        (!p_fh))
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_nh: %p, p_fh: %p\r\n",
                   __FUNCTION__, p_nh, p_fh);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
               p_nh->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
               p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
               p_fh->key.if_index);

    p_link_node = (t_fib_link_node *) FIB_LINK_NODE_MEM_MALLOC ();

    if (p_link_node == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Memory alloc failed\r\n", __FUNCTION__);

        return NULL;
    }

    memset (p_link_node, 0, sizeof (t_fib_link_node));

    p_link_node->self = p_fh;

    std_dll_insertatback (&p_nh->fh_list, &p_link_node->glue);

    p_fh->nh_ref_count++;

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "nh_ref_count: %d\r\n",
               p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
               p_fh->key.if_index, p_fh->nh_ref_count);

    return p_link_node;
}

t_fib_link_node *fib_get_nh_fh (t_fib_nh *p_nh, t_fib_nh *p_fh)
{
    t_fib_link_node  *p_link_node = NULL;
    t_fib_nh        *p_temp_fh = NULL;
    t_fib_nh_holder  nh_holder;

    if ((!p_nh) ||
        (!p_fh))
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_nh: %p, p_fh: %p\r\n",
                   __FUNCTION__, p_nh, p_fh);

        return NULL;
    }

    FIB_FOR_EACH_FH_FROM_NH (p_nh, p_temp_fh, nh_holder)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                   "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
                   p_temp_fh->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_temp_fh->key.ip_addr),
                   p_temp_fh->key.if_index);

        if ((p_fh->vrf_id == p_temp_fh->vrf_id) &&
            ((memcmp (&p_fh->key, &p_temp_fh->key, sizeof (t_fib_nh_key))) == 0))
        {
            p_link_node = FIB_GET_LINK_NODE_FROM_NH_HOLDER (nh_holder);

            return p_link_node;
        }
    }

    return NULL;
}

int fib_del_nh_fh (t_fib_nh *p_nh, t_fib_link_node *p_link_node)
{
    t_fib_nh   *p_fh = NULL;

    if ((!p_nh) ||
        (!p_link_node))
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_nh: %p, p_link_node: %p\r\n",
                   __FUNCTION__, p_nh, p_link_node);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    p_fh = (t_fib_nh *) p_link_node->self;

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "nh_ref_count: %d\r\n",  p_nh->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
               p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
               p_fh->key.if_index, p_fh->nh_ref_count);


    if (p_fh->nh_ref_count > 0)
    {
        p_fh->nh_ref_count--;

        fib_check_and_delete_nh (p_fh);
    }

    std_dll_remove (&p_nh->fh_list, &p_link_node->glue);

    memset (p_link_node, 0, sizeof (t_fib_link_node));

    FIB_LINK_NODE_MEM_FREE (p_link_node);

    return STD_ERR_OK;
}

int fib_delete_all_nh_fh (t_fib_nh *p_nh)
{
    t_fib_nh         *p_fh = NULL;
    t_fib_link_node   *p_link_node = NULL;
    t_fib_nh_holder   nh_holder;

    if (!p_nh)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_nh: %p\r\n",
                   __FUNCTION__, p_nh);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
               p_nh->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index);

    FIB_FOR_EACH_FH_FROM_NH (p_nh, p_fh, nh_holder)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                   "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                   "nh_ref_count: %d\r\n",  p_fh->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr), p_fh->key.if_index,
                   p_fh->nh_ref_count);

        p_link_node = FIB_GET_LINK_NODE_FROM_NH_HOLDER (nh_holder);

        fib_del_nh_fh (p_nh, p_link_node);
    }

    return STD_ERR_OK;
}

t_fib_tunnel_fh *fib_add_nh_tunnel_fh (t_fib_nh *p_nh, t_fib_nh *p_fh)
{
    t_fib_tunnel_fh *p_tunnel_fh_node = NULL;

    if ((!p_nh) ||
        (!p_fh))
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_nh: %p, p_fh: %p\r\n",
                   __FUNCTION__, p_nh, p_fh);

        return NULL;
    }

    p_tunnel_fh_node = fib_get_nh_tunnel_fh (p_nh, p_fh);

    if (p_tunnel_fh_node != NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                   "Duplicate NHFH addition. "
                   "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                   "status_flag: 0x%x, owner_flag: 0x%x, "
                   "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                   "status_flag: 0x%x, owner_flag: 0x%x\r\n",
                   p_nh->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                   p_nh->key.if_index, p_nh->status_flag,
                   p_nh->owner_flag, p_fh->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                   p_fh->key.if_index, p_fh->status_flag, p_fh->owner_flag);

        return p_tunnel_fh_node;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
               p_nh->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
               p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
               p_fh->key.if_index);

    p_tunnel_fh_node = fib_alloc_tunnel_fh_node ();

    if (p_tunnel_fh_node == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Memory alloc failed\r\n", __FUNCTION__);

        return NULL;
    }

    p_tunnel_fh_node->link_node.self = p_fh;
    p_tunnel_fh_node->is_nh_ref       = true;

    std_dll_insertatback (&p_nh->tunnel_fh_list, &p_tunnel_fh_node->link_node.glue);

    p_fh->tunnel_nh_ref_count++;

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "tunnel_nh_ref_count: %d\r\n",
               p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
               p_fh->key.if_index, p_fh->tunnel_nh_ref_count);

    return p_tunnel_fh_node;
}

t_fib_tunnel_fh *fib_get_nh_tunnel_fh (t_fib_nh *p_nh, t_fib_nh *p_fh)
{
    t_fib_tunnel_fh  *p_tunnel_fh = NULL;
    t_fib_nh        *p_temp_fh = NULL;
    t_fib_nh_holder  nh_holder;

    if ((!p_nh) ||
        (!p_fh))
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_nh: %p, p_fh: %p\r\n",
                   __FUNCTION__, p_nh, p_fh);

        return NULL;
    }

    FIB_FOR_EACH_FH_FROM_TUNNEL_NH (p_nh, p_temp_fh, nh_holder)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                   "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                   "tunnel_nh_ref_count: %d\r\n",
                   p_temp_fh->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_temp_fh->key.ip_addr),
                   p_temp_fh->key.if_index, p_temp_fh->tunnel_nh_ref_count);

        if ((p_fh->vrf_id == p_temp_fh->vrf_id) &&
            ((memcmp (&p_fh->key, &p_temp_fh->key, sizeof (t_fib_nh_key))) == 0))
        {
            p_tunnel_fh = FIB_GET_TUNNEL_NHFH_NODE_FROM_NH_HOLDER (nh_holder);

            return p_tunnel_fh;
        }
    }

    return NULL;
}

int fib_del_nh_tunnel_fh (t_fib_nh *p_nh, t_fib_nh *p_fh)
{
    t_fib_tunnel_fh   *p_tunnel_fh = NULL;

    if ((!p_nh) ||
        (!p_fh))
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_nh: %p, p_fh: %p\r\n",
                   __FUNCTION__, p_nh, p_fh);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "nh_ref_count: %d\r\n",  p_nh->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
               p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
               p_fh->key.if_index, p_fh->nh_ref_count);

    p_tunnel_fh = fib_get_nh_tunnel_fh (p_nh, p_fh);

    if (p_tunnel_fh == NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH", "Tunnel FH is NULL.\r\n");

        return STD_ERR_OK;
    }

    p_tunnel_fh->is_nh_ref = false;

    /* Remove from the tunnel_fh_list */
    std_dll_remove (&p_nh->tunnel_fh_list, &p_tunnel_fh->link_node.glue);

    if (p_fh->tunnel_nh_ref_count > 0)
    {
        p_fh->tunnel_nh_ref_count--;
    }

    fib_check_and_delete_tunnel_fh (p_tunnel_fh);

    fib_check_and_delete_nh (p_fh);

    return STD_ERR_OK;
}

int fib_check_and_delete_tunnel_fh (t_fib_tunnel_fh *p_tunnel_fh)
{
    if ((!p_tunnel_fh))
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_tunnel_fh: %p\r\n",
                   __FUNCTION__, p_tunnel_fh);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    if ((p_tunnel_fh->is_nh_ref == false) &&
        (p_tunnel_fh->dr_ref_count == 0))
    {
        fib_free_tunnel_fh_node (p_tunnel_fh);
    }

    return STD_ERR_OK;
}

int fib_resolve_connected_tunnel_nh (uint32_t vrf_id, t_fib_nh *p_fh)
{
    t_fib_nh  *p_temp_nh = NULL;

    HAL_RT_LOG_DEBUG("HAL-RT-NH", "FH: vrf_id: %d, ip_addr: %s,"
               " if_index: 0x%x \r\n",
               vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
               p_fh->key.if_index);

    /* Resolve the directly-connected Tunnel NH nodes for this FH */
    p_temp_nh = fib_get_next_nh (vrf_id, &p_fh->key.ip_addr, 0);

    while (p_temp_nh != NULL)
    {
        if ((p_fh->key.ip_addr.af_index == p_temp_nh->key.ip_addr.af_index) &&
            (memcmp (p_fh->key.ip_addr.u.v6_addr, p_temp_nh->key.ip_addr.u.v6_addr,
                   STD_IP_AFINDEX_TO_ADDR_LEN (p_temp_nh->key.ip_addr.af_index)) == 0))
        {

            p_temp_nh = fib_get_next_nh (vrf_id, &p_temp_nh->key.ip_addr,
                                    p_temp_nh->key.if_index);
        }
        else
        {
            break;
        }
    }

    return STD_ERR_OK;
}

t_fib_nh_dep_dr *fib_add_nh_dep_dr (t_fib_nh *p_nh, t_fib_dr *p_dr)
{
    t_fib_nh_dep_dr  *p_nh_dep_dr = NULL;
    std_rt_head      *p_radix_head = NULL;

    if ((!p_nh) ||
        (!p_dr))
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_nh: %p, p_dr: %p\r\n",
                   __FUNCTION__, p_nh, p_dr);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "Dep DR: vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
               p_nh->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
               p_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
               p_dr->prefix_len);

    p_nh_dep_dr = (t_fib_nh_dep_dr *) FIB_NH_DEP_DR_MEM_MALLOC ();

    if (p_nh_dep_dr == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Memory alloc failed\r\n", __FUNCTION__);

        return NULL;
    }

    memset (p_nh_dep_dr, 0, sizeof (t_fib_nh_dep_dr));

    p_nh_dep_dr->key.vrf_id = p_dr->vrf_id;

    memcpy (&p_nh_dep_dr->key.dr_key, &p_dr->key, sizeof (t_fib_dr_key));

    p_nh_dep_dr->rt_head.rth_addr = (uint8_t *) (&(p_nh_dep_dr->key));

    p_radix_head =
        std_radix_insert (p_nh->dep_dr_tree,
                        (std_rt_head *)(&p_nh_dep_dr->rt_head),
                        FIB_GET_RDX_NH_DEP_DR_KEY_LEN (&p_nh_dep_dr->key,
                                                       p_dr->prefix_len));

    if (p_radix_head == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Radix insertion failed. "
                   "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                   "Dep DR: vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
                   __FUNCTION__, p_nh->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
                   p_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                   p_dr->prefix_len);

        FIB_NH_DEP_DR_MEM_FREE (p_nh_dep_dr);
        return NULL;
    }

    if (p_radix_head != ((std_rt_head *)p_nh_dep_dr))
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                   "Duplicate radix insertion. "
                   "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                   "Dep DR: vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
                   p_nh->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
                   p_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                   p_dr->prefix_len);

        FIB_NH_DEP_DR_MEM_FREE (p_nh_dep_dr);

        p_nh_dep_dr = (t_fib_nh_dep_dr *)p_radix_head;

        return p_nh_dep_dr;
    }
    if ((p_nh->p_arp_info) && (p_nh->p_arp_info->state == FIB_ARP_RESOLVED))
        p_dr->is_nh_resolved = true;

    p_nh_dep_dr->prefix_len = p_dr->prefix_len;
    p_nh_dep_dr->p_dr       = p_dr;

    return p_nh_dep_dr;
}

t_fib_nh_dep_dr *fib_get_nh_dep_dr (t_fib_nh *p_nh, t_fib_dr *p_dr)
{
    t_fib_nh_dep_dr_key    key;
    t_fib_nh_dep_dr      *p_nh_dep_dr = NULL;

    if ((!p_dr) ||
        (!p_nh))
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_nh: %p, p_dr: %p\r\n",
                   __FUNCTION__, p_nh, p_dr);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "Dep DR: vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
               p_nh->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
               p_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
               p_dr->prefix_len);

    memset (&key, 0, sizeof (t_fib_nh_dep_dr_key));

    key.vrf_id = p_dr->vrf_id;

    memcpy (&key.dr_key, &p_dr->key, sizeof (t_fib_dr_key));

    p_nh_dep_dr = (t_fib_nh_dep_dr *)
        std_radix_getexact (p_nh->dep_dr_tree,
                          (uint8_t *)&key,
                          FIB_GET_RDX_NH_DEP_DR_KEY_LEN (&key,
                                                         p_dr->prefix_len));

    return p_nh_dep_dr;
}

t_fib_nh_dep_dr *fib_get_first_nh_dep_dr (t_fib_nh *p_nh)
{
    t_fib_nh_dep_dr      *p_nh_dep_dr = NULL;
    t_fib_nh_dep_dr_key    key;

    if (!p_nh)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_nh: %p\r\n",
                   __FUNCTION__, p_nh);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
               p_nh->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index);

    memset (&key, 0, sizeof (t_fib_nh_dep_dr_key));

    p_nh_dep_dr = (t_fib_nh_dep_dr *)
        std_radix_getexact (p_nh->dep_dr_tree,
                          (uint8_t *)&key,
                          FIB_GET_RDX_NH_DEP_DR_KEY_LEN (&key, 0));

    if (p_nh_dep_dr == NULL)
    {
        p_nh_dep_dr = (t_fib_nh_dep_dr *)
            std_radix_getnext (p_nh->dep_dr_tree,
                             (uint8_t *)&key,
                             FIB_GET_RDX_NH_DEP_DR_KEY_LEN (&key, 0));
    }

    return p_nh_dep_dr;
}

t_fib_nh_dep_dr *fib_get_next_nh_dep_dr (t_fib_nh *p_nh, uint32_t vrf_id,
                                t_fib_ip_addr *p_prefix, uint8_t prefix_len)
{
    t_fib_nh_dep_dr      *p_nh_dep_dr = NULL;
    t_fib_nh_dep_dr_key    key;

    if ((!p_nh) ||
        (!p_prefix))
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_nh: %p, p_prefix: %p\r\n",
                   __FUNCTION__, p_nh, p_prefix);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "Input: vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
               p_nh->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
               vrf_id, FIB_IP_ADDR_TO_STR (p_prefix), prefix_len);

    memset (&key, 0, sizeof (t_fib_nh_dep_dr_key));

    key.vrf_id = vrf_id;

    memcpy (&key.dr_key.prefix, p_prefix, sizeof (t_fib_ip_addr));

    p_nh_dep_dr = (t_fib_nh_dep_dr *)
        std_radix_getnext (p_nh->dep_dr_tree,
                         (uint8_t *)&key,
                         FIB_GET_RDX_NH_DEP_DR_KEY_LEN (&key, prefix_len));

    return p_nh_dep_dr;
}

int fib_del_nh_dep_dr (t_fib_nh *p_nh, t_fib_nh_dep_dr *p_nh_dep_dr)
{
    if ((!p_nh) ||
        (!p_nh_dep_dr))
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_nh: %p, p_nh_dep_dr: %p\r\n",
                   __FUNCTION__, p_nh, p_nh_dep_dr);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "Dep DR: vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
               p_nh->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
               p_nh_dep_dr->key.vrf_id,
               FIB_IP_ADDR_TO_STR (&p_nh_dep_dr->key.dr_key.prefix),
               p_nh_dep_dr->prefix_len);

    std_radix_remove (p_nh->dep_dr_tree, (std_rt_head *)(&p_nh_dep_dr->rt_head));

    memset (p_nh_dep_dr, 0, sizeof (t_fib_nh_dep_dr));

    FIB_NH_DEP_DR_MEM_FREE (p_nh_dep_dr);

    return STD_ERR_OK;
}

int fib_delete_all_nh_dep_dr (t_fib_nh *p_nh)
{
    t_fib_nh_dep_dr      *p_nh_dep_dr = NULL;
    t_fib_nh_dep_dr_key    key;
    uint8_t         prefix_len = 0;

    if (!p_nh)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_nh: %p\r\n",
                   __FUNCTION__, p_nh);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
               p_nh->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index);

    memset (&key, 0, sizeof (t_fib_nh_dep_dr_key));

    p_nh_dep_dr = fib_get_first_nh_dep_dr (p_nh);

    while (p_nh_dep_dr != NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                   "Dep DR: vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
                   p_nh_dep_dr->key.vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_nh_dep_dr->key.dr_key.prefix),
                   p_nh_dep_dr->prefix_len);

        memcpy (&key, &p_nh_dep_dr->key, sizeof (t_fib_nh_dep_dr_key));

        prefix_len = p_nh_dep_dr->prefix_len;

        fib_del_nh_dep_dr (p_nh, p_nh_dep_dr);

        p_nh_dep_dr = fib_get_next_nh_dep_dr (p_nh, key.vrf_id, &key.dr_key.prefix,
                                      prefix_len);
    }

    return STD_ERR_OK;
}

int fib_add_nh_best_fit_dr (t_fib_nh *p_nh, t_fib_dr *p_best_fit_dr)
{
    if ((!p_nh) ||
        (!p_best_fit_dr))
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_nh: %p, p_best_fit_dr: %p\r\n",
                   __FUNCTION__, p_nh, p_best_fit_dr);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "DR: vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
               p_nh->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
               p_best_fit_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_best_fit_dr->key.prefix),
               p_best_fit_dr->prefix_len);

    p_nh->p_best_fit_dr = p_best_fit_dr;

    fib_add_dr_dep_nh (p_best_fit_dr, p_nh);

    return STD_ERR_OK;
}

t_fib_dr *fib_get_nh_best_fit_dr (t_fib_nh *p_nh)
{
    t_fib_dr  *p_dr = NULL;

    if (!p_nh)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_nh: %p\r\n",
                   __FUNCTION__, p_nh);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
               p_nh->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index);

    p_dr = fib_get_best_fit_dr (p_nh->vrf_id, &p_nh->key.ip_addr);

    return p_dr;
}

int fib_del_nh_best_fit_dr (t_fib_nh *p_nh)
{
    t_fib_link_node  *p_link_node = NULL;

    if (!p_nh)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_nh: %p\r\n",
                   __FUNCTION__, p_nh);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
               p_nh->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index);

    if (p_nh->p_best_fit_dr == NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                   "Best fit DR not present. "
                   "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
                   p_nh->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index);

        return STD_ERR_OK;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "Best Fit DR: vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
               p_nh->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
               p_nh->p_best_fit_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_nh->p_best_fit_dr->key.prefix),
               p_nh->p_best_fit_dr->prefix_len);

    p_link_node = fib_get_dr_dep_nh (p_nh->p_best_fit_dr, p_nh);

    if (p_link_node == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): DR Dep NH not found. "
                   "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                   "Best Fit DR: vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
                   __FUNCTION__, p_nh->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
                   p_nh->p_best_fit_dr->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_nh->p_best_fit_dr->key.prefix),
                   p_nh->p_best_fit_dr->prefix_len);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    fib_del_dr_dep_nh (p_nh->p_best_fit_dr, p_link_node);

    p_nh->p_best_fit_dr = NULL;

    return STD_ERR_OK;
}

t_fib_intf *fib_add_intf (uint32_t if_index, uint32_t vrf_id, uint8_t af_index)
{
    t_fib_intf  *p_intf = NULL;
    std_rt_head   *p_radix_head = NULL;

    p_intf = (t_fib_intf *) FIB_INTF_MEM_MALLOC ();

    if (p_intf == NULL) {
        HAL_RT_LOG_ERR("HAL-RT-NH", "%s (): Memory alloc failed\r\n", __FUNCTION__);
        return NULL;
    }

    memset (p_intf, 0, sizeof (t_fib_intf));

    p_intf->key.if_index = if_index;
    p_intf->key.vrf_id   = vrf_id;
    p_intf->key.af_index = af_index;

    p_intf->rt_head.rth_addr = (uint8_t *) (&(p_intf->key));

    p_radix_head = std_radix_insert (rt_intf_tree, (std_rt_head *)(&p_intf->rt_head),
                                     FIB_RDX_INTF_KEY_LEN);

    if (p_radix_head == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Radix insertion failed. "
                   "Intf: if_index: 0x%x, vrf_id: %d, af_index: %d\r\n",
                   __FUNCTION__, p_intf->key.if_index,
                   p_intf->key.vrf_id, p_intf->key.af_index);

        FIB_INTF_MEM_FREE (p_intf);
        return NULL;
    }

    if (p_radix_head != ((std_rt_head *)p_intf))
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                   "Duplicate radix insertion. "
                   "Intf: if_index: 0x%x, vrf_id: %d, af_index: %d\r\n",
                   p_intf->key.if_index,
                   p_intf->key.vrf_id, p_intf->key.af_index);

        FIB_INTF_MEM_FREE (p_intf);

        p_intf = (t_fib_intf *) p_radix_head;
    }

    return p_intf;
}

t_fib_intf *fib_get_intf (uint32_t if_index, uint32_t vrf_id, uint8_t af_index)
{
    t_fib_intf_key   key;
    t_fib_intf     *p_intf = NULL;

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "if_index: 0x%x, vrf_id: %d, af_index: %d\r\n",
               if_index, vrf_id, af_index);

    memset (&key, 0, sizeof (t_fib_intf_key));

    key.if_index = if_index;
    key.vrf_id   = vrf_id;
    key.af_index = af_index;

    p_intf = (t_fib_intf *)
              std_radix_getexact (rt_intf_tree, (uint8_t *)&key, FIB_RDX_INTF_KEY_LEN);

    return p_intf;
}

int fib_del_intf (t_fib_intf *p_intf)
{
    if (!p_intf)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_intf: %p\r\n",
                   __FUNCTION__, p_intf);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "if_index: 0x%x, vrf_id: %d, af_index: %d\r\n",
               p_intf->key.if_index, p_intf->key.vrf_id,
               p_intf->key.af_index);

    std_radix_remove (rt_intf_tree, (std_rt_head *)(&p_intf->rt_head));

    memset (p_intf, 0, sizeof (t_fib_intf));

    FIB_INTF_MEM_FREE (p_intf);

    return STD_ERR_OK;
}

t_fib_link_node *fib_add_intf_fh (t_fib_intf *p_intf, t_fib_nh *p_fh)
{
    t_fib_link_node  *p_link_node = NULL;

    if ((!p_intf) ||
        (!p_fh))
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_intf: %p, p_fh: %p\r\n",
                   __FUNCTION__, p_intf, p_fh);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "Intf: if_index: 0x%x, vrf_id: %d, af_index: %d, "
               "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
               p_intf->key.if_index, p_intf->key.vrf_id, p_intf->key.af_index,
               p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
               p_fh->key.if_index);

    p_link_node = (t_fib_link_node *) FIB_LINK_NODE_MEM_MALLOC ();

    if (p_link_node == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Memory alloc failed\r\n", __FUNCTION__);

        return NULL;
    }

    memset (p_link_node, 0, sizeof (t_fib_link_node));

    p_link_node->self = p_fh;

    std_dll_insertatback (&p_intf->fh_list, &p_link_node->glue);

    return p_link_node;
}

t_fib_link_node *fib_get_intf_fh (t_fib_intf *p_intf, t_fib_nh *p_fh)
{
    t_fib_link_node  *p_link_node = NULL;
    t_fib_nh        *p_temp_fh = NULL;
    t_fib_nh_holder  nh_holder;

    if ((!p_intf) ||
        (!p_fh))
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_intf: %p, p_fh: %p\r\n",
                   __FUNCTION__, p_intf, p_fh);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "Intf: if_index: 0x%x, vrf_id: %d, af_index: %d, "
               "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
               p_intf->key.if_index, p_intf->key.vrf_id, p_intf->key.af_index,
               p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
               p_fh->key.if_index);

    FIB_FOR_EACH_FH_FROM_INTF (p_intf, p_temp_fh, nh_holder)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                   "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
                   p_temp_fh->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_temp_fh->key.ip_addr),
                   p_temp_fh->key.if_index);

        if ((memcmp (&p_fh->key, &p_temp_fh->key, sizeof (t_fib_nh_key))) == 0)
        {
            p_link_node = FIB_GET_LINK_NODE_FROM_NH_HOLDER (nh_holder);

            return p_link_node;
        }
    }

    return NULL;
}

int fib_del_intf_fh (t_fib_intf *p_intf, t_fib_link_node *p_link_node)
{
    if ((!p_intf) ||
        (!p_link_node))
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_intf: %p, p_link_node: %p\r\n",
                   __FUNCTION__, p_intf, p_link_node);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "Intf: if_index: 0x%x, vrf_id: %d, af_index: %d\r\n",
               p_intf->key.if_index, p_intf->key.vrf_id,
               p_intf->key.af_index);

    std_dll_remove (&p_intf->fh_list, &p_link_node->glue);

    memset (p_link_node, 0, sizeof (t_fib_link_node));

    FIB_LINK_NODE_MEM_FREE (p_link_node);

    return STD_ERR_OK;
}

t_fib_link_node *fib_add_intf_pending_fh (t_fib_intf *p_intf, t_fib_nh *p_fh)
{
    t_fib_link_node  *p_link_node = NULL;

    if ((!p_intf) ||
        (!p_fh))
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_intf: %p, p_fh: %p\r\n",
                   __FUNCTION__, p_intf, p_fh);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "Intf: if_index: 0x%x, vrf_id: %d, af_index: %d, "
               "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
               p_intf->key.if_index, p_intf->key.vrf_id, p_intf->key.af_index,
               p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
               p_fh->key.if_index);

    p_link_node = (t_fib_link_node *) FIB_LINK_NODE_MEM_MALLOC ();

    if (p_link_node == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Memory alloc failed\r\n", __FUNCTION__);

        return NULL;
    }

    memset (p_link_node, 0, sizeof (t_fib_link_node));

    p_link_node->self = p_fh;

    std_dll_insertatback (&p_intf->pending_fh_list, &p_link_node->glue);

    return p_link_node;
}

t_fib_link_node *fib_get_intf_pending_fh (t_fib_intf *p_intf, t_fib_nh *p_fh)
{
    t_fib_link_node  *p_link_node = NULL;
    t_fib_nh        *p_temp_fh = NULL;
    t_fib_nh_holder  nh_holder;

    if ((!p_intf) ||
        (!p_fh))
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_intf: %p, p_fh: %p\r\n",
                   __FUNCTION__, p_intf, p_fh);

        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "Intf: if_index: 0x%x, vrf_id: %d, af_index: %d, "
               "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
               p_intf->key.if_index, p_intf->key.vrf_id, p_intf->key.af_index,
               p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
               p_fh->key.if_index);

    FIB_FOR_EACH_PENDING_FH_FROM_INTF (p_intf, p_temp_fh, nh_holder)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                   "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
                   p_temp_fh->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_temp_fh->key.ip_addr),
                   p_temp_fh->key.if_index);

        if ((memcmp (&p_fh->key, &p_temp_fh->key, sizeof (t_fib_nh_key))) == 0)
        {
            p_link_node = FIB_GET_LINK_NODE_FROM_NH_HOLDER (nh_holder);

            return p_link_node;
        }
    }

    return NULL;
}

int fib_del_intf_pending_fh (t_fib_intf *p_intf, t_fib_link_node *p_link_node)
{
    if ((!p_intf) ||
        (!p_link_node))
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_intf: %p, p_link_node: %p\r\n",
                   __FUNCTION__, p_intf, p_link_node);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "Intf: if_index: 0x%x, vrf_id: %d, af_index: %d\r\n",
               p_intf->key.if_index, p_intf->key.vrf_id,
               p_intf->key.af_index);

    std_dll_remove (&p_intf->pending_fh_list, &p_link_node->glue);

    memset (p_link_node, 0, sizeof (t_fib_link_node));

    FIB_LINK_NODE_MEM_FREE (p_link_node);

    return STD_ERR_OK;
}

int fib_check_and_delete_nh (t_fib_nh *p_nh)
{
    if (!p_nh)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_nh: %p\r\n",
                   __FUNCTION__, p_nh);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "status_flag: 0x%x, owner_flag: 0x%x, "
               "rtm_ref_count: %d, dr_ref_count: %d, nh_ref_count: %d\r\n",
               p_nh->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
               p_nh->key.if_index, p_nh->status_flag, p_nh->owner_flag,
               p_nh->rtm_ref_count, p_nh->dr_ref_count, p_nh->nh_ref_count);

    if (FIB_IS_NH_REQ_RESOLVE (p_nh))
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                   "NH in request resolving state. "
                   "vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
                   p_nh->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                   p_nh->key.if_index);

        return STD_ERR_OK;
    }

    if ((!(FIB_IS_NH_OWNER_RTM (p_nh))) &&
        (!(FIB_IS_NH_OWNER_ARP (p_nh))))
    {
        if (FIB_IS_FH_PENDING (p_nh))
        {
            fib_proc_pending_fh_del (p_nh);
        }
    }

    if ((p_nh->owner_flag == 0) &&
        (p_nh->rtm_ref_count == 0) &&
        (p_nh->dr_ref_count == 0) &&
        (p_nh->nh_ref_count == 0) &&
        (p_nh->tunnel_nh_ref_count == 0))
    {
        if (FIB_IS_NH_FH (p_nh))
        {
            HAL_RT_LOG_DEBUG("HAL-RT-NH",
                       "NH is a FH. "
                       "vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
                       p_nh->vrf_id,
                       FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                       p_nh->key.if_index);

            fib_proc_del_intf_fh (p_nh, false);

            memset (p_nh->p_arp_info, 0, sizeof (t_fib_arp_info));

            FIB_ARP_INFO_MEM_FREE (p_nh->p_arp_info);

            p_nh->p_arp_info = NULL;
        }

        fib_del_nh_best_fit_dr (p_nh);

        fib_delete_all_nh_fh (p_nh);

        fib_delete_all_nh_dep_dr (p_nh);

        /*
         * While deleting the NH node, the associated next_hop id must be deleted.
         * This would be originally created during SAI route creation and associated to
         * NH node.
         */

        if (hal_fib_next_hop_del(p_nh) != DN_HAL_ROUTE_E_NONE)
            fib_mark_nh_for_resolution(p_nh);
        else {
            fib_destroy_nh_dep_dr_tree (p_nh);
            fib_del_nh (p_nh);
        }
    }

    return STD_ERR_OK;
}

int fib_check_and_delete_intf (t_fib_intf *p_intf)
{
    if (!p_intf)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_intf: %p\r\n",
                   __FUNCTION__, p_intf);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "Intf: if_index: 0x%x, vrf_id: %d, af_index: %d\r\n",
               p_intf->key.if_index, p_intf->key.vrf_id,
               p_intf->key.af_index);

    if ((std_dll_getfirst (&p_intf->fh_list) == NULL) &&
        (std_dll_getfirst (&p_intf->pending_fh_list) == NULL))
    {
        fib_del_intf (p_intf);
    }

    return STD_ERR_OK;
}

int fib_nh_walker_init (void)
{
    pthread_mutex_init(&fib_nh_mutex, NULL);
    pthread_cond_init (&fib_nh_cond, NULL);

    return STD_ERR_OK;
}

int fib_nh_walker_main (void)
{
    t_fib_vrf_info         *p_vrf_info = NULL;
    std_radix_version_t  marker_version = 0;
    std_radix_version_t  max_version = 0;
    std_radix_version_t  max_walker_version = 0;
    uint32_t             tot_nh_processed = 0;
    uint32_t             num_active_vrfs = 0;
    uint32_t             vrf_id = 0;
    int                  af_index = 0;
    int                  rc = STD_ERR_OK;

    HAL_RT_LOG_DEBUG("HAL-RT-NH", "af_index: %d\r\n", af_index);

    for (vrf_id = FIB_MIN_VRF; vrf_id < FIB_MAX_VRF; vrf_id++) {
        for (af_index = FIB_MIN_AFINDEX; af_index < FIB_MAX_AFINDEX; af_index++) {
            p_vrf_info = FIB_GET_VRF_INFO (vrf_id, af_index);
            if (p_vrf_info == NULL) {
                HAL_RT_LOG_DEBUG("HAL-RT-NH", "Vrf info NULL. "
                             "vrf_id: %d, af_index: %d\r\n", vrf_id, af_index);
                continue;
            }
            memset (&p_vrf_info->nh_radical_marker, 0, sizeof (std_radical_ref_t));
            std_radical_walkconstructor (p_vrf_info->nh_tree,
                                   &p_vrf_info->nh_radical_marker);
        }
    }

    for ( ; ;)
    {
        pthread_mutex_lock( &fib_nh_mutex );
        while (is_nh_pending_for_processing == 0) // check predicate for signal before wait
        {
            pthread_cond_wait( &fib_nh_cond, &fib_nh_mutex );
        }
        is_nh_pending_for_processing = 0; //reset the predicate for signal
        pthread_mutex_unlock( &fib_nh_mutex );

        tot_nh_processed = 0;
        num_active_vrfs  = 0;

        for (vrf_id = FIB_MIN_VRF; vrf_id < FIB_MAX_VRF; vrf_id++) {
            for (af_index = FIB_MIN_AFINDEX; af_index < FIB_MAX_AFINDEX; af_index++) {
                p_vrf_info = FIB_GET_VRF_INFO (vrf_id, af_index);
                if (p_vrf_info == NULL) {
                    HAL_RT_LOG_DEBUG("HAL-RT-NH", "Vrf info NULL. "
                               "vrf_id: %d, af_index: %d\r\n", vrf_id, af_index);
                    continue;
                }

                if ((p_vrf_info->dr_clear_on == true) ||
                    (p_vrf_info->dr_ha_on == true)) {
                    HAL_RT_LOG_DEBUG("HAL-RT-NH", "DR clear or HA in progress."
                           "vrf_id: %d, af_index: %d, dr_clear_on: %d, dr_ha_on: %d\r\n",
                           vrf_id, af_index, p_vrf_info->dr_clear_on, p_vrf_info->dr_ha_on);
                    continue;
                }

                nas_l3_lock();

                p_vrf_info->num_nh_processed_by_walker = 0;
                if (p_vrf_info->nh_clear_on == true) {
                    max_walker_version = p_vrf_info->nh_clear_max_radix_ver;
                } else if (p_vrf_info->nh_ha_on == true) {
                    max_walker_version = p_vrf_info->nh_ha_max_radix_ver;
                } else {
                    max_walker_version = std_radix_getversion (p_vrf_info->nh_tree);
                }

                /* Process a maximum of FIB_NH_WALKER_COUNT nodes per vrf */

                std_radical_walkchangelist (p_vrf_info->nh_tree,
                                      &p_vrf_info->nh_radical_marker,
                                      fib_nh_walker_call_back,
                                      0,
                                      FIB_NH_WALKER_COUNT,
                                      max_walker_version,
                                      &rc);

                /* @@TODO: Need to handle version wrap */

                max_version    = std_radix_getversion (p_vrf_info->nh_tree);
                marker_version = p_vrf_info->nh_radical_marker.rth_version;

                if (marker_version != max_version) {
                    num_active_vrfs++;
                }
                /*
                 * 'p_vrf_info->num_nh_processed_by_walker' is updated in
                 * fib_nh_walker_call_back ().
                 */
                if (p_vrf_info->num_nh_processed_by_walker == FIB_NH_WALKER_COUNT) {
                    HAL_RT_LOG_DEBUG("HAL-RT-NH", "Max NH processed per walk, relinquish now",
                                     tot_nh_processed);
                    is_nh_pending_for_processing = true;
                }
                tot_nh_processed += p_vrf_info->num_nh_processed_by_walker;
                nas_l3_unlock();
            }
        }  /* End of vrf loop */


        HAL_RT_LOG_DEBUG("HAL-RT-NH", "Total NH processed %d",  tot_nh_processed);

        if(tot_nh_processed) {
            fib_resume_dr_walker_thread (af_index);
        }
    } /* End of infinite loop */

    return STD_ERR_OK;
}

int fib_nh_walker_call_back (std_radical_head_t *p_rt_head, va_list ap)
{
    t_fib_vrf_info   *p_vrf_info = NULL;
    t_fib_nh        *p_nh = NULL;
    dn_hal_route_err     hal_err = DN_HAL_ROUTE_E_NONE;
    bool           is_host_ready = true;
    t_fib_dr        *p_dr = NULL;

    if (!p_rt_head)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_rt_head: %p\r\n",
                   __FUNCTION__, p_rt_head);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    p_nh = (t_fib_nh *) p_rt_head;

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "NH: vrf_id: %d, ip_addr: %s, if_index: %d, "
               "status_flag: 0x%x, owner_flag: 0x%x\r\n",
               p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
               p_nh->status_flag, p_nh->owner_flag);

    p_vrf_info = FIB_GET_VRF_INFO (p_nh->vrf_id,
                                 p_nh->key.ip_addr.af_index);

    if (p_vrf_info == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Vrf info NULL. vrf_id: %d, af_index: %d\r\n",
                   __FUNCTION__, p_nh->vrf_id, p_nh->key.ip_addr.af_index);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "num_nh_processed_by_walker: %d, nh_clear_on: %d, "
               "nh_ha_on: %d, arp_last_update_time: %lld\r\n",
               p_vrf_info->num_nh_processed_by_walker, p_vrf_info->nh_clear_on,
               p_vrf_info->nh_ha_on, p_nh->arp_last_update_time);

    p_vrf_info->num_nh_processed_by_walker++;

    if ((p_vrf_info->clear_ip_fib_on == true) ||
        (p_vrf_info->clear_arp_on == true))
    {
        if (FIB_IS_NH_OWNER_ARP (p_nh))
        {
            fib_proc_nh_delete (p_nh, FIB_NH_OWNER_TYPE_ARP, 0);

            p_nh->status_flag |= FIB_NH_STATUS_REQ_RESOLVE;
        }
    }

    if (!(p_nh->status_flag & FIB_NH_STATUS_REQ_RESOLVE))
    {
        return STD_ERR_OK;
    }

    /* Addition */
    if (p_nh->status_flag & FIB_NH_STATUS_ADD)
    {
        fib_del_nh_best_fit_dr (p_nh);

        fib_delete_all_nh_fh (p_nh);

        /* Update NH resolution status in the route entry */
        fib_update_nh_dep_dr_resolution_status(p_nh);

        /* First Hop */
        if (FIB_IS_NH_FH (p_nh))
        {
            if (is_host_ready == true)
            {
                if (FIB_IS_FH_PENDING (p_nh))
                {
                    fib_proc_pending_fh_del (p_nh);
                }

                hal_err = hal_fib_host_add (p_nh->vrf_id, p_nh);

                if (hal_err == DN_HAL_ROUTE_E_NONE)
                {
                    if ((FIB_IS_NH_OWNER_ARP (p_nh)))
                    {
                        p_nh->status_flag |= FIB_NH_STATUS_WRITTEN;
                        if ((p_nh->is_cam_host_count_incremented == false))
                        {
                            p_nh->is_cam_host_count_incremented = true;

                            FIB_INCR_CNTRS_CAM_HOST_ENTRIES (p_nh->vrf_id, p_nh->key.ip_addr.af_index);
                        }
                        fib_check_threshold_for_all_cams (true);
                    }
                    else
                    {
                        p_nh->status_flag &= ~FIB_NH_STATUS_WRITTEN;

                        if ((p_nh->is_cam_host_count_incremented == true))
                        {
                            p_nh->is_cam_host_count_incremented = false;

                            FIB_DECR_CNTRS_CAM_HOST_ENTRIES (p_nh->vrf_id, p_nh->key.ip_addr.af_index);
                        }
                        fib_check_threshold_for_all_cams (false);
                    }
                }
                else
                {
                    HAL_RT_LOG_DEBUG("HAL-RT-NH",
                               "Error hal_fib_host_add. "
                               "vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                               "hal_err: %d (%s)\r\n",
                               p_nh->vrf_id,
                               FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                               p_nh->key.if_index, hal_err,
                               HAL_RT_GET_ERR_STR (hal_err));

                    if (FIB_IS_NH_WRITTEN (p_nh))
                    {
                        p_nh->status_flag &= ~FIB_NH_STATUS_WRITTEN;

                        FIB_DECR_CNTRS_CAM_HOST_ENTRIES (p_nh->vrf_id, p_nh->key.ip_addr.af_index);
                    }
                }
            }
        }
        else /* Next Hop */
        {
            if (FIB_IS_NH_OWNER_RTM (p_nh))
            {
                fib_resolve_nh (p_nh);
            }
        }

        fib_mark_nh_dep_dr_for_resolution (p_nh);

        p_nh->status_flag &= ~FIB_NH_STATUS_REQ_RESOLVE;

        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                   "End of processing NH addition. "
                   "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                   "status_flag: 0x%x, owner_flag: 0x%x\r\n",
                    p_nh->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
                   p_nh->status_flag, p_nh->owner_flag);
    }
    else if (p_nh->status_flag & FIB_NH_STATUS_DEL) /* Deletion */
    {
        /* Update NH resolution status in the route entry */
        fib_update_nh_dep_dr_resolution_status(p_nh);
        if (FIB_IS_NH_FH (p_nh))
        {
            HAL_RT_LOG_DEBUG("HAL-RT-NH",
                       "NH is a FH. "
                       "vrf_id: %d, ip_addr: %s, if_index: 0x%x\r\n",
                        p_nh->vrf_id,
                       FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                       p_nh->key.if_index);

            if (FIB_IS_NH_WRITTEN (p_nh))
            {
                hal_err = hal_fib_host_del (p_nh->vrf_id, p_nh);

                if (hal_err == DN_HAL_ROUTE_E_NONE)
                {
                    fib_check_threshold_for_all_cams (false);

                    p_nh->status_flag &= ~FIB_NH_STATUS_WRITTEN;

                    FIB_DECR_CNTRS_CAM_HOST_ENTRIES (p_nh->vrf_id, p_nh->key.ip_addr.af_index);

                    p_dr = fib_get_dr (p_nh->vrf_id, &p_nh->key.ip_addr, FIB_AFINDEX_TO_PREFIX_LEN(p_nh->key.ip_addr.af_index));

                    if ((p_dr != NULL) && (!(FIB_IS_DR_WRITTEN (p_dr))))
                    {
                        HAL_RT_LOG_DEBUG("HAL-RT-NH", "Full length route is available for resolution "
                                "Vrf_id: %d, prefix %s\r\n",  p_nh->vrf_id,
                                FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr));

                        fib_mark_dr_for_resolution (p_dr);
                    }
                }
                else
                {
                    HAL_RT_LOG_DEBUG("HAL-RT-NH",
                               "Error hal_fib_host_del. "
                               "vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                               "hal_err: %d (%s)\r\n",
                               p_nh->vrf_id,
                               FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                               p_nh->key.if_index, hal_err,
                               HAL_RT_GET_ERR_STR (hal_err));
                }
            }
        }

        fib_mark_nh_dep_dr_for_resolution (p_nh);

        fib_del_nh_best_fit_dr (p_nh);

        fib_delete_all_nh_fh (p_nh);

        fib_delete_all_nh_dep_dr (p_nh);

        p_nh->status_flag &= ~FIB_NH_STATUS_REQ_RESOLVE;

        fib_check_and_delete_nh (p_nh);
    }

    return STD_ERR_OK;
}

int fib_resolve_nh (t_fib_nh *p_nh)
{
    t_fib_dr  *p_best_fit_dr = NULL;

    if (!p_nh)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_nh: %p\r\n",
                   __FUNCTION__, p_nh);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "status_flag: 0x%x, owner_flag: 0x%x\r\n",
                p_nh->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
               p_nh->status_flag, p_nh->owner_flag);

    fib_del_nh_best_fit_dr (p_nh);

    fib_delete_all_nh_fh (p_nh);

    p_best_fit_dr = fib_get_nh_best_fit_dr (p_nh);

    if (p_best_fit_dr == NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                   "NH best fit DR not found. "
                   "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                   "status_flag: 0x%x, owner_flag: 0x%x\r\n",
                    p_nh->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
                   p_nh->status_flag, p_nh->owner_flag);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "status_flag: 0x%x, owner_flag: 0x%x, "
               "Best Fit DR: vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
                p_nh->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
               p_nh->status_flag, p_nh->owner_flag, p_best_fit_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_best_fit_dr->key.prefix),
               p_best_fit_dr->prefix_len);

    fib_add_nh_best_fit_dr (p_nh, p_best_fit_dr);

    if (FIB_IS_DR_REQ_RESOLVE (p_best_fit_dr))
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                   "Best fit DR in request resolve state. "
                   "Best Fit DR: vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
                    p_best_fit_dr->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_best_fit_dr->key.prefix),
                   p_best_fit_dr->prefix_len);

        return STD_ERR_OK;
    }

    fib_add_nh_fh_from_best_fit_dr_nh (p_nh, p_best_fit_dr);

    return STD_ERR_OK;
}

int fib_add_nh_fh_from_best_fit_dr_nh (t_fib_nh *p_nh, t_fib_dr *p_best_fit_dr)
{
    t_fib_link_node   *p_link_node = NULL;
    t_fib_nh         *p_fh = NULL;
    t_fib_nh_holder   nh_holder;

    if ((!p_nh) ||
        (!p_best_fit_dr))
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_nh: %p, p_best_fit_dr: %p\r\n",
                   __FUNCTION__, p_nh, p_best_fit_dr);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "status_flag: 0x%x, owner_flag: 0x%x, "
               "Best Fit DR: vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
                p_nh->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
               p_nh->status_flag, p_nh->owner_flag, p_best_fit_dr->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_best_fit_dr->key.prefix),
               p_best_fit_dr->prefix_len);

    if (FIB_IS_DR_REQ_RESOLVE (p_best_fit_dr))
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                   "Best fit DR in request resolve state. "
                   "Best Fit DR: vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
                    p_best_fit_dr->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_best_fit_dr->key.prefix),
                   p_best_fit_dr->prefix_len);
        return STD_ERR_OK;
    }

    FIB_FOR_EACH_FH_FROM_DR (p_best_fit_dr, p_fh, nh_holder)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                   "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                   "status_flag: 0x%x, owner_flag: 0x%x\r\n",
                    p_fh->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr), p_fh->key.if_index,
                   p_fh->status_flag, p_fh->owner_flag);

        p_link_node = fib_get_nh_fh (p_nh, p_fh);

        if (p_link_node != NULL)
        {
            HAL_RT_LOG_DEBUG("HAL-RT-NH",
                       "Duplicate NHFH addition. "
                       "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                       "status_flag: 0x%x, owner_flag: 0x%x, "
                       "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                       "status_flag: 0x%x, owner_flag: 0x%x\r\n",
                        p_nh->vrf_id,
                       FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                       p_nh->key.if_index, p_nh->status_flag,
                       p_nh->owner_flag, p_fh->vrf_id,
                       FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                       p_fh->key.if_index, p_fh->status_flag, p_fh->owner_flag);

            continue;
        }

        p_link_node = fib_add_nh_fh (p_nh, p_fh);

        if (p_link_node == NULL)
        {
            HAL_RT_LOG_ERR("HAL-RT-NH",
                       "%s (): NHFH addition failed. "
                       "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                       "status_flag: 0x%x, owner_flag: 0x%x, "
                       "FH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                       "status_flag: 0x%x, owner_flag: 0x%x\r\n",
                       __FUNCTION__, p_nh->vrf_id,
                       FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                       p_nh->key.if_index, p_nh->status_flag,
                       p_nh->owner_flag, p_fh->vrf_id,
                       FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                       p_fh->key.if_index, p_fh->status_flag, p_fh->owner_flag);

        }

    }

    return STD_ERR_OK;
}

int fib_mark_nh_for_resolution (t_fib_nh *p_nh)
{
    uint8_t   af_index = 0;
    uint32_t  vrf_id = 0;

    if (!p_nh)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_nh: %p\r\n",
                   __FUNCTION__, p_nh);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "NH: vrf_id: %d, ip_addr: %s, if_index: %d, "
               "status_flag: 0x%x, owner_flag: 0x%x\r\n",
                p_nh->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
               p_nh->status_flag, p_nh->owner_flag);

    p_nh->status_flag |= FIB_NH_STATUS_REQ_RESOLVE;

    vrf_id   = p_nh->vrf_id;
    af_index = p_nh->key.ip_addr.af_index;

    std_radical_appendtochangelist (hal_rt_access_fib_vrf_nh_tree(vrf_id, af_index),
                                  (std_radical_head_t *)&(p_nh->radical));

    //fib_resume_nh_walker_thread(af_index);

    return STD_ERR_OK;
}

int fib_mark_nh_dep_dr_for_resolution (t_fib_nh *p_nh)
{
    t_fib_dr_key      key;
    t_fib_nh_dep_dr   *p_nh_dep_dr = NULL;

    if (!p_nh)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_nh: %p\r\n",
                   __FUNCTION__, p_nh);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "status_flag: 0x%x, owner_flag: 0x%x\r\n",
                p_nh->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
               p_nh->status_flag, p_nh->owner_flag);

    memset (&key, 0, sizeof (t_fib_dr_key));

    p_nh_dep_dr = fib_get_first_nh_dep_dr (p_nh);

    while (p_nh_dep_dr != NULL)
    {
        if (p_nh_dep_dr->p_dr == NULL)
        {
            p_nh_dep_dr =
                fib_get_next_nh_dep_dr (p_nh, p_nh_dep_dr->key.vrf_id,
                                   &p_nh_dep_dr->key.dr_key.prefix,
                                   p_nh_dep_dr->prefix_len);

            continue;
        }

        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                   "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                   "status_flag: 0x%x, owner_flag: 0x%x, "
                   "NH Dep DR: vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
                    p_nh->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
                   p_nh->status_flag, p_nh->owner_flag, p_nh_dep_dr->key.vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_nh_dep_dr->key.dr_key.prefix),
                   p_nh_dep_dr->prefix_len);

        /*
         * Mark DR for resolution only for ECMP case
         */
        if(p_nh_dep_dr->p_dr->num_nh > 1)
            fib_mark_dr_for_resolution (p_nh_dep_dr->p_dr);

        p_nh_dep_dr =
            fib_get_next_nh_dep_dr (p_nh, p_nh_dep_dr->key.vrf_id,
                               &p_nh_dep_dr->key.dr_key.prefix,
                               p_nh_dep_dr->prefix_len);
    }

    return STD_ERR_OK;
}

int fib_update_nh_dep_dr_resolution_status (t_fib_nh *p_nh)
{
    t_fib_dr_key      key;
    t_fib_nh_dep_dr   *p_nh_dep_dr = NULL;

    if (!p_nh)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_nh: %p\r\n",
                   __FUNCTION__, p_nh);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
               "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
               "status_flag: 0x%x, owner_flag: 0x%x\r\n",
                p_nh->vrf_id,
               FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
               p_nh->status_flag, p_nh->owner_flag);

    memset (&key, 0, sizeof (t_fib_dr_key));

    p_nh_dep_dr = fib_get_first_nh_dep_dr (p_nh);

    while (p_nh_dep_dr != NULL)
    {
        if (p_nh_dep_dr->p_dr == NULL)
        {
            p_nh_dep_dr =
                fib_get_next_nh_dep_dr (p_nh, p_nh_dep_dr->key.vrf_id,
                                   &p_nh_dep_dr->key.dr_key.prefix,
                                   p_nh_dep_dr->prefix_len);

            continue;
        }

        HAL_RT_LOG_DEBUG("HAL-RT-NH",
                   "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                   "status_flag: 0x%x, owner_flag: 0x%x, "
                   "NH Dep DR: vrf_id: %d, prefix: %s, prefix_len: %d\r\n",
                    p_nh->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
                   p_nh->status_flag, p_nh->owner_flag, p_nh_dep_dr->key.vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_nh_dep_dr->key.dr_key.prefix),
                   p_nh_dep_dr->prefix_len);

        if ((p_nh->p_arp_info) && (p_nh->p_arp_info->state == FIB_ARP_RESOLVED)) {
            p_nh_dep_dr->p_dr->is_nh_resolved = true;
        } else {
            p_nh_dep_dr->p_dr->is_nh_resolved = false;
        }

        p_nh_dep_dr =
            fib_get_next_nh_dep_dr (p_nh, p_nh_dep_dr->key.vrf_id,
                               &p_nh_dep_dr->key.dr_key.prefix,
                               p_nh_dep_dr->prefix_len);
    }

    return STD_ERR_OK;
}


int fib_resume_nh_walker_thread (uint8_t af_index)
{
    int retval;

    HAL_RT_LOG_DEBUG("HAL-RT-NH", "af_index: %d\r\n",  af_index);
    pthread_mutex_lock( &fib_nh_mutex );
    is_nh_pending_for_processing = 1; //set the predicate for signal
    if((retval = pthread_cond_signal( &fib_nh_cond)) != 0) {
        HAL_RT_LOG_DEBUG("HAL-RT-NH", "pthread cond signal failed %d", retval);
    }
    pthread_mutex_unlock( &fib_nh_mutex );
    return STD_ERR_OK;
}
