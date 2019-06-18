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
 * \file   hal_rt_leak.c
 * \brief  This file handles the route leaking related functionality.
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


static std_rt_table   *leaked_rt_tree = NULL;

int fib_create_leaked_rt_tree(void)
{
    if (leaked_rt_tree != NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-DR-LEAK", "Leaked route tree already created");
        return STD_ERR_OK;
    }

    leaked_rt_tree = std_radix_create ("fib_leaked_rt_tree", FIB_RDX_LEAKED_RT_KEY_LEN, NULL, NULL, 0);
    if (leaked_rt_tree == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR-LEAK", " Leaked route tree creation failed!");
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    return STD_ERR_OK;
}

int fib_destroy_leaked_rt_tree(void)
{
    if (leaked_rt_tree == NULL)
    {
        HAL_RT_LOG_ERR("HAL-RT-DR-LEAK", "Leaked route tree does not exist!");
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    std_radix_destroy (leaked_rt_tree);

    leaked_rt_tree = NULL;

    return STD_ERR_OK;
}

t_fib_leaked_rt *fib_get_leaked_rt (uint32_t vrf_id, t_fib_ip_addr *p_prefix, int prefix_len) {
    t_fib_leaked_rt *p_leaked_rt = NULL;
    t_fib_leaked_rt_key key;

    memset (&key, 0, sizeof (t_fib_leaked_rt_key));
    key.vrf_id = vrf_id;
    memcpy (&key.prefix, p_prefix, sizeof (t_fib_ip_addr));
    key.prefix_len = prefix_len;

    HAL_RT_LOG_INFO("HAL-RT-LEAK-GET", "Keys - vrf_id: %d, prefix: %s(%d)",
                    key.vrf_id, FIB_IP_ADDR_TO_STR (&key.prefix), key.prefix_len);
    p_leaked_rt = (t_fib_leaked_rt*) std_radix_getexact (leaked_rt_tree,
                                                         (uint8_t *)&key, FIB_RDX_LEAKED_RT_KEY_LEN);
    if (p_leaked_rt != NULL) {
        HAL_RT_LOG_INFO("HAL-RT-LEAK-GET", "vrf_id: %d, prefix: %s(%d)",
                        vrf_id, FIB_IP_ADDR_TO_STR (p_prefix), prefix_len);
    }

    return p_leaked_rt;
}


t_std_error hal_rt_add_dep_leaked_vrf (t_fib_leaked_rt_key *p_parent_route, hal_vrf_id_t vrf_id)
{
    t_fib_link_node  *p_link_node = NULL;

    t_fib_leaked_rt *p_leaked_rt = fib_get_leaked_rt(p_parent_route->vrf_id, &p_parent_route->prefix,
                                                     p_parent_route->prefix_len);
    if (p_leaked_rt == NULL) {
        p_leaked_rt = (t_fib_leaked_rt*) FIB_LEAKED_RT_MEM_MALLOC();
        if (p_leaked_rt == NULL) {
            HAL_RT_LOG_ERR("DR-LEAK-VRF-ADD","Leaked rt memory allocation failed!");
            return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
        }

        HAL_RT_LOG_INFO("DR-LEAK-VRF-ADD", "Add - parent route node - vrf_id: %d, prefix: %s/%d, "
                         "leaked VRF-id:%d", p_parent_route->vrf_id,
                         FIB_IP_ADDR_TO_STR (&p_parent_route->prefix), p_parent_route->prefix_len,
                         vrf_id);
        memset(p_leaked_rt, 0, sizeof(t_fib_leaked_rt));
        std_dll_init (&p_leaked_rt->leaked_vrf_list);
        p_leaked_rt->key.vrf_id = p_parent_route->vrf_id;
        memcpy (&p_leaked_rt->key.prefix, &p_parent_route->prefix, sizeof (t_fib_ip_addr));
        p_leaked_rt->key.prefix_len = p_parent_route->prefix_len;

        p_leaked_rt->rt_head.rth_addr = (uint8_t *) (&(p_leaked_rt->key));
        std_rt_head *p_radix_head = std_radix_insert (leaked_rt_tree, (std_rt_head *)(&p_leaked_rt->rt_head),
                                                      FIB_RDX_LEAKED_RT_KEY_LEN);
        if (p_radix_head == NULL)
        {
            HAL_RT_LOG_ERR("DR-LEAK-VRF-ADD","Radix insertion failed. ");
            FIB_LEAKED_RT_MEM_FREE(p_leaked_rt);
            return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
        }

        if (p_radix_head != ((std_rt_head *)p_leaked_rt))
        {
            HAL_RT_LOG_ERR("DR-LEAK-VRF-ADD","Duplicate Radix insertion for leaked route!");
            FIB_LEAKED_RT_MEM_FREE(p_leaked_rt);
            p_leaked_rt = (t_fib_leaked_rt *) p_radix_head;
        }
    }

    p_link_node = (t_fib_link_node *) FIB_LINK_NODE_MEM_MALLOC ();
    if (p_link_node == NULL)
    {
        HAL_RT_LOG_ERR("DR-LEAK-VRF-ADD","Memory alloc failed for leak VRF node!");
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }
    hal_vrf_id_t *p_vrf_id = (hal_vrf_id_t *) FIB_VRF_ID_MEM_MALLOC();
    if (p_vrf_id == NULL)
    {
        FIB_LINK_NODE_MEM_FREE(p_link_node);
        HAL_RT_LOG_ERR("DR-LEAK-VRF-ADD","Memory alloc failed for VRF!");
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    memset (p_link_node, 0, sizeof (t_fib_link_node));
    *p_vrf_id = vrf_id;

    p_link_node->self = p_vrf_id;

    std_dll_insertatback (&p_leaked_rt->leaked_vrf_list, &p_link_node->glue);

    HAL_RT_LOG_INFO("DR-LEAK-VRF-ADD", "Add - parent route node - vrf_id: %d, prefix: %s/%d, "
                    "leaked VRF-id:%d successful", p_parent_route->vrf_id,
                    FIB_IP_ADDR_TO_STR (&p_parent_route->prefix), p_parent_route->prefix_len,
                    vrf_id);
    t_fib_leaked_rt *p_get_leaked_rt = fib_get_leaked_rt(p_parent_route->vrf_id, &p_parent_route->prefix,
                                                     p_parent_route->prefix_len);
    if (p_get_leaked_rt == NULL) {
        HAL_RT_LOG_ERR("DR-LEAK-VRF-ADD", "Add - parent route node - vrf_id: %d, prefix: %s/%d, "
                       "leaked VRF-id:%d failed!", p_parent_route->vrf_id,
                       FIB_IP_ADDR_TO_STR (&p_parent_route->prefix), p_parent_route->prefix_len,
                       vrf_id);
        FIB_LINK_NODE_MEM_FREE(p_link_node);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }
    t_fib_vrf_holder vrf_holder;
    FIB_FOR_EACH_LEAKED_VRF_FROM_DR(p_get_leaked_rt, p_vrf_id, vrf_holder)
    {
        HAL_RT_LOG_INFO("DR-LEAK-VRF-ADD", "Current leaked VRF:%d", *p_vrf_id);
    }
    return STD_ERR_OK;
}

int hal_rt_del_dep_leaked_vrf(t_fib_leaked_rt_key *p_parent_route, hal_vrf_id_t vrf_id)
{
    t_fib_link_node  *p_link_node = NULL;
    hal_vrf_id_t     *p_vrf_id = NULL;
    t_fib_vrf_holder vrf_holder;

    t_fib_leaked_rt *p_leaked_rt = fib_get_leaked_rt(p_parent_route->vrf_id,
                                                     &p_parent_route->prefix, p_parent_route->prefix_len);
    if (p_leaked_rt == NULL) {
        HAL_RT_LOG_ERR("DR-LEAK-VRF-DEL", "parent route node - vrf_id: %d, prefix: %s/%d, "
                       "leaked VRF-id:%d does not exist!", p_parent_route->vrf_id,
                       FIB_IP_ADDR_TO_STR (&p_parent_route->prefix), p_parent_route->prefix_len,
                       vrf_id);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }
    FIB_FOR_EACH_LEAKED_VRF_FROM_DR(p_leaked_rt, p_vrf_id, vrf_holder)
    {
        if ((*p_vrf_id >= FIB_MAX_VRF) || (hal_rt_access_fib_vrf(*p_vrf_id) == NULL)) {
            HAL_RT_LOG_ERR("DR-LEAK-VRF-DEL", "Invalid VRF-id:%d", *p_vrf_id);
            continue;
        }

        if (*p_vrf_id == vrf_id) {
            p_link_node = FIB_GET_LINK_NODE_FROM_VRF_HOLDER(vrf_holder);
            if (p_link_node) {
                std_dll_remove (&p_leaked_rt->leaked_vrf_list, &p_link_node->glue);

                FIB_VRF_ID_MEM_FREE(p_link_node->self);
                memset (p_link_node, 0, sizeof (t_fib_link_node));
                FIB_LINK_NODE_MEM_FREE (p_link_node);
                HAL_RT_LOG_INFO("DR-LEAK-VRF-DEL", "Parent route node - vrf_id: %d, prefix: %s/%d, "
                                "leaked VRF-id:%d deletion successful", p_parent_route->vrf_id,
                                FIB_IP_ADDR_TO_STR (&p_parent_route->prefix), p_parent_route->prefix_len,
                                vrf_id);
            }

            break;
        }
    }

    if (FIB_GET_FIRST_LEAKED_VRF_FROM_DR(p_leaked_rt, vrf_holder) == NULL) {
        std_radix_remove (leaked_rt_tree, (std_rt_head *)(&p_leaked_rt->rt_head));
        memset (p_leaked_rt, 0, sizeof (t_fib_leaked_rt));
        FIB_LEAKED_RT_MEM_FREE(p_leaked_rt);
        HAL_RT_LOG_INFO("DR-LEAK-VRF-DEL", "Parent route node - vrf_id: %d, prefix: %s/%d deleted!",
                        p_parent_route->vrf_id, FIB_IP_ADDR_TO_STR (&p_parent_route->prefix),
                        p_parent_route->prefix_len);
    }
    return STD_ERR_OK;
}

/* This function programs the parent ARPs/Neighbors into the leaked VRF
 * when the ARPs/Neighbors programming is successful in the parent VRF. */
t_std_error fib_prg_nbr_to_leaked_vrfs_on_parent_nbr_update(t_fib_nh *p_fh, bool is_add)
{
    hal_vrf_id_t     *p_vrf_id = NULL;
    t_fib_vrf_holder vrf_holder;
    t_fib_nh_holder     nh_holder;

    if (!p_fh) {
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    t_fib_vrf_info *p_vrf_info = hal_rt_access_fib_vrf_info(p_fh->vrf_id, p_fh->key.ip_addr.af_index);
    if (p_vrf_info == NULL) {
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_INFO("HAL-RT-DR-LEAK", "is_add:%d FH: vrf_id: %d(%s), host: %s",
                   is_add, p_fh->vrf_id, p_vrf_info->vrf_name,
                   FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr));
    t_fib_dr *p_dr = fib_get_best_fit_dr(p_fh->vrf_id, &p_fh->key.ip_addr);
    while(p_dr) {
        HAL_RT_LOG_INFO("HAL-RT-DR-LEAK", "is_add:%d DR: vrf_id: %d(%s), prefix: %s/%d ",
                        is_add, p_dr->vrf_id, p_vrf_info->vrf_name,
                        FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len);
        t_fib_nh *p_nh = FIB_GET_FIRST_NH_FROM_DR(p_dr, nh_holder);
        if ((p_dr->num_nh != 1) || (p_dr->rt_type == RT_CACHE) ||
            (p_nh == NULL) || (p_nh->key.if_index != p_fh->key.if_index) || !(FIB_IS_NH_ZERO(p_nh))) {
            break;
        }
        if (p_nh) {
            HAL_RT_LOG_INFO("HAL-RT-DR-LEAK", "is_add:%d DR: vrf_id: %d(%s), prefix: %s/%d NH:%s nh-cnt:%d if-index nh:%d fh:%d",
                            is_add, p_dr->vrf_id, p_vrf_info->vrf_name,
                            FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len, FIB_IP_ADDR_TO_STR(&p_nh->key.ip_addr),
                            p_dr->num_nh,
                            p_nh->key.if_index, p_fh->key.if_index);
        }
        t_fib_leaked_rt *p_leaked_rt = fib_get_leaked_rt(p_dr->vrf_id, &p_dr->key.prefix, p_dr->prefix_len);
        if (p_leaked_rt) {
            FIB_FOR_EACH_LEAKED_VRF_FROM_DR(p_leaked_rt, p_vrf_id, vrf_holder)
            {
                if ((*p_vrf_id >= FIB_MAX_VRF) || (hal_rt_access_fib_vrf(*p_vrf_id) == NULL)) {
                    HAL_RT_LOG_ERR("HAL-RT-DR-LEAK", "Invalid VRF-id:%d", *p_vrf_id);
                    continue;
                }
                p_vrf_info = hal_rt_access_fib_vrf_info(*p_vrf_id, p_fh->key.ip_addr.af_index);
                if (p_vrf_info == NULL) {
                    HAL_RT_LOG_ERR("HAL-RT-DR-LEAK", "is_add:%d leaked-VRF:%d is not found!",
                                   is_add, *p_vrf_id);
                    continue;
                }
                HAL_RT_LOG_INFO("HAL-RT-DR-LEAK", "is_add:%d host:%s leaked-VRF:%d(%s)!",
                                is_add, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr), *p_vrf_id, p_vrf_info->vrf_name);
                hal_rt_leaked_nbr_prg(*p_vrf_id, p_fh, is_add);
            }
        }
        break;
    }

    return STD_ERR_OK;
}

/* Program the neighbors from parent VRF context to leaked VRF context */
t_std_error fib_prg_parent_nbrs_on_leaked_vrf(hal_ifindex_t if_index, const t_fib_dr *p_parent_dr,
                                              hal_vrf_id_t leaked_vrf_id, bool is_add) {
    t_fib_nh        *p_fh = NULL;
    t_fib_nh_holder nh_holder;
    t_fib_intf *p_intf = NULL;
    t_fib_ip_addr mask;

    HAL_RT_LOG_INFO("DR-LEAK-NBR-PRG", "is_add:%d intf:%d vrf_id: %d, prefix: %s, prefix_len: %d leaked-VRF:%d",
                    is_add, if_index, p_parent_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_parent_dr->key.prefix),
                    p_parent_dr->prefix_len, leaked_vrf_id);
    p_intf = fib_get_intf (if_index, p_parent_dr->vrf_id, p_parent_dr->key.prefix.af_index);
    if (p_intf == NULL) {
        HAL_RT_LOG_ERR("DR-LEAK-NBR-PRG", "intf:%d not present for vrf_id: %d, prefix: %s, prefix_len: %d leaked-VRF:%d",
                       if_index, p_parent_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_parent_dr->key.prefix),
                       p_parent_dr->prefix_len, leaked_vrf_id);
        return STD_ERR_OK;
    }
    memset (&mask, 0, sizeof (t_fib_ip_addr));
    if (nas_rt_get_mask (p_parent_dr->key.prefix.af_index, p_parent_dr->prefix_len, &mask) == false) {
        HAL_RT_LOG_ERR("DR-LEAK-NBR-PRG", "intf:%d vrf_id: %d, prefix: %s, prefix_len: %d leaked-VRF:%d get mask failed",
                       if_index, p_parent_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_parent_dr->key.prefix),
                       p_parent_dr->prefix_len, leaked_vrf_id);
        return STD_ERR_OK;
    }

    /* Loop for all the FH and program into the leaked VRF */
    FIB_FOR_EACH_FH_FROM_INTF (p_intf, p_fh, nh_holder) {
        if (FIB_IS_NH_ZERO(p_fh)) {
            HAL_RT_LOG_INFO("DR-LEAK-NBR-PRG", "intf:%d vrf_id: %d, prefix: %s, prefix_len: %d leaked-VRF:%d NH zero",
                           if_index, p_parent_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_parent_dr->key.prefix),
                           p_parent_dr->prefix_len, leaked_vrf_id);
            continue;
        }
        if (FIB_IS_IP_ADDR_IN_PREFIX(&p_fh->key.ip_addr, &mask, &p_parent_dr->key.prefix)) {
            HAL_RT_LOG_INFO("DR-LEAK-NBR-PRG", "is_add:%d host:%s leaked-VRF:%d",
                           is_add, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr), leaked_vrf_id);
            hal_rt_leaked_nbr_prg(leaked_vrf_id, p_fh, is_add);
        }
    }
    return STD_ERR_OK;
}

/* On connected route update, handle the ARPs/Neighbors for leaked VRF. */
t_std_error fib_prg_leaked_nbrs_on_leaked_route_update(hal_ifindex_t if_index, t_fib_dr *p_parent_dr,
                                                       hal_vrf_id_t leaked_vrf_id, bool is_add) {
    return (fib_prg_parent_nbrs_on_leaked_vrf(if_index, p_parent_dr, leaked_vrf_id, is_add));
}


t_std_error fib_prg_leaked_nbrs_on_parent_route_update(t_fib_dr *p_dr, bool is_add) {
    t_fib_nh_holder nh_holder;
    t_fib_vrf_holder vrf_holder;
    hal_vrf_id_t     *p_vrf_id = NULL;

    t_fib_leaked_rt *p_leaked_rt = fib_get_leaked_rt(p_dr->vrf_id, &p_dr->key.prefix, p_dr->prefix_len);
    if (p_leaked_rt == NULL) {
        return STD_ERR_OK;
    }
    t_fib_nh *p_nh = FIB_GET_FIRST_NH_FROM_DR(p_dr, nh_holder);
    if ((p_dr->num_nh != 1) || (p_dr->rt_type == RT_CACHE) ||
        (p_nh == NULL) || !(FIB_IS_NH_ZERO(p_nh))) {
        return STD_ERR_OK;
    }
    FIB_FOR_EACH_LEAKED_VRF_FROM_DR(p_leaked_rt, p_vrf_id, vrf_holder)
    {
        HAL_RT_LOG_INFO("LEAK-DR-UPD", "VRF-id:%d prefix:%s(%d) leaked:%d", p_dr->vrf_id,
                       FIB_IP_ADDR_TO_STR(&p_dr->key.prefix), p_dr->prefix_len, *p_vrf_id);
        if ((*p_vrf_id >= FIB_MAX_VRF) || (hal_rt_access_fib_vrf(*p_vrf_id) == NULL)) {
            HAL_RT_LOG_ERR("HAL-RT-DR-LEAK", "Invalid VRF-id:%d", *p_vrf_id);
            continue;
        }
        fib_prg_parent_nbrs_on_leaked_vrf(p_nh->key.if_index, p_dr, *p_vrf_id, is_add);
    }

    return STD_ERR_OK;
}


t_std_error hal_rt_leaked_nbr_prg(hal_vrf_id_t vrf_id, t_fib_nh *p_fh, bool is_add) {
    t_fib_nh *p_nh = NULL;

    if (is_add) {
        p_nh = fib_proc_nh_add (vrf_id, &p_fh->key.ip_addr,
                                p_fh->key.if_index, FIB_NH_OWNER_TYPE_ARP, 0, false, p_fh->vrf_id, 0);
        if (p_nh == NULL) {
            HAL_RT_LOG_ERR("LEAK-NBR-PRG", "NH addition failed. "
                           "Leaked VRF:%d parent VRF:%d, ip_addr:%s, if_index: %d",
                           vrf_id, p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                           p_fh->key.if_index);
            return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
        }

        if (p_nh->p_arp_info == NULL) {
            HAL_RT_LOG_ERR("LEAK-NBR-PRG", "NH's ARP info is NULL"
                           "Leaked VRF:%d parent VRF:%d, ip_addr:%s, if_index: %d",
                           vrf_id, p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                           p_fh->key.if_index);
            return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
        }

        p_nh->p_arp_info->if_index = p_fh->p_arp_info->if_index;
        p_nh->p_arp_info->mbr_if_index = p_fh->p_arp_info->mbr_if_index;
        memcpy((uint8_t *)&p_nh->p_arp_info->mac_addr, (uint8_t *)&p_fh->p_arp_info->mac_addr, HAL_RT_MAC_ADDR_LEN);
        p_nh->p_arp_info->arp_status = p_fh->p_arp_info->arp_status;
        if (p_nh->p_arp_info->arp_status == RT_NUD_REACHABLE)
            p_nh->reachable_state_time_stamp = nas_rt_get_clock_sec();

        p_nh->p_arp_info->state = p_fh->p_arp_info->state;
        p_nh->p_arp_info->is_l2_fh = p_fh->p_arp_info->is_l2_fh;
    } else {
        p_nh = fib_get_nh (vrf_id, &p_fh->key.ip_addr, p_fh->key.if_index);
        if ((p_nh == NULL) ||
            (p_nh->p_arp_info == NULL)) {
            HAL_RT_LOG_INFO("LEAK-NBR-PRG", "NH or NH's ARP info is NULL"
                           "Leaked VRF:%d parent VRF:%d, ip_addr:%s, if_index: %d",
                           vrf_id, p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                           p_fh->key.if_index);
            return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
        }

        fib_proc_nh_delete (p_nh, FIB_NH_OWNER_TYPE_ARP, 0);
    }

    fib_resume_nh_walker_thread(p_fh->key.ip_addr.af_index);
    return STD_ERR_OK;
}

t_std_error fib_process_neigh_flush(t_fib_neigh_flush *flush)
{
    hal_vrf_id_t parent_vrf_id = 0, nh_vrf_id = 0;
    t_fib_ip_addr nh_addr;
    hal_ifindex_t if_index = 0;
    t_fib_nh *parent_nh = NULL;

    if (!(FIB_IS_VRF_ID_VALID (flush->vrf_id))) {
        HAL_RT_LOG_ERR("NEIGH-FLUSH", "VRF-id:%d  is not valid!", flush->vrf_id);
        return STD_ERR_OK;
    }

    t_fib_nh *p_nh = fib_get_first_nh(flush->vrf_id, flush->af_index);
    while (p_nh) {
        nh_vrf_id = p_nh->vrf_id;
        parent_vrf_id = p_nh->parent_vrf_id;
        if_index = p_nh->key.if_index;
        memcpy(&nh_addr, &p_nh->key.ip_addr, sizeof(nh_addr));
        if ((nh_vrf_id != parent_vrf_id) &&
            ((flush->if_index == 0) || (if_index == flush->if_index))) {

            fib_nh_del_nh(p_nh, false);

            /* Check if there is a parent NH, if exists, re-program the neighbor, if not delete the cache */
            parent_nh = fib_get_nh (parent_vrf_id, &nh_addr, if_index);
            if (parent_nh) {
                hal_rt_leaked_nbr_prg(flush->vrf_id, parent_nh, true);
            }
        }
        p_nh = fib_get_next_nh (nh_vrf_id, &nh_addr, if_index);
    }
    fib_resume_nh_walker_thread(flush->af_index);
    return STD_ERR_OK;
}

