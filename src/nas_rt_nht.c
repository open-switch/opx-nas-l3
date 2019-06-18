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
 * filename: nas_rt_nht.c
 * \brief  Next-Hop Tracking Functionality
 * \author Venkatesan Mahalingam and Karthikeyan Arumugam
 */


#include "dell-base-routing.h"
#include "nas_rt_api.h"
#include "hal_rt_util.h"
#include "hal_rt_mem.h"
#include "event_log_types.h"
#include "event_log.h"
#include "std_mutex_lock.h"

#include "cps_class_map.h"
#include "cps_api_object_key.h"
#include "cps_api_operation.h"
#include "cps_api_events.h"

#include <stdio.h>
#include <stdint.h>

int fib_create_nht_tree (t_fib_vrf_info *p_vrf_info) {
    char tree_name_str [FIB_RDX_MAX_NAME_LEN];

    if (!p_vrf_info) {
        HAL_RT_LOG_ERR("HAL-RT-NHT", "%s (): Invalid input param. p_vrf_info: %p",
                   __FUNCTION__, p_vrf_info);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NHT", "Vrf_id: %d, af_index: %s",
                p_vrf_info->vrf_id,
               STD_IP_AFINDEX_TO_STR (p_vrf_info->af_index));

    if (p_vrf_info->nht_tree != NULL) {
        HAL_RT_LOG_DEBUG("HAL-RT-NHT", "NHT tree already created. "
                   "vrf_id: %d, af_index: %d",
                    p_vrf_info->vrf_id, p_vrf_info->af_index);
        return STD_ERR_OK;
    }

    memset (tree_name_str, 0, FIB_RDX_MAX_NAME_LEN);

    snprintf (tree_name_str, FIB_RDX_MAX_NAME_LEN, "Fib%s_nht_tree_vrf%d",
             STD_IP_AFINDEX_TO_STR (p_vrf_info->af_index), p_vrf_info->vrf_id);

    p_vrf_info->nht_tree = std_radix_create (tree_name_str, FIB_RDX_NHT_KEY_LEN,
                                       NULL, NULL, 0);
    if (p_vrf_info->nht_tree == NULL) {
        HAL_RT_LOG_ERR("HAL-RT-NHT",
                   "%s (): std_radix_create failed. Vrf_id: %d, "
                   "af_index: %s", __FUNCTION__, p_vrf_info->vrf_id,
                   STD_IP_AFINDEX_TO_STR (p_vrf_info->af_index));

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    return STD_ERR_OK;
}

int fib_destroy_nht_tree (t_fib_vrf_info *p_vrf_info) {
    if (!p_vrf_info) {
        HAL_RT_LOG_ERR("HAL-RT-NHT",
                   "%s (): Invalid input param. p_vrf_info: %p",
                   __FUNCTION__, p_vrf_info);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    if (p_vrf_info->nht_tree == NULL) {
        HAL_RT_LOG_ERR("HAL-RT-NHT",
                   "%s (): DR tree not present. "
                   "vrf_id: %d, af_index: %d",
                   __FUNCTION__, p_vrf_info->vrf_id, p_vrf_info->af_index);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    std_radix_destroy (p_vrf_info->nht_tree);

    p_vrf_info->nht_tree = NULL;

    return STD_ERR_OK;
}

t_fib_nht *fib_add_nht (t_fib_nht *p_nht) {
    t_fib_nht    *p_nht_new = NULL;
    std_rt_head *p_radix_head = NULL;
    uint8_t      af_index = 0;

    if (!p_nht) {
        HAL_RT_LOG_ERR("HAL-RT-NHT", "%s (): NHT is NULL", __FUNCTION__);
        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NHT", "vrf_id:%d, dest_addr:%s ",
                 p_nht->vrf_id, FIB_IP_ADDR_TO_STR (&p_nht->key.dest_addr));

    p_nht_new = fib_alloc_nht_node ();

    if (p_nht_new == NULL) {
        HAL_RT_LOG_ERR("HAL-RT-NHT", "%s (): Memory alloc failed. vrf_id: %d, dest_addr: %s ",
                   __FUNCTION__, p_nht->vrf_id, FIB_IP_ADDR_TO_STR (&p_nht->key.dest_addr));
        return NULL;
    }

    af_index = p_nht->key.dest_addr.af_index;
    p_nht_new->vrf_id = p_nht->vrf_id;
    memcpy (&p_nht_new->key.dest_addr, &p_nht->key.dest_addr, sizeof (p_nht->key.dest_addr));
    p_nht_new->rt_head.rth_addr = (uint8_t *) (&(p_nht_new->key));
    p_radix_head = std_radix_insert (hal_rt_access_fib_vrf_nht_tree(p_nht->vrf_id, af_index),
                                     (std_rt_head *)(&p_nht_new->rt_head),
                                     FIB_RDX_NHT_KEY_LEN);
    if (p_radix_head == NULL) {
        HAL_RT_LOG_ERR("HAL-RT-NHT", "%s (): Radix insertion failed. "
                   "vrf_id:%d, dest_addr:%s", __FUNCTION__, p_nht->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_nht->key.dest_addr));
        fib_free_nht_node (p_nht_new);
        return NULL;
    }

    if (p_radix_head != ((std_rt_head *)p_nht_new)) {
        HAL_RT_LOG_ERR("HAL-RT-NHT", "%s (): Duplicate addition. "
                   "vrf_id:%d, dest_addr:%s", __FUNCTION__, p_nht->vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_nht->key.dest_addr));

        fib_free_nht_node (p_nht_new);

        p_nht_new = (t_fib_nht *)p_radix_head;
    }

    return p_nht_new;
}

int fib_del_nht (t_fib_nht *p_nht) {
    uint32_t  vrf_id = 0;
    uint8_t   af_index = 0;

    if (p_nht == NULL) {
        HAL_RT_LOG_ERR("HAL-RT-NHT", "%s (): NHT is NULL", __FUNCTION__);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NHT", "vrf_id:%d, dest_addr:%s", p_nht->vrf_id,
                 FIB_IP_ADDR_TO_STR (&p_nht->key.dest_addr));

    vrf_id   = p_nht->vrf_id;
    af_index = p_nht->key.dest_addr.af_index;

    std_radix_remove (hal_rt_access_fib_vrf_nht_tree(vrf_id, af_index), (std_rt_head *)(&p_nht->rt_head));

    fib_free_nht_node (p_nht);

    return STD_ERR_OK;
}

t_fib_nht *fib_get_nht (uint32_t vrf_id, t_fib_ip_addr *p_dest_addr) {
    t_fib_nht      *p_nht = NULL;
    t_fib_nht_key   key;
    uint8_t        af_index = 0;

    if (!p_dest_addr) {
        HAL_RT_LOG_ERR("HAL-RT-NHT", "%s Destination is NULL",__FUNCTION__);
        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NHT", "vrf_id:%d, dest_addr:%s",
                 vrf_id, FIB_IP_ADDR_TO_STR (p_dest_addr));

    af_index = p_dest_addr->af_index;
    memset (&key, 0, sizeof (t_fib_nht_key));
    memcpy (&key.dest_addr, p_dest_addr, sizeof (t_fib_ip_addr));

    p_nht = (t_fib_nht *)
        std_radix_getexact (hal_rt_access_fib_vrf_nht_tree(vrf_id, af_index),
                            (uint8_t *)&key, FIB_RDX_NHT_KEY_LEN);
    if (p_nht != NULL) {
        HAL_RT_LOG_DEBUG("HAL-RT-NHT", "vrf_id: %d, dest_addr: %s, p_nht: %p",
                     vrf_id, FIB_IP_ADDR_TO_STR (&p_nht->key.dest_addr), p_nht);
    }

    return p_nht;
}

t_fib_nht *fib_get_nht_with_bit_len (uint32_t vrf_id, t_fib_ip_addr *p_dest_addr, uint8_t prefix_len) {
    t_fib_nht      *p_nht = NULL;
    t_fib_nht_key   key;
    uint8_t        af_index = 0;

    if (!p_dest_addr) {
        HAL_RT_LOG_ERR("HAL-RT-NHT", "%s Destination is NULL",__FUNCTION__);
        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NHT", "vrf_id:%d, dest_addr:%s",
                 vrf_id, FIB_IP_ADDR_TO_STR (p_dest_addr));

    af_index = p_dest_addr->af_index;
    memset (&key, 0, sizeof (t_fib_nht_key));
    memcpy (&key.dest_addr, p_dest_addr, sizeof (t_fib_ip_addr));

    p_nht = (t_fib_nht *)
        std_radix_getexact (hal_rt_access_fib_vrf_nht_tree(vrf_id, af_index),
                            (uint8_t *)&key, FIB_RDX_NHT_KEY_LEN);
    if (p_nht != NULL) {
        HAL_RT_LOG_DEBUG("HAL-RT-NHT", "vrf_id: %d, dest_addr: %s, p_nht: %p",
                     vrf_id, FIB_IP_ADDR_TO_STR (&p_nht->key.dest_addr), p_nht);
    }

    return p_nht;
}

t_fib_nht *fib_get_first_nht (uint32_t vrf_id, uint8_t af_index) {
    t_fib_nht     *p_nht = NULL;
    t_fib_nht_key  key;

    HAL_RT_LOG_DEBUG("HAL-RT-NHT",
               "vrf_id: %d, af_index: %d",
               vrf_id, af_index);

    memset (&key, 0, sizeof (t_fib_nht_key));

    key.dest_addr.af_index = af_index;

    p_nht = (t_fib_nht *)
        std_radix_getexact (hal_rt_access_fib_vrf_nht_tree(vrf_id, af_index),
                            (uint8_t *)&key, FIB_RDX_NHT_KEY_LEN);
    if (p_nht == NULL) {
        p_nht = (t_fib_nht *)
            std_radix_getnext (hal_rt_access_fib_vrf_nht_tree(vrf_id, af_index),
                               (uint8_t *)&key, FIB_RDX_NHT_KEY_LEN);
    }

    if (p_nht != NULL) {
        HAL_RT_LOG_DEBUG("HAL-RT-NHT", "vrf_id:%d, dest_addr:%s",
                   vrf_id, FIB_IP_ADDR_TO_STR (&p_nht->key.dest_addr));
    }

    return p_nht;
}

t_fib_nht *fib_get_next_nht (uint32_t vrf_id, t_fib_ip_addr *p_dest_addr) {
    t_fib_nht     *p_nht = NULL;
    t_fib_nht_key  key;
    uint8_t       af_index = 0;

    if (!p_dest_addr) {
        HAL_RT_LOG_ERR("HAL-RT-NHT",
                   "%s (): Invalid input param. p_dest_addr: %p",
                   __FUNCTION__, p_dest_addr);
        return NULL;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NHT", "vrf_id:%d, dest_addr:%s",
                 vrf_id, FIB_IP_ADDR_TO_STR (p_dest_addr));

    af_index = p_dest_addr->af_index;

    memset (&key, 0, sizeof (t_fib_nht_key));

    memcpy (&key.dest_addr, p_dest_addr, sizeof (t_fib_ip_addr));

    p_nht = (t_fib_nht *)
        std_radix_getnext (hal_rt_access_fib_vrf_nht_tree(vrf_id, af_index),
                           (uint8_t *) &key, FIB_RDX_NHT_KEY_LEN);

    if (p_nht != NULL) {
        HAL_RT_LOG_DEBUG("HAL-RT-NHT", "vrf_id:%d, dest_addr:%s",
                     vrf_id, FIB_IP_ADDR_TO_STR (&p_nht->key.dest_addr));
    }

    return p_nht;
}

/* Active prefix is down, find the next best prefix for the all NHTs or find the best nexthop/Route
 * for the given p_fib_nht if not NULL */
int nas_rt_find_next_best_dr_for_nht(t_fib_nht *p_fib_nht, int vrf_id, t_fib_ip_addr *dest_addr, uint8_t prefix_len,
                                         bool *is_next_best_rt_found) {
    t_fib_dr *p_best_dr = NULL;
    t_fib_nh *p_nh = NULL;
    bool is_multiple_nht = false, is_conn_route_found = false;
    t_fib_nh_holder nh_holder;
    t_fib_ip_addr mask;
    int parent_vrf_id = vrf_id;

    *is_next_best_rt_found = false;
    memset (&mask, 0, sizeof (t_fib_ip_addr));
    if (nas_rt_get_mask (dest_addr->af_index, prefix_len, &mask) == false) {
        HAL_RT_LOG_DEBUG("HAL-RT-NHT", "Not a valid address family %d",
                         dest_addr->af_index);
        return STD_ERR_OK;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NHT", "vrf_id:%d, Route/NH/NHT:%s/%d NHT:%p ",
                 vrf_id, FIB_IP_ADDR_TO_STR (dest_addr), prefix_len, p_fib_nht);

    /* If NHT is not NULL, find the best route for that NHT only */
    if (p_fib_nht == NULL) {
        p_fib_nht = fib_get_next_nht(vrf_id, dest_addr);
        is_multiple_nht = true;
    }

    if (p_fib_nht == NULL) {
        HAL_RT_LOG_DEBUG("HAL-RT-NHT", "No match:%s found in NHT",
                     FIB_IP_ADDR_TO_STR (dest_addr));
        return STD_ERR_OK;
    }

    p_best_dr = fib_get_best_fit_dr(vrf_id, dest_addr);
    while(p_best_dr) {
        HAL_RT_LOG_INFO("HAL-RT-NHT", "vrf_id:%d, parent vrf:%d route:%s/%d is best match for %s/%d is_multiple_nht:%d"
                         " nh_handle:%lu nh-resolved:%d", vrf_id, p_best_dr->parent_vrf_id, FIB_IP_ADDR_TO_STR (&p_best_dr->key.prefix),
                         p_best_dr->prefix_len, FIB_IP_ADDR_TO_STR(dest_addr), prefix_len, p_best_dr->nh_handle,
                         p_best_dr->is_nh_resolved, is_multiple_nht);
        if (p_best_dr->is_mgmt_route) {
            p_best_dr = fib_get_next_best_fit_dr(vrf_id, &p_best_dr->key.prefix, p_best_dr->prefix_len);
            continue;
        }
        if ((is_multiple_nht == false) &&
            (!(STD_IP_IS_ADDR_ZERO(&p_best_dr->key.prefix))) &&
            ((p_nh = FIB_GET_FIRST_NH_FROM_DR(p_best_dr, nh_holder)) != NULL) &&
            (FIB_IS_NH_ZERO(p_nh))) {
            /* Connected route found for the NHT destination, create the NH and resolve the NH proactively
             * if there is no best resolved route found */
            is_conn_route_found = true;
            parent_vrf_id = p_best_dr->parent_vrf_id;
        }
        if (p_best_dr->is_nh_resolved) {
            *is_next_best_rt_found = true;
            break;
        }
        p_best_dr = fib_get_next_best_fit_dr(vrf_id, &p_best_dr->key.prefix, p_best_dr->prefix_len);
    }
    if (*is_next_best_rt_found == false) {
        if (p_nh && is_conn_route_found) {
            /* There is a connected route to reach the NHT nexthop, resolve the NH thru Nbr-Mgr */
            if (p_nh->vrf_id != p_nh->parent_vrf_id) {
                t_fib_nh *p_parent_nh = fib_get_nh (p_nh->parent_vrf_id, dest_addr, p_nh->key.if_index);
                if (p_parent_nh == NULL) {
                    /* If parent NH is not present, create it before creating the leaked NH */
                    fib_proc_nh_add (p_nh->parent_vrf_id, dest_addr, p_nh->key.if_index,
                                     FIB_NH_OWNER_TYPE_CLIENT, 0, false, p_nh->parent_vrf_id, 0);
                }
            }
            fib_proc_nh_add (vrf_id, dest_addr, p_nh->key.if_index,
                             FIB_NH_OWNER_TYPE_CLIENT, 0, false, parent_vrf_id, 0);
        }
        return STD_ERR_OK;
    }

    while(p_fib_nht) {
        HAL_RT_LOG_DEBUG("HAL-RT-NHT",
                     "vrf_id:%d, NHT match:%s/%d cur best match:%s/%d is_multiple_nht:%d",
                     vrf_id, FIB_IP_ADDR_TO_STR (&p_fib_nht->fib_match_dest_addr), p_fib_nht->prefix_len,
                     FIB_IP_ADDR_TO_STR(&p_best_dr->key.prefix), p_best_dr->prefix_len,
                     is_multiple_nht);

        if ((FIB_IS_AFINDEX_VALID(dest_addr->af_index)) &&
            (FIB_IS_IP_ADDR_IN_PREFIX(dest_addr, &mask, &p_fib_nht->key.dest_addr) == false)) {
            break;
        }

        if ((!(FIB_IS_AFINDEX_VALID (p_fib_nht->fib_match_dest_addr.af_index)) &&
             (STD_IP_IS_ADDR_ZERO(&p_fib_nht->fib_match_dest_addr))) ||
            ((memcmp(&p_fib_nht->fib_match_dest_addr, dest_addr, sizeof(t_fib_ip_addr)) == 0) &&
             (p_fib_nht->prefix_len == prefix_len))) {
            memcpy(&p_fib_nht->fib_match_dest_addr, &p_best_dr->key.prefix, sizeof(p_best_dr->key.prefix));
            p_fib_nht->prefix_len = p_best_dr->prefix_len;
            nas_rt_publish_nht(p_fib_nht, p_best_dr, NULL, true);
            if (is_multiple_nht == false)
                break;
        }
        p_fib_nht = fib_get_next_nht(vrf_id, &p_fib_nht->key.dest_addr);
    }

    return STD_ERR_OK;
}

int fib_handle_nh_dep_dr_for_nht (t_fib_nh *p_nh, bool is_add)
{
    t_fib_dr_key      key;
    t_fib_nh_dep_dr   *p_nh_dep_dr = NULL;

    if (!p_nh)
    {
        HAL_RT_LOG_ERR("HAL-RT-NH",
                   "%s (): Invalid input param. p_nh: %p",
                   __FUNCTION__, p_nh);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG("HAL-RT-NH",
                 "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                 "status_flag: 0x%x, owner_flag: 0x%x",
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
                     "status_flag: 0x%x, owner_flag: 0x%x, handle:%lu "
                     "NH Dep DR: vrf_id: %d, prefix: %s, prefix_len: %d %lu",
                     p_nh->vrf_id,
                     FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
                     p_nh->status_flag, p_nh->owner_flag, p_nh->next_hop_id, p_nh_dep_dr->key.vrf_id,
                     FIB_IP_ADDR_TO_STR (&p_nh_dep_dr->key.dr_key.prefix),
                     p_nh_dep_dr->prefix_len, p_nh_dep_dr->p_dr->nh_handle);

        /* Hanlde only non-ECMP case here, route add/del will be notified
         * to NHT as part of the ECMP route handling */
        if (p_nh_dep_dr->p_dr->nh_handle == p_nh->next_hop_id)
            nas_rt_handle_dest_change(p_nh_dep_dr->p_dr, NULL, is_add);

        p_nh_dep_dr =
            fib_get_next_nh_dep_dr (p_nh, p_nh_dep_dr->key.vrf_id,
                                    &p_nh_dep_dr->key.dr_key.prefix,
                                    p_nh_dep_dr->prefix_len);
    }

    return STD_ERR_OK;
}

/* NH handle flush cases
1) is_add = true change of best_match (one route to another)
   NHT current route (old) to NH handle reference to be cleaned
   - given that current NH handle is NOT being used by any other NHT.

2) is_add = false, next best_match change could be present.
   NH handle reference to be cleaned
    - given that NH handle of the deleted route, NOT referenced by any NHT
3) is_add = false, no best_match present.
   NH handle reference to be cleaned
    - given that NH handle of the deleted route, NOT referenced by any NHT

4) is_add = true Same best_match change of NH handle (one ECMP to other ECMP or ECMP to non-ECMP or non-ECMP to ECMP)
   i) best match route is deleted
      NHT current route (old) to NH handle reference to be cleaned
      - given that current NH handle is NOT being used by any other NHT.
   ii) new bext match route is added
      NHT current route (old) to NH handle reference to be cleaned
      - given that current NH handle is NOT being used by any other NHT.
   iii) same route, but NH handle is changing (one ECMP to other/ECMP to non-ECMP/non-ECMP to ECMP)
       This route's old NH handle reference to be cleaned
      - given that old NH handle is NOT being used by any other NHT.
*/
static int nas_rt_check_nht_and_flush_acls(t_fib_ip_addr *dest_addr, t_fib_ip_addr *mask,
                                           uint8_t prefix_len, t_fib_dr *p_dr, t_fib_nh *p_nh,
                                           bool is_force_flush) {
    t_fib_nht *p_fib_nht = NULL;
    hal_vrf_id_t vrf_id = 0;
    uint8_t af_index = 0;
    t_fib_nh *p_tmp_nh = NULL;

    next_hop_id_t next_hop_id = 0;
    if (p_nh) {
        vrf_id = p_nh->vrf_id;
        af_index = p_nh->key.ip_addr.af_index;
        next_hop_id = p_nh->next_hop_id;
    } else if (p_dr) {
        vrf_id = p_dr->vrf_id;
        af_index = p_dr->key.prefix.af_index;
        if (p_dr->old_nh_handle_nht) {
            next_hop_id = p_dr->old_nh_handle_nht;
        } else {
            next_hop_id = p_dr->nh_handle;
        }
    } else {
        return true;
    }
    HAL_RT_LOG_INFO("RT-NHT-ACL", "Dependent ACLs cleanup for Addr:%s/%d,"
                    "nh:%p dr:%p nh_id:%lu dr handle old:%lu new:%lu force_del:%d",
                    FIB_IP_ADDR_TO_STR (dest_addr), prefix_len,
                    p_nh, p_dr, next_hop_id, (p_dr ? p_dr->old_nh_handle_nht : 0),
                    (p_dr ? p_dr->nh_handle : 0), is_force_flush);
    if (next_hop_id == 0) {
        return true;
    }

    t_fib_dr *p_temp_dr = NULL;
    p_fib_nht = fib_get_first_nht(vrf_id, af_index);
    while(p_fib_nht) {
        HAL_RT_LOG_INFO("HAL-RT-NHT", "NHT:%s NH/Route Match addr:%s/%d dest:%s/%d force-del:%d",
                        FIB_IP_ADDR_TO_STR(&p_fib_nht->key.dest_addr),
                        FIB_IP_ADDR_TO_STR(&p_fib_nht->fib_match_dest_addr),
                        p_fib_nht->prefix_len,
                        FIB_IP_ADDR_TO_STR(dest_addr), prefix_len, is_force_flush);

        if (FIB_IS_AFINDEX_VALID (p_fib_nht->fib_match_dest_addr.af_index)) {
            /* Force ACL clean-up case, ignore the NHTs using the same route/NH */
            if (is_force_flush && (memcmp(&p_fib_nht->fib_match_dest_addr,
                                          dest_addr, sizeof(t_fib_ip_addr)) == 0)  &&
                (p_fib_nht->prefix_len == prefix_len)) {
                p_fib_nht = fib_get_next_nht(vrf_id, &p_fib_nht->key.dest_addr);
                continue;
            }
            /*
             * Current NH handle reference to ACL has to be cleaned only when
             * this NH handle is not used by other NHT.
             */
            p_tmp_nh = fib_get_next_nh(p_fib_nht->vrf_id, &p_fib_nht->key.dest_addr, 0);
            if (p_tmp_nh && (memcmp(&p_tmp_nh->key.ip_addr, &p_fib_nht->key.dest_addr,
                            sizeof(t_fib_ip_addr)) == 0) && (p_tmp_nh->next_hop_id == next_hop_id)) {
                return true;
            }

            p_temp_dr = fib_get_dr (vrf_id, &p_fib_nht->fib_match_dest_addr,
                                    p_fib_nht->prefix_len);
            HAL_RT_LOG_INFO("HAL-RT-NHT", "NHT:%s NH/Route Match addr:%s/%d "
                            "dest-chg:%s/%d nh-id:%lu rt-nh-id:%lu",
                            FIB_IP_ADDR_TO_STR(&p_fib_nht->key.dest_addr),
                            FIB_IP_ADDR_TO_STR(&p_fib_nht->fib_match_dest_addr),
                            p_fib_nht->prefix_len,
                            FIB_IP_ADDR_TO_STR(dest_addr), prefix_len, next_hop_id,
                            (p_temp_dr ? p_temp_dr->nh_handle : 0));
            if (p_temp_dr && (p_temp_dr->nh_handle == next_hop_id)) {
                return true;
            }
        }
        p_fib_nht = fib_get_next_nht(vrf_id, &p_fib_nht->key.dest_addr);
    }

    if (nas_route_flush_acls(&next_hop_id) != STD_ERR_OK) {
        HAL_RT_LOG_ERR("RT-NHT-ACL", "Dependent ACLs cleanup failed for Addr:%s/%d,"
                       "nh_id:%lu ", FIB_IP_ADDR_TO_STR (dest_addr), prefix_len,
                       next_hop_id);
        return false;
    }
    HAL_RT_LOG_INFO("RT-NHT-ACL", "Dependent ACLs cleanup successful for Addr:%s/%d,"
                    "nh_id:%lu ", FIB_IP_ADDR_TO_STR (dest_addr), prefix_len,
                    next_hop_id);
    return true;
}

int nas_rt_handle_dest_change(t_fib_dr *p_dr, t_fib_nh *p_nh, bool is_add) {

    t_fib_nht *p_fib_nht = NULL;
    t_fib_nh *p_fh = NULL;
    hal_vrf_id_t    vrf_id = 0, parent_vrf_id = 0;
    t_fib_ip_addr   dest_addr, mask;
    bool is_rt_found = false, is_next_best_rt_found = false,
         is_exact_match_req = false, is_conn_route = false;
    uint8_t prefix_len = 0;

    if (p_dr) {
        if (p_dr->is_mgmt_route) {
            return STD_ERR_OK;
        }
        /* no NHT entries configured, so simply return */
        if (FIB_GET_CNTRS_NHT_ENTRIES (p_dr->vrf_id, p_dr->key.prefix.af_index) == 0) return STD_ERR_OK;
    } else if (p_nh) {
        if (p_nh->is_mgmt_nh) {
            return STD_ERR_OK;
        }
        /* no NHT entries configured, so simply return */
        if (FIB_GET_CNTRS_NHT_ENTRIES (p_nh->vrf_id, p_nh->key.ip_addr.af_index) == 0) return STD_ERR_OK;
    }
    else {
        /* If both are NULL, return */
        return STD_ERR_OK;
    }


    if (p_nh) {
        /* If there is no match in NHT, return from here */
        p_fib_nht = fib_get_nht(p_nh->vrf_id, &p_nh->key.ip_addr);
        if (p_fib_nht == NULL) {
            /* See if there is a NHT match on dependent DR(s) */
            fib_handle_nh_dep_dr_for_nht(p_nh, is_add);
            return STD_ERR_OK;
        }

        if (is_add && (p_nh->next_hop_id == 0)) {
            bool rif_update = true;
            if (p_nh->vrf_id != p_nh->parent_vrf_id) {
                t_fib_nh *p_parent_nh = fib_get_nh (p_nh->parent_vrf_id, &p_nh->key.ip_addr,
                                                    p_nh->key.if_index);
                if (p_parent_nh && (p_parent_nh->next_hop_id)) {
                    rif_update = false;
                }
            }
            if (hal_fib_next_hop_add(p_nh) != DN_HAL_ROUTE_E_NONE) {
                HAL_RT_LOG_ERR("HAL-RT-NHT", "NextHop Add %s/%d NH-handle:%lu add failed!",
                               FIB_IP_ADDR_TO_STR(&p_nh->key.ip_addr), prefix_len, p_nh->next_hop_id);
            } else {
                /* increment the RIF for the first time update */
                if (rif_update) {
                    hal_rt_rif_ref_inc(p_nh->parent_vrf_id, p_nh->key.if_index);
                }
            }
        }

        vrf_id = p_nh->vrf_id;
        memcpy(&dest_addr, &p_nh->key.ip_addr, sizeof(p_nh->key.ip_addr));
        prefix_len = FIB_AFINDEX_TO_PREFIX_LEN (p_nh->key.ip_addr.af_index);
        is_exact_match_req = true;
        HAL_RT_LOG_INFO("HAL-RT-NHT", "NextHop %s %s/%d NH-handle:%lu",
                     ((is_add) ? "Add" : "Del"), FIB_IP_ADDR_TO_STR(&dest_addr), prefix_len,
                     p_nh->next_hop_id);
    } else { /* p_dr case */
        if (p_dr->nh_handle == 0) {
            t_fib_nh_holder nh_holder;
            p_fh = FIB_GET_FIRST_NH_FROM_DR(p_dr, nh_holder);
            /* Mark the connected route flag true only if the NH is zero. */
            if (p_fh && (FIB_IS_NH_ZERO(p_fh))) {
                is_conn_route = true;
                parent_vrf_id = p_fh->parent_vrf_id;
            }
        }

        if (p_dr->prefix_len == FIB_AFINDEX_TO_PREFIX_LEN (p_dr->key.prefix.af_index)) {
            is_exact_match_req = true;
            p_fib_nht = fib_get_nht(p_dr->vrf_id, &p_dr->key.prefix);
        } else {
            /* Search for the best matches in NHT */
            p_fib_nht = fib_get_next_nht(p_dr->vrf_id, &p_dr->key.prefix);
        }

        /* If there is no match in NHT, return from here */
        if (p_fib_nht == NULL)
            return STD_ERR_OK;

        vrf_id = p_dr->vrf_id;
        memcpy(&dest_addr, &p_dr->key.prefix, sizeof(p_dr->key.prefix));
        prefix_len = p_dr->prefix_len;
        HAL_RT_LOG_INFO("HAL-RT-NHT", "Route %s %s/%d exact_match_req:%d NH-handle:%lu is_conn_route:%d parent VRF:%d",
                         ((is_add) ? "Add" : "Del"), FIB_IP_ADDR_TO_STR(&dest_addr), prefix_len,
                         is_exact_match_req, p_dr->nh_handle, is_conn_route, parent_vrf_id);
    }

    do {
        memset (&mask, 0, sizeof (t_fib_ip_addr));
        nas_rt_get_mask (dest_addr.af_index, prefix_len, &mask);
        HAL_RT_LOG_DEBUG("HAL-RT-NHT", "dest_addr:%s/%d Mask:%s ",
                     FIB_IP_ADDR_TO_STR(&dest_addr), prefix_len, FIB_IP_ADDR_TO_STR(&mask));

        while(p_fib_nht) {
            HAL_RT_LOG_INFO("HAL-RT-NHT", "NHT:%s NH/Route Match addr:%s/%d is_conn_route:%d parent VRF:%d",
                             FIB_IP_ADDR_TO_STR(&p_fib_nht->key.dest_addr),
                             FIB_IP_ADDR_TO_STR(&p_fib_nht->fib_match_dest_addr),
                             p_fib_nht->prefix_len, is_conn_route, parent_vrf_id);

            if (FIB_IS_IP_ADDR_IN_PREFIX(&dest_addr, &mask, &p_fib_nht->key.dest_addr) == false)
                break;

            if (is_add) {
                if (is_conn_route) {
                    if (p_fh->vrf_id != p_fh->parent_vrf_id) {
                        t_fib_nh *p_parent_nh = fib_get_nh (p_fh->parent_vrf_id, &p_fib_nht->key.dest_addr, p_fh->key.if_index);
                        if (p_parent_nh == NULL) {
                            /* If parent NH is not present, create it before creating the leaked NH */
                            fib_proc_nh_add (p_fh->parent_vrf_id, &p_fib_nht->key.dest_addr, p_fh->key.if_index,
                                             FIB_NH_OWNER_TYPE_CLIENT, 0, false, p_fh->parent_vrf_id, 0);
                        }
                    }

                    fib_proc_nh_add (p_fib_nht->vrf_id, &p_fib_nht->key.dest_addr,
                                     p_fh->key.if_index, FIB_NH_OWNER_TYPE_CLIENT, 0, false, parent_vrf_id, 0);
                    /* Check if this Route is better match for NHT(s) */
                } else if ((!(FIB_IS_AFINDEX_VALID (p_fib_nht->fib_match_dest_addr.af_index)) &&
                            (STD_IP_IS_ADDR_ZERO(&p_fib_nht->fib_match_dest_addr))) ||
                           /* Publish the NHT, even if the dest_addr is exact match with fib_match_dest_addr,
                            * because incase of multipath, we expect to receive the dest_change
                            * with different handle (multiple NHs) */
                           ((memcmp(&p_fib_nht->fib_match_dest_addr, &dest_addr, sizeof(dest_addr)) <= 0) &&
                            (p_fib_nht->prefix_len <= prefix_len))) {
                    /* Best match is found, publish the information */
                    /* Check if the dest addr is being used for some other NHT,
                     * if none of the NHTs use this NH/DR, clean up the associated ACLs */
                    t_fib_dr *p_old_dr = NULL;
                    if ((FIB_IS_AFINDEX_VALID (p_fib_nht->fib_match_dest_addr.af_index)) &&
                        (memcmp(&p_fib_nht->fib_match_dest_addr, &dest_addr, sizeof(dest_addr)) < 0)  &&
                        (p_fib_nht->prefix_len < prefix_len)) {

                        p_old_dr = fib_get_dr (vrf_id, &p_fib_nht->fib_match_dest_addr,
                                               p_fib_nht->prefix_len);
                    }
                    memcpy(&p_fib_nht->fib_match_dest_addr, &dest_addr, sizeof(dest_addr));
                    p_fib_nht->prefix_len = prefix_len;
                    if (p_old_dr) {
                        /* Better match found, flush the ACLs associated with
                         * current route handle (p_old_dr) if no other routes are using the same handle. */
                        t_fib_ip_addr dr_mask;
                        memset (&dr_mask, 0, sizeof (t_fib_ip_addr));
                        nas_rt_get_mask (p_old_dr->key.prefix.af_index, p_old_dr->prefix_len, &dr_mask);
                        nas_rt_check_nht_and_flush_acls(&p_old_dr->key.prefix, &dr_mask,
                                                        p_old_dr->prefix_len, p_old_dr, NULL, false);
                    } else if (p_dr && (p_dr->old_nh_handle_nht) &&
                               (FIB_IS_AFINDEX_VALID (p_fib_nht->fib_match_dest_addr.af_index)) &&
                               (memcmp(&p_fib_nht->fib_match_dest_addr, &dest_addr, sizeof(dest_addr)) == 0) &&
                               (p_fib_nht->prefix_len == prefix_len)) {
                        /* Route is changing from ECMP to Non-ECMP or ECMP to ECMP (with different nh handle) or
                         * non-ECMP to ECMP cases, flush the current handle if no other NHTs are using it */
                        nas_rt_check_nht_and_flush_acls(&dest_addr, &mask, prefix_len, p_dr, p_nh, false);
                    }
                    nas_rt_publish_nht(p_fib_nht, p_dr, p_nh, true);
                }
            } else if (is_conn_route) {
                p_fh = fib_get_next_nh(p_fib_nht->vrf_id, &p_fib_nht->key.dest_addr, 0);
                if (p_fh && (memcmp(&p_fh->key.ip_addr, &p_fib_nht->key.dest_addr,
                                    sizeof(t_fib_ip_addr)) == 0)) {
                    HAL_RT_LOG_INFO("HAL-RT-NHT", "vrf_id: %d, nh_addr: %s is_add:%d state:%d"
                                     " NH_handle:%lu next match found in NH table",
                                     p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr), is_add,
                                     ((p_fh->p_arp_info) ? p_fh->p_arp_info->state : 0), p_fh->next_hop_id);

                    fib_proc_nh_delete (p_fh, FIB_NH_OWNER_TYPE_CLIENT, 0);
                }
            } else if ((memcmp(&p_fib_nht->fib_match_dest_addr, &dest_addr, sizeof(dest_addr)) == 0) &&
                       (p_fib_nht->prefix_len == prefix_len)) {
                /* This p_dr is being used by some NHT, find the next best DR */
                is_rt_found = true;
                break;
            }

            /* If there is an exact match, dont look for further matches in the NHT */
            if(is_exact_match_req)
                break;

            p_fib_nht = fib_get_next_nht(vrf_id, &p_fib_nht->key.dest_addr);
        }

        if (is_add || (is_rt_found == false)) {
            /* This route is not used by NHT, return */
            break;
        }

        nas_rt_check_nht_and_flush_acls(&dest_addr, &mask, prefix_len, p_dr, p_nh, true);
        nas_rt_find_next_best_dr_for_nht(NULL, vrf_id, &dest_addr, prefix_len, &is_next_best_rt_found);
        if (is_next_best_rt_found)
            break;

        /* Notify NHT unresolved status */
        while(p_fib_nht) {
            HAL_RT_LOG_DEBUG("HAL-RT-NHT", "NHT:%s NH/Route Match addr:%s ",
                         FIB_IP_ADDR_TO_STR(&p_fib_nht->key.dest_addr), FIB_IP_ADDR_TO_STR(&p_fib_nht->fib_match_dest_addr));
            if (FIB_IS_IP_ADDR_IN_PREFIX(&dest_addr, &mask, &p_fib_nht->key.dest_addr) == false)
                break;
            if ((memcmp(&p_fib_nht->fib_match_dest_addr, &dest_addr, sizeof(dest_addr)) == 0)  &&
                (p_fib_nht->prefix_len == prefix_len)) {
                memset(&p_fib_nht->fib_match_dest_addr, 0, sizeof(dest_addr));
                p_fib_nht->prefix_len = 0;
                nas_rt_publish_nht(p_fib_nht, p_dr, p_nh, is_add);
            }

            /* If there is an exact match, dont look for further matches in the NHT */
            if(is_exact_match_req)
                break;

            p_fib_nht = fib_get_next_nht(vrf_id, &p_fib_nht->key.dest_addr);
        }
    } while(0);
    /* When there is a change in NH, take care handling the dependent routes also,
     * we dont program the NPU with route add/del when the arp is resolved/unresolved because
     * the egress object is being shared by both the host and routes in the NPU,
     * updating the host will update the egress object and routes too */
    if (p_nh) {
        fib_handle_nh_dep_dr_for_nht(p_nh, is_add);

        if ((is_add == false) && (p_nh->next_hop_id) &&
            (FIB_IS_NH_REF_COUNT_ZERO (p_nh))) {
            if (hal_fib_next_hop_del(p_nh) == DN_HAL_ROUTE_E_FAIL) {
                HAL_RT_LOG_ERR("HAL-RT-NHT", "NextHop Del VRF:%d Parent:%d %s/%d NH-handle:%lu del failed!",
                               p_nh->vrf_id, p_nh->parent_vrf_id, FIB_IP_ADDR_TO_STR(&dest_addr),
                               prefix_len, p_nh->next_hop_id);
            }
            p_nh->next_hop_id = 0;
        }
    }
    return STD_ERR_OK;
}

int nas_rt_handle_nht (t_fib_nht *p_nht_info, bool is_add, bool is_force_del) {

    t_fib_nh *p_nh = NULL;
    t_fib_dr *p_dr = NULL;
    t_fib_nht *p_nht = NULL;
    bool is_best_rt_found = false;

    p_nht = fib_get_nht (p_nht_info->vrf_id, &p_nht_info->key.dest_addr);
    if (p_nht != NULL) {
        HAL_RT_LOG_INFO("HAL-RT-NHT",
                         "vrf_id: %d, dest_addr: %s already exists, ref-cnt:%d force-del:%d",
                         p_nht->vrf_id,
                         FIB_IP_ADDR_TO_STR (&p_nht->key.dest_addr), p_nht->ref_count, is_force_del);
        if (is_add == false) { /* Delete NHT case handling */
            if (is_force_del) {
                p_nht->ref_count = 0;
            } else if (p_nht->ref_count)
                --(p_nht->ref_count);

            if (!p_nht->ref_count) {
                /* If no more clients interested for this NHT, delete NHT */
                FIB_DECR_CNTRS_NHT_ENTRIES (p_nht->vrf_id, p_nht->key.dest_addr.af_index);
                /* Publish the NHT delete upon last app. NHT config delete */

                p_nh = fib_get_next_nh(p_nht_info->vrf_id, &p_nht_info->key.dest_addr, 0);
                if (p_nh && (memcmp(&p_nh->key.ip_addr, &p_nht->key.dest_addr,
                                    sizeof(t_fib_ip_addr)) == 0)) {
                    HAL_RT_LOG_INFO("HAL-RT-NHT", "vrf_id: %d, nh_addr: %s is_add:%d state:%d"
                                    " NH_handle:%lu next match found in NH table",
                                    p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), is_add,
                                    ((p_nh->p_arp_info) ? p_nh->p_arp_info->state : 0), p_nh->next_hop_id);

                    if (p_nh->vrf_id != p_nh->parent_vrf_id) {
                        fib_proc_nh_delete (p_nh, FIB_NH_OWNER_TYPE_CLIENT, 0);
                        t_fib_nh *p_parent_nh = fib_get_nh (p_nh->parent_vrf_id, &p_nh->key.ip_addr, p_nh->key.if_index);
                        if (p_parent_nh && (p_parent_nh->clnts_ref_cnt == 0)) {
                            fib_proc_nh_delete (p_parent_nh, FIB_NH_OWNER_TYPE_CLIENT, 0);
                        }
                    } else if (p_nh->clnts_ref_cnt == 0) {
                        /* Parent NH can be deleted only if there is reference to leaked NH */
                        fib_proc_nh_delete (p_nh, FIB_NH_OWNER_TYPE_CLIENT, 0);
                    }
                } else if (FIB_IS_AFINDEX_VALID(p_nht->fib_match_dest_addr.af_index)) {
                    p_dr = fib_get_dr (p_nht->vrf_id, &p_nht->fib_match_dest_addr,
                                       p_nht->prefix_len);
                }
                t_fib_ip_addr fib_match_dest_addr, mask;
                uint8_t prefix_len;

                memcpy(&fib_match_dest_addr, &p_nht->fib_match_dest_addr, sizeof(t_fib_ip_addr));
                prefix_len = p_nht->prefix_len;
                memset(&p_nht->fib_match_dest_addr, 0, sizeof(t_fib_ip_addr));
                p_nht->prefix_len = 0;
                memset (&mask, 0, sizeof (t_fib_ip_addr));
                if (nas_rt_get_mask (fib_match_dest_addr.af_index, prefix_len, &mask)) {
                    nas_rt_check_nht_and_flush_acls(&fib_match_dest_addr,
                                                    &mask, prefix_len, p_dr, p_nh, false);
                }
                nas_rt_publish_nht(p_nht, NULL, NULL, is_add);
                if (fib_del_nht(p_nht) != STD_ERR_OK) {
                    HAL_RT_LOG_ERR("HAL-RT-NHT",
                                   "vrf_id: %d, dest_addr: %s del failed!",
                                   p_nht_info->vrf_id,
                                   FIB_IP_ADDR_TO_STR (&p_nht_info->key.dest_addr));
                    return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
                }
            }
            return STD_ERR_OK;
        }
    } else if (is_add == false) {
        HAL_RT_LOG_ERR("HAL-RT-NHT",
                       "vrf_id: %d, dest_addr: %s del failed, entry not present!",
                       p_nht_info->vrf_id,
                       FIB_IP_ADDR_TO_STR (&p_nht_info->key.dest_addr));
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    /* add could be from multiple clients for same NHT,
     * so just trigger publish if NH is resolved.
     */
    if (p_nht == NULL) {
        if ((p_nht = fib_add_nht(p_nht_info)) != NULL) {
            FIB_INCR_CNTRS_NHT_ENTRIES (p_nht->vrf_id, p_nht->key.dest_addr.af_index);
        } else {
            HAL_RT_LOG_ERR("HAL-RT-NHT", "vrf_id: %d, dest_addr: %s add failed!",
                           p_nht_info->vrf_id, FIB_IP_ADDR_TO_STR (&p_nht_info->key.dest_addr));
            return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
        }
    }
    ++(p_nht->ref_count);
    /* If there are more than one apps interested for this NHT,
     * let all apps except the first one do the get_all for all already existing NHT info. */
    if (p_nht->ref_count > 1)
        return STD_ERR_OK;

    /* Check if this dest_addr is already resolved in NextHop or Route table
     * NH lookup required ifIndex, but we don't need one for NHT flow, so getnext with 0
     * and use the returned NH if the NH ip address matches with NHT dest address.
     */
    p_nh = fib_get_next_nh(p_nht_info->vrf_id, &p_nht_info->key.dest_addr, 0);
    if (p_nh) {
        HAL_RT_LOG_DEBUG("HAL-RT-NHT", "vrf_id: %d, nh_addr: %s is_add:%d state:%d"
                         " NH_handle:%lu next match found in NH table",
                         p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), is_add,
                         ((p_nh->p_arp_info) ? p_nh->p_arp_info->state : 0), p_nh->next_hop_id);
    }
    /* do DR lookup in following scenario:
     * if NH is not present or NH address is different from NHT address or
     * ARP is not resolved for that NH.
     */
    if ((p_nh == NULL) || (p_nh->is_mgmt_nh) ||
        (memcmp(&p_nh->key.ip_addr, &p_nht->key.dest_addr, sizeof(t_fib_ip_addr)))) {

        HAL_RT_LOG_DEBUG("HAL-RT-NHT", "vrf_id: %d, dest_addr: %s is_add:%d "
                         "exact resolved fit not found in NH table", p_nht->vrf_id,
                         FIB_IP_ADDR_TO_STR (&p_nht->key.dest_addr), is_add);

        /* If there is no exact match in the nexthop table, look up in the route table */
        if (!FIB_IS_AFINDEX_VALID(p_nht->fib_match_dest_addr.af_index)) {
            /* No NH/DR table match yet, find it */
            nas_rt_find_next_best_dr_for_nht(p_nht, p_nht_info->vrf_id, &p_nht_info->key.dest_addr,
                                             FIB_AFINDEX_TO_PREFIX_LEN (p_nht_info->key.dest_addr.af_index), &is_best_rt_found);
        } else {
            /* When there is more than one client interested for this NHT, publish the route info. in the below function */
            nas_rt_find_next_best_dr_for_nht(p_nht, p_nht_info->vrf_id, &p_nht->fib_match_dest_addr,
                                             p_nht->prefix_len, &is_best_rt_found);
        }
    } else {
        HAL_RT_LOG_DEBUG("HAL-RT-NHT",
                         "vrf_id: %d, nexthop: %s exact resolved fit found in NH table Add:%d "
                         "resolved:%s group-id:%lu rt-cnt:%d",
                         p_nht_info->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), is_add,
                         ((p_nh->p_arp_info->state == FIB_ARP_RESOLVED) ? "Yes" : "No"),
                         p_nh->next_hop_id, p_nh->rtm_ref_count);

        if (p_nh->vrf_id != p_nh->parent_vrf_id) {
            t_fib_nh *p_parent_nh = fib_get_nh (p_nh->parent_vrf_id, &p_nht_info->key.dest_addr, p_nh->key.if_index);
            if (p_parent_nh == NULL) {
                /* If parent NH is not present, create it before creating the leaked NH */
                fib_proc_nh_add (p_nh->parent_vrf_id, &p_nht_info->key.dest_addr, p_nh->key.if_index,
                                 FIB_NH_OWNER_TYPE_CLIENT, 0, false, p_nh->parent_vrf_id, 0);
            }
        }

        fib_proc_nh_add (p_nht_info->vrf_id, &p_nht_info->key.dest_addr,
                         p_nh->key.if_index, FIB_NH_OWNER_TYPE_CLIENT, 0, false, p_nh->parent_vrf_id, 0);
        if (p_nh->p_arp_info->state != FIB_ARP_RESOLVED) {
            return STD_ERR_OK;
        }

        if (is_add && (p_nh->next_hop_id == 0)) {
            HAL_RT_LOG_INFO("HAL-RT-NHT",
                            "vrf_id: %d, nexthop: %s NH table Add:%d "
                            "resolved:%s group-id:%lu rt-cnt:%d",
                            p_nht_info->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), is_add,
                            ((p_nh->p_arp_info->state == FIB_ARP_RESOLVED) ? "Yes" : "No"),
                            p_nh->next_hop_id, p_nh->rtm_ref_count);
            bool rif_update = true;
            if (p_nh->vrf_id != p_nh->parent_vrf_id) {
                t_fib_nh *p_parent_nh = fib_get_nh (p_nh->parent_vrf_id, &p_nh->key.ip_addr,
                                                    p_nh->key.if_index);
                if (p_parent_nh && (p_parent_nh->next_hop_id)) {
                    rif_update = false;
                }
            }

            if (hal_fib_next_hop_add(p_nh) != DN_HAL_ROUTE_E_NONE) {
                HAL_RT_LOG_ERR("HAL-RT-NHT", "vrf_id: %d, nexthop: %s exact fit found "
                               "and resolved: %s but group-id:%lu add failed!",
                               p_nht_info->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                               ((p_nh->p_arp_info->state == FIB_ARP_RESOLVED) ? "Yes" : "No"), p_nh->next_hop_id);
                return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
            }
            if (rif_update) {
                /* increment the RIF for the first time update */
                hal_rt_rif_ref_inc(p_nh->parent_vrf_id, p_nh->key.if_index);
            }
        }
        /* NH should always be matched for exact address.
         * check if returned NH address is same as NHT dest address
         * before publishing event
         */
        if (memcmp(&p_nht_info->key.dest_addr, &p_nh->key.ip_addr, sizeof(p_nh->key.ip_addr)) == 0) {
            memcpy(&p_nht->fib_match_dest_addr, &p_nh->key.ip_addr, sizeof(p_nh->key.ip_addr));
            p_nht->prefix_len = FIB_AFINDEX_TO_PREFIX_LEN (p_nh->key.ip_addr.af_index);
            /* Publish the event */
            nas_rt_publish_nht(p_nht, NULL, p_nh, true);
        }
    }

    /* There is no resolved NH available now, just publish the NHT CREATE*/
    if (p_nht->is_create_pub == false) {
        nas_rt_publish_nht(p_nht, NULL, NULL, true);
    }
    return STD_ERR_OK;
}

t_std_error nas_rt_flush_nhts(hal_vrf_id_t vrf_id, int af_index) {
    t_fib_nht *p_fib_nht = NULL, *p_fib_del_nht = NULL;

    p_fib_nht = fib_get_first_nht(vrf_id, af_index);
    while(p_fib_nht) {
        if (p_fib_del_nht) {
            HAL_RT_LOG_INFO("NHT-FLUSH", "vrf_id: %d, dest_addr: %s already exists, ref-cnt:%d",
                            p_fib_del_nht->vrf_id,
                            FIB_IP_ADDR_TO_STR (&p_fib_del_nht->key.dest_addr), p_fib_del_nht->ref_count);

            nas_rt_handle_nht(p_fib_del_nht, false, true);
        }
        p_fib_del_nht = p_fib_nht;
        p_fib_nht = fib_get_next_nht(vrf_id, &p_fib_nht->key.dest_addr);
    }

    if (p_fib_del_nht) {
        HAL_RT_LOG_INFO("NHT-FLUSH", "vrf_id: %d, dest_addr: %s already exists, ref-cnt:%d",
                        p_fib_del_nht->vrf_id,
                        FIB_IP_ADDR_TO_STR (&p_fib_del_nht->key.dest_addr), p_fib_del_nht->ref_count);
        nas_rt_handle_nht(p_fib_del_nht, false, true);
    }
    return STD_ERR_OK;
}

