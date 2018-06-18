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
 * \file   hal_rt_mpath_grp.c
 * \brief  NAS Routing  ECMP Multipath Group Object functions
 * \date   03-2015
 * \author Satish Mynam
 */

#include "hal_rt_mpath_grp.h"
#include "hal_rt_util.h"
#include "nas_ndi_route.h"
#include "event_log.h"
#include "std_error_codes.h"


#include <string.h>
#include "std_ip_utils.h"
#include <stdio.h>


static void fib_update_mp_obj_info (t_fib_dr *p_dr, npu_id_t unit, t_fib_hal_dr_info *p_hal_dr_info,
                          uint8_t is_ecmp, void *p_nh_or_mp_obj)
{
    t_fib_mp_obj  *p_old_mp_obj;
    t_fib_mp_obj  *p_mp_obj;

    if (p_hal_dr_info->a_obj_status [unit] != HAL_RT_STATUS_ECMP_INVALID)
    {
        /* This is a Route Update */
        if (p_hal_dr_info->a_obj_status [unit] == HAL_RT_STATUS_ECMP)
        {
            /* Old Route is ECMP */
            p_old_mp_obj = p_hal_dr_info->ap_mp_obj [unit];

            if (is_ecmp == true)
            {
                /* Old Route and new Route are ECMP. */
                p_mp_obj = (t_fib_mp_obj *) p_nh_or_mp_obj;

                if (p_old_mp_obj != p_mp_obj)
                {
                    (p_mp_obj)->ref_count++;
                    p_hal_dr_info->ap_mp_obj [unit] = p_mp_obj;

                    if (p_old_mp_obj != NULL && (p_old_mp_obj->ref_count > 0))
                    {
                        if ((p_old_mp_obj)->ref_count > 0)
                                (p_old_mp_obj)->ref_count--;

                        if (p_old_mp_obj->sai_ecmp_gid != p_mp_obj->sai_ecmp_gid)
                        {
                            /*
                             * New groupid created, so check if old mp_obj group id can be removed
                             */
                            hal_rt_fib_check_and_delete_mp_obj (p_dr, p_old_mp_obj, unit, true, false);
                        }
                        else /* Multipath object replace scenario */
                        {
                            hal_rt_fib_check_and_delete_mp_obj (p_dr, p_old_mp_obj, unit, false, false);
                        }
                    }
                }
            }
            else
            {
                /* Old Route is ECMP and new Route is non-ECMP */

                p_hal_dr_info->ap_mp_obj [unit] = NULL;

                if (p_old_mp_obj != NULL && (p_old_mp_obj->ref_count > 0))
                {
                    if ((p_old_mp_obj)->ref_count > 0)
                        (p_old_mp_obj)->ref_count--;
                    hal_rt_fib_check_and_delete_mp_obj (p_dr, p_old_mp_obj, unit, true, true);
                }

                p_hal_dr_info->a_obj_status [unit] = HAL_RT_STATUS_NON_ECMP;
            }
        }
        else
        {
            /* Old Route is non_ECMP */

            if (is_ecmp == true)
            {
                /* Old Route is non_ECMP and new Route is ECMP */
                p_mp_obj = (t_fib_mp_obj *) p_nh_or_mp_obj;



                (p_mp_obj)->ref_count++;
                p_hal_dr_info->ap_mp_obj [unit] = p_mp_obj;


                p_hal_dr_info->a_obj_status [unit] = HAL_RT_STATUS_ECMP;
            } else {
                p_hal_dr_info->ap_mp_obj [unit] =  NULL;
            }

        }
    }
    else
    {
        /* This is a new Route addition */
        if (is_ecmp == true)
        {
            p_mp_obj = (t_fib_mp_obj *) p_nh_or_mp_obj;

            (p_mp_obj)->ref_count++;

            p_hal_dr_info->ap_mp_obj [unit]    = p_mp_obj;
            p_hal_dr_info->a_obj_status [unit] = HAL_RT_STATUS_ECMP;
        }
        else
        {
            p_hal_dr_info->a_obj_status [unit] = HAL_RT_STATUS_NON_ECMP;
        }
    }
}


static inline void hal_dump_ecmp_nh_list(next_hop_id_t a_nh_obj_id [], int count) {

    static char buf[HAL_RT_MAX_BUFSZ * 10];

    hal_rt_format_nh_list(a_nh_obj_id, count, buf, HAL_RT_MAX_BUFSZ * 10);
    HAL_RT_LOG_DEBUG("HAL-RT-NDI",
            "Sorted ecmp_next_hop_id_list%d]: %s", count, buf);

}

/*
 * Create ECMP Group ID: Pass list of nh and get ECMP group ID
 */
t_std_error hal_rt_find_or_create_ecmp_group(t_fib_dr *p_dr, ndi_nh_group_t *entry,
        next_hop_id_t *handle, bool *p_out_is_mp_table_full, ndi_nh_group_t *removed_nh_group_entry)
{

    npu_id_t            unit;
    int                 is_mp_obj_created;
    int                 is_mp_obj_replaced;
    int                 error_occured = false;
    int                 ecmp_count;
    t_fib_hal_dr_info   *p_hal_dr_info;
    t_fib_mp_obj        *p_mp_obj = NULL;
    t_fib_mp_obj        *p_old_mp_obj = NULL;
    uint8_t             aui1_md5_digest [HAL_RT_MD5_DIGEST_LEN];
    next_hop_id_t       a_nh_obj_id [HAL_RT_MAX_ECMP_PATH];

    p_hal_dr_info = (t_fib_hal_dr_info *) p_dr->p_hal_dr_handle;
    unit = entry->npu_id;

    *p_out_is_mp_table_full   = false;
    is_mp_obj_created  = false;
    is_mp_obj_replaced = false;
    if (p_dr->nh_count > ((hal_rt_access_fib_config())->ecmp_max_paths)) {
        ecmp_count         = (hal_rt_access_fib_config())->ecmp_max_paths;
    }else {
        ecmp_count         = p_dr->nh_count;
    }
    p_old_mp_obj       = NULL;

        memset (aui1_md5_digest, 0, sizeof (aui1_md5_digest));
        memset (a_nh_obj_id, 0, sizeof (a_nh_obj_id));

        if ((p_hal_dr_info->a_obj_status [unit] == HAL_RT_STATUS_ECMP) &&
            (p_hal_dr_info->ap_mp_obj [unit] != NULL))
        {
            if (p_hal_dr_info->ap_mp_obj[unit]->ref_count > 0 )
                p_old_mp_obj = p_hal_dr_info->ap_mp_obj [unit];
        }

        /*
         * copy nh_list to  tmp list
         */
        size_t i;
        for (i=0; i<p_dr->nh_count; i++) {
            a_nh_obj_id[i] = entry->nh_list[i].id;

        }

        /*
         * Sort the NH list for optimal ECMP groups allocation
         */
        hal_rt_sort_array(a_nh_obj_id, p_dr->nh_count);
        entry->nhop_count = ecmp_count;

        /*
         * Disable ECMP MD5 debugging and enable only when needed by
         * setting hal_rt_fib_form_md5_key 'debug' to true, when needed
         * Dump ECMP list entries using:
         * hal_dump_ecmp_nh_list(a_nh_obj_id, ecmp_count);
         */

        hal_rt_fib_form_md5_key(aui1_md5_digest, a_nh_obj_id, HAL_RT_MAX_ECMP_PATH, false);

        p_mp_obj = hal_rt_fib_get_mp_obj (p_dr, entry, aui1_md5_digest, ecmp_count, a_nh_obj_id);
        HAL_RT_LOG_DEBUG ("HAL-RT-NDI",
                          "Get Multipath mp_obj Node  =%p (ref_cnt=%d) "
                          "Unit: %d.\n",p_mp_obj, p_mp_obj? p_mp_obj->ref_count :-1, unit);
        if (p_mp_obj == NULL)
        {
            HAL_RT_LOG_DEBUG ("HAL-RT-NDI", "Multipath Node mp_obj not present"
                            "Unit: %d.\n", unit);

            /*
             * If this is the only route referring to the multipath object,
             * then simply replace the multipath object instead of
             * creating a new multipath object.
             */

            if ((p_old_mp_obj != NULL) &&
                (p_old_mp_obj->ref_count == 1))
            {
                p_mp_obj = hal_rt_fib_create_mp_obj (p_dr, entry, aui1_md5_digest, ecmp_count,
                                         a_nh_obj_id, true,
                                         p_old_mp_obj->sai_ecmp_gid,
                                         p_out_is_mp_table_full);

                if (p_mp_obj == NULL)
                {
                    HAL_RT_LOG_ERR ("HAL-RT-NDI",
                                    "Failed to replace Multipath mp_obj Node."
                                    "Vrf_id: %d, Unit: %d.\n", p_dr->vrf_id, unit);

                    /* on failure to create the new NH group,
                     * NDI will clean-up the NH group if it is created.
                     */
                    error_occured = true;
                }
                else
                {
                    is_mp_obj_replaced = true;
                }
            }
            else
            {
                /* if there are only removed NH's then check if we can reuse the existing MP group */
                if (removed_nh_group_entry->nhop_count != 0)
                {
                    p_mp_obj = hal_rt_check_and_reuse_mp_obj (p_dr, entry,
                                           p_out_is_mp_table_full, removed_nh_group_entry,
                                           p_old_mp_obj, a_nh_obj_id, aui1_md5_digest);
                }

                if (p_mp_obj == NULL)
                {
                    /*
                     * Create a new MP node
                     */

                    p_mp_obj = hal_rt_fib_create_mp_obj (p_dr, entry, aui1_md5_digest, ecmp_count,
                                             a_nh_obj_id, false,
                                             0, p_out_is_mp_table_full);

                    if (p_mp_obj == NULL)
                    {
                        HAL_RT_LOG_ERR ("HAL-RT-NDI",
                                        "Failed to create New Multipath mp_obj Node. "
                                        "Vrf_id: %d, Unit: %d.\n",
                                        p_dr->vrf_id, unit);

                        error_occured = true;
                    }

                    is_mp_obj_created = true;
                }
            }
        }

        if (p_old_mp_obj == p_mp_obj)
        {
            /* Nothing has changed. So do nothing */
            HAL_RT_LOG_DEBUG ("HAL-RT-NDI", "Duplicate ECMP route add. "
                            "Unit: %d.\n", unit);
        }


        if (error_occured == false) {
            /*
             * Update ECMP Group ID in handle
             */
            *handle = p_mp_obj->sai_ecmp_gid;

            fib_update_mp_obj_info (p_dr, unit, p_hal_dr_info, true, (void *) p_mp_obj);
        } else  {
            if (is_mp_obj_created == true)
            {
                hal_rt_fib_check_and_delete_mp_obj (p_dr, p_mp_obj, entry->npu_id, true, false);
            }
            if (is_mp_obj_replaced == true) {
                hal_rt_fib_check_and_delete_mp_obj (p_dr, p_mp_obj, entry->npu_id, false, false);
            }

            if (*p_out_is_mp_table_full == true) {
                /*
                 *  @@TODO Do appropriate action when SAI ECMP groups are full
                 *
                 */
                return (STD_ERR(ROUTE, FAIL, 0));
            }

            return (STD_ERR(ROUTE, FAIL, 0));
        }

    return STD_ERR_OK;
}


/*
 * Check and reuse MP object: Pass list of nh, list of removed nh and old MP object.
 */
t_fib_mp_obj *hal_rt_check_and_reuse_mp_obj (t_fib_dr *p_dr,
                   ndi_nh_group_t *entry, bool *p_out_is_mp_table_full,
                   ndi_nh_group_t *removed_nh_group_entry,
                   t_fib_mp_obj *p_old_mp_obj,
                   next_hop_id_t a_new_nh_obj_id [],
                   uint8_t *pu1_new_md5_digest)
{
    npu_id_t            unit;
    int                 rc;
    t_fib_mp_obj       *p_mp_obj = NULL;
    uint8_t             aui1_tmp_md5_digest [HAL_RT_MD5_DIGEST_LEN];
    next_hop_id_t       tmp_a_nh_obj_id [HAL_RT_MAX_ECMP_PATH];

    memset (aui1_tmp_md5_digest, 0, sizeof (aui1_tmp_md5_digest));
    memset (tmp_a_nh_obj_id, 0, sizeof (tmp_a_nh_obj_id));

    unit = entry->npu_id;

    /* if there are only removed NH's then check if we can reuse the existing MP group */
    if (removed_nh_group_entry->nhop_count != 0)
    {
        HAL_RT_LOG_INFO ("HAL-RT-MP",
                         "ECMP NH removal scenario. No MP obj found. Trying to find one for OLD NH list. "
                         "VRF %d Prefix: %s/%d "
                         "New nh_count:%d, Removed nh_count:%d ",
                         p_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                         p_dr->nh_count, removed_nh_group_entry->nhop_count);

        /*
         * copy nh_list to  tmp list
         */
        size_t i;
        for (i=0; i<p_dr->nh_count; i++) {
            tmp_a_nh_obj_id[i] = entry->nh_list[i].id;

        }
        for (i=0; i<removed_nh_group_entry->nhop_count; i++) {
            tmp_a_nh_obj_id[p_dr->nh_count+i] = removed_nh_group_entry->nh_list[i].id;
        }

        /*
         * Sort the NH list for optimal ECMP groups allocation
         */
        hal_rt_sort_array(tmp_a_nh_obj_id, (p_dr->nh_count + removed_nh_group_entry->nhop_count));

        hal_rt_fib_form_md5_key(aui1_tmp_md5_digest, tmp_a_nh_obj_id, HAL_RT_MAX_ECMP_PATH, false);

        p_mp_obj = hal_rt_fib_get_mp_obj (p_dr, entry, aui1_tmp_md5_digest,
                                          (p_dr->nh_count + removed_nh_group_entry->nhop_count), tmp_a_nh_obj_id);
        if (p_mp_obj != NULL)
        {
            HAL_RT_LOG_INFO ("HAL-RT-MP",
                             "ECMP NH removal scenario. Found MP obj for OLD NH list. "
                             "VRF %d Prefix: %s/%d "
                             "mp nh_count:%d, mp GID:%lu, ref_cnt:%d",
                             p_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                             p_mp_obj->ecmp_count, p_mp_obj->sai_ecmp_gid, p_mp_obj->ref_count);

            if (p_old_mp_obj == p_mp_obj)
            {
                rc = hal_rt_fib_remove_members_from_mp_obj (p_dr, p_mp_obj,
                                 removed_nh_group_entry,
                                 pu1_new_md5_digest, entry->nhop_count,
                                 a_new_nh_obj_id, true,
                                 p_mp_obj->sai_ecmp_gid,
                                 p_out_is_mp_table_full);
                if (rc != STD_ERR_OK)
                {
                    HAL_RT_LOG_ERR ("HAL-RT-MP",
                                    "Failed to update Multipath mp_obj Node for NH removal. "
                                    "Unit:%d, Vrf_id:%d, Prefix: %s/%d mp GID:%lu\n",
                                    unit, p_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                                    p_dr->prefix_len, p_mp_obj->sai_ecmp_gid);
                    /* failed to update MP group. So switch to regular flow and create a new group */
                    p_mp_obj = NULL;
                }
                else
                {

                    HAL_RT_LOG_INFO ("HAL-RT-MP",
                                     "ECMP NH removal scenario. Removed NH's from current MP obj. "
                                     "VRF %d Prefix: %s/%d "
                                     "removed nh_count:%d, mp GID:%lu, ref_cnt:%d",
                                     p_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                                     removed_nh_group_entry->nhop_count, p_mp_obj->sai_ecmp_gid, p_mp_obj->ref_count);
                }
            } else {
                p_mp_obj = NULL;
            }
        }
    }

    return p_mp_obj;
}

/*
 * Delete ECMP Group ID: Pass ECMP group ID,
 * route status: update or delete
 */
t_std_error hal_rt_delete_ecmp_group(t_fib_dr *p_dr, ndi_route_t  *entry,
                                     next_hop_id_t gid_handle, bool route_delete)
{
    t_fib_hal_dr_info  *p_hal_dr_info;
    t_fib_mp_obj      *p_mp_obj;
    npu_id_t             unit;
    int             rc;

    p_hal_dr_info = (t_fib_hal_dr_info *) p_dr->p_hal_dr_handle;
    unit = entry->npu_id;

    p_mp_obj = p_hal_dr_info->ap_mp_obj [unit];

    if (p_mp_obj == NULL)
    {
        HAL_RT_LOG_DEBUG("HAL-RT-NDI",
                   "Multipath Object is NULL. Vrf_id: %lu, Unit: "
                   "%d.\n", entry->vrf_id, unit);
        return STD_ERR_OK;
    }

        p_hal_dr_info->a_obj_status[unit] = HAL_RT_STATUS_ECMP_INVALID;
        p_hal_dr_info->ap_mp_obj[unit]    = NULL;

        if ((p_mp_obj)->ref_count > 0)
            (p_mp_obj)->ref_count--;

        rc = hal_rt_fib_check_and_delete_mp_obj (p_dr, p_mp_obj, entry->npu_id, true, route_delete);
        if (rc != STD_ERR_OK) {
            HAL_RT_LOG_DEBUG("HAL-RT-MP",
                    "NH Group: Failed to delete ECMP group:%d mp_obj_id:%d "
                    "Vrf_id: %lu, Unit: %d. Err: %d ", (int) p_dr->nh_handle,
                    (int) p_mp_obj->sai_ecmp_gid, entry->vrf_id, entry->npu_id, rc);

            return (STD_ERR(ROUTE, FAIL, 0));
        }

    return STD_ERR_OK;
}
