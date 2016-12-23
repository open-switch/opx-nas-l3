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
 * \file   hal_rt_mpath_util.c
 * \brief  NAS Routing ECMP Multipath Group utility functions
 * \date   03-2015
 * \author Satish Mynam
 */

#include "hal_rt_mpath_grp.h"
#include "nas_ndi_route.h"
#include "hal_rt_util.h"

#include "event_log.h"
#include "std_ip_utils.h"
#include "std_error_codes.h"

#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>


void hal_rt_fib_form_md5_key (uint8_t t_md5_digest [], next_hop_id_t a_nh_obj_id [],
                    uint32_t ecmp_count, uint32_t debug)
{
    MD5_CTX      md5_context;


    MD5_Init(&md5_context);
    MD5_Update(&md5_context,(uint8_t *) a_nh_obj_id,
               sizeof (next_hop_id_t) * ecmp_count);
    MD5_Final(t_md5_digest, &md5_context);

    if (debug)
    {
        char buf[HAL_RT_MAX_BUFSZ], buf1[HAL_RT_MAX_BUFSZ];
        char *ptr, *sptr;
        int len, i;
        memset(buf, ' ', sizeof(buf));
        buf[0] = '\0';
        ptr = &buf[0];
        sptr = ptr;
        for (i = 0; i < HAL_RT_MD5_DIGEST_LEN; i++) {
            memset(buf1, ' ', sizeof(buf1));
            len = snprintf(buf1, HAL_RT_MAX_BUFSZ, "%02x ", t_md5_digest[i]);
            if ((ptr-sptr + len) >= HAL_RT_MAX_BUFSZ )
                break;
            strncat(ptr, buf1, len);
            ptr += len;
        }
        HAL_RT_LOG_DEBUG ("HAL-RT-MP","MD5 Digest = %s", buf);
    }

}

static t_std_error fib_add_mp_obj_in_mp_md5_tree (t_fib_dr *p_dr, t_fib_mp_obj *p_mp_obj,
                                                   uint8_t *pu1_md5_digest)
{
    t_fib_mp_md5_node_key  key;
    t_fib_mp_md5_node    *p_mp_md5_node;
    std_rt_head          *p_rt_head;

    memset(&key, 0, sizeof(key));
    key.unit = p_mp_obj->unit;
    memcpy (key.md5_digest, pu1_md5_digest, sizeof (key.md5_digest));

    p_mp_md5_node = (t_fib_mp_md5_node *)
        std_radix_getexact (hal_rt_access_fib_vrf_mp_md5_tree(p_dr->vrf_id,
                            p_dr->key.prefix.af_index),
                            (uint8_t *) &key, HAL_RT_MP_MD5_NODE_TREE_KEY_SIZE);

    if (p_mp_md5_node == NULL)
    {
        p_mp_md5_node = hal_rt_fib_calloc_mp_md5_node ();

        if (p_mp_md5_node == NULL)
        {

            HAL_RT_LOG_ERR ("HAL_RT-MPATH",
                            "Failed to allocate Mp_md5 node "
                            "Unit: %d\n", p_mp_obj->unit);

            return (STD_ERR(ROUTE, FAIL, 0));
        }
        p_mp_md5_node->num_nodes = 0;

        std_dll_init (&p_mp_md5_node->mp_node_list);

        p_mp_md5_node->key.unit = p_mp_obj->unit;
        memcpy (p_mp_md5_node->key.md5_digest,
                pu1_md5_digest, sizeof (p_mp_md5_node->key.md5_digest));

        p_mp_md5_node->rt_head.rth_addr = (uint8_t *) &p_mp_md5_node->key;

        p_rt_head = std_radix_insert (hal_rt_access_fib_vrf_mp_md5_tree(p_dr->vrf_id,
                                        p_dr->key.prefix.af_index),
                                        &p_mp_md5_node->rt_head,
                                        HAL_RT_MP_MD5_NODE_TREE_KEY_SIZE);

        if (p_rt_head == NULL)
        {
            HAL_RT_LOG_ERR ("HAL_RT-MPATH",
                            "Failed to insert Mp_md5 node in "
                            "the tree. Unit: %d\n", p_mp_obj->unit);

            hal_rt_fib_free_mp_md5_node (p_mp_md5_node);

            return (STD_ERR(ROUTE, FAIL, 0));
        }
    }

    std_dll_insertatback (&p_mp_md5_node->mp_node_list, &p_mp_obj->glue);
    p_mp_md5_node->num_nodes++;

    p_mp_obj->p_md5_node = p_mp_md5_node;

    return STD_ERR_OK;
}


static t_std_error fib_del_mp_obj_from_mp_md5_tree (t_fib_dr *p_dr, t_fib_mp_obj *p_mp_obj)
{
    t_fib_mp_md5_node *p_mp_md5_node;

    if (p_mp_obj->p_md5_node == NULL)
    {
        HAL_RT_LOG_DEBUG ("HAL_RT-MPATH",
                          "Delete MP MD5 Tree: p_mp_obj->p_mp_md5_node "
                          "is NULL Unit: %d\n", p_mp_obj->unit);
        return (STD_ERR(ROUTE, FAIL, 0));
    }


    p_mp_md5_node = p_mp_obj->p_md5_node;

    if (p_mp_md5_node) {

        HAL_RT_LOG_DEBUG ("HAL_RT-MPATH",
                          "Delete MP MD5 Tree: #nodes:%d p_mp_obj: %p  p_mp_md5_node: %p "
                          "Unit: %d\n", p_mp_md5_node->num_nodes,
                          p_mp_obj, p_mp_md5_node,p_mp_obj->unit);

        if (p_mp_md5_node->num_nodes >= 1)
        {
            p_mp_md5_node->num_nodes--;
        }

        if ( p_mp_md5_node->num_nodes == 0)
        {
            std_radix_remove (hal_rt_access_fib_vrf_mp_md5_tree(p_dr->vrf_id,
                              p_dr->key.prefix.af_index), &p_mp_md5_node->rt_head);

        }

        std_dll_remove (&p_mp_md5_node->mp_node_list, &p_mp_obj->glue);
        /*
         * Free p_mp_md5_node node
         */
        if ( p_mp_md5_node->num_nodes == 0)
            hal_rt_fib_free_mp_md5_node(p_mp_md5_node);
    }

    p_mp_obj->p_md5_node = NULL;
    return STD_ERR_OK;
}

t_fib_mp_obj *hal_rt_fib_create_mp_obj (t_fib_dr *p_dr, ndi_nh_group_t *entry,
                                 uint8_t *pu1_md5_digest, int ecmp_count,
                                 next_hop_id_t a_nh_obj_id [],
                                 bool is_with_id, uint32_t sai_ecmp_gid,
                                 bool *p_out_is_mp_table_full)
{
    t_fib_mp_obj   *p_mp_obj;
    int             rc;
    next_hop_id_t   nh_group_handle = 0;

    *p_out_is_mp_table_full = false;


    /*
     * If ecmp_group id is already present and ref_cnt == 1, then update
     *  his ecmp_group id instead of creating new id unless its for the first time
     *  changing to ECMP from non-ECMP
     *
     *
     *  Two methods: Check nexthop_id list and compare new list with old
     *  list and find the difference in NHs to add and delete for the existing
     *  nexthop_group or else the easy way is to add a new group id for the new NH
     *  list and then delete old group id.
     *  Currently optimizing by creating a new group id and later deleting the old group id
     *
     */

    /*
     * Add new group-id for the new list
     *
     */
    rc = ndi_route_next_hop_group_create (entry, &nh_group_handle);

    if (is_with_id == true) {

            /*
             * If the earlier nh_handle is ecmp group id, mark it for deletion
             * after the route points to the new group id
             */
        if (p_dr->ecmp_handle_created) {

            p_dr->remove_old_handle = true;
            p_dr->onh_handle = sai_ecmp_gid;

           /*
            * ndi_route_next_hop_group_delete is called in the ecmp_add
            * where we add the new group id.
            */
        }
    }


    if (rc != STD_ERR_OK) {
        HAL_RT_LOG_DEBUG ("HAL-RT-NDI",
                "NH Group: %s Group ID failed. VRF %d. Prefix: "
                "%s/%d, Unit: %d, Err: %d\r\n",
                is_with_id ? "Update":"Create", p_dr->vrf_id,
                FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                p_dr->prefix_len, entry->npu_id, rc);
        /*
         * set  group table as full
         */
        *p_out_is_mp_table_full = true;

        return NULL;
    } else {
        HAL_RT_LOG_DEBUG ("HAL-RT-NDI",
                "NH Group: %s New Group ID: %d Old GID=%d. VRF %d. Prefix: "
                "%s/%d,Unit: %d, Err: %d\r\n", is_with_id ? "Updated":"Created",
                        nh_group_handle, sai_ecmp_gid, p_dr->vrf_id,
                FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                p_dr->prefix_len,  entry->npu_id, rc);

        /*
         * Create new mp_obj and add group_id to it.
         */
        p_mp_obj = hal_rt_fib_calloc_mp_obj_node ();
        HAL_RT_LOG_DEBUG ("HAL_RT-MPATH", "In Create MP Object: "
                          "Unit %d.\n", entry->npu_id);

        if (p_mp_obj == NULL)
        {
            HAL_RT_LOG_DEBUG ("HAL_RT-MPATH", "Create MP Object: "
                              "Failed to allocate Multipath Object "
                              "node. Unit %d.\n", entry->npu_id);

            return NULL;
        }

        p_mp_obj->unit      = entry->npu_id;
        p_mp_obj->ecmp_count = ecmp_count;
        memcpy (p_mp_obj->a_nh_obj_id, a_nh_obj_id, sizeof (p_mp_obj->a_nh_obj_id));

        rc = fib_add_mp_obj_in_mp_md5_tree (p_dr, p_mp_obj, pu1_md5_digest);

        if (STD_IS_ERR(rc))
        {
            HAL_RT_LOG_DEBUG ("HAL_RT-MPATH", "Create MP Object: "
                              "Failed to insert p_mp_obj in Tree. Unit: %d\n.", entry->npu_id);

            hal_rt_fib_free_mp_obj_node (p_mp_obj);
            return NULL;
        }


        /*
         * Update ECMP group id on p_mp_obj
         */
        p_mp_obj->sai_ecmp_gid = nh_group_handle;
        p_dr->onh_handle = p_dr->nh_handle;
        p_dr->ecmp_handle_created = true;
    }

    return p_mp_obj;
}

static t_fib_mp_obj *fib_find_mp_obj_in_md5_digest_list (t_fib_mp_md5_node *p_mp_md5_node,
                                      int  ecmp_count,  next_hop_id_t a_nh_obj_id[])
{
    t_fib_mp_obj *p_mp_obj;

    p_mp_obj = (t_fib_mp_obj *) std_dll_getfirst (&p_mp_md5_node->mp_node_list);

    while (p_mp_obj != NULL)
    {
        if ((ecmp_count == p_mp_obj->ecmp_count) &&
                !memcmp (p_mp_obj->a_nh_obj_id, a_nh_obj_id,
                        sizeof (p_mp_obj->a_nh_obj_id)))
        {
            return p_mp_obj;
        }

        p_mp_obj = (t_fib_mp_obj *) std_dll_getnext (&p_mp_md5_node->mp_node_list,
                                              &p_mp_obj->glue);
    }

    return NULL;
}

t_fib_mp_obj *hal_rt_fib_get_mp_obj (t_fib_dr *p_dr, ndi_nh_group_t *entry, uint8_t *pu1_md5_digest,
                        int ecmp_count, next_hop_id_t a_nh_obj_id[])
{
    t_fib_mp_md5_node_key  key;
    t_fib_mp_md5_node    *p_mp_md5_node;
    t_fib_mp_obj         *p_mp_obj;
    std_rt_head          *p_rt_head;

    memset(&key, 0, sizeof(key));
    key.unit = entry->npu_id;
    memcpy (key.md5_digest, pu1_md5_digest, sizeof (key.md5_digest));

    p_rt_head = std_radix_getexact (hal_rt_access_fib_vrf_mp_md5_tree(p_dr->vrf_id,
                                    p_dr->key.prefix.af_index), (uint8_t *) &key,
                                    HAL_RT_MP_MD5_NODE_TREE_KEY_SIZE);

    if (p_rt_head == NULL)
    {
        return NULL;
    }

    p_mp_md5_node = (t_fib_mp_md5_node *) p_rt_head;

    if (p_mp_md5_node->num_nodes == 1)
    {
        p_mp_obj = (t_fib_mp_obj *) std_dll_getfirst (&p_mp_md5_node->mp_node_list);

        if(ecmp_count != p_mp_obj->ecmp_count)
        {
            HAL_RT_LOG_DEBUG ("HAL_RT-MPATH",
                              "Ecmp_count mismatch. ecmp_count: %d,"
                              " p_mp_obj->ecmp_count: %d, Unit: %d.\n",
                              ecmp_count, p_mp_obj->ecmp_count, entry->npu_id);

            return NULL;
        }
    }
    else
    {
        p_mp_obj = fib_find_mp_obj_in_md5_digest_list (p_mp_md5_node, ecmp_count,
                                                       a_nh_obj_id);
    }
    return p_mp_obj;
}

/*
 * Delete old group id that was marked for deletion
 */

t_std_error hal_rt_fib_check_and_delete_old_groupid(t_fib_dr *p_dr, npu_id_t  unit)
{
    int             rc;

    if (p_dr->remove_old_handle) {
        rc = ndi_route_next_hop_group_delete (unit,  p_dr->onh_handle);
        if (rc != STD_ERR_OK) {
            HAL_RT_LOG_DEBUG ("HAL-RT-NDI",
                              "NH Group: Old Group ID delete failed. gid %d VRF %d. Prefix: "
                              "%s/%d, Unit: %d, Err: %d\r\n",
                              p_dr->onh_handle,  p_dr->vrf_id,
                              FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                              p_dr->prefix_len, unit, rc);
            return (STD_ERR(ROUTE, FAIL, 0));
        } else {
            HAL_RT_LOG_DEBUG ("HAL-RT-NDI",
                              "NH Group: Old Group ID delete SUCCESS. gid %d VRF %d. Prefix: "
                              "%s/%d, Unit: %d, Err: %d\r\n",
                              p_dr->onh_handle,  p_dr->vrf_id,
                              FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                              p_dr->prefix_len, unit, rc);
        }
        p_dr->remove_old_handle = false;
        p_dr->onh_handle = 0;
        return STD_ERR_OK;
    }
    return (STD_ERR(ROUTE, FAIL, 0));
}
t_std_error hal_rt_fib_check_and_delete_mp_obj (t_fib_dr *p_dr, t_fib_mp_obj *p_mp_obj, npu_id_t  unit,
                                                bool is_sai_del, bool route_delete)
{


    if (p_mp_obj && (p_mp_obj->ref_count == 0))
    {
        if (is_sai_del == true)
        {

            /*
             * Mark old group  id for deletion, a new route update will
             * call hal_rt_fib_check_and_delete_old_groupid() to remove the gid.
             * NOTE: a gid in sai cannot be removed when a route is holding it
             * and it can be removed only when the route updatesd to new group id or n.
             */
            p_dr->remove_old_handle = true;
            p_dr->onh_handle = p_mp_obj->sai_ecmp_gid;

            /*
             * If route is getting delete, check and delete groupid
             */
            if (route_delete) {
                hal_rt_fib_check_and_delete_old_groupid(p_dr, unit);
            }

        }

        fib_del_mp_obj_from_mp_md5_tree (p_dr, p_mp_obj);
        hal_rt_fib_free_mp_obj_node (p_mp_obj);
        return STD_ERR_OK;
    }

    return STD_ERR_OK;
}

int fib_create_mp_md5_tree (t_fib_vrf_info *p_vrf_info)
{
    char tree_name_str [FIB_RDX_MAX_NAME_LEN];

    if (!p_vrf_info)
    {
        HAL_RT_LOG_DEBUG ("HAL-RT-MP", "Invalid input param. p_vrf_info: %p\r\n",
                          p_vrf_info);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    HAL_RT_LOG_DEBUG ("HAL-RT-MP", "Vrf_id: %d, af_index: %s\r\n",
                      p_vrf_info->vrf_id,
                      STD_IP_AFINDEX_TO_STR (p_vrf_info->af_index));

    if (p_vrf_info->mp_md5_tree != NULL)
    {
        HAL_RT_LOG_DEBUG ("HAL-RT-MP", "MP MD5 tree already created. "
                          "vrf_id: %d, af_index: %d\r\n",
                           p_vrf_info->vrf_id, p_vrf_info->af_index);

        return STD_ERR_OK;
    }

    memset (tree_name_str, 0, FIB_RDX_MAX_NAME_LEN);

    snprintf (tree_name_str, FIB_RDX_MAX_NAME_LEN, "Fib%s_mp_md5_tree_vrf%d",
             STD_IP_AFINDEX_TO_STR (p_vrf_info->af_index), p_vrf_info->vrf_id);

    p_vrf_info->mp_md5_tree = std_radix_create (tree_name_str, HAL_RT_MP_MD5_NODE_TREE_KEY_SIZE,
                                       NULL, NULL, 0);

    if (p_vrf_info->mp_md5_tree == NULL)
    {
        HAL_RT_LOG_DEBUG ("HAL-RT-MP",
                          "std_radix_create failed. Vrf_id: %d, "
                          "af_index: %s\r\n", p_vrf_info->vrf_id,
                          STD_IP_AFINDEX_TO_STR (p_vrf_info->af_index));

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    /*
     * Make sure to disable radical for mp_md5 tree as there is no walker needed
     */
    std_radix_disable_radical (p_vrf_info->mp_md5_tree);
    return STD_ERR_OK;
}

int fib_destroy_mp_md5_tree (t_fib_vrf_info *p_vrf_info)
{
    if (!p_vrf_info)
    {
        HAL_RT_LOG_DEBUG ("HAL-RT-MP",
                          "Invalid input param. p_vrf_info: %p\r\n",
                          p_vrf_info);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    if (p_vrf_info->mp_md5_tree == NULL)
    {
        HAL_RT_LOG_DEBUG ("HAL-RT-MP",
                          "MP MD5 tree not present. "
                          "vrf_id: %d, af_index: %d\r\n",
                          p_vrf_info->vrf_id, p_vrf_info->af_index);

        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    std_radix_destroy (p_vrf_info->mp_md5_tree);
    p_vrf_info->mp_md5_tree = NULL;

    return STD_ERR_OK;
}

void fib_dump_mp_obj_node (t_fib_mp_obj *p_mp_obj, int add_indendation)
{
    int   index;
    char *p_indent_str = "";
    char *p_nh_obj_indent_str = HAL_RT_3_SPACE_INDENT;

    if (add_indendation)
        p_indent_str= HAL_RT_17_SPACE_INDENT;

    printf ("%sp_mp_obj      : %p\n", p_indent_str, p_mp_obj);
    printf ("%sunit        : %d\n", p_indent_str, p_mp_obj->unit);
    printf ("%secmp_count   : %d\n", p_indent_str, p_mp_obj->ecmp_count);
    printf ("%shw_mp_index   : %d\n", p_indent_str, (int) p_mp_obj->sai_ecmp_gid);
    printf ("%sref_count    : %d\n", p_indent_str, p_mp_obj->ref_count);
    printf ("%sp_mdp_md5_node : %p\n", p_indent_str, p_mp_obj->p_md5_node);

    printf ("%snh_obj_list  : ", p_indent_str);

    for (index = 0; index < p_mp_obj->ecmp_count; index++)
    {
        printf ("%s (%d)%s%s",
                (index == 0) ? "" :
                (((index % 4) == 0) ? p_nh_obj_indent_str : ""),
                (int) p_mp_obj->a_nh_obj_id [index],
                (index == (p_mp_obj->ecmp_count - 1)) ? "" : ", ",
                ((index % 4) == 3) ? "\n" : "");
    }

    printf ("\n\n");
}

void fib_dump_mp_md5_node (t_fib_mp_md5_node *p_md5_node, int dump_mp_obj)
{
    uint8_t  *md5_digest;
    uint32_t  index;
    t_fib_mp_obj  *p_mp_obj;

    md5_digest = p_md5_node->key.md5_digest;

    printf ("\n");
    printf ("p_mp_md5_node  : %p\n", p_md5_node);
    printf ("unit        : %d\n", p_md5_node->key.unit);
    printf ("md5_digest   : ");

    for (index = 0; index < HAL_RT_MD5_DIGEST_LEN; index++)
    {
        printf ("%02x%s%s", md5_digest [index],
                ((index % 4) == 3) ? " " : "",
                (index == (HAL_RT_MD5_DIGEST_LEN - 1)) ? "\n" : "");
    }

    printf ("num_nodes   : %d\n", p_md5_node->num_nodes);

    p_mp_obj = (t_fib_mp_obj *) std_dll_getfirst (&p_md5_node->mp_node_list);

    while (p_mp_obj != NULL)
    {
        printf ("p_mp_obj      : %p\n", p_mp_obj);

        if (dump_mp_obj)
        {
            fib_dump_mp_obj_node (p_mp_obj, 1);
        }

        p_mp_obj = (t_fib_mp_obj *)
            std_dll_getnext (&p_md5_node->mp_node_list, &p_mp_obj->glue);
    }
}
