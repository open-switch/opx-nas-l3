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
 * \file   hal_rt_mpath_grp.h
 * \brief  This file contains the type definitions for multipath grouping.
 * \date   04-2014, 4-2015
 * \author Satish Mynam
 */

#ifndef __HAL_RT_MPATH_GROUP_H__
#define __HAL_RT_MPATH_GROUP_H__

#include <stdint.h>

#include "hal_rt_route.h"
#include "std_radix.h"
#include "std_radical.h"
#include "std_ip_utils.h"



typedef struct _t_fib_nh_obj {
    std_rt_head         rt_head;
    next_hop_id_t       key;
    uint32_t            flags;
    uint32_t            ref_count;
    next_hop_id_t       sai_nh_id;
} t_fib_nh_obj;

#define HAL_RT_MD5_DIGEST_LEN             16
#define HAL_RT_3_SPACE_INDENT "  "
#define HAL_RT_17_SPACE_INDENT "                 "


typedef struct _t_fib_mp_md5_node_key {
    npu_id_t        unit;
    uint8_t         md5_digest[HAL_RT_MD5_DIGEST_LEN];
} t_fib_mp_md5_node_key;

typedef struct _t_fib_mp_md5_node {
    /*
     * The key to this tree is MD5 Digest key. MD5 collisions are
     * possible. So we need to maintain a list of Multipath nodes
     * which have the same MD5 key, in a DLL.
     */
    std_rt_head             rt_head;
    t_fib_mp_md5_node_key   key;
    uint32_t                num_nodes;
    std_dll_head            mp_node_list; /* Each node is of type 't_fib_mp_obj' */
} t_fib_mp_md5_node;


typedef struct _t_fib_mp_obj {
    std_dll             glue;
    npu_id_t            unit;
    int                 ecmp_count;
    next_hop_id_t       a_nh_obj_id [HAL_RT_MAX_ECMP_PATH];
    next_hop_id_t       sai_ecmp_gid;
    t_fib_mp_md5_node   *p_md5_node;
    uint32_t            ref_count;
} t_fib_mp_obj;

typedef struct _t_fib_hal_dr_info {
    /*
     * Need to have 'a_obj_status' per unit, because, the route could change
     * from ECMP to non_ECMP (and vice-versa). The egress/multipath objects
     * have to be cleaned up and this happens per unit. We cannot rely
     * on 'status' of t_fib_hal_dr_info, since it is not per unit.
     */
    t_fib_ecmp_status  a_obj_status [HAL_RT_MAX_INSTANCE];
    t_fib_mp_obj       *ap_mp_obj [HAL_RT_MAX_INSTANCE];
} t_fib_hal_dr_info;

typedef struct _t_fib_hal_nh_info {
    t_fib_nh_obj *ap_nh_obj [HAL_RT_MAX_INSTANCE];
    t_fib_mp_obj  *ap_mp_obj [HAL_RT_MAX_INSTANCE];
} t_fib_hal_nh_info;


typedef struct _t_fib_merge_sort_context {
    t_fib_nh_obj      **ap_nh_obj;
    t_fib_nh_obj      **ap_tmp_nh_obj;
    next_hop_id_t      *a_nh_obj_id;
} t_fib_merge_sort_context;


#define HAL_RT_MP_MD5_NODE_TREE_KEY_SIZE   (sizeof (t_fib_mp_md5_node_key) * 8)

/* Function signatures for mpath.c - Start */
bool hal_rt_is_ecmp_enabled();

/* Function signatures for mpath_grp.c - Start */
int fib_create_mp_md5_tree (t_fib_vrf_info *p_vrf_info);
int fib_destroy_mp_md5_tree (t_fib_vrf_info *p_vrf_info);
std_rt_table * hal_rt_access_fib_vrf_mp_md5_tree(uint32_t vrf_id, uint8_t af_index);

t_std_error hal_rt_find_or_create_ecmp_group(t_fib_dr *p_dr, ndi_nh_group_t *entry,
        next_hop_id_t *handle, bool *p_out_is_mp_table_full);
t_std_error hal_rt_delete_ecmp_group(t_fib_dr *p_dr, ndi_route_t  *entry,
                                     next_hop_id_t gid_handle, bool route_delete);
t_fib_mp_md5_node *hal_rt_fib_calloc_mp_md5_node (void);
void hal_rt_fib_free_mp_md5_node (t_fib_mp_md5_node *p_mp_md5_node);
t_fib_mp_obj *hal_rt_fib_calloc_mp_obj_node (void);
void hal_rt_fib_free_mp_obj_node (t_fib_mp_obj *p_mp_obj);
void *fib_calloc_hal_nh_info_node (void);
void fib_free_hal_nh_info_node (void *p_hal_nh_info);
t_fib_mp_obj *hal_rt_fib_get_mp_obj (t_fib_dr *p_dr, ndi_nh_group_t *entry, uint8_t *pu1_md5_digest,
                        int ecmp_count, next_hop_id_t a_nh_obj_id[]);
t_std_error hal_rt_fib_check_and_delete_mp_obj (t_fib_dr *p_dr, t_fib_mp_obj *p_mp_obj, npu_id_t  unit,
                                                bool is_sai_del, bool route_delete);
t_fib_mp_obj *hal_rt_fib_create_mp_obj (t_fib_dr *p_dr, ndi_nh_group_t *entry, uint8_t *pu1_md5_digest,
                                 int ecmp_count, next_hop_id_t a_nh_obj_id [],
                                 bool is_with_id, uint32_t sai_ecmp_gid,
                                 bool *p_out_is_mp_table_full);
void hal_rt_fib_form_md5_key (uint8_t t_md5_digest [], next_hop_id_t a_nh_obj_id [],
                        uint32_t ecmp_count, uint32_t debug);
void hal_rt_fib_sort_nh_obj_id (next_hop_id_t a_nh_obj_id [], t_fib_nh_obj *ap_nh_obj [],
                          uint32_t ecmp_count, uint32_t debug);
t_std_error hal_rt_fib_check_and_delete_old_groupid(t_fib_dr *p_dr, npu_id_t  unit);
void hal_dump_ecmp_route_entry(ndi_nh_group_t *p_route_entry);
void hal_rt_format_nh_list(next_hop_id_t nh_list[],  int count, char *buf, int s_buf);
#endif /* __HAL_RT_MPATH_GROUP_H__ */
