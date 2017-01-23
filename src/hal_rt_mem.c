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
 * \file   hal_rt_mem.c
 * \brief  Hal Routing Memory management functionality
 * \date   05-2014
 */

#include "hal_rt_main.h"
#include "hal_rt_mem.h"
#include "hal_rt_route.h"
#include "hal_rt_debug.h"
#include "hal_rt_mpath_grp.h"

#include "event_log.h"

#include <string.h>

t_fib_dr *fib_alloc_dr_node (void)
{
    t_fib_dr          *p_dr;
    t_fib_hal_dr_info *p_hal_dr_info;
    void              *p_buf = NULL;

    p_dr = (t_fib_dr *) FIB_DR_MEM_MALLOC ();

    if (p_dr == NULL) {
        return NULL;
    }

    memset (p_dr, 0, sizeof (t_fib_dr));

       p_buf = malloc(sizeof (t_fib_hal_dr_info));
       if (p_buf != NULL) {
           memset (p_buf, 0, sizeof (t_fib_hal_dr_info));

           p_hal_dr_info = (t_fib_hal_dr_info *) p_buf;
           int unit;
           for (unit = 0; unit <= hal_rt_access_fib_config()->max_num_npu; unit++) {
               p_hal_dr_info->a_obj_status [unit] = HAL_RT_STATUS_ECMP_INVALID;
           }
       }
       p_dr->p_hal_dr_handle = (void *) p_buf;

    return p_dr;
}

void fib_free_dr_node (t_fib_dr *p_dr)
{
    if (p_dr->p_hal_dr_handle != NULL) {
        free ((void *) p_dr->p_hal_dr_handle);
        p_dr->p_hal_dr_handle = NULL;
    }

    FIB_DR_MEM_FREE (p_dr);
}

t_fib_nh *fib_alloc_nh_node (void)
{
    t_fib_nh *p_nh;

    p_nh = (t_fib_nh *) FIB_NH_MEM_MALLOC ();

    if (p_nh == NULL) {
        return NULL;
    }

    memset (p_nh, 0, sizeof (t_fib_nh));

    return p_nh;
}

void fib_free_nh_node (t_fib_nh *p_nh)
{
    if (p_nh->p_hal_nh_handle != NULL) {
        free(p_nh->p_hal_nh_handle);
        p_nh->p_hal_nh_handle = NULL;
    }

    FIB_NH_MEM_FREE (p_nh);
}

static int num_tunnel_fh_nodes = 0;

int fib_num_tunnel_fh_nodes (void)
{
    return num_tunnel_fh_nodes;
}

t_fib_tunnel_fh *fib_alloc_tunnel_fh_node (void)
{
    t_fib_tunnel_fh *p_tunnel_fh = NULL;

    p_tunnel_fh = FIB_TUNNEL_FH_MEM_MALLOC();

    if (p_tunnel_fh == NULL) {
        return NULL;
    }

    memset (p_tunnel_fh, 0, sizeof (t_fib_tunnel_fh));

    num_tunnel_fh_nodes++;

    return p_tunnel_fh;
}

void fib_free_tunnel_fh_node (t_fib_tunnel_fh *p_tunnel_fh)
{
    if (p_tunnel_fh->p_hal_nh_handle != NULL) {
        p_tunnel_fh->p_hal_nh_handle = NULL;
    }

    FIB_TUNNEL_FH_MEM_FREE (p_tunnel_fh);

    if (num_tunnel_fh_nodes > 0) {
        num_tunnel_fh_nodes--;
    }
}

t_fib_tunnel_dr_fh *fib_alloc_tunnel_dr_fh_node (void)
{
    t_fib_tunnel_dr_fh *p_tunnel_dr_fh = NULL;

    p_tunnel_dr_fh = FIB_TUNNEL_DR_FH_MEM_MALLOC();
    if (p_tunnel_dr_fh == NULL) {
        return NULL;
    }

    memset (p_tunnel_dr_fh, 0, sizeof (t_fib_tunnel_dr_fh));

    return p_tunnel_dr_fh;
}

void fib_free_tunnel_dr_fh_node (t_fib_tunnel_dr_fh *p_tunnel_dr_fh)
{
    FIB_TUNNEL_DR_FH_MEM_FREE (p_tunnel_dr_fh);
}

/*
 * ECMP Grouping: MD5 tree, mp_obj malloc/free APIs
 */
t_fib_mp_md5_node *hal_rt_fib_calloc_mp_md5_node (void)
{
    void *p_buf = NULL;


    p_buf = malloc(sizeof (t_fib_mp_md5_node));

    if (p_buf != NULL)
    {
        memset (p_buf, 0, sizeof (t_fib_mp_md5_node));
    }

    return ((t_fib_mp_md5_node *) p_buf);
}

void hal_rt_fib_free_mp_md5_node (t_fib_mp_md5_node *p_mp_md5_node)
{
    free ((void *) p_mp_md5_node);
}

t_fib_mp_obj *hal_rt_fib_calloc_mp_obj_node (void)
{
    void *p_buf = NULL;

    p_buf = malloc(sizeof (t_fib_mp_obj));
    if (p_buf != NULL) {
        memset (p_buf, 0, sizeof (t_fib_mp_obj));
    }

    return ((t_fib_mp_obj *) p_buf);
}

void hal_rt_fib_free_mp_obj_node (t_fib_mp_obj *p_mp_obj)
{
    free ((void *) p_mp_obj);
}

void *hal_rt_fib_calloc_hal_nh_info_node (void)
{
    void *p_buf = NULL;

    p_buf = malloc(sizeof (t_fib_hal_nh_info));
    if (p_buf != NULL) {
        memset (p_buf, 0, sizeof (t_fib_hal_nh_info));
    }

    return ((void *) p_buf);
}

void hal_rt_fib_free_hal_nh_info_node (void *p_hal_nh_info)
{
    free ((void *) p_hal_nh_info);
}

t_fib_nht *fib_alloc_nht_node (void)
{
    t_fib_nht *p_nht;

    p_nht = (t_fib_nht *) FIB_NHT_MEM_MALLOC ();

    if (p_nht == NULL) {
        return NULL;
    }
    memset (p_nht, 0, sizeof (t_fib_nht));
    return p_nht;
}

void fib_free_nht_node (t_fib_nht *p_nht)
{
    if (p_nht)
        FIB_NHT_MEM_FREE (p_nht);
}


