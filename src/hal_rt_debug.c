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
 * \file   hal_rt_debug.c
 * \brief  Hal Routing Debug functionality
 * \date   05-2014
 */

#include "hal_rt_main.h"
#include "hal_rt_route.h"
#include "hal_rt_api.h"
#include "hal_rt_debug.h"
#include "hal_rt_util.h"
#include "hal_rt_mpath_grp.h"
#include "nas_rt_api.h"
#include "hal_shell.h"

#include "std_ip_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>

void fib_help (void)
{
    printf ("**************************************************\r\n");

    printf ("  fib_dump_config ()\r\n");
    printf ("  fib_dump_gbl_info ()\r\n");

    printf ("  fib_dump_vrf_info_per_vrf_per_af (uint32_t vrf_id, \r\n");
    printf ("                             uint8_t af_index)\r\n");

    printf ("  fib_dump_vrf_info_per_vrf (uint32_t vrf_id)\r\n");

    printf ("  fib_dump_vrf_info_per_af (uint8_t af_index)\r\n");

    printf ("  fib_dump_all_vrf_info ()\r\n");

    printf ("  fib_dump_dr (uint32_t vrf_id, uint8_t af_index, \r\n");
    printf ("             uint8_t *p_in_prefix, uint8_t prefix_len)\r\n");

    printf ("  fib_dump_dr_per_vrf_per_af (uint32_t vrf_id, \r\n");
    printf ("                        uint8_t af_index)\r\n");

    printf ("  fib_dump_dr_per_vrf (uint32_t vrf_id)\r\n");

    printf ("  fib_dump_dr_per_af (uint8_t af_index)\r\n");

    printf ("  fib_dump_all_dr ()\r\n");

    printf ("  fib_dump_nh (uint32_t vrf_id, uint8_t af_index, \r\n");
    printf ("             uint8_t *p_in_ip_addr, uint32_t if_index)\r\n");

    printf ("  fib_dump_nh_per_vrf_per_af (uint32_t vrf_id, \r\n");
    printf ("                        uint8_t af_index, bool dump_dep_dr)\r\n");

    printf ("  fib_dump_nh_per_vrf (uint32_t vrf_id)\r\n");

    printf ("  fib_dump_nh_per_af (uint8_t af_index)\r\n");

    printf ("  fib_dump_all_nh ()\r\n");

    printf ("  fib_dump_intf (uint32_t if_index, uint32_t vrf_id, \r\n");
    printf ("               uint8_t af_index)\r\n");

    printf ("  fib_dump_intf_per_if_index (uint32_t if_index)\r\n");

    printf ("  fib_dump_intf_per_if_index_per_vrf (uint32_t if_index, \r\n");
    printf ("                               uint32_t vrf_id)\r\n");

    printf ("  fib_dump_all_intf ()\r\n");

    printf ("  fib_dump_route_summary_per_vrf_per_af (uint32_t vrf_id, \r\n");
    printf ("                                  uint8_t af_index)\r\n");

    printf ("  fib_dump_route_summary_per_vrf (uint32_t vrf_id)\r\n");

    printf ("  fib_dump_vrf_cntrs_per_vrf_per_af (uint32_t vrf_id, \r\n");
    printf ("                              uint8_t af_index)\r\n");

    printf ("  fib_dump_vrf_cntrs_per_vrf (uint32_t vrf_id)\r\n");

    printf ("  fib_dump_vrf_cntrs_per_af (uint8_t af_index)\r\n");

    printf ("  fib_dump_all_vrf_cntrs ()\r\n");

    printf ("  fib_dump_all_cntrs ()\r\n");

    printf ("  fib_dump_all_db ()\r\n");

    printf ("  fib_dump_peer_mac_db_get_all_with_vrf(uint8_t vrf_id)\r\n");

    printf ("  fib_dump_nht (vrf_id, af_index, p_dest_addr <NULL - will loop all entries>)\r\n");

    printf ("  fib_dump_all_rif ()\r\n");

    printf ("  fib_dump_intf_rif (uint32_t vrf_id, uint32_t if_index)\r\n");

    printf ("  fib_dump_mp_info_per_vrf_per_af (uint32_t vrf_id, uint32_t af_index)\r\n");

    printf ("  fib_dump_all_mp_info ()\r\n");

    printf ("**************************************************\r\n");

    return;
}

void fib_dump_config (void)
{
    printf ("**************************************************\r\n");

    printf ("  ecmp_max_paths                      :  %d\r\n",
            (hal_rt_access_fib_config())->ecmp_max_paths);

    printf ("  ecmp_path_fall_back                  :  %d\r\n",
            (hal_rt_access_fib_config())->ecmp_path_fall_back);

    printf ("  ecmp_hash_sel                       :  %d\r\n",
            (hal_rt_access_fib_config())->ecmp_hash_sel);

    printf ("**************************************************\r\n");

    return;
}

void fib_dump_gbl_info(void)
{
    printf ("**************************************************\r\n");
    printf ("  total_msgs                :  %d\r\n",
            (hal_rt_access_fib_gbl_info())->num_tot_msg);
    printf ("  num_int_msg               :  %d\r\n",
            (hal_rt_access_fib_gbl_info())->num_int_msg);
    printf ("  num_err_msg               :  %d\r\n",
            (hal_rt_access_fib_gbl_info())->num_err_msg);
    printf ("  num_route_msg             :  %d\r\n",
            (hal_rt_access_fib_gbl_info())->num_route_msg);
    printf ("  num_nbr_msg               :  %d\r\n",
            (hal_rt_access_fib_gbl_info())->num_nei_msg);
    printf ("  num_unknown_msg           :  %d\r\n",
            (hal_rt_access_fib_gbl_info())->num_unk_msg);
    printf ("  num_ip_msg                :  %d\r\n",
            (hal_rt_access_fib_gbl_info())->num_ip_msg);
    printf ("**************************************************\r\n");

    return;
}

void fib_dump_gbl_info_clear_cntr(void)
{
    (hal_rt_access_fib_gbl_info())->num_tot_msg = 0;
    (hal_rt_access_fib_gbl_info())->num_int_msg = 0;
    (hal_rt_access_fib_gbl_info())->num_err_msg = 0;
    (hal_rt_access_fib_gbl_info())->num_route_msg = 0;
    (hal_rt_access_fib_gbl_info())->num_nei_msg = 0;
    (hal_rt_access_fib_gbl_info())->num_unk_msg = 0;
    (hal_rt_access_fib_gbl_info())->num_ip_msg = 0;

    return;
}

void fib_dump_vrf_info_per_vrf_per_af (uint32_t vrf_id, uint32_t in_af_index)
{
    uint8_t     af_index;
    t_fib_vrf_info  *p_vrf_info = NULL;

    af_index = (uint8_t) in_af_index;

    if (!(FIB_IS_VRF_ID_VALID (vrf_id)))
    {
        printf (" Invalid vrf_id. Vrf_id: %d\r\n", vrf_id);
        return;
    }

    if (af_index >= FIB_MAX_AFINDEX)
    {
        printf (" Invalid af_index. Af_index: %d\r\n", af_index);
        return;
    }

    p_vrf_info = FIB_GET_VRF_INFO (vrf_id, af_index);

    if (p_vrf_info == NULL)
    {
        printf (" Vrf info NULL\r\n");
        return;
    }

    printf ("**************************************************\r\n");
    printf ("  Vrf_id: %d, Af_index: %s\r\n", vrf_id,
            STD_IP_AFINDEX_TO_STR (af_index));
    printf ("**************************************************\r\n");

    printf ("**************************************************\r\n");
    printf ("  vrf_id                     :  %d\r\n", p_vrf_info->vrf_id);
    printf ("  vrf_name                   :  %s\r\n", p_vrf_info->vrf_name);
    printf ("  is_vrf_created             :  %d\r\n", p_vrf_info->is_vrf_created);
    printf ("  af_index                   :  %d\r\n", p_vrf_info->af_index);

    printf ("  num_dr_processed_by_walker :  %d\r\n",
            p_vrf_info->num_dr_processed_by_walker);

    printf ("  num_nh_processed_by_walker :  %d\r\n",
            p_vrf_info->num_nh_processed_by_walker);

    printf ("  clear_ip_fib_on            :  %d\r\n", p_vrf_info->clear_ip_fib_on);
    printf ("  clear_ip_route_on          :  %d\r\n", p_vrf_info->clear_ip_route_on);
    printf ("  clear_arp_on               :  %d\r\n", p_vrf_info->clear_arp_on);
    printf ("  dr_clear_on                :  %d\r\n", p_vrf_info->dr_clear_on);
    printf ("  nh_clear_on                :  %d\r\n", p_vrf_info->nh_clear_on);
    printf ("  dr_clear_max_radix_ver     :  %lld\r\n",
            p_vrf_info->dr_clear_max_radix_ver);
    printf ("  nh_clear_max_radix_ver     :  %lld\r\n",
            p_vrf_info->nh_clear_max_radix_ver);
    printf ("  dr_ha_on                   :  %d\r\n", p_vrf_info->dr_ha_on);
    printf ("  nh_ha_on                   :  %d\r\n", p_vrf_info->nh_ha_on);
    printf ("  is_catch_all_disabled      :  %d\r\n",
            p_vrf_info->is_catch_all_disabled);
    printf ("  dr_ha_max_radix_ver        :  %lld\r\n",
            p_vrf_info->dr_ha_max_radix_ver);
    printf ("  nh_ha_max_radix_ver        :  %lld\r\n",
            p_vrf_info->nh_ha_max_radix_ver);

    printf ("**************************************************\r\n");

    return;
}

void fib_dump_vrf_info_per_vrf (uint32_t vrf_id)
{
    uint8_t  af_index = 0;

    if (!(FIB_IS_VRF_ID_VALID (vrf_id)))
    {
        printf ("Invalid vrf_id. Vrf_id: %d\r\n", vrf_id);
        return;
    }

    for (af_index = FIB_MIN_AFINDEX; af_index < FIB_MAX_AFINDEX; af_index++)
    {
        fib_dump_vrf_info_per_vrf_per_af (vrf_id, af_index);
    }

    return;
}

void fib_dump_vrf_info_per_af (uint32_t in_af_index)
{
    uint8_t   af_index;
    uint32_t  vrf_id = 0;

    af_index = (uint8_t) in_af_index;

    if (af_index >= FIB_MAX_AFINDEX)
    {
        printf ("Invalid af_index. Af_index: %d\r\n", af_index);
        return;
    }

    for (vrf_id = FIB_MIN_VRF; vrf_id < FIB_MAX_VRF; vrf_id++)
    {
        fib_dump_vrf_info_per_vrf_per_af (vrf_id, af_index);
    }

    return;
}

void fib_dump_all_vrf_info (void)
{
    uint32_t  vrf_id = 0;
    uint8_t   af_index = 0;

    for (vrf_id = FIB_MIN_VRF; vrf_id < FIB_MAX_VRF; vrf_id++)
    {
        for (af_index = FIB_MIN_AFINDEX; af_index < FIB_MAX_AFINDEX; af_index++)
        {
            fib_dump_vrf_info_per_vrf_per_af (vrf_id, af_index);
        }
    }

    return;
}

void fib_dump_dr_node_key (t_fib_dr *p_dr)
{
    if (!p_dr)
    {
        printf (" DR node NULL\r\n");
        return;
    }

    printf ("  p_dr              :  %p\r\n", p_dr);
    printf ("  af_index          :  %d\r\n", p_dr->key.prefix.af_index);
    printf ("  prefix            :  %s\r\n", FIB_IP_ADDR_TO_STR (&p_dr->key.prefix));
    printf ("  prefix_len        :  %d\r\n", p_dr->prefix_len);
    printf ("  vrf_id            :  %d\r\n", p_dr->vrf_id);
    printf ("  vrf_name          :  %s\r\n", FIB_GET_VRF_NAME(p_dr->vrf_id, p_dr->key.prefix.af_index));

    return;
}

void fib_dump_nh_node_key (t_fib_nh *p_nh)
{
    if (!p_nh)
    {
        printf (" NH node NULL\r\n");
        return;
    }

    printf ("  p_nh              :  %p\r\n", p_nh);
    printf ("  af_index          :  %d\r\n", p_nh->key.ip_addr.af_index);
    printf ("  ip_addr           :  %s\r\n", FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr));
    printf ("  if_index          :  0x%x\r\n", p_nh->key.if_index);
    printf ("  vrf_id            :  %d\r\n", p_nh->vrf_id);
    printf ("  vrf_name          :  %s\r\n", FIB_GET_VRF_NAME(p_nh->vrf_id, p_nh->key.ip_addr.af_index));

    return;
}

void fib_dump_dr_node (t_fib_dr *p_dr)
{
    t_fib_nh         *p_nh = NULL;
    t_fib_nh         *p_fh = NULL;
    t_fib_dr_fh       *p_dr_fh = NULL;
    t_fib_nh_holder   nh_holder;
    t_fib_nh_holder   nh_holder1;
    uint32_t      count = 0;
    uint32_t      tunnel_count = 0;
    t_fib_tunnel_dr_fh *p_tunnel_dr_fh = NULL;
    t_fib_tunnel_fh   *p_tunnel_fh = NULL;

    if (!p_dr)
    {
        printf (" DR node NULL\r\n");
        return;
    }

    printf ("**************************************************\r\n");

    fib_dump_dr_node_key (p_dr);

    printf ("  proto            :  %d\r\n", p_dr->proto);
    printf ("  rt_type          :  %d\r\n", p_dr->rt_type);
    printf ("  default_dr_owner   :  %d\r\n", p_dr->default_dr_owner);
    printf ("  status_flag       :  0x%x\r\n", p_dr->status_flag);
    printf ("  last_update_time   :  %ld\r\n", p_dr->last_update_time);
    printf ("  p_hal_dr_handle       :  %p\r\n", p_dr->p_hal_dr_handle);
    printf ("  num_nh            :  %d\r\n", p_dr->num_nh);
    printf ("  num_fh            :  %d\r\n", p_dr->num_fh);

    if (STD_IP_IS_ADDR_LINK_LOCAL(&p_dr->key.prefix)) {
        printf ("  num_ipv6_link_local      :  %d\r\n", p_dr->num_ipv6_link_local);
        printf ("  num_ipv6_rif_link_local  :  %d\r\n", p_dr->num_ipv6_rif_link_local);
    }

    printf ("**************************************************\r\n");
    printf ("  NH List:\r\n");
    printf ("**************************************************\r\n");

    count = 0;

    FIB_FOR_EACH_NH_FROM_DR (p_dr, p_nh, nh_holder)
    {
        printf ("  NH%d:\r\n", count);

        printf ("-------------------------------------\r\n");
        fib_dump_nh_node_key (p_nh);
        printf ("-------------------------------------\r\n");

        count++;
    }

    printf ("**************************************************\r\n");
    printf ("  FH List:\r\n");
    printf ("**************************************************\r\n");

    count       = 0;
    tunnel_count = 0;

    FIB_FOR_EACH_FH_FROM_DR (p_dr, p_fh, nh_holder)
    {
        printf ("  FH%d:\r\n", count);

        printf ("-------------------------------------\r\n");
        fib_dump_nh_node_key (p_fh);

        p_dr_fh = FIB_GET_DRFH_NODE_FROM_NH_HOLDER (nh_holder);

        printf ("  status                   :  %d\r\n", p_dr_fh->status);
        printf ("-------------------------------------\r\n");

        count++;

        printf ("**************************************************\r\n");
        printf ("  Tunnel FH List:\r\n");
        printf ("**************************************************\r\n");

        FIB_FOR_EACH_FH_FROM_TUNNEL_DRFH (p_dr_fh, p_tunnel_fh, nh_holder1)
        {
            p_fh         = FIB_GET_FH_FROM_TUNNEL_FH (p_tunnel_fh);
            p_tunnel_dr_fh = FIB_GET_TUNNEL_DRFH_NODE_FROM_NH_HOLDER (nh_holder1);

            printf ("  FH%d:\r\n", tunnel_count);

            printf ("-------------------------------------\r\n");
            fib_dump_nh_node_key (p_fh);

            printf ("  status                   :  %d\r\n",
                    p_tunnel_dr_fh->status);
            printf ("-------------------------------------\r\n");

            tunnel_count++;
        }
    }

    printf ("**************************************************\r\n");
    printf ("  Dep_nh List:\r\n");
    printf ("**************************************************\r\n");

    count = 0;

    FIB_FOR_EACH_DEP_NH_FROM_DR (p_dr, p_nh, nh_holder)
    {
        printf ("  Dep_nh%d:\r\n", count);
        printf ("-------------------------------------\r\n");
        fib_dump_nh_node_key (p_nh);
        printf ("-------------------------------------\r\n");

        count++;
    }

    p_fh = (t_fib_nh *) (p_dr->degen_dr_fh.link_node.self);

    if (p_fh != NULL)
    {
        printf ("**************************************************\r\n");
        printf ("Degen FH:\r\n");
        printf ("**************************************************\r\n");

        fib_dump_nh_node_key (p_fh);

        p_dr_fh = &(p_dr->degen_dr_fh);

        printf ("  status                   :  %d\r\n", p_dr_fh->status);
        printf ("**************************************************\r\n");
    }

    return;
}

void fib_dump_nh_node (t_fib_nh *p_nh, bool dump_dep_dr)
{
    t_fib_nh_dep_dr   *p_nh_dep_dr = NULL;
    t_fib_nh        *p_fh = NULL;
    t_fib_nh_holder  nh_holder;
    uint32_t     count = 0;
    t_fib_tunnel_fh  *p_tunnel_fh = NULL;
    char              p_buf[HAL_RT_MAX_BUFSZ];

    if (!p_nh)
    {
        printf (" NH node NULL\r\n");
        return;
    }

    printf ("**************************************************\r\n");

    fib_dump_nh_node_key (p_nh);

    printf ("  Best_fit DR: \r\n");

    printf ("-------------------------------------\r\n");
    fib_dump_dr_node_key (p_nh->p_best_fit_dr);
    printf ("-------------------------------------\r\n");

    printf ("  num_fh              :  %d\r\n", p_nh->num_fh);

    printf ("**************************************************\r\n");
    printf ("  FH List:\r\n");
    printf ("**************************************************\r\n");

    count = 0;

    FIB_FOR_EACH_FH_FROM_NH (p_nh, p_fh, nh_holder)
    {
        printf ("  FH%d:\r\n", count);

        printf ("-------------------------------------\r\n");
        fib_dump_nh_node_key (p_fh);
        printf ("-------------------------------------\r\n");

        count++;
    }

    if (p_nh->p_arp_info != NULL)
    {
        printf ("**************************************************\r\n");
        printf ("  Arp Info:\r\n");
        printf ("**************************************************\r\n");

        printf ("-------------------------------------\r\n");
        printf ("  vlan_id         :  %d\r\n", p_nh->p_arp_info->vlan_id);
        printf ("  mac_addr        :  %s\r\n",
                hal_rt_mac_to_str (&p_nh->p_arp_info->mac_addr, p_buf, HAL_RT_MAX_BUFSZ));
        printf ("  state          :  %d\r\n", p_nh->p_arp_info->state);
        printf ("  if_index        :  0x%x\r\n", p_nh->p_arp_info->if_index);
        printf ("-------------------------------------\r\n");
    }

    printf ("  owner_flag          :  0x%x\r\n", p_nh->owner_flag);
    printf ("  status_flag         :  0x%x\r\n", p_nh->status_flag);
    printf ("  rtm_ref_count        :  %d\r\n", p_nh->rtm_ref_count);
    printf ("  dr_ref_count         :  %d\r\n", p_nh->dr_ref_count);
    printf ("  nh_ref_count         :  %d\r\n", p_nh->nh_ref_count);
    printf ("  tunnel_nh_ref_count   :  %d\r\n", p_nh->tunnel_nh_ref_count);
    printf ("  arp_last_update_time  :  %ld\r\n", p_nh->arp_last_update_time);
    printf ("  p_hal_nh_handle         :  %p\r\n", p_nh->p_hal_nh_handle);

    if (dump_dep_dr)
    {
        printf ("**************************************************\r\n");
        printf ("  Dep_dr List:\r\n");
        printf ("**************************************************\r\n");

        count = 0;

        p_nh_dep_dr = fib_get_first_nh_dep_dr (p_nh);

        while (p_nh_dep_dr != NULL)
        {
            printf ("  Dep_dr%d:\r\n", count);

            printf ("-------------------------------------\r\n");

            printf ("  vrf_id        :  %d\r\n", p_nh_dep_dr->key.vrf_id);
            printf ("  vrf_name      :  %s\r\n", FIB_GET_VRF_NAME(p_nh_dep_dr->key.vrf_id,
                                                                  p_nh_dep_dr->key.dr_key.prefix.af_index));
            printf ("  af_index      :  %d\r\n",
                    p_nh_dep_dr->key.dr_key.prefix.af_index);
            printf ("  prefix       :  %s\r\n",
                    FIB_IP_ADDR_TO_STR (&p_nh_dep_dr->key.dr_key.prefix));
            printf ("  prefix_len    :  %d\r\n", p_nh_dep_dr->prefix_len);
            printf ("  p_dr          :  %p\r\n", p_nh_dep_dr->p_dr);

            printf ("-------------------------------------\r\n");

            p_nh_dep_dr = fib_get_next_nh_dep_dr (p_nh, p_nh_dep_dr->key.vrf_id,
                                          &p_nh_dep_dr->key.dr_key.prefix,
                                          p_nh_dep_dr->prefix_len);
            count++;
        }
    }

    printf ("**************************************************\r\n");
    printf ("  Tunnel FH List:\r\n");
    printf ("**************************************************\r\n");

    count = 0;

    FIB_FOR_EACH_FH_FROM_TUNNEL_NH (p_nh, p_fh, nh_holder)
    {
        p_tunnel_fh  = FIB_GET_TUNNEL_NHFH_NODE_FROM_NH_HOLDER (nh_holder);

        printf ("  FH%d:\r\n", count);

        printf ("-------------------------------------\r\n");
        fib_dump_nh_node_key (p_fh);

        printf ("  dr_ref_count       :  %d\r\n",
                p_tunnel_fh->dr_ref_count);

        printf ("  is_nh_ref          :  %d\r\n",
                p_tunnel_fh->is_nh_ref);

        count++;
    }

    return;
}

void fib_dump_dr (uint32_t vrf_id, uint32_t in_af_index, uint8_t *p_in_prefix, uint32_t in_prefix_len)
{
    uint8_t          af_index;
    uint8_t          prefix_len;
    t_fib_dr            *p_dr = NULL;
    struct in_addr     fib4_addr;
    struct in6_addr    fib6_addr;
    t_fib_ip_addr         prefix;

    af_index   = (uint8_t) in_af_index;
    prefix_len = (uint8_t) in_prefix_len;

    if (!p_in_prefix)
    {
        printf (" Invalid prefix\r\n");
        return;
    }

    if (!(FIB_IS_VRF_ID_VALID (vrf_id)))
    {
        printf (" Invalid vrf_id. Vrf_id: %d\r\n", vrf_id);
        return;
    }

    if (af_index >= FIB_MAX_AFINDEX)
    {
        printf (" Invalid af_index. Af_index: %d\r\n", af_index);
        return;
    }

    if (!(FIB_IS_PREFIX_LEN_VALID (af_index, prefix_len)))
    {
        printf (" Invalid prefix length\r\n");
        return;
    }

    memset (&prefix, 0, sizeof (t_fib_ip_addr));

    if (STD_IP_IS_AFINDEX_V4 (af_index))
    {
        inet_pton (AF_INET, (char *)p_in_prefix, (void *) &fib4_addr);

        prefix.af_index = HAL_RT_V4_AFINDEX;

        memcpy (&prefix.u.v4_addr, &fib4_addr.s_addr, HAL_RT_V4_ADDR_LEN);
    }
    else
    {
        inet_pton (AF_INET6, (char *)p_in_prefix, (void *) &fib6_addr);

        prefix.af_index = HAL_RT_V6_AFINDEX;

        memcpy (&prefix.u.v6_addr, &fib6_addr.s6_addr, HAL_RT_V6_ADDR_LEN);
    }

    p_dr = fib_get_dr (vrf_id, &prefix, prefix_len);

    if (p_dr == NULL)
    {
        printf (" DR node not found\r\n");
        return;
    }

    printf ("----------------------------------------\r\n");

    fib_dump_dr_node (p_dr);

    printf ("----------------------------------------\r\n");

    return;
}

void fib_dump_dr_per_vrf_per_af (uint32_t vrf_id, uint32_t in_af_index)
{
    uint8_t    af_index;
    t_fib_dr      *p_dr = NULL;
    uint32_t   count = 0;

    af_index = (uint8_t) in_af_index;

    if (!(FIB_IS_VRF_ID_VALID (vrf_id)))
    {
        printf (" Invalid vrf_id. Vrf_id: %d\r\n", vrf_id);
        return;
    }

    if (af_index >= FIB_MAX_AFINDEX)
    {
        printf (" Invalid af_index. Af_index: %d\r\n", af_index);
        return;
    }

    count = 0;

    p_dr = fib_get_first_dr (vrf_id, af_index);

    if (p_dr != NULL)
    {
        printf ("***********************************************\r\n");
        printf ("  Vrf_id: %d, Af_index: %s\r\n", vrf_id, STD_IP_AFINDEX_TO_STR (af_index));
        printf ("***********************************************\r\n");
    }

    while (p_dr != NULL)
    {
        printf ("  DR%d:\r\n", count);
        printf ("----------------------------------------\r\n");

        fib_dump_dr_node (p_dr);

        printf ("----------------------------------------\r\n");

        p_dr = fib_get_next_dr (vrf_id, &p_dr->key.prefix, p_dr->prefix_len);

        count++;
    }

    if (count != 0)
    {
        printf ("***********************************************\r\n");
        printf ("  Vrf_id: %d, Af_index: %s, Count: %d\r\n",
                vrf_id, STD_IP_AFINDEX_TO_STR (af_index), count);
        printf ("***********************************************\r\n");
    }

    return;
}

void fib_dump_dr_per_vrf (uint32_t vrf_id)
{
    uint8_t   af_index = 0;

    if (!(FIB_IS_VRF_ID_VALID (vrf_id)))
    {
        printf (" Invalid vrf_id. Vrf_id: %d\r\n", vrf_id);
        return;
    }

    for (af_index = FIB_MIN_AFINDEX; af_index < FIB_MAX_AFINDEX; af_index++)
    {
        fib_dump_dr_per_vrf_per_af (vrf_id, af_index);
    }

    return;
}

void fib_dump_dr_per_af (uint32_t in_af_index)
{
    uint8_t   af_index;
    uint32_t  vrf_id = 0;

    af_index = (uint8_t) in_af_index;

    for (vrf_id = FIB_MIN_VRF; vrf_id < FIB_MAX_VRF; vrf_id++)
    {
        fib_dump_dr_per_vrf_per_af (vrf_id, af_index);
    }

    return;
}

void fib_dump_all_dr (void)
{
    uint32_t  vrf_id = 0;
    uint8_t   af_index = 0;

    for (vrf_id = FIB_MIN_VRF; vrf_id < FIB_MAX_VRF; vrf_id++)
    {
        for (af_index = FIB_MIN_AFINDEX; af_index < FIB_MAX_AFINDEX; af_index++)
        {
            fib_dump_dr_per_vrf_per_af (vrf_id, af_index);
        }
    }

    return;
}

void fib_dump_nh (uint32_t vrf_id, uint32_t in_af_index, uint8_t *p_in_ip_addr, uint32_t if_index)
{
    uint8_t          af_index;
    t_fib_nh            *p_nh = NULL;
    struct in_addr     fib4_addr;
    struct in6_addr    fib6_addr;
    t_fib_ip_addr         ip_addr;

    af_index = (uint8_t) in_af_index;

    if (!p_in_ip_addr)
    {
        printf (" Invalid ip_addr\r\n");
        return;
    }

    if (!(FIB_IS_VRF_ID_VALID (vrf_id)))
    {
        printf (" Invalid vrf_id. Vrf_id: %d\r\n", vrf_id);
        return;
    }

    if (af_index >= FIB_MAX_AFINDEX)
    {
        printf (" Invalid af_index. Af_index: %d\r\n", af_index);
        return;
    }

    memset (&ip_addr, 0, sizeof (t_fib_ip_addr));

    if (STD_IP_IS_AFINDEX_V4 (af_index))
    {
        inet_pton (AF_INET, (char *)p_in_ip_addr, (void *) &fib4_addr);

        ip_addr.af_index = HAL_RT_V4_AFINDEX;

        memcpy (&ip_addr.u.v4_addr, &fib4_addr.s_addr, HAL_RT_V4_ADDR_LEN);
    }
    else
    {
        inet_pton (AF_INET6, (char *)p_in_ip_addr, (void *) &fib6_addr);

        ip_addr.af_index = HAL_RT_V6_AFINDEX;

        memcpy (&ip_addr.u.v6_addr, &fib6_addr.s6_addr, HAL_RT_V6_ADDR_LEN);
    }

    p_nh = fib_get_nh (vrf_id, &ip_addr, if_index);

    if (p_nh == NULL)
    {
        printf (" NH node not found\r\n");
        return;
    }

    printf ("----------------------------------------\r\n");

    fib_dump_nh_node (p_nh, true);

    printf ("----------------------------------------\r\n");

    return;
}

void fib_dump_nh_per_vrf_per_af (uint32_t vrf_id, uint32_t in_af_index, bool dump_dep_dr)
{
    t_fib_nh      *p_nh = NULL;
    uint32_t   count = 0;
    uint8_t    af_index;

    af_index = (uint8_t) in_af_index;

    if (!(FIB_IS_VRF_ID_VALID (vrf_id)))
    {
        printf (" Invalid vrf_id. Vrf_id: %d\r\n", vrf_id);
        return;
    }

    if (af_index >= FIB_MAX_AFINDEX)
    {
        printf (" Invalid af_index. Af_index: %d\r\n", af_index);
        return;
    }

    count = 0;

    p_nh = fib_get_first_nh (vrf_id, af_index);

    if (p_nh != NULL)
    {
        printf ("***********************************************\r\n");
        printf ("  Vrf_id: %d, Af_index: %s\r\n", vrf_id,
                STD_IP_AFINDEX_TO_STR (af_index));
        printf ("***********************************************\r\n");
    }

    while (p_nh != NULL)
    {
        printf ("  NH%d:\r\n", count);
        printf ("----------------------------------------\r\n");

        fib_dump_nh_node (p_nh, dump_dep_dr);

        printf ("----------------------------------------\r\n");

        p_nh = fib_get_next_nh (vrf_id, &p_nh->key.ip_addr, p_nh->key.if_index);

        count++;
    }

    if (count != 0)
    {
        printf ("***********************************************\r\n");
        printf ("  Vrf_id: %d, Af_index: %s, Count: %d\r\n",
                vrf_id, STD_IP_AFINDEX_TO_STR (af_index), count);
        printf ("***********************************************\r\n");
    }

    return;
}

void fib_dump_nh_per_vrf (uint32_t vrf_id)
{
    uint8_t   af_index = 0;

    if (!(FIB_IS_VRF_ID_VALID (vrf_id)))
    {
        printf (" Invalid vrf_id. Vrf_id: %d\r\n", vrf_id);
        return;
    }

    for (af_index = FIB_MIN_AFINDEX; af_index < FIB_MAX_AFINDEX; af_index++)
    {
        fib_dump_nh_per_vrf_per_af (vrf_id, af_index, true);
    }

    return;
}

void fib_dump_nh_per_af (uint32_t in_af_index)
{
    uint8_t   af_index;
    uint32_t  vrf_id = 0;

    af_index = (uint8_t) in_af_index;

    for (vrf_id = FIB_MIN_VRF; vrf_id < FIB_MAX_VRF; vrf_id++)
    {
        fib_dump_nh_per_vrf_per_af (vrf_id, af_index, true);
    }

    return;
}

void fib_dump_all_nh (void)
{
    uint32_t  vrf_id = 0;
    uint8_t   af_index = 0;

    for (vrf_id = FIB_MIN_VRF; vrf_id < FIB_MAX_VRF; vrf_id++)
    {
        for (af_index = FIB_MIN_AFINDEX; af_index < FIB_MAX_AFINDEX; af_index++)
        {
            fib_dump_nh_per_vrf_per_af (vrf_id, af_index, true);
        }
    }

    return;
}

void fib_dump_intf_node_key (t_fib_intf *p_intf)
{
    if (!p_intf)
    {
        printf (" Intf node NULL\r\n");
        return;
    }

    printf ("  p_intf            :  %p\r\n", p_intf);
    printf ("  if_index          :  %d\r\n", p_intf->key.if_index);
    printf ("  vrf_id            :  %d\r\n", p_intf->key.vrf_id);
    printf ("  vrf_name          :  %s\r\n", FIB_GET_VRF_NAME(p_intf->key.vrf_id,
                                                              p_intf->key.af_index));
    printf ("  af_index          :  %d\r\n", p_intf->key.af_index);
    printf ("  admin             :  %d\r\n", p_intf->admin_status);
    printf ("  if_name           :  %s\r\n", p_intf->if_name);

    return;
}

void fib_dump_intf_node (t_fib_intf *p_intf)
{
    t_fib_nh       *p_fh = NULL;
    t_fib_nh_holder nh_holder;
    uint32_t    count = 0;
    char              p_buf[HAL_RT_MAX_BUFSZ];

    if (!p_intf)
    {
        printf (" Intf node NULL\r\n");
        return;
    }

    printf ("**************************************************\r\n");

    fib_dump_intf_node_key (p_intf);

    printf(" IPv4 unreachable status:%d \r\n", p_intf->is_ipv4_unreachables_set);
    printf(" IPv6 unreachable status:%d \r\n", p_intf->is_ipv6_unreachables_set);
    printf (" mode               :  %s\r\n", hal_rt_intf_mode_to_str(p_intf->mode));
    printf (" MAC address        :  %s\r\n",
            hal_rt_mac_to_str (&p_intf->mac_addr, p_buf, HAL_RT_MAX_BUFSZ));
    printf ("**************************************************\r\n");
    printf ("  FH List:\r\n");
    printf ("**************************************************\r\n");

    count = 0;

    FIB_FOR_EACH_FH_FROM_INTF (p_intf, p_fh, nh_holder)
    {
        printf ("  FH%d:\r\n", count);

        printf ("-------------------------------------\r\n");
        fib_dump_nh_node_key (p_fh);
        printf ("-------------------------------------\r\n");

        count++;
    }

    printf ("**************************************************\r\n");
    printf ("  Pending FH List:\r\n");
    printf ("**************************************************\r\n");

    count = 0;

    FIB_FOR_EACH_PENDING_FH_FROM_INTF (p_intf, p_fh, nh_holder)
    {
        printf ("  FH%d:\r\n", count);

        printf ("-------------------------------------\r\n");
        fib_dump_nh_node_key (p_fh);
        printf ("-------------------------------------\r\n");

        count++;
    }

    t_fib_ip_addr    *p_temp_ip = NULL;
    t_fib_ip_holder  ip_holder;
    printf ("**************************************************\r\n");

    FIB_FOR_EACH_IP_FROM_INTF (p_intf, p_temp_ip, ip_holder)
    {
        printf( "IP address: %s \r\n", FIB_IP_ADDR_TO_STR (p_temp_ip));
    }
    return;
}

void fib_dump_intf (uint32_t if_index, uint32_t vrf_id, uint32_t in_af_index)
{
    uint8_t  af_index;
    t_fib_intf  *p_intf = NULL;

    af_index = (uint8_t) in_af_index;

    if (!(FIB_IS_VRF_ID_VALID (vrf_id)))
    {
        printf (" Invalid vrf_id. Vrf_id: %d\r\n", vrf_id);
        return;
    }

    if (af_index >= FIB_MAX_AFINDEX)
    {
        printf (" Invalid af_index. Af_index: %d\r\n", af_index);
        return;
    }

    p_intf = fib_get_intf (if_index, vrf_id, af_index);

    if (p_intf == NULL)
    {
        printf (" Intf node NULL\r\n");
        return;
    }

    fib_dump_intf_node (p_intf);

    return;
}

void fib_dump_intf_per_if_index (uint32_t if_index)
{
    t_fib_intf     *p_intf = NULL;
    t_fib_intf_key   key;
    uint32_t    count = 0;

    memset (&key, 0, sizeof (t_fib_intf_key));

    key.if_index = if_index;

    p_intf = (t_fib_intf *)
        std_radix_getexact (hal_rt_access_intf_tree(), (uint8_t *)&key, FIB_RDX_INTF_KEY_LEN);

    if (p_intf == NULL)
    {
        p_intf = (t_fib_intf *)
            std_radix_getnext (hal_rt_access_intf_tree(), (uint8_t *)&key, FIB_RDX_INTF_KEY_LEN);
    }

    count = 0;

    while (p_intf != NULL)
    {
        if (p_intf->key.if_index > if_index)
        {
            break;
        }

        printf ("  Intf%d: \r\n", count);
        printf ("---------------------------------------\r\n");
        fib_dump_intf_node (p_intf);
        printf ("---------------------------------------\r\n");

        count++;

        p_intf = (t_fib_intf *)
            std_radix_getnext (hal_rt_access_intf_tree(), (uint8_t *)&p_intf->key, FIB_RDX_INTF_KEY_LEN);
    }

    if (count != 0)
    {
        printf ("************************************************\r\n");
        printf ("  If_index: 0x%x, Count: %d\r\n", if_index, count);
        printf ("************************************************\r\n");
    }
    return;
}

void fib_dump_intf_per_if_index_per_vrf (uint32_t if_index, uint32_t vrf_id)
{
    t_fib_intf     *p_intf = NULL;
    t_fib_intf_key   key;
    uint32_t    count = 0;

    memset (&key, 0, sizeof (t_fib_intf_key));

    key.if_index = if_index;
    key.vrf_id   = vrf_id;

    p_intf = (t_fib_intf *)
        std_radix_getnext (hal_rt_access_intf_tree(), (uint8_t *)&key, FIB_RDX_INTF_KEY_LEN);

    count = 0;

    while (p_intf != NULL)
    {
        if (p_intf->key.vrf_id > vrf_id)
        {
            break;
        }

        if (p_intf->key.if_index > if_index)
        {
            break;
        }

        printf ("  Intf%d: \r\n", count);
        printf ("---------------------------------------\r\n");
        fib_dump_intf_node (p_intf);
        printf ("---------------------------------------\r\n");

        count++;

        p_intf = (t_fib_intf *)
            std_radix_getnext (hal_rt_access_intf_tree(), (uint8_t *)&key, FIB_RDX_INTF_KEY_LEN);
    }

    if (count != 0)
    {
        printf ("************************************************\r\n");
        printf ("  If_index: 0x%x, Vrf_id: %d, Count: %d\r\n",
                if_index, vrf_id, count);
        printf ("************************************************\r\n");
    }

    return;
}

void fib_dump_all_intf (void)
{
    t_fib_intf     *p_intf = NULL;
    t_fib_intf_key   key;
    uint32_t    count = 0;

    memset (&key, 0, sizeof (t_fib_intf_key));

    p_intf = (t_fib_intf *)
        std_radix_getnext (hal_rt_access_intf_tree(), (uint8_t *)&key, FIB_RDX_INTF_KEY_LEN);

    count = 0;

    while (p_intf != NULL)
    {
        printf ("  Intf%d: \r\n", count);
        printf ("---------------------------------------\r\n");
        fib_dump_intf_node (p_intf);
        memcpy(&key, &(p_intf->key), sizeof (t_fib_intf_key));
        printf ("---------------------------------------\r\n");

        count++;

        p_intf = (t_fib_intf *)
            std_radix_getnext (hal_rt_access_intf_tree(), (uint8_t *)&key, FIB_RDX_INTF_KEY_LEN);
    }

    if (count != 0)
    {
        printf ("************************************************\r\n");
        printf ("  Count: %d\r\n", count);
        printf ("************************************************\r\n");
    }

    return;
}

void fib_dump_route_summary_per_vrf_per_af (uint32_t vrf_id,
                                     uint32_t in_af_index)
{
    t_fib_route_summary   *p_route_summary = NULL;
    uint8_t           af_index;
    uint8_t           prefix_len = 0;
    bool            print_header = false;

    af_index = (uint8_t) in_af_index;

    if (!(FIB_IS_VRF_ID_VALID (vrf_id)))
    {
        printf (" Invalid vrf_id. Vrf_id: %d\r\n", vrf_id);
        return;
    }

    if (af_index >= FIB_MAX_AFINDEX)
    {
        printf (" Invalid af_index. Af_index: %d\r\n", af_index);
        return;
    }

    p_route_summary = FIB_GET_ROUTE_SUMMARY (vrf_id, af_index);

    if (p_route_summary == NULL)
    {
        printf (" Route summary NULL\r\n");
        return;
    }

    print_header = true;

    for (prefix_len = 0; prefix_len <= HAL_RT_V6_PREFIX_LEN; prefix_len++)
    {
        if ((p_route_summary->a_curr_count [prefix_len]) != 0)
        {
            if (print_header == true)
            {
                printf ("***********************************************\r\n");
                printf ("  Vrf_id: %d, Af_index: %s\r\n", vrf_id, STD_IP_AFINDEX_TO_STR (af_index));
                printf ("***********************************************\r\n");

                print_header = false;
            }

            printf ("----------------------------------------------\r\n");
            printf ("  prefix_len                  :  %d\r\n", prefix_len);
            printf ("  a_curr_count                 :  %d\r\n",
                    p_route_summary->a_curr_count [prefix_len]);
            printf ("----------------------------------------------\r\n");
        }
    }

    printf ("**************************************************\r\n");

    return;
}

void fib_dump_route_summary_per_vrf (uint32_t vrf_id)
{
    uint8_t  af_index = 0;

    if (!(FIB_IS_VRF_ID_VALID (vrf_id)))
    {
        printf (" Invalid vrf_id. Vrf_id: %d\r\n", vrf_id);
        return;
    }

    for (af_index = FIB_MIN_AFINDEX; af_index < FIB_MAX_AFINDEX; af_index++)
    {
        fib_dump_route_summary_per_vrf_per_af (vrf_id, af_index);
    }

    return;
}

void fib_dump_route_summary_per_af (uint32_t in_af_index)
{
    uint8_t   af_index;
    uint32_t  vrf_id = 0;

    af_index = (uint8_t) in_af_index;

    for (vrf_id = FIB_MIN_VRF; vrf_id < FIB_MAX_VRF; vrf_id++)
    {
        fib_dump_nh_per_vrf_per_af (vrf_id, af_index, true);
    }

    return;
}

void fib_dump_all_route_summary (void)
{
    uint32_t  vrf_id = 0;
    uint8_t   af_index = 0;

    for (vrf_id = FIB_MIN_VRF; vrf_id < FIB_MAX_VRF; vrf_id++)
    {
        for (af_index = FIB_MIN_AFINDEX; af_index < FIB_MAX_AFINDEX; af_index++)
        {
            fib_dump_route_summary_per_vrf_per_af (vrf_id, af_index);
        }
    }

    return;
}

void fib_dump_vrf_cntrs_per_vrf_per_af (uint32_t vrf_id, uint32_t in_af_index)
{
    uint8_t      af_index;
    t_fib_vrf_cntrs  *p_vrf_cntrs = NULL;

    af_index = (uint8_t) in_af_index;

    if (!(FIB_IS_VRF_ID_VALID (vrf_id)))
    {
        printf (" Invalid vrf_id. Vrf_id: %d\r\n", vrf_id);
        return;
    }

    if (af_index >= FIB_MAX_AFINDEX)
    {
        printf (" Invalid af_index. Af_index: %d\r\n", af_index);
        return;
    }

    p_vrf_cntrs = hal_rt_access_fib_vrf_cntrs(vrf_id, af_index);

    if (p_vrf_cntrs == NULL)
    {
        printf (" Vrf counters NULL\r\n");
        return;
    }

    printf ("***********************************************\r\n");
    printf ("  Vrf_id: %d, Af_index: %s\r\n", vrf_id, STD_IP_AFINDEX_TO_STR (af_index));
    printf ("***********************************************\r\n");

    printf ("  num_route_add            :  %d\r\n", p_vrf_cntrs->num_route_add);
    printf ("  num_route_del            :  %d\r\n", p_vrf_cntrs->num_route_del);
    printf ("  num_vrf_add              :  %d\r\n", p_vrf_cntrs->num_vrf_add);
    printf ("  num_vrf_del              :  %d\r\n", p_vrf_cntrs->num_vrf_del);
    printf ("  num_route_clear          :  %d\r\n", p_vrf_cntrs->num_route_clear);
    printf ("  num_unknown_msg          :  %d\r\n", p_vrf_cntrs->num_unknown_msg);
    printf ("  num_nbr_add              :  %d\r\n", p_vrf_cntrs->num_nbr_add);
    printf ("  num_nbr_add_incomplete   :  %d\r\n", p_vrf_cntrs->num_nbr_add_incomplete);
    printf ("  num_nbr_add_reachable    :  %d\r\n", p_vrf_cntrs->num_nbr_add_reachable);
    printf ("  num_nbr_add_stale        :  %d\r\n", p_vrf_cntrs->num_nbr_add_stale);
    printf ("  num_nbr_add_delay        :  %d\r\n", p_vrf_cntrs->num_nbr_add_delay);
    printf ("  num_nbr_add_probe        :  %d\r\n", p_vrf_cntrs->num_nbr_add_probe);
    printf ("  num_nbr_add_failed       :  %d\r\n", p_vrf_cntrs->num_nbr_add_failed);
    printf ("  num_nbr_add_permanent    :  %d\r\n", p_vrf_cntrs->num_nbr_add_permanent);
    printf ("  num_nbr_del              :  %d\r\n", p_vrf_cntrs->num_nbr_del);
    printf ("  num_nbr_resolving        :  %d\r\n", p_vrf_cntrs->num_nbr_resolving);
    printf ("  num_nbr_un_rslvd         :  %d\r\n", p_vrf_cntrs->num_nbr_un_rslvd);
    printf ("  num_nbr_clear            :  %d\r\n", p_vrf_cntrs->num_nbr_clear);
    printf ("  num_fib_host_entries     :  %d\r\n", p_vrf_cntrs->num_fib_host_entries);
    printf ("  num_fib_route_entries    :  %d\r\n", p_vrf_cntrs->num_fib_route_entries);
    printf ("  num_cam_host_entries     :  %d\r\n", p_vrf_cntrs->num_cam_host_entries);
    printf ("  num_cam_route_entries    :  %d\r\n", p_vrf_cntrs->num_cam_route_entries);
    printf ("  num_nht_entries          :  %d\r\n", p_vrf_cntrs->num_nht_entries);
    printf ("  num_catch_all_intf_entries:  %d\r\n", p_vrf_cntrs->num_catch_all_intf_entries);

    printf ("**************************************************\r\n");

    return;
}

void fib_dump_vrf_cntrs_per_vrf (uint32_t vrf_id)
{
    uint8_t   af_index = 0;

    if (!(FIB_IS_VRF_ID_VALID (vrf_id)))
    {
        printf (" Invalid vrf_id. Vrf_id: %d\r\n", vrf_id);
        return;
    }

    for (af_index = FIB_MIN_AFINDEX; af_index < FIB_MAX_AFINDEX; af_index++)
    {
        fib_dump_vrf_cntrs_per_vrf_per_af (vrf_id, af_index);
    }

    return;
}

void fib_dump_vrf_cntrs_per_af (uint32_t in_af_index)
{
    uint8_t   af_index;
    uint32_t  vrf_id = 0;

    af_index = (uint8_t) in_af_index;

    for (vrf_id = FIB_MIN_VRF; vrf_id < FIB_MAX_VRF; vrf_id++)
    {
        fib_dump_vrf_cntrs_per_vrf_per_af (vrf_id, af_index);
    }

    return;
}

void fib_dump_all_vrf_cntrs (void)
{
    uint32_t  vrf_id = 0;
    uint8_t   af_index = 0;

    for (vrf_id = FIB_MIN_VRF; vrf_id < FIB_MAX_VRF; vrf_id++)
    {
        for (af_index = FIB_MIN_AFINDEX; af_index < FIB_MAX_AFINDEX; af_index++)
        {
            fib_dump_vrf_cntrs_per_vrf_per_af (vrf_id, af_index);
        }
    }

    return;
}

void fib_dump_all_cntrs (void)
{

    printf ("**************************************************\r\n");
    printf ("             Vrf Counters                         \r\n");
    printf ("**************************************************\r\n");

    fib_dump_all_vrf_cntrs ();

    printf ("**************************************************\r\n");

    return;
}

void fib_dump_all_db (void)
{
    printf ("**************************************************\r\n");
    printf ("              Config                              \r\n");
    printf ("**************************************************\r\n");

    fib_dump_config();
    fib_dump_gbl_info();

    printf ("**************************************************\r\n");
    printf ("              DR Database                         \r\n");
    printf ("**************************************************\r\n");

    fib_dump_all_dr ();

    printf ("**************************************************\r\n");
    printf ("              NH Database                         \r\n");
    printf ("**************************************************\r\n");

    fib_dump_all_nh ();

    printf ("**************************************************\r\n");
    printf ("              Route Summary                       \r\n");
    printf ("**************************************************\r\n");

    fib_dump_all_route_summary ();

    printf ("**************************************************\r\n");
    printf ("             Counters                             \r\n");
    printf ("**************************************************\r\n");

    fib_dump_all_cntrs ();

    return;
}

void fib_dbg_clear_vrf_cntrs_per_vrf_per_af (uint32_t vrf_id, uint32_t in_af_index)
{
    t_fib_vrf_cntrs  *p_vrf_cntrs = NULL;
    uint8_t      af_index;

    af_index = (uint8_t) in_af_index;

    if (!(FIB_IS_VRF_ID_VALID (vrf_id)))
    {
        printf (" Invalid vrf_id. Vrf_id: %d\r\n", vrf_id);
        return;
    }

    if (af_index >= FIB_MAX_AFINDEX)
    {
        printf (" Invalid af_index. Af_index: %d\r\n", af_index);
        return;
    }

    p_vrf_cntrs = hal_rt_access_fib_vrf_cntrs(vrf_id, af_index);

    if (p_vrf_cntrs == NULL)
    {
        printf (" Vrf counters NULL\r\n");
        return;
    }

    memset (p_vrf_cntrs, 0, sizeof (t_fib_vrf_cntrs));

    return;
}

void fib_dbg_clear_vrf_cntrs_per_vrf (uint32_t vrf_id)
{
    uint8_t   af_index = 0;

    if (!(FIB_IS_VRF_ID_VALID (vrf_id)))
    {
        printf (" Invalid vrf_id. Vrf_id: %d\r\n", vrf_id);
        return;
    }

    for (af_index = FIB_MIN_AFINDEX; af_index < FIB_MAX_AFINDEX; af_index++)
    {
        fib_dbg_clear_vrf_cntrs_per_vrf_per_af (vrf_id, af_index);
    }

    return;
}

void fib_dbg_clear_vrf_cntrs_per_af (uint32_t in_af_index)
{
    uint32_t  vrf_id = 0;
    uint8_t   af_index;

    af_index = (uint8_t) in_af_index;

    for (vrf_id = FIB_MIN_VRF; vrf_id < FIB_MAX_VRF; vrf_id++)
    {
        fib_dbg_clear_vrf_cntrs_per_vrf_per_af (vrf_id, af_index);
    }

    return;
}

void fib_dbg_clear_all_vrf_cntrs (void)
{
    uint32_t  vrf_id = 0;
    uint8_t   af_index = 0;

    for (vrf_id = FIB_MIN_VRF; vrf_id < FIB_MAX_VRF; vrf_id++)
    {
        for (af_index = FIB_MIN_AFINDEX; af_index < FIB_MAX_AFINDEX; af_index++)
        {
            fib_dbg_clear_vrf_cntrs_per_vrf_per_af (vrf_id, af_index);
        }
    }

    return;
}

void fib_dbg_clear_all_cntrs (void)
{
    fib_dbg_clear_all_vrf_cntrs ();

    return;
}

void fib_dump_nht(int vrf_id, int af_index, char *p_dest_addr)
{
    t_fib_ip_addr ip_addr;
    t_fib_nht *p_nht = NULL;
    struct in_addr     fib4_addr;
    struct in6_addr    fib6_addr;

    if (!(FIB_IS_VRF_ID_VALID (vrf_id)))
    {
        printf (" Invalid vrf_id. Vrf_id: %d\r\n", vrf_id);
        return;
    }

    if (af_index >= FIB_MAX_AFINDEX)
    {
        printf (" Invalid af_index. Af_index: %d should be IPv4-2, IPv6-10\r\n", af_index);
        return;
    }

    if (p_dest_addr != NULL) {
        memset (&ip_addr, 0, sizeof (t_fib_ip_addr));
        if (STD_IP_IS_AFINDEX_V4 (af_index))
        {
            inet_pton (AF_INET, (char *)p_dest_addr, (void *) &fib4_addr);

            ip_addr.af_index = HAL_RT_V4_AFINDEX;

            memcpy (&ip_addr.u.v4_addr, &fib4_addr.s_addr, HAL_RT_V4_ADDR_LEN);
        }
        else
        {
            inet_pton (AF_INET6, (char *)p_dest_addr, (void *) &fib6_addr);

            ip_addr.af_index = HAL_RT_V6_AFINDEX;

            memcpy (&ip_addr.u.v6_addr, &fib6_addr.s6_addr, HAL_RT_V6_ADDR_LEN);
        }

        p_nht = fib_get_nht (vrf_id, &ip_addr);
    } else {
        p_nht = fib_get_first_nht(vrf_id, af_index);
    }

    while (p_nht != NULL) {
        printf(" vrf_id: %d, af: %d, dest: %s fib-match:%s/%d ref-cnt:%d\r\n",
               vrf_id, af_index, FIB_IP_ADDR_TO_STR (&(p_nht->key.dest_addr)),
               FIB_IP_ADDR_TO_STR(&(p_nht->fib_match_dest_addr)), p_nht->prefix_len, p_nht->ref_count);

        if (p_dest_addr != NULL) break;
        p_nht = fib_get_next_nht (vrf_id, &p_nht->key.dest_addr);
    }
    return;
}

void fib_dump_all_rif ()
{
    uint32_t       count = 0;

    printf ("%-5s %-5s %-15s %-5s %-15s %-32s\r\n", "VRF Id", "Intf", "RIF Id", "Ref count", "Intf name", "VRF name");
    printf ("****************************************************************************************\r\n");
    t_fib_intf *p_intf = fib_get_next_intf(0, 0, 0);
    while (p_intf != NULL) {
        if (p_intf->key.af_index == HAL_RT_V4_AFINDEX) {
            printf ("%-5d %-5d %-15lx %-5d %-15s %-32s\r\n", p_intf->key.vrf_id, p_intf->key.if_index,
                    p_intf->rif_info.rif_id,  p_intf->rif_info.ref_count, p_intf->if_name,
                    FIB_GET_VRF_NAME(p_intf->key.vrf_id, p_intf->key.af_index));
            if (p_intf->rif_info.rif_id)
                count++;
        }
        p_intf = fib_get_next_intf (p_intf->key.if_index,
                                    p_intf->key.vrf_id, p_intf->key.af_index);
    }

    if (count != 0)
    {
        printf ("************************************************\r\n");
        printf ("  Total RIF Count: %d\r\n", count);
        printf ("************************************************\r\n");
    }
    return;
}

void fib_dump_intf_rif (uint32_t vrf_id, uint32_t if_index)
{
    uint32_t      ref_count = 0;
    ndi_rif_id_t  rif_id = 0;

    if (hal_rif_info_get (vrf_id, if_index, &rif_id, &ref_count) == STD_ERR_OK) {
        printf ("%-10s %-10s %-10s\r\n", "Intf", "RIF Id", "Ref count");
        printf ("*********************************************************\r\n");
        printf ("%-10d %-10lx %-10d\r\n", if_index, (long int) rif_id, ref_count);
    }
    return;
}

void fib_dump_mp_obj_node (t_fib_mp_obj *p_mp_obj, int add_indendation)
{
    int   index;
    char *p_indent_str = "";
    char *p_nh_obj_indent_str = HAL_RT_3_SPACE_INDENT;

    if (add_indendation)
        p_indent_str= HAL_RT_17_SPACE_INDENT;

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

void fib_dump_mp_info_per_vrf_per_af (uint32_t vrf_id, uint32_t af_index)
{
    t_fib_mp_md5_node_key  key;
    t_fib_mp_md5_node    *p_mp_md5_node;
    std_rt_head          *p_rt_head;

    if (!(FIB_IS_VRF_ID_VALID (vrf_id)))
    {
        return;
    }

    if (af_index >= FIB_MAX_AFINDEX)
    {
        return;
    }

    if (hal_rt_access_fib_vrf_mp_md5_tree (vrf_id, af_index) == NULL)
    {
        return;
    }

    memset(&key, 0, sizeof(key));

    p_rt_head = std_radix_getnext (hal_rt_access_fib_vrf_mp_md5_tree(vrf_id,
                af_index), (uint8_t *) &key,
            HAL_RT_MP_MD5_NODE_TREE_KEY_SIZE);

    while(p_rt_head) {
        p_mp_md5_node = (t_fib_mp_md5_node *) p_rt_head;

        fib_dump_mp_md5_node (p_mp_md5_node, true);

        memcpy(&key, &(p_mp_md5_node->key), sizeof(t_fib_mp_md5_node_key));
        p_rt_head = std_radix_getnext (hal_rt_access_fib_vrf_mp_md5_tree(vrf_id,
                    af_index), (uint8_t *) &key,
                HAL_RT_MP_MD5_NODE_TREE_KEY_SIZE);
    }

    return;
}

void fib_dump_all_mp_info ()
{
    uint32_t  vrf_id = 0;
    uint8_t   af_index = 0;

    for (vrf_id = FIB_MIN_VRF; vrf_id < FIB_MAX_VRF; vrf_id++)
    {
        for (af_index = FIB_MIN_AFINDEX; af_index < FIB_MAX_AFINDEX; af_index++)
        {
            fib_dump_mp_info_per_vrf_per_af (vrf_id, af_index);
        }
    }

    return;
}

static void nas_rt_shell_debug_counters_help(void)
{
    printf("::nas-rt-debug counters all\r\n");
    printf("\t- Dumps the nas-rt all counters\r\n");
    printf("::nas-rt-debug counters <vrf-id> [af-id]\r\n");
    printf("\t- Dumps nas-rt VRF counters for given vrf/af\r\n");
    printf("::nas-rt-debug counters clear\r\n");
    printf("\t- Clears all nas-rt VRF counters\r\n");
    return;
}

static void nas_rt_shell_debug_counters (std_parsed_string_t handle)
{
    size_t ix=1;
    const char *token = NULL;

    if((token = std_parse_string_next(handle,&ix))!= NULL) {
        if(!strcmp(token,"help")) {
            nas_rt_shell_debug_counters_help();
        } else if(!strcmp(token,"all")) {
            fib_dump_all_cntrs();
        } else if(!strcmp(token,"clear")) {
            fib_dbg_clear_all_cntrs();
        } else if(NULL != token) {
            uint32_t vrf_id = strtol(token,NULL,0);
            token = std_parse_string_next(handle,&ix);

            if(NULL != token) {
                uint8_t af_index = strtol(token,NULL,0);
                fib_dump_vrf_cntrs_per_vrf_per_af (vrf_id, af_index);
            } else {
                fib_dump_vrf_cntrs_per_vrf (vrf_id);
            }
        }
    } else {
        nas_rt_shell_debug_counters_help();
    }
    return;
}

static void nas_rt_shell_debug_intf_help(void)
{
    printf("::nas-rt-debug intf all\r\n");
    printf("\t- Dumps the nas-rt all interfaces\r\n");
    printf("::nas-rt-debug intf <if-index>\r\n");
    printf("\t- Dumps nas-rt interface for given if-index\r\n");
    return;
}

static void nas_rt_shell_debug_intf (std_parsed_string_t handle)
{
    size_t ix=1;
    const char *token = NULL;

    if((token = std_parse_string_next(handle,&ix))!= NULL) {
        if(!strcmp(token,"help")) {
            nas_rt_shell_debug_intf_help();
        } else if(!strcmp(token,"all")) {
            fib_dump_all_intf();
        } else if(NULL != token) {
            uint32_t if_index = strtol(token,NULL,0);
            fib_dump_intf_per_if_index (if_index);
        }
    } else {
        nas_rt_shell_debug_intf_help();
    }
    return;
}

static void nas_rt_shell_debug_vrf_help(void)
{
    printf("::nas-rt-debug vrf all\r\n");
    printf("\t- Dumps the nas-rt all vrf's\r\n");
    printf("::nas-rt-debug vrf <vrf-id> [af-id]\r\n");
    printf("\t- Dumps nas-rt VRF info for given vrf/af\r\n");
    return;
}

static void nas_rt_shell_debug_vrf(std_parsed_string_t handle)
{
    size_t ix=1;
    const char *token = NULL;

    if((token = std_parse_string_next(handle,&ix))!= NULL) {
        if(!strcmp(token,"help")) {
            nas_rt_shell_debug_vrf_help();
        } else if(!strcmp(token,"all")) {
            fib_dump_all_vrf_info();
        } else if(NULL != token) {
            uint32_t vrf_id = strtol(token,NULL,0);
            token = std_parse_string_next(handle,&ix);

            if(NULL != token) {
                uint8_t af_index = strtol(token,NULL,0);
                fib_dump_vrf_info_per_vrf_per_af (vrf_id, af_index);
            } else {
                fib_dump_vrf_info_per_vrf(vrf_id);
            }
        }
    } else {
        nas_rt_shell_debug_vrf_help();
    }
    return;
}

static void nas_rt_shell_debug_dr_help(void)
{
    printf("::nas-rt-debug dr all\r\n");
    printf("\t- Dumps the nas-rt all dr's\r\n");
    printf("::nas-rt-debug dr <vrf-id> [af-id] [prefix-string] [prefix-len]\r\n");
    printf("\t- Dumps nas-rt DR info for given vrf/af/prefix/prefix-len\r\n");
    return;
}

static void nas_rt_shell_debug_dr(std_parsed_string_t handle)
{
    size_t ix=1;
    const char *token = NULL;
    const char *token2 = NULL;

    if((token = std_parse_string_next(handle,&ix))!= NULL) {
        if(!strcmp(token,"help")) {
            nas_rt_shell_debug_dr_help();
        } else if(!strcmp(token,"all")) {
            fib_dump_all_dr();
        } else if(NULL != token) {
            uint32_t vrf_id = strtol(token,NULL,0);
            token = std_parse_string_next(handle,&ix);
            if(NULL != token) {
                uint32_t af_index = strtol(token,NULL,0);
                token = std_parse_string_next(handle,&ix);
                if((NULL != token) &&
                   ((token2 = std_parse_string_next(handle,&ix)) != NULL)) {
                    uint32_t pref_len = strtol(token2,NULL,0);
                    fib_dump_dr (vrf_id, af_index, (uint8_t *) token, pref_len);
                } else {
                    fib_dump_dr_per_vrf_per_af (vrf_id, af_index);
                }
            } else {
               fib_dump_dr_per_vrf(vrf_id);
            }
        }
    } else {
        nas_rt_shell_debug_dr_help();
    }
    return;
}

static void nas_rt_shell_debug_nh_help(void)
{
    printf("::nas-rt-debug nh all\r\n");
    printf("\t- Dumps the nas-rt all nh's\r\n");
    printf("::nas-rt-debug nh <vrf-id> [af-id] [NH-ipaddr] [NH-ifindex] [dump-dep-dr]\r\n");
    printf("\t- Dumps nas-rt NH info for given vrf/af/ip-addr/ifindex\r\n");
    return;
}

static void nas_rt_shell_debug_nh(std_parsed_string_t handle)
{
    size_t ix=1;
    const char *token = NULL;
    const char *token2 = NULL;

    if((token = std_parse_string_next(handle,&ix))!= NULL) {
        if(!strcmp(token,"help")) {
            nas_rt_shell_debug_nh_help();
        } else if(!strcmp(token,"all")) {
            fib_dump_all_nh();
        } else if(NULL != token) {
            uint32_t vrf_id = strtol(token,NULL,0);
            token = std_parse_string_next(handle,&ix);
            if(NULL != token) {
                uint32_t af_index = strtol(token,NULL,0);
                token = std_parse_string_next(handle,&ix);
                if((NULL != token) &&
                   ((token2 = std_parse_string_next(handle,&ix)) != NULL)) {
                    if(!strcmp(token2,"dump-dep-dr")) {
                        fib_dump_nh_per_vrf_per_af (vrf_id, af_index, true);
                    } else {
                        uint32_t if_index = strtol(token2,NULL,0);
                        fib_dump_nh (vrf_id, af_index, (uint8_t *) token, if_index);
                    }
                } else {
                    fib_dump_nh_per_vrf_per_af (vrf_id, af_index, false);
                }
            } else {
               fib_dump_nh_per_vrf (vrf_id);
            }
        }
    } else {
        nas_rt_shell_debug_nh_help();
    }
    return;
}


static void nas_rt_shell_debug_rif_help(void)
{
    printf("::nas-rt-debug rif all\r\n");
    printf("\t- Dumps all nas-rt rif information\r\n");
    printf("::nas-rt-debug rif <if-index>\r\n");
    printf("\t- Dumps nas-rt rif information for given if-index\r\n");
    return;
}

static void nas_rt_shell_debug_rif (std_parsed_string_t handle)
{
    size_t ix=1;
    const char *token = NULL;

    if((token = std_parse_string_next(handle,&ix))!= NULL) {
        if(!strcmp(token,"help")) {
            nas_rt_shell_debug_rif_help();
        } else if(!strcmp(token,"all")) {
            fib_dump_all_rif ();
        } else if(NULL != token) {
            uint32_t if_index = strtol(token,NULL,0);
            fib_dump_intf_rif (0, if_index);
        }
    } else {
        nas_rt_shell_debug_rif_help();
    }
    return;
}

static void nas_rt_shell_debug_multipath_help(void)
{
    printf("::nas-rt-debug multipath all\r\n");
    printf("\t- Dumps all nas-rt multipath information\r\n");
    printf("::nas-rt-debug multipath <vrf-id> <af-id>\r\n");
    printf("\t- Dumps nas-rt multipath info for given vrf and af\r\n");
    return;
}

static void nas_rt_shell_debug_multipath (std_parsed_string_t handle)
{
    size_t ix=1;
    const char *token = NULL;
    bool print_help = true;

    if((token = std_parse_string_next(handle,&ix))!= NULL) {
        if(!strcmp(token,"all")) {
            fib_dump_all_mp_info ();
            print_help = false;
        } else if(NULL != token) {
            uint32_t vrf_id = strtol(token,NULL,0);
            token = std_parse_string_next(handle,&ix);
            if(NULL != token) {
                uint32_t af_index = strtol(token,NULL,0);
                fib_dump_mp_info_per_vrf_per_af (vrf_id, af_index);
                print_help = false;
            }
        }
    }
    if (print_help) {
        nas_rt_shell_debug_multipath_help();
    }
    return;
}


/*Dump nas routing module info*/
static void nas_rt_shell_debug_help(void)
{
    printf("::nas-rt-debug config\r\n");
    printf("\t- Config dump\r\n");
    printf("::nas-rt-debug global-info\r\n");
    printf("\t- Global info dump\r\n");
    printf("::nas-rt-debug counters\r\n");
    printf("\t- Counter module commands\r\n");
    printf("::nas-rt-debug intf\r\n");
    printf("\t- Intf module commands\r\n");
    printf("::nas-rt-debug vrf\r\n");
    printf("\t- Vrf module commands\r\n");
    printf("::nas-rt-debug dr\r\n");
    printf("\t- Route module commands\r\n");
    printf("::nas-rt-debug nh\r\n");
    printf("\t- NH module commands\r\n");
    printf("::nas-rt-debug rif\r\n");
    printf("\t- RIF module commands\r\n");
    printf("::nas-rt-debug multipath\r\n");
    printf("\t- Multipath module commands\r\n");

    return;
}

void nas_rt_shell_dbg (std_parsed_string_t handle)
{
   const char *token = NULL;

    if((token = std_parse_string_at(handle,0)) != NULL) {
        if(!strcmp(token,"help")) {
            nas_rt_shell_debug_help();
        } else if(!strcmp(token,"config")) {
            fib_dump_config();
        } else if(!strcmp(token,"global-info")) {
            fib_dump_gbl_info();
        } else if(!strcmp(token,"counters")) {
            nas_rt_shell_debug_counters(handle);
        } else if(!strcmp(token,"intf")) {
            nas_rt_shell_debug_intf(handle);
        } else if(!strcmp(token,"vrf")) {
            nas_rt_shell_debug_vrf(handle);
        } else if(!strcmp(token,"dr")) {
            nas_rt_shell_debug_dr(handle);
        } else if(!strcmp(token,"nh")) {
            nas_rt_shell_debug_nh(handle);
        } else if(!strcmp(token,"rif")) {
            nas_rt_shell_debug_rif(handle);
        } else if(!strcmp(token,"multipath")) {
            nas_rt_shell_debug_multipath(handle);
        } else {
            nas_rt_shell_debug_help();
        }
    } else {
        nas_rt_shell_debug_help();
    }

    return;
}

/*Initialize the debug command*/
void nas_rt_shell_debug_command_init (void) {
    hal_shell_cmd_add("nas-rt-debug",nas_rt_shell_dbg,
                      "nas-rt-debug <type> <params> ...");
}
