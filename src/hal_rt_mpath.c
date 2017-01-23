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
 * \file   hal_rt_mpath.c
 * \brief NAS Routing - ECMP functions(add, modify, delte)
 * \date   04-2014
 * \author Satish Mynam
 */

#include "hal_rt_main.h"
#include "hal_rt_route.h"
#include "hal_rt_util.h"
#include "hal_rt_api.h"
#include "hal_rt_mpath_grp.h"
#include "std_error_codes.h"
#include "nas_ndi_route.h"
#include "nas_ndi_router_interface.h"

#include "event_log.h"
#include "std_ip_utils.h"
#include <stdio.h>
#include <string.h>

/*
 * Enable ECMP based on CPS/CLI later
 */
static bool ecmp_enabled = true;

bool hal_rt_is_ecmp_enabled() {
    return ecmp_enabled;
}

void hal_form_ecmp_route_entry(ndi_nh_group_t *p_route_entry, t_fib_dr *p_dr) {
    if (p_dr->key.prefix.af_index == HAL_RT_V4_AFINDEX) {
        memcpy(&(p_route_entry->prefix.u.v4_addr),
                &(p_dr->key.prefix.u.v4_addr), HAL_RT_V4_ADDR_LEN);
    } else {
        memcpy(&(p_route_entry->prefix.u.v6_addr),
                &(p_dr->key.prefix.u.v6_addr), HAL_RT_V6_ADDR_LEN);
    }
    p_route_entry->prefix.af_index = p_dr->key.prefix.af_index;
    p_route_entry->mask_len = p_dr->prefix_len;
    /*
     *  Set default ECMP mode
     */
    p_route_entry->group_type = NDI_ROUTE_NH_GROUP_TYPE_ECMP;

}

void hal_rt_format_nh_list(next_hop_id_t nh_list[],  int count, char *buf, int s_buf)
{
    char buf1[s_buf];
       char *ptr, *sptr;
       int len, i;

       memset(buf, ' ', s_buf);
       buf[0] = '\0';
       ptr = &buf[0];
       sptr = ptr;

       for (i = 0; i < count; i++) {
           memset(buf1, ' ', sizeof(buf1));
           len = snprintf(buf1, HAL_RT_MAX_BUFSZ, "%d ", (int)nh_list[i]);

           if ((ptr-sptr + len) >= s_buf)
               break;
           strncat(ptr, buf1, len);
           ptr += len;
        }
}

 void hal_dump_ecmp_route_entry(ndi_nh_group_t *p_route_entry) {
    size_t i;
    char buf[HAL_RT_MAX_BUFSZ * 10];
    next_hop_id_t  nh_list[HAL_RT_MAX_ECMP_PATH];

    for (i=0; i<p_route_entry->nhop_count; i++) {
        nh_list[i] = p_route_entry->nh_list[i].id;
    }

    hal_rt_format_nh_list(nh_list, p_route_entry->nhop_count, buf, HAL_RT_MAX_BUFSZ * 10);

    HAL_RT_LOG_DEBUG("HAL-RT-NDI",
            "NH Group: VRF %d. Prefix: " "%s/%d flags 0x%x group type %d "
            "nh_group_handle %d npu_id %d ecmp_count %d, next_hop_id_list hal_rt_format_nh_list: %s\r\n",
            p_route_entry->vrf_id, FIB_IP_ADDR_TO_STR(&(p_route_entry->prefix)),
            p_route_entry->mask_len, p_route_entry->flags,
            p_route_entry->group_type, p_route_entry->nh_group_handle,
            p_route_entry->npu_id, p_route_entry->nhop_count, buf);

}

dn_hal_route_err hal_fib_ecmp_route_add(uint32_t vrf_id, t_fib_dr *p_dr)
{
    next_hop_id_t nh_handle = 0;
    next_hop_id_t nh_group_handle = 0;
    npu_id_t npu_id;
    bool error_occured = false, is_ecmp_table_full = false;
    bool ecmp_handle_created = false;
    int valid_ecmp_count = 0;
    ndi_rif_id_t rif_id = 0;
    t_fib_nh *p_fh;
    t_fib_dr_fh *p_dr_fh;
    t_fib_nh_holder nh_holder;
    ndi_route_t route_entry;
    ndi_nh_group_t nh_group_entry;
    t_fib_nh_holder nh_holder1;
    t_fib_tunnel_fh *p_tunnel_fh = NULL;
    t_fib_tunnel_dr_fh *p_tunnel_dr_fh = NULL;
    t_std_error rc;
    ndi_neighbor_t nbr_entry;

    HAL_RT_LOG_INFO("HAL-RT-NDI",
                    "ECMP route add - MP NH Group: VRF %d. " "Prefix: %s/%d, num_fh: %d\r\n", vrf_id,
                    FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                    p_dr->num_fh);

    /*
     * Initialize NH Group entry
     */
    memset(&nh_group_entry, 0, sizeof(ndi_nh_group_t));
    hal_form_ecmp_route_entry(&nh_group_entry, p_dr);

    /*
     * Initialize ECMP route entry
     */
    memset(&route_entry, 0, sizeof(route_entry));
    hal_form_route_entry(&route_entry, p_dr, false);

    for (npu_id = 0; npu_id < hal_rt_access_fib_config()->max_num_npu;
            npu_id++) {
        valid_ecmp_count = 0;
        route_entry.npu_id = npu_id;
        route_entry.vrf_id = hal_vrf_obj_get(npu_id, p_dr->vrf_id);
        nh_group_entry.vrf_id = route_entry.vrf_id;

        FIB_FOR_EACH_FH_FROM_DR (p_dr, p_fh, nh_holder)
        {
            p_dr_fh = FIB_GET_DRFH_NODE_FROM_NH_HOLDER(nh_holder);
            if (FIB_IS_FH_IP_TUNNEL(p_fh)) {
                FIB_FOR_EACH_FH_FROM_TUNNEL_DRFH (p_dr_fh, p_tunnel_fh, nh_holder1)
                {
                    p_fh = FIB_GET_FH_FROM_TUNNEL_FH(p_tunnel_fh);
                    p_tunnel_dr_fh = FIB_GET_TUNNEL_DRFH_NODE_FROM_NH_HOLDER(nh_holder1);

                    if (!FIB_IS_FH_VALID_ECMP(p_fh, valid_ecmp_count)) {
                        p_tunnel_dr_fh->status = FIB_DRFH_STATUS_UNWRITTEN;
                        continue;
                    }

                    p_tunnel_dr_fh->status = FIB_DRFH_STATUS_WRITTEN;

                    HAL_RT_LOG_DEBUG("HAL-RT-NDI",
                            "NH Group:VRF %d. Tunnel FH: %d\r\n", p_fh->vrf_id,
                            p_fh->key.if_index);

                    nh_handle = p_tunnel_fh->next_hop_id;

                    if (STD_IP_IS_ADDR_LINK_LOCAL(&(p_fh->key.ip_addr))) {
                        //@TODO Handle this case
                    }
                }
            } else {
                if (!FIB_IS_FH_VALID_ECMP(p_fh, valid_ecmp_count)) {
                    p_dr_fh->status = FIB_DRFH_STATUS_UNWRITTEN;
                    HAL_RT_LOG_DEBUG("HAL-RT-NDI",
                            "NH Group Add SKIP!!: VRF %d. Prefix: %s/%d, " "FH: %d, NH handle: %d\r\n",
                            p_fh->vrf_id,
                            FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                            p_dr->prefix_len, p_fh->key.if_index,
                            p_fh->next_hop_id);
                    continue;
                }

                p_dr_fh->status = FIB_DRFH_STATUS_WRITTEN;
                HAL_RT_LOG_DEBUG("HAL-RT-NDI",
                        "NH Group Add VRF %d, FH: %d, nh_count: %d, " "NH handle: %d\r\n",
                        p_fh->vrf_id, p_fh->key.if_index, valid_ecmp_count,
                        p_fh->next_hop_id);
                nh_handle = p_fh->next_hop_id;

                if (nh_handle == 0) {
                    HAL_RT_LOG_DEBUG("HAL-RT-NDI",
                            "NH Group: FH nh_handle is NULL. " "Vrf_id: %d.\r\n",
                            vrf_id);
                    /*
                     * If fh has no nh_handle, create one
                     */
                    if (nh_handle == 0) {
                        HAL_RT_LOG_DEBUG("HAL-RT-NDI",
                                "NH Group: FH nh_handle is NULL. Creating!" "if_index %d Vrf_id: %d.\r\n",
                                p_fh->key.if_index, vrf_id);

                        rif_id = hal_rif_index_get(npu_id, vrf_id, p_fh->key.if_index);
                        HAL_RT_LOG_DEBUG("HAL-RT-NDI",
                                "NH Group: RIF ID %d!" "Vrf_id: %d.\r\n",
                                rif_id, vrf_id);

                        memset(&nbr_entry, 0, sizeof(nbr_entry));
                        if (hal_form_nbr_entry(&nbr_entry, p_fh) == STD_ERR_OK) {
                            nbr_entry.rif_id = rif_id;
                            /*
                             * NDI Nexthop add API & Neighbor API uses the same ndi_neighbor_t
                             * data structure. A next-hop id is created for the route next-hop
                             * and passed as an index to NDI/SAI.
                             */
                            if (ndi_route_next_hop_add(&nbr_entry,&nh_handle) != STD_ERR_OK) {
                                return STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0);
                            }
                            p_fh->next_hop_id = nh_handle;
                            hal_rt_rif_ref_inc(p_fh->key.if_index);
                        }
                    }

                }

                nh_group_entry.nh_list[valid_ecmp_count].id = nh_handle;
                nh_group_entry.nh_list[valid_ecmp_count].weight = 1;
                /*
                 * @@TODO: verify wecmp
                 *
                 */

                HAL_RT_LOG_DEBUG("HAL-RT-NDI",
                        "NH Group Add to NHLIST: VRF %d. Prefix: %s/%d, "
                        "FH: %d, nh_id[%d]: %d\r\n",
                        p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                        p_dr->prefix_len, p_fh->key.if_index, valid_ecmp_count,
                        nh_handle);
                valid_ecmp_count++;

                if (STD_IP_IS_ADDR_LINK_LOCAL(&(p_fh->key.ip_addr))) {
                    //@TODO Handle this case
                } else {
                    //@TODO Handle this case
                }
            }

        } /* End of FIB_FOR_EACH_FH_FROM_DR */

        /*
         * Create Multipath NH Group object(ECMP Group ID)
         */
        nh_group_entry.npu_id = npu_id;
        nh_group_entry.nhop_count = valid_ecmp_count;
        p_dr->nh_count = valid_ecmp_count;
        hal_dump_ecmp_route_entry(&nh_group_entry);

        HAL_RT_LOG_DEBUG("HAL-RT-NDI",
                "OLD NH Group: VRF %d. " "Prefix: %s/%d, num_fh: %d, valid_ecmp_count=%d, " "OLD NH Group ID =%d \n",
                vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                p_dr->prefix_len, p_dr->num_fh, valid_ecmp_count,
                p_dr->nh_handle);

        if ((valid_ecmp_count == 0) && (p_dr->num_fh > 0)) {
            /*
             * @@TODO If there is no valid ECMP FH but we have NHs (which are not ARP resolved),
             * trap packets to CPU for ARP resolution. This case should not arise
             */
            route_entry.action = NDI_ROUTE_PACKET_ACTION_TRAPCPU;
            HAL_RT_LOG_DEBUG("HAL-RT-NDI",
                    "NH Group: VRF %d. " "Prefix: %s/%d, num_fh: %d, valid_ecmp_count=%d, "
                    "NH Group ID =%d  ERROR!!!!!ERROR!!!! \n",
                    vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                    p_dr->prefix_len, p_dr->num_fh, valid_ecmp_count,
                    p_dr->nh_handle);
        } else {

            /*
             * ECMP Grouping: Find or create ECMP group ID(Group Table ID)
             *
             */
            is_ecmp_table_full = false;
            rc = hal_rt_find_or_create_ecmp_group(p_dr, &nh_group_entry,
                    &nh_group_handle, &is_ecmp_table_full);
            if (rc != STD_ERR_OK) {
                HAL_RT_LOG_ERR("HAL-RT-NDI",
                        "ECMP Group: Create Group ID failed. VRF %d. Prefix: " "%s/%d, Unit: %d, Err: %d, %s %d\r\n",
                        vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                        p_dr->prefix_len, npu_id, rc,
                        is_ecmp_table_full ?
                                "as Group ECMP table is FULL" : "");
                error_occured = true;

            } else {
                HAL_RT_LOG_DEBUG("HAL-RT-NDI",
                        "ECMP Group: Using Group ID: %d. VRF %d. Prefix: " "%s/%d,Unit: %d, Err: %d\r\n",
                        nh_group_handle, vrf_id,
                        FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                        p_dr->prefix_len, npu_id, rc);
                ecmp_handle_created = true;
                p_dr->ecmp_handle_created = true;
            }

        }

        /*
         * Prepare ECMP Multipath Route for NPU L3 routing table
         */
        /*
         *  Add the Multipath Route using the
         *     ECMP group ID(Group Table ID)
         */
        /*
         *  Route Entry NH ID: Set NDI route flags to set appropriate SAI ECMP/NH flag for the route
         */
        if (!is_ecmp_table_full) {
            route_entry.flags = NDI_ROUTE_L3_ECMP;

            /*
             * Use new nh_group_handle for route update
             */
            route_entry.nh_handle = nh_group_handle;
        } else {
            /*
             * If ECMP group table us full, set the route as non-ECMP
             */
            route_entry.flags = NDI_ROUTE_L3_NEXT_HOP_ID;
            /*
             * Use first NH in the NH list to install the route as non-ECMP
             */
             route_entry.nh_handle = nh_group_entry.nh_list[0].id;
        }

        route_entry.npu_id = npu_id;

        if (valid_ecmp_count == 0){
            /*
             * @@TODO check this and add exact code
             */
            route_entry.action = NDI_ROUTE_PACKET_ACTION_TRAPCPU;
        } else {
            route_entry.action = NDI_ROUTE_PACKET_ACTION_FORWARD;
        }

        HAL_RT_LOG_INFO("HAL-RT-NDI",
                "MP: Multi-path Route Add " "contents: VRF %d, Prefix: %s/%d, NH_handle=%d, action=%d, "
                "num_fh=%d, valid_ecmp_count=%d, Unit: %d",
                vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                p_dr->prefix_len, nh_group_handle, route_entry.action,
                p_dr->num_fh, valid_ecmp_count, npu_id);

        /* New Route add case */
        if (!p_dr->a_is_written[npu_id]) {

            hal_dump_route_entry(&route_entry);
            rc = ndi_route_add(&route_entry);
            if (rc != STD_ERR_OK) { /* failure */
                HAL_RT_LOG_ERR("HAL-RT-NDI",
                               "ECMP Route Add: Failed. VRF %d, " "Prefix: %s/%d, Unit: %d, Err: %d",
                               vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                               p_dr->prefix_len, npu_id, rc);
                error_occured = true;
                break;
            } else { /* success */
                p_dr->a_is_written[npu_id] = true;
                /*
                 * Update handle in p_dr
                 */
                p_dr->nh_handle = nh_group_handle;
                HAL_RT_LOG_INFO("HAL-RT-NDI",
                                " MP: ECMP Route Add (%s): Successful. VRF %d. " "Prefix: %s/%d, num_fh: %d, "
                                "nh_group_id %d \n",(is_ecmp_table_full)? "non-ECMP due to FULL":"",
                                vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                                p_dr->prefix_len, p_dr->num_fh, p_dr->nh_handle);
                p_dr->nh_handle = route_entry.nh_handle;
            }
        } else if (p_dr->nh_handle != nh_group_handle) { /* Update route NH */

            hal_dump_route_entry(&route_entry);
            rc = ndi_route_set_attribute(&route_entry);
            if (rc != STD_ERR_OK) {
                HAL_RT_LOG_ERR("HAL-RT-NDI",
                                "MP: ECMP Route Update: Failed. Attribute Group Nexthop ID set failed."
                                "Prefix: %s/%d Unit: %d, Err: %d, old gid %d, new gid to set %d\r\n",
                                FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                                p_dr->prefix_len, npu_id, rc, p_dr->nh_handle,
                                route_entry.nh_handle);
                error_occured = true;
                break;
            }
            HAL_RT_LOG_INFO("HAL-RT-NDI",
                            "MP: ECMP Route Update:  Successful, VRF %d, Prefix: %s/%d - "
                            "old gid %d, new gid %d %s\r\n",
                            vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                            p_dr->prefix_len, p_dr->nh_handle, nh_group_handle,
                            (ecmp_handle_created && p_dr->ofh_cnt <= 1) ?
                            "(Changed non-ECMP to ECMP)" : "");
            /*
             * Change to new group handle
             */
            p_dr->nh_handle = route_entry.nh_handle;

        } else {
            /*
             * This case is hit when ARP is re-resolved and DR thread walks
             * over the existing routes or when ecmp table is full.
             * If there is no change in the route entry or nh handle, just return success.
             */
            HAL_RT_LOG_DEBUG("HAL-RT-NDI",
                    "MP: ECMP Route already programmed as %s! Prefix: %s/%d "
                    "- old gid %d, new gid %d!\r\n",
                    is_ecmp_table_full ? "Non-ECMP as Group ECMP table is full" : "ECMP",
                    FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                    p_dr->nh_handle, nh_group_handle);
        }

    }

    if (error_occured == false) {

        /*
         * Delete old group id that was marked for deletion
         * as route got added to a new group
         */

        hal_rt_fib_check_and_delete_old_groupid(p_dr, route_entry.npu_id);
        p_dr->ofh_cnt = valid_ecmp_count;

        /* Notify the Route add to NHT only if the action is forward */
        if (route_entry.action == NDI_ROUTE_PACKET_ACTION_FORWARD)
            nas_rt_handle_dest_change(p_dr, NULL, true);
    } else {
        /*
         * @@TODO either delete route hal_fib_route_del or take appropriate action
         * to return  DN_HAL_ROUTE_E_FAIL
         */

    }

    return (DN_HAL_ROUTE_E_NONE);
}

dn_hal_route_err hal_fib_ecmp_route_del(uint32_t vrf_id, t_fib_dr *p_dr) {
    npu_id_t npu_id;
    ndi_route_t route_entry;
    bool error_occured = false;
    t_std_error rc;

    HAL_RT_LOG_INFO("HAL-RT-NDI",
                    "ECMP route del - VRF %d, Prefix: %s/%d, num_fh: %d\r\n", vrf_id,
                    FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                    p_dr->num_fh);

    memset(&route_entry, 0, sizeof(route_entry));
    hal_form_route_entry(&route_entry, p_dr, false);

    for (npu_id = 0; npu_id < hal_rt_access_fib_config()->max_num_npu;
            npu_id++) {
        if (p_dr->a_is_written[npu_id] == false) {
            HAL_RT_LOG_ERR("HAL-RT-NDI",
                    "%s (): ECMP route not programmed in " "hardware. Vrf_id: %d, Unit: %d.\r\n",
                    __FUNCTION__, vrf_id, npu_id);
            continue;
        }

        /*
         * Delete the Multi-path Route from NPU L3 routing table
         * using the ECMP group ID(Group Table ID)
         */
        route_entry.nh_handle = p_dr->nh_handle;
        route_entry.npu_id = npu_id;
        route_entry.vrf_id = hal_vrf_obj_get(npu_id, p_dr->vrf_id);
        hal_dump_route_entry(&route_entry);
        rc = ndi_route_delete(&route_entry);
        if (rc != STD_ERR_OK) {
            HAL_RT_LOG_ERR("HAL-RT-NDI",
                           "MP:Multi-path Route Delete failed. VRF %d, " "Prefix: %s/%d, Unit: %d, Err: %",
                           vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                           p_dr->prefix_len, npu_id, rc);
            error_occured = true;
            return DN_HAL_ROUTE_E_FAIL;
        }

        /*
         * Delete the NH group(mostly decrement refcount or delete
         * in SAI (decrement ref cnt) and if group rf cnt is 0 delete from HW)
         */
        HAL_RT_LOG_INFO("HAL-RT-NDI",
                        "NH Group delete: VRF %d. Prefix: %s/%d, num_fh: %d, " "nh_group_id =%d \n",
                        vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                        p_dr->prefix_len, p_dr->num_fh, p_dr->nh_handle);
        rc = hal_rt_delete_ecmp_group(p_dr, &route_entry, p_dr->nh_handle, true);

        if (rc != STD_ERR_OK) {
            HAL_RT_LOG_ERR("HAL-RT-MP",
                           "NH Group:Failed to delete Route, group:%d. " "Vrf_id: %d, Unit: %d. Err: %d \r\n",
                           p_dr->nh_handle, vrf_id, npu_id, rc);
            error_occured = true;
        }

        p_dr->a_is_written[npu_id] = false;
        p_dr->nh_handle = 0;
        p_dr->ecmp_handle_created = false;
        p_dr->num_fh = 0;
        p_dr->nh_count = 0;
        p_dr->ofh_cnt = 0;
    }
    if (error_occured == true) {
        return DN_HAL_ROUTE_E_FAIL;
    }
    nas_rt_handle_dest_change(p_dr, NULL, false);
    return DN_HAL_ROUTE_E_NONE;
}

dn_hal_route_err hal_fib_ecmp_route_add_un_supp_mask(uint32_t vrf_id,
        t_fib_dr *p_dr) {
    t_fib_nh *p_fh;
    t_fib_dr_fh *p_dr_fh;
    t_fib_nh_holder nh_holder;
    dn_hal_route_err rc = DN_HAL_ROUTE_E_NONE;
    int route_written = false;

    FIB_FOR_EACH_FH_FROM_DR (p_dr, p_fh, nh_holder)
    {
        /* @@TODO Handle the Tunnel FH here */
        p_dr_fh = FIB_GET_DRFH_NODE_FROM_NH_HOLDER(nh_holder);
        p_dr_fh->status = FIB_DRFH_STATUS_UNWRITTEN;

        if ((route_written == false) && (FIB_IS_FH_VALID_ECMP(p_fh, 0))) {
            if (_hal_fib_route_add(vrf_id, p_dr, p_dr_fh)
                    == DN_HAL_ROUTE_E_NONE) {
                p_dr_fh->status = FIB_DRFH_STATUS_WRITTEN;
                route_written = true;
                rc = DN_HAL_ROUTE_E_NONE;
            }
        }
    }

    if (route_written == false) {
        rc = _hal_fib_route_add(vrf_id, p_dr, NULL);
    }

    return rc;
}

bool hal_fib_is_route_really_ecmp(t_fib_dr *p_dr, bool *p_out_is_cpu_route) {
    t_fib_nh *p_fh;
    t_fib_nh_holder nh_holder;
    uint32_t valid_ecmp_count = 0;
    t_fib_tunnel_fh *p_tunnel_fh = NULL;
    t_fib_nh_holder nh_holder1;
    t_fib_dr_fh *p_dr_fh = NULL;

    *p_out_is_cpu_route = true;

    FIB_FOR_EACH_FH_FROM_DR (p_dr, p_fh, nh_holder)
    {
        if (FIB_IS_FH_IP_TUNNEL(p_fh)) {
            p_dr_fh = FIB_GET_DRFH_NODE_FROM_NH_HOLDER(nh_holder);

            FIB_FOR_EACH_FH_FROM_TUNNEL_DRFH (p_dr_fh, p_tunnel_fh, nh_holder1)
            {
                p_fh = FIB_GET_FH_FROM_TUNNEL_FH(p_tunnel_fh);

                if (FIB_IS_FH_VALID_ECMP(p_fh, valid_ecmp_count)) {
                    valid_ecmp_count++;
                    *p_out_is_cpu_route = false;
                }

                if (valid_ecmp_count > 1) {
                    return true;
                }
            }
        } else {
            if (FIB_IS_FH_VALID_ECMP(p_fh, valid_ecmp_count)) {
                valid_ecmp_count++;
                *p_out_is_cpu_route = false;
            }

            if (valid_ecmp_count > 1) {
                return true;
            }
        }
    }

    return false;
}
