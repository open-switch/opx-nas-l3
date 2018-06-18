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
 * \file   hal_rt_route.c
 * \brief  Hal Routing south bound APIs
 * \date   04-2014
 * \author Satish Mynam/Prince Sunny
 */

#include "hal_rt_main.h"
#include "hal_rt_route.h"
#include "hal_rt_util.h"
#include "hal_rt_api.h"
#include "hal_rt_mpath_grp.h"
#include "hal_if_mapping.h"
#include "cps_api_interface_types.h"
#include "std_error_codes.h"
#include "nas_ndi_route.h"
#include "nas_ndi_router_interface.h"

#include "event_log.h"
#include "std_utils.h"
#include "std_ip_utils.h"
#include <stdio.h>
#include <string.h>


/* this function is called during route programming to NPU if DR rt_type
 * is blackhole/unreachable/prohibit.
 */
static inline uint32_t hal_rt_type_to_packet_action (t_rt_type rt_type)
{
    /* return packet action according to the route type */
    return ((rt_type == RT_BLACKHOLE) ? NDI_ROUTE_PACKET_ACTION_DROP :
            /* RT_UNREACHABLE, RT_PROHIBIT and other cases, TRAP to CPU */
            NDI_ROUTE_PACKET_ACTION_TRAPCPU);
}
dn_hal_route_err hal_fib_route_add(uint32_t vrf_id, t_fib_dr *p_dr) {
    t_fib_nh *p_fh;
    t_fib_dr_fh *p_dr_fh;
    t_fib_nh_holder nh_holder;
    uint32_t valid_ecmp_count;
    dn_hal_route_err rc = DN_HAL_ROUTE_E_NONE;
    bool is_cpu_route = false;
    t_fib_tunnel_fh *p_tunnel_fh = NULL;
    t_fib_nh_holder nh_holder1;
    t_fib_tunnel_dr_fh *p_tunnel_dr_fh = NULL;

    HAL_RT_LOG_INFO("HAL-RT-NDI", "NPU route add - VRF %d. Prefix: %s/%d, num_fh: %d%s", vrf_id,
                    FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                    p_dr->num_fh,
                    (p_dr->status_flag & FIB_DR_STATUS_DEGENERATED) ? ", Degen DR" : "");

    if (!FIB_IS_VRF_ID_VALID(vrf_id)) {
        HAL_RT_LOG_ERR("HAL-RT-NDI",
                "%s (): Invalid VRF %d.", __FUNCTION__, vrf_id);
        return DN_HAL_ROUTE_E_PARAM;
    }

    if (FIB_IS_MGMT_ROUTE(vrf_id, p_dr) || (p_dr->rt_type == RT_CACHE)) {
        return DN_HAL_ROUTE_E_PARAM;
    }
    /*
     * ECMP case
     */
    if (hal_rt_is_ecmp_enabled() && (p_dr->num_fh > 1)) {
        if (p_dr->status_flag & FIB_DR_STATUS_DEGENERATED) {
            rc = _hal_fib_route_add(vrf_id, p_dr, &p_dr->degen_dr_fh);
        } else {
            if (hal_fib_is_route_really_ecmp(p_dr, &is_cpu_route) == true) {
                rc = hal_fib_ecmp_route_add(vrf_id, p_dr);
            } else {
                valid_ecmp_count = 0;
                FIB_FOR_EACH_FH_FROM_DR (p_dr, p_fh, nh_holder)
                {
                    p_dr_fh = FIB_GET_DRFH_NODE_FROM_NH_HOLDER(nh_holder);

                    if (FIB_IS_FH_IP_TUNNEL(p_fh)) {
                        FIB_FOR_EACH_FH_FROM_TUNNEL_DRFH (p_dr_fh, p_tunnel_fh,
                                nh_holder1)
                        {
                            p_fh = FIB_GET_FH_FROM_TUNNEL_FH(p_tunnel_fh);

                            p_tunnel_dr_fh =
                                    FIB_GET_TUNNEL_DRFH_NODE_FROM_NH_HOLDER(
                                            nh_holder1);
                            p_tunnel_dr_fh->status = FIB_DRFH_STATUS_UNWRITTEN;

                            if (FIB_IS_FH_VALID_ECMP(p_fh, valid_ecmp_count)) {
                                valid_ecmp_count++;

                                if (valid_ecmp_count == 1) {
                                    rc = _hal_fib_route_add(vrf_id, p_dr,
                                            p_dr_fh);
                                }
                            }
                        }
                    } else {
                        p_dr_fh->status = FIB_DRFH_STATUS_UNWRITTEN;

                        if (FIB_IS_FH_VALID_ECMP(p_fh, valid_ecmp_count)) {
                            valid_ecmp_count++;

                            if (valid_ecmp_count == 1) {
                                rc = _hal_fib_route_add(vrf_id, p_dr, p_dr_fh);
                            }
                        } else {
                            if (is_cpu_route == true) {
                                is_cpu_route = false;
                                rc = _hal_fib_route_add(vrf_id, p_dr, NULL);
                            }
                        }
                    }
                }
            }
        }
    } else {
        /*
         * Non-ECMP case
         */
        p_fh = FIB_GET_FIRST_FH_FROM_DR(p_dr, nh_holder);
        p_dr_fh = FIB_GET_DRFH_NODE_FROM_NH_HOLDER(nh_holder);
        rc = _hal_fib_route_add(vrf_id, p_dr, p_dr_fh);
    }

    return (rc);
}

dn_hal_route_err hal_fib_route_del(uint32_t vrf_id, t_fib_dr *p_dr) {
    dn_hal_route_err rc = DN_HAL_ROUTE_E_NONE;

    HAL_RT_LOG_INFO("HAL-RT-NDI", " NPU route del - VRF %d. Prefix: %s/%d, num_fh: %d",
                    vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                    p_dr->num_fh);

    if (!FIB_IS_VRF_ID_VALID(vrf_id)) {
        HAL_RT_LOG_ERR("HAL-RT-NDI",
                "%s (): Invalid VRF %d.", __FUNCTION__, vrf_id);
        return DN_HAL_ROUTE_E_PARAM;
    }

    if (FIB_IS_MGMT_ROUTE(vrf_id, p_dr) || (p_dr->rt_type == RT_CACHE)) {
        return DN_HAL_ROUTE_E_PARAM;
    }
    hal_fib_set_all_dr_fh_to_un_written(p_dr);

    if (p_dr->ecmp_handle_created == false) {
        rc = _hal_fib_route_del(vrf_id, p_dr);
    } else {
        rc = hal_fib_ecmp_route_del(vrf_id, p_dr);
    }

    return (rc);
}

void hal_form_route_entry(ndi_route_t *p_route_entry, t_fib_dr *p_dr,
        uint8_t is_l3_terminated)
{
    if (p_dr->key.prefix.af_index == HAL_RT_V4_AFINDEX) {
        memcpy(&(p_route_entry->prefix.u.v4_addr),
                &(p_dr->key.prefix.u.v4_addr), HAL_RT_V4_ADDR_LEN);
    } else {
        memcpy(&(p_route_entry->prefix.u.v6_addr),
                &(p_dr->key.prefix.u.v6_addr), HAL_RT_V6_ADDR_LEN);
    }
    p_route_entry->prefix.af_index = p_dr->key.prefix.af_index;
    p_route_entry->mask_len = p_dr->prefix_len;
    if (is_l3_terminated) {
        p_route_entry->flags = NDI_ROUTE_L3_TERMINATED;
    }
}

void hal_dump_route_entry(ndi_route_t *p_route_entry) {
    HAL_RT_LOG_DEBUG("HAL-RT-NDI",
            "VRF %lu. Prefix: %s/%d flags 0x%x " "nh_handle %lu npu_id %d action %d",
            p_route_entry->vrf_id, FIB_IP_ADDR_TO_STR(&(p_route_entry->prefix)),
            p_route_entry->mask_len, p_route_entry->flags,
            p_route_entry->nh_handle, p_route_entry->npu_id,
            p_route_entry->action);
}

dn_hal_route_err _hal_fib_route_add(uint32_t vrf_id, t_fib_dr *p_dr,
        t_fib_dr_fh *p_dr_fh) {
    next_hop_id_t nh_handle = 0, old_nh_handle = 0;
    ndi_rif_id_t rif_id = 0;
    bool is_l3_terminated = false;
    t_fib_nh_holder nh_holder;
    t_fib_nh *p_fh = NULL;
    t_fib_nh *p_nh = NULL;
    uint8_t *p_status = NULL;
    t_fib_tunnel_fh *p_tunnel_fh = NULL;
    t_fib_tunnel_dr_fh *p_tunnel_dr_fh = NULL;
    npu_id_t npu_id = 0;
    ndi_route_t route_entry;
    ndi_neighbor_t nbr_entry;
    t_std_error rc;
    bool error_occured = false;
    bool rif_update = false;
    bool is_link_local_addr = false, is_nht_notif_done = false;
    hal_ifindex_t  if_index = 0;

    if (STD_IP_IS_ADDR_LINK_LOCAL(&p_dr->key.prefix))
        is_link_local_addr = true;

    if (p_dr_fh != NULL) {
        p_fh = FIB_GET_FH_FROM_DRFH(p_dr_fh);
        p_status = &p_dr_fh->status;
        HAL_RT_LOG_DEBUG("HAL-RT-NDI",
                "VRF %d. Prefix: %s/%d, FH:%d", vrf_id,
                FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                p_fh->key.if_index);
        if ((FIB_IS_FH_IP_TUNNEL(p_fh)) && (!FIB_IS_NH_ZERO(p_fh))) {
            p_tunnel_fh = FIB_GET_FIRST_TUNNEL_FH_FROM_DRFH(p_dr_fh, nh_holder);
            p_tunnel_dr_fh = FIB_GET_TUNNEL_DRFH_NODE_FROM_NH_HOLDER(nh_holder);

            if (p_tunnel_fh != NULL) {
                nh_handle = p_tunnel_fh->next_hop_id;
                p_status = &p_tunnel_dr_fh->status;

                if (nh_handle == 0) {
                    HAL_RT_LOG_ERR("HAL-RT-NDI",
                            "%s (): nh_handle is NULL. " "Vrf_id: %d.",
                            __FUNCTION__, vrf_id);
                    return STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0);
                }
            }
        } else {
            nh_handle = p_fh->next_hop_id;

            if (nh_handle == 0) {
                HAL_RT_LOG_DEBUG("HAL-RT-NDI",
                                 "nh_handle is NULL. Creating..!!" "if_index %d Vrf_id: %d.",
                                 p_fh->key.if_index, vrf_id);
                //@Todo, Handle multi-npu case
                /* For link local address on interface,
                 * rif would be created before this function.
                 * So no need to create again.
                 */
                if (!is_link_local_addr &&
                    (hal_rif_index_get_or_create(npu_id, vrf_id, p_fh->key.if_index,
                                                &rif_id) != STD_ERR_OK)) {
                    HAL_RT_LOG_ERR("HAL-RT-NDI", "RIF creation failed. VRF %d."
                                   " Prefix: %s/%d: if-index:%d",
                                   vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                                   p_dr->prefix_len, p_fh->key.if_index);
                    return DN_HAL_ROUTE_E_FAIL;
                }
                HAL_RT_LOG_DEBUG("HAL-RT-NDI",
                        "RIF ID 0x%lx!" "Vrf_id: %d.", rif_id, vrf_id);

                memset(&nbr_entry, 0, sizeof(nbr_entry));
                if (hal_form_nbr_entry(&nbr_entry, p_fh) == STD_ERR_OK) {
                    nbr_entry.rif_id = rif_id;
                    /*
                     * NDI Nexthop add API & Neighbor API uses the same ndi_neighbor_t
                     * data structure. A next-hop id is created for the route next-hop
                     * and passed as an index to NDI/SAI.
                     */
                    if (ndi_route_next_hop_add(&nbr_entry, &nh_handle) != STD_ERR_OK) {
                        return STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0);
                    }
                    p_fh->next_hop_id = nh_handle;
                    if ((p_fh->p_arp_info) && (p_fh->p_arp_info->state == FIB_ARP_RESOLVED)) {
                        /* If this NH is interested for NHT, but route add only creates the NH_handle, so,
                         * we could have got the host add(NHT could have simply ignored it because the handle was null)
                         * before this route add, so notify dest change to NHT now */
                        nas_rt_handle_dest_change(NULL, p_fh, true);
                    }
                }
                /* update rif only if its not link local address */
                if (!is_link_local_addr)
                    rif_update = true;
                if_index = p_fh->key.if_index;
            }
        }

        *p_status = FIB_DRFH_STATUS_UNWRITTEN;

        if (FIB_IS_NH_LOOP_BACK(p_fh)) {
            is_l3_terminated = true;
        }
    } else {
        HAL_RT_LOG_DEBUG("HAL-RT-NDI",
                "VRF %d. Prefix: %s/%d, rt_type: %d, NULL FH", vrf_id,
                FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len, p_dr->rt_type);
    }

    memset(&route_entry, 0, sizeof(route_entry));
    hal_form_route_entry(&route_entry, p_dr, is_l3_terminated);
    /*
     * Save old handle
     */
    old_nh_handle = p_dr->nh_handle;

    for (npu_id = 0; npu_id < hal_rt_access_fib_config()->max_num_npu;
            npu_id++) {
        route_entry.npu_id = npu_id;
        route_entry.vrf_id = hal_vrf_obj_get(npu_id, p_dr->vrf_id);

        if (FIB_IS_RESERVED_RT_TYPE(p_dr->rt_type)) {
            route_entry.action = hal_rt_type_to_packet_action (p_dr->rt_type);
            rif_update = false;
            if_index = 0;
        } else if (p_fh == NULL) {
            p_nh = FIB_GET_FIRST_NH_FROM_DR(p_dr, nh_holder);
            if (!p_nh) {
                // @Todo, Need to handle this case
                HAL_RT_LOG_DEBUG("HAL-RT-NDI", "Null NH!");
                return DN_HAL_ROUTE_E_FAIL;
            }
            /* For link local address on interface,
             * rif would be created before this function.
             * So no need to create again.
             */
            if (!is_link_local_addr &&
                (hal_rif_index_get_or_create(npu_id, vrf_id, p_nh->key.if_index,
                                            &rif_id) != STD_ERR_OK)) {
                HAL_RT_LOG_ERR("HAL-RT-NDI", "RIF creation failed VRF %d."
                               " Prefix: %s/%d: if-index:%d",
                               vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                               p_dr->prefix_len, p_nh->key.if_index);
                return DN_HAL_ROUTE_E_FAIL;
            }

            HAL_RT_LOG_DEBUG("HAL-RT-NDI",
                    "RIF ID 0x%lx, Vrf_id: %d.", rif_id, vrf_id);

            memset(&nbr_entry, 0, sizeof(nbr_entry));
            if (hal_form_nbr_entry(&nbr_entry, p_nh) == STD_ERR_OK) {
                nbr_entry.rif_id = rif_id;
                if (p_nh->next_hop_id == 0) {
                    if (ndi_route_next_hop_add(&nbr_entry, &nh_handle) != STD_ERR_OK) {
                        return STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0);
                    }
                    HAL_RT_LOG_DEBUG("HAL-RT-NDI",
                                 "Created nh handle %lu..!!" "Vrf_id: %d.", nh_handle, vrf_id);
                    p_nh->next_hop_id = nh_handle;
                    if ((p_nh->p_arp_info) && (p_nh->p_arp_info->state == FIB_ARP_RESOLVED)) {
                        /* If this NH is interested for NHT, but route add only creates the NH_handle, so,
                         * we could have got the host add(NHT could have simply ignored it because the handle was null)
                         * before this route add, so notify dest change to NHT now */
                        nas_rt_handle_dest_change(NULL, p_nh, true);
                    }
                    /* update rif only if its not link local address */
                    if (!is_link_local_addr)
                        rif_update = true;
                } else {
                    HAL_RT_LOG_DEBUG("HAL-RT-NDI",
                                 "nh handle already exists %lu..!!" "Vrf_id: %d.",
                                 p_nh->next_hop_id, vrf_id);
                    nh_handle = p_nh->next_hop_id;
                }
                route_entry.action = NDI_ROUTE_PACKET_ACTION_FORWARD;
            } else {
                HAL_RT_LOG_DEBUG("HAL-RT-NDI",
                                 "NH IP Zero, Vrf_id: %d.", vrf_id);
                /* update rif only if its not link local address */
                if (!is_link_local_addr)
                    rif_update = true;
                route_entry.action = NDI_ROUTE_PACKET_ACTION_TRAPCPU;
            }
            if_index = p_nh->key.if_index;
        } else {
            if (FIB_IS_FH_IP_TUNNEL(p_fh)) {
                if (FIB_IS_NH_ZERO(p_fh)) {
                    /* receive-only tunnel */
                    route_entry.action = NDI_ROUTE_PACKET_ACTION_DROP;
                } else {
                    route_entry.action = NDI_ROUTE_PACKET_ACTION_FORWARD;
                }
            } else if (FIB_IS_NH_ZERO(p_fh)) {
                route_entry.action = NDI_ROUTE_PACKET_ACTION_TRAPCPU;
                /* update rif only if its not link local address */
                if (!is_link_local_addr)
                    rif_update = true;
                if_index = p_fh->key.if_index;
            } else {
                route_entry.action = NDI_ROUTE_PACKET_ACTION_FORWARD;
            }
        }

        route_entry.nh_handle = nh_handle;
        hal_dump_route_entry(&route_entry);
        if (!p_dr->a_is_written[npu_id]) {
            rc = ndi_route_add(&route_entry);
            if (rc != STD_ERR_OK) {
                HAL_RT_LOG_ERR("HAL-RT-NDI",
                               "Route Add: Failed. VRF %d. Prefix: %s/%d: NH:%s NH Handle:%lu",
                               vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                               p_dr->prefix_len, (p_fh ? FIB_IP_ADDR_TO_STR(&p_fh->key.ip_addr):
                                                  (p_nh ? FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr): "N/A")),
                               route_entry.nh_handle);

                error_occured = true;
                break;
            } else {
                /*
                 * Update RIF reference count for self-ip entries that are programmed in NPU
                 * Not keeping track of associated indirect routes
                 */
                if(rif_update)
                    hal_rt_rif_ref_inc(vrf_id, if_index);
                p_dr->a_is_written[npu_id] = true;
                p_dr->nh_handle = nh_handle;
                HAL_RT_LOG_INFO("HAL-RT-NDI(RT-END)",
                                "Route Add: Successful. VRF %d. Prefix: %s/%d: NH:%s NH Handle %lu RIF 0x%lx action:%s",
                                vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                                p_dr->prefix_len, (p_fh ? FIB_IP_ADDR_TO_STR(&p_fh->key.ip_addr):
                                                   (p_nh ? FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr): "N/A")),
                                route_entry.nh_handle, rif_id,
                                ((route_entry.action == NDI_ROUTE_PACKET_ACTION_FORWARD) ? "Forward" :
                                 ((route_entry.action == NDI_ROUTE_PACKET_ACTION_TRAPCPU) ? "TrapToCpu" : "Drop")));
            }
        } else if (p_dr->nh_handle != nh_handle) {
            if (nh_handle != 0) {
                route_entry.flags = NDI_ROUTE_L3_NEXT_HOP_ID;
                rc = ndi_route_set_attribute(&route_entry);
                if (rc != STD_ERR_OK) {
                    HAL_RT_LOG_ERR("HAL-RT-NDI",
                               "Route Attribute Nexthop ID set failed.Unit: %d, " "Err: %d",
                               npu_id, rc);
                    error_occured = true;
                    break;
                }
                /* NDI doesn't accept multiple attributes for update;
                 * Hence set attribute is called for each attribute that is
                 * updated.
                 */
                route_entry.flags = NDI_ROUTE_L3_PACKET_ACTION;
                rc = ndi_route_set_attribute(&route_entry);
                if (rc != STD_ERR_OK) {
                    HAL_RT_LOG_ERR("HAL-RT-NDI",
                               "Route Attribute Packet Action set failed.Unit: %d, " "Err: %d",
                               npu_id, rc);
                    error_occured = true;
                    break;
                }
                HAL_RT_LOG_INFO("HAL-RT-NDI(RT-END)",
                                "RT modified - VRF %d. Prefix: %s/%d: NH:%s old hdl %lu, new hdl %lu RIF 0x%lx",
                                vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len,
                                (p_fh ? FIB_IP_ADDR_TO_STR(&p_fh->key.ip_addr):
                                 (p_nh ? FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr): "N/A")),
                                p_dr->nh_handle, nh_handle, rif_id);
            } else {
                /* Route changed from ECMP/Non-ECMP to connected route */
                rc = ndi_route_delete(&route_entry);
                if (rc != STD_ERR_OK) {
                    HAL_RT_LOG_ERR("HAL-RT-NDI",
                                   "Route Delete: Failed. VRF %d. Prefix: %s/%d: hdl:%lu", vrf_id,
                                   FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len, p_dr->nh_handle);
                }
                rc = ndi_route_add(&route_entry);
                if (rc != STD_ERR_OK) {
                    HAL_RT_LOG_ERR("HAL-RT-NDI",
                                   "Connected Route Add: Failed. VRF %d. Prefix: %s/%d: " "NH Handle %lu",
                                   vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                                   p_dr->prefix_len, route_entry.nh_handle);
                    error_occured = true;
                    break;
                }
                HAL_RT_LOG_INFO("HAL-RT-NDI",
                               "Connected Route Add: Successful.. VRF %d. Prefix: %s/%d: NH Handle old:%lu new:%lu",
                               vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                               p_dr->prefix_len, p_dr->nh_handle, route_entry.nh_handle);

            }

            p_dr->nh_handle = nh_handle;

            if(rif_update)
                hal_rt_rif_ref_inc(vrf_id, if_index);
        } else {
            /*
             * This case is hit when ARP is re-resolved and DR thread walks
             * over the existing routes. If there is no change in the route
             * entry or nh handle, just return success..
             */
            HAL_RT_LOG_DEBUG("HAL-RT-NDI(RT-END)",
                    "Route already programmed!");
        }

        /*
         * After successful programming the non-ECMP route, check for
         * whether the route was previously an ECMP route and then remove it from
         * the group(ECMP to non-ECMP case)
         */
        if (p_dr->ecmp_handle_created && old_nh_handle != 0) {
            HAL_RT_LOG_INFO("HAL-RT-NDI",
                            "Route group Changed from ECMP to non-ECMP, VRF %d Prefix: %s/%d, "
                            "num_fh: %d, Old nh_group_id =%lu, New NH=%lu Unit: %d\n",
                            vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                            p_dr->prefix_len, p_dr->num_fh, old_nh_handle, nh_handle,
                            npu_id);
            p_dr->old_nh_handle_nht = old_nh_handle;
            if ((is_nht_notif_done == false) &&
                (((p_fh && (p_fh->p_arp_info) && (p_fh->p_arp_info->state == FIB_ARP_RESOLVED)) ||
                  (p_nh && (p_nh->p_arp_info) && p_nh->p_arp_info->state == FIB_ARP_RESOLVED)) ||
                 (route_entry.action == NDI_ROUTE_PACKET_ACTION_TRAPCPU))) {
                /* Notify the route add only if the NH is resolved */
                nas_rt_handle_dest_change(p_dr, NULL, true);
                is_nht_notif_done = true;
            }
            p_dr->old_nh_handle_nht = 0;
            /*
             * Update the route by removing the ECMP group as it is now a non-ECMP route
             */
            rc = hal_rt_delete_ecmp_group(p_dr, &route_entry, old_nh_handle, true);

            if (rc != STD_ERR_OK) {
                HAL_RT_LOG_DEBUG("HAL-RT-NDI",
                        "ECMP:Failed to delete route from NH group :%lu Prefix: %s/%d ,"
                        "Vrf_id: %d, Unit: %d Err: %d ",
                        old_nh_handle, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                        p_dr->prefix_len, vrf_id, npu_id, rc);
                /*
                 * @@TODO Add error case
                 */
            }

            p_dr->ecmp_handle_created = false;
        }
    } /* end of npu */

    if (error_occured == true) {
        hal_fib_route_del(vrf_id, p_dr);
        return DN_HAL_ROUTE_E_FAIL;
    } else if ((is_nht_notif_done == false) &&
               (((p_fh && (p_fh->p_arp_info) && (p_fh->p_arp_info->state == FIB_ARP_RESOLVED)) ||
                 (p_nh && (p_nh->p_arp_info) && p_nh->p_arp_info->state == FIB_ARP_RESOLVED)) ||
                (route_entry.action == NDI_ROUTE_PACKET_ACTION_TRAPCPU))) {
        /* Notify the route add only if the NH is resolved */
        nas_rt_handle_dest_change(p_dr, NULL, true);
    }

    if (p_dr_fh != NULL) {
        *p_status = FIB_DRFH_STATUS_WRITTEN;
    }

    return DN_HAL_ROUTE_E_NONE;
}

dn_hal_route_err _hal_fib_route_del(uint32_t vrf_id, t_fib_dr *p_dr) {
    npu_id_t npu_id;
    ndi_route_t route_entry;
    t_std_error rc = STD_ERR_OK;

    HAL_RT_LOG_DEBUG("HAL-RT-NDI", "VRF %d.", vrf_id);

    memset(&route_entry, 0, sizeof(route_entry));
    hal_form_route_entry(&route_entry, p_dr, false);

    hal_dump_route_entry(&route_entry);
    for (npu_id = 0; npu_id < hal_rt_access_fib_config()->max_num_npu;
            npu_id++) {
        if (p_dr->a_is_written[npu_id] == false) {
            HAL_RT_LOG_DEBUG("HAL-RT-NDI",
                    "Error. Route is not programmed. " "Vrf_id: %d, Unit: %d.",
                    vrf_id, npu_id);
            continue;
        }

        route_entry.npu_id = npu_id;
        route_entry.vrf_id = hal_vrf_obj_get(npu_id, p_dr->vrf_id);
        rc = ndi_route_delete(&route_entry);
        if (rc != STD_ERR_OK) {
            HAL_RT_LOG_ERR("HAL-RT-NDI",
                           "Route Delete: Failed. VRF %d. Prefix: %s/%d: ", vrf_id,
                           FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len);
        } else {
            HAL_RT_LOG_INFO("HAL-RT-NDI",
                            "Route Delete : Successful. VRF %d. Prefix: %s/%d: ",
                            vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                            p_dr->prefix_len);
        }

        p_dr->a_is_written[npu_id] = false;
    }
    if (rc == STD_ERR_OK) {
        /* Mark the NH resolve as false, to avoid taking this route for NHT */
        p_dr->is_nh_resolved = false;
        nas_rt_handle_dest_change(p_dr, NULL, false);
    }
    return DN_HAL_ROUTE_E_NONE;
}


int hal_fib_set_all_dr_fh_to_un_written(t_fib_dr *p_dr) {
    t_fib_nh *p_fh = NULL;
    t_fib_dr_fh *p_dr_fh = NULL;
    t_fib_tunnel_fh *p_tunnel_fh = NULL;
    t_fib_tunnel_dr_fh *p_tunnel_dr_fh = NULL;
    t_fib_nh_holder nh_holder;
    t_fib_nh_holder nh_holder1;

    if (!p_dr) {
        HAL_RT_LOG_ERR("HAL-RT-NDI",
                "%s (): Invalid input param. p_dr: %p", __FUNCTION__, p_dr);
        return STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0);
    }

    p_dr->degen_dr_fh.status = FIB_DRFH_STATUS_UNWRITTEN;

    FIB_FOR_EACH_FH_FROM_DR (p_dr, p_fh, nh_holder)
    {
        p_dr_fh = FIB_GET_DRFH_NODE_FROM_NH_HOLDER(nh_holder);

        if (FIB_IS_FH_IP_TUNNEL(p_fh)) {
            FIB_FOR_EACH_FH_FROM_TUNNEL_DRFH (p_dr_fh, p_tunnel_fh, nh_holder1)
            {
                p_tunnel_dr_fh = FIB_GET_TUNNEL_DRFH_NODE_FROM_NH_HOLDER(
                        nh_holder1);
                p_tunnel_dr_fh->status = FIB_DRFH_STATUS_UNWRITTEN;
            }
        } else {
            p_dr_fh->status = FIB_DRFH_STATUS_UNWRITTEN;
        }
    }

    return STD_ERR_OK;
}

/* configure virtual routing ip to NDI.
 * For now this is configured as a route entry with trap to cpu action.
 */
t_std_error _hal_rt_virtual_routing_ip_cfg(nas_rt_virtual_routing_ip_config_t *p_cfg, bool status) {
    npu_id_t          unit;
    ndi_route_t       route_entry;
    t_std_error       rc = STD_ERR_OK;

    memset(&route_entry, 0, sizeof(route_entry));

    if(p_cfg->ip_addr.af_index == HAL_RT_V4_AFINDEX) {
        memcpy(&(route_entry.prefix.u.v4_addr),
                &(p_cfg->ip_addr.u.v4_addr), HAL_RT_V4_ADDR_LEN);
    } else {
        memcpy(&(route_entry.prefix.u.v6_addr),
                &(p_cfg->ip_addr.u.v6_addr), HAL_RT_V6_ADDR_LEN);
    }
    route_entry.prefix.af_index = p_cfg->ip_addr.af_index;
    route_entry.mask_len = FIB_AFINDEX_TO_PREFIX_LEN(route_entry.prefix.af_index);

    for (unit = 0; unit < hal_rt_access_fib_config()->max_num_npu; unit++) {
        route_entry.npu_id = unit;
        route_entry.vrf_id = hal_vrf_obj_get(unit, p_cfg->vrf_id);

        route_entry.action = NDI_ROUTE_PACKET_ACTION_TRAPCPU;

        if (status) {
            rc = ndi_route_add (&route_entry);
            if (rc != STD_ERR_OK) {
                HAL_RT_LOG_ERR("HAL-RT-NDI",
                               "Route create failed. virtual routing config "
                               "Vrf:%d if-name:%s IP:%s",
                               p_cfg->vrf_id, p_cfg->if_name, FIB_IP_ADDR_TO_STR(&p_cfg->ip_addr));
                continue;
            }
        } else {
            rc = ndi_route_delete(&route_entry);
            if (rc != STD_ERR_OK) {
                HAL_RT_LOG_ERR("HAL-RT-NDI",
                               "Route delete failed. virtual routing config "
                               "Vrf:%d if-name:%s IP:%s",
                               p_cfg->vrf_id, p_cfg->if_name, FIB_IP_ADDR_TO_STR(&p_cfg->ip_addr));
                continue;
            }
        }
    }

    return rc;
}

