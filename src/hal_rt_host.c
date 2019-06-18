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
 * \file   hal_rt_host.c
 * \brief  Hal Routing south bound APIs
 * \date   04-2014
 * \author Satish Mynam/Prince Sunny
 */

#include "hal_rt_main.h"
#include "hal_rt_route.h"
#include "hal_rt_util.h"
#include "hal_rt_api.h"
#include "nas_rt_api.h"
#include "cps_api_interface_types.h"
#include "std_error_codes.h"
#include "nas_ndi_route.h"
#include "nas_ndi_router_interface.h"

#include "event_log.h"
#include "hal_if_mapping.h"
#include "std_ip_utils.h"

#include <string.h>

dn_hal_route_err hal_fib_validate_nh_params(uint32_t vrf_id, t_fib_nh *p_fh)
{
    if (!FIB_IS_VRF_ID_VALID (vrf_id)) {
        return DN_HAL_ROUTE_E_PARAM;
    }

    if (p_fh->p_arp_info == NULL) {
        HAL_RT_LOG_ERR("HAL-RT-NDI", "%s () p_fh->p_arp_info is NULL. VrfId: %d.",
                   __FUNCTION__, vrf_id);
        return DN_HAL_ROUTE_E_FAIL;
    }

    return DN_HAL_ROUTE_E_NONE;
}

dn_hal_route_err hal_fib_host_add (uint32_t vrf_id, t_fib_nh *p_fh)
{
    dn_hal_route_err rc;

    HAL_RT_LOG_DEBUG("HAL-RT-NDI", "VRF %d. Addr: %s, Interface id: %d",
                 vrf_id, (char *)FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr), p_fh->key.if_index);

    if((rc = hal_fib_validate_nh_params(vrf_id, p_fh)) != DN_HAL_ROUTE_E_NONE){
        return (rc);
    }

    if (FIB_IS_FH_IP_TUNNEL (p_fh)) {
        /* This will handle the tunnel case specially */
        rc = hal_fib_tunnel_remote_host_add (p_fh);
        return (rc);
    }

    rc = _hal_fib_host_add (vrf_id, p_fh);
    return (rc);
}

dn_hal_route_err hal_fib_next_hop_add(t_fib_nh *p_nh)
{
    npu_id_t    npu_id;
    ndi_rif_id_t rif_id = 0;
    next_hop_id_t nh_handle = 0;
    ndi_neighbor_t nbr_entry;

    if ((STD_IP_IS_ADDR_ZERO(&p_nh->key.ip_addr)) ||
        (FIB_IS_MGMT_NH(p_nh->vrf_id, p_nh))) {
        return DN_HAL_ROUTE_E_NONE;
    }
    HAL_RT_LOG_INFO("HAL-RT-NDI(NH-ADD)","NH Add: VRF:%d parent VRF:%d Addr: %s, Interface: %d, nh_id %lu",
                   p_nh->vrf_id, p_nh->parent_vrf_id,
                   FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index, p_nh->next_hop_id);
    if (p_nh->vrf_id != p_nh->parent_vrf_id) {
        /* Check whether the NH exists in the parent VRF, if exists,
         * copy the next_hop_id if created already to NH created in the parent VRF. */
        t_fib_nh *p_parent_nh = fib_get_nh (p_nh->parent_vrf_id, &p_nh->key.ip_addr,
                                            p_nh->key.if_index);
        if (p_parent_nh && (p_parent_nh->next_hop_id)) {
            p_nh->next_hop_id = p_parent_nh->next_hop_id;
            HAL_RT_LOG_INFO("HAL-RT-NDI","Parent NH handle copied - NH Add: VRF:%d parent:%d "
                            "Addr: %s, Interface: %d, nh_id %lu",
                            p_nh->vrf_id, p_nh->parent_vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                            p_nh->key.if_index, p_nh->next_hop_id);
            return DN_HAL_ROUTE_E_NONE;
        }
    }
    for (npu_id = 0; npu_id < hal_rt_access_fib_config()->max_num_npu; npu_id++) {
        if(p_nh->next_hop_id == 0) {
            if (hal_rif_index_get_or_create(npu_id, p_nh->parent_vrf_id, p_nh->key.if_index,
                                            &rif_id) != STD_ERR_OK) {
                HAL_RT_LOG_ERR("HAL-RT-NDI", "RIF creation failed for NH: %s intf:%d",
                               FIB_IP_ADDR_TO_STR(&(p_nh->key.ip_addr)), p_nh->key.if_index);
                return DN_HAL_ROUTE_E_FAIL;
            }

            HAL_RT_LOG_DEBUG("HAL-RT-NDI",
                         "NH Group: RIF ID 0x%lx!" "Vrf_id: %d.",
                         rif_id, p_nh->vrf_id);

            memset(&nbr_entry, 0, sizeof(nbr_entry));
            if (hal_form_nbr_entry(&nbr_entry, p_nh) == STD_ERR_OK) {
                nbr_entry.rif_id = rif_id;
                /*
                 * NDI Nexthop add API & Neighbor API uses the same ndi_neighbor_t
                 * data structure. A next-hop id is created for the route next-hop
                 * and passed as an index to NDI/SAI.
                 */
                if (ndi_route_next_hop_add(&nbr_entry,&nh_handle) != STD_ERR_OK) {
                    return STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0);
                }
                p_nh->next_hop_id = nh_handle;
                if (p_nh->vrf_id != p_nh->parent_vrf_id) {
                    /* Check whether the NH exists in the parent VRF, if exists,
                     * copy the next_hop_id if created already to NH created in the leaked VRF. */
                    t_fib_nh *p_parent_nh = fib_get_nh (p_nh->parent_vrf_id, &p_nh->key.ip_addr,
                                                        p_nh->key.if_index);
                    if (p_parent_nh && (p_parent_nh->next_hop_id == 0)) {
                        p_parent_nh->next_hop_id = p_nh->next_hop_id;
                    }
                }
            }
        }
    }

    return DN_HAL_ROUTE_E_NONE;
}

dn_hal_route_err hal_fib_next_hop_del(t_fib_nh *p_nh)
{
    t_std_error rc = STD_ERR_OK;
    npu_id_t    unit;

    if ((STD_IP_IS_ADDR_ZERO(&p_nh->key.ip_addr)) ||
        (FIB_IS_MGMT_NH(p_nh->vrf_id, p_nh))) {
        return DN_HAL_ROUTE_E_NONE;
    }

    HAL_RT_LOG_INFO("HAL-RT-NDI(NH-DEL)",
                    "NH Del: VRF:%d parent VRF:%d Addr: %s, Interface: %d, nh_id %lu RIF-cnt%d",
                    p_nh->vrf_id, p_nh->parent_vrf_id,
                    FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index,
                    p_nh->next_hop_id, hal_rt_rif_ref_get(p_nh->parent_vrf_id, p_nh->key.if_index));

    for (unit = 0; unit < hal_rt_access_fib_config()->max_num_npu; unit++) {
        if ((p_nh->next_hop_id) && (p_nh->vrf_id == p_nh->parent_vrf_id)) {
            rc = ndi_route_next_hop_delete(unit, p_nh->next_hop_id);
            if(rc != STD_ERR_OK) {
                HAL_RT_LOG_ERR("HAL-RT-NDI", "Failed to delete NH. "
                           "Unit: %d VRF:%d NH Addr: %s Interface: %d nh_id: %lu RIF-cnt: %d Err: %d",
                           unit, p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                           p_nh->key.if_index, p_nh->next_hop_id,
                           hal_rt_rif_ref_get(p_nh->vrf_id, p_nh->key.if_index), rc);
                return DN_HAL_ROUTE_E_FAIL;
            }
            if(!hal_rt_rif_ref_dec(p_nh->parent_vrf_id, p_nh->key.if_index))
                hal_rif_index_remove(0, p_nh->parent_vrf_id, p_nh->key.if_index);
            p_nh->next_hop_id = 0;
        }
    }

    return DN_HAL_ROUTE_E_NONE;
}

dn_hal_route_err hal_fib_host_del (uint32_t vrf_id, t_fib_nh *p_fh)
{
    dn_hal_route_err   rc;

    HAL_RT_LOG_INFO("HAL-RT-NDI(ARP-END)", "NPU host del - VRF %d. Addr: %s, Interface: %d",
                    vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr), p_fh->key.if_index);

    if((rc = hal_fib_validate_nh_params(vrf_id, p_fh)) != DN_HAL_ROUTE_E_NONE){
        return (rc);
    }

    if (FIB_IS_FH_IP_TUNNEL (p_fh)) {
        /* This will handle the tunnel case specially */
        rc = hal_fib_tunnel_remote_host_del (p_fh);
        return (rc);
    }

    rc = _hal_fib_host_del (vrf_id, p_fh);
    return rc;
}

t_std_error hal_form_nbr_entry(ndi_neighbor_t *p_nbr_entry, t_fib_nh *p_nh)
{
    if(STD_IP_IS_ADDR_ZERO(&p_nh->key.ip_addr))
        return STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0);

    if(p_nh->key.ip_addr.af_index == HAL_RT_V4_AFINDEX) {
        memcpy(&(p_nbr_entry->ip_addr.u.v4_addr), &(p_nh->key.ip_addr.u.v4_addr), HAL_RT_V4_ADDR_LEN);
    } else {
        memcpy(&(p_nbr_entry->ip_addr.u.v6_addr), &(p_nh->key.ip_addr.u.v6_addr), HAL_RT_V6_ADDR_LEN);
    }
    p_nbr_entry->ip_addr.af_index = p_nh->key.ip_addr.af_index;

    if (p_nh->p_arp_info) {
        memcpy(&(p_nbr_entry->egress_data.neighbor_mac), &(p_nh->p_arp_info->mac_addr), HAL_RT_MAC_ADDR_LEN);
        p_nbr_entry->egress_data.vlan_id  = p_nh->p_arp_info->vlan_id;

        /* Dont program the link local in the host table, set the state as NDI_NEIGHBOR_ENTRY_NO_HOST_ROUTE
         * for NDI to add SAI_NEIGHBOR_ENTRY_ATTR_NO_HOST_ROUTE */
        if (STD_IP_IS_ADDR_LINK_LOCAL(&(p_nh->key.ip_addr)) ||
            std_is_ip_v4_linklocal_addr(&(p_nh->key.ip_addr))) {
            p_nbr_entry->state = NDI_NEIGHBOR_ENTRY_NO_HOST_ROUTE;
        } else if (p_nh->p_arp_info->state != 0) {
            p_nbr_entry->state  = (uint32_t)p_nh->p_arp_info->state;
        } else {
            HAL_RT_LOG_ERR("HAL-RT-NDI", "ARP state is invalid!");
            return STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0);
        }

        interface_ctrl_t intf_ctrl;
        memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
        intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
        intf_ctrl.if_index = p_nh->p_arp_info->if_index;

        if ((dn_hal_get_interface_info(&intf_ctrl)) == STD_ERR_OK) {
            p_nbr_entry->egress_data.port_tgid = intf_ctrl.port_id;
        }
    }

    return STD_ERR_OK;

}

inline void hal_dump_nbr_entry(ndi_neighbor_t *p_nbr_entry)
{
    char           p_buf[HAL_RT_MAX_BUFSZ];
    HAL_RT_LOG_DEBUG( "HAL-RT-NDI", "VRF %lu. Nbr Addr: %s "
                 "npu_id %d, port %d Rif 0x%lx MAC %s state %d action %d",
                 p_nbr_entry->vrf_id, FIB_IP_ADDR_TO_STR(&(p_nbr_entry->ip_addr)),
                 p_nbr_entry->npu_id, p_nbr_entry->egress_data.port_tgid,
                 p_nbr_entry->rif_id, hal_rt_mac_to_str (&p_nbr_entry->egress_data.neighbor_mac,
                                                         p_buf, HAL_RT_MAX_BUFSZ),
                 p_nbr_entry->state, p_nbr_entry->action);
}

dn_hal_route_err _hal_fib_host_add (uint32_t vrf_id, t_fib_nh *p_fh)
{
    npu_id_t       unit;
    int            rc = STD_ERR_OK;
    bool           error_occured = false;
    ndi_neighbor_t nbr_entry;
    char           p_buf[HAL_RT_MAX_BUFSZ];
    ndi_route_action       action = NDI_ROUTE_PACKET_ACTION_FORWARD;

    if ((FIB_IS_NH_LOOP_BACK (p_fh)) || (FIB_IS_NH_ZERO (p_fh))) {
        rc = hal_fib_reserved_host_add (vrf_id, p_fh);
        return (rc);
    }

    if (p_fh->p_arp_info != NULL) {
        HAL_RT_LOG_INFO("RT-HOST-NDI", "NPU host add - VRF:%d parent VRF:%d nbr: %s p_arp_info - vlan_id: %d, mac_addr: %s, "
                        "state: %d, port: %d status:0x%x", vrf_id, p_fh->parent_vrf_id,
                        FIB_IP_ADDR_TO_STR(&(p_fh->key.ip_addr)), p_fh->p_arp_info->vlan_id,
                        hal_rt_mac_to_str (&p_fh->p_arp_info->mac_addr, p_buf, HAL_RT_MAX_BUFSZ),
                        p_fh->p_arp_info->state, p_fh->p_arp_info->if_index, p_fh->p_arp_info->arp_status);
        if(hal_rt_is_mac_address_zero((const hal_mac_addr_t *)p_fh->p_arp_info->mac_addr)) {
            if (p_fh->p_arp_info->arp_status & RT_NUD_INCOMPLETE) {
                /* ARP resolve in progress, drop the packets destined to this NH */
                action = NDI_ROUTE_PACKET_ACTION_DROP;
            } else {
                /* There is no ARP resolve triggered by kernel yet, delete the NH created */
                _hal_fib_host_del (vrf_id, p_fh);
                return DN_HAL_ROUTE_E_NONE;
            }
        }
    } else {
        HAL_RT_LOG_DEBUG("HOST-NDI", "VRF %d.Arp info null!", vrf_id);
        return rc;
    }

    if ((STD_IP_IS_ADDR_LINK_LOCAL(&(p_fh->key.ip_addr)) == false) &&
        (std_is_ip_v4_linklocal_addr(&(p_fh->key.ip_addr)) == false)) {

        t_fib_nh *p_nh = fib_get_next_nh(vrf_id, &(p_fh->key.ip_addr),0);
        while (p_nh && (FIB_IS_NH_WRITTEN (p_nh)) && (p_nh->p_arp_info) &&
               (memcmp(&(p_nh->key.ip_addr), &(p_fh->key.ip_addr), sizeof(t_fib_ip_addr)) == 0)) {

            if (p_nh->p_arp_info->if_index != p_fh->p_arp_info->if_index) {
                /* The programmed nbr is associated with different interface, delete it. */
                _hal_fib_host_del (vrf_id, p_nh);
            }
            p_nh = fib_get_next_nh (vrf_id, &p_nh->key.ip_addr, p_nh->key.if_index);
        }
    }
    memset(&nbr_entry, 0, sizeof(ndi_neighbor_t));

    if (hal_form_nbr_entry(&nbr_entry, p_fh) != STD_ERR_OK) {
        HAL_RT_LOG_DEBUG("HOST-NDI", "NBR Entry zero!.");
        return DN_HAL_ROUTE_E_FAIL;
    }

    for (unit = 0; unit < hal_rt_access_fib_config()->max_num_npu; unit++) {
        if (action != NDI_ROUTE_PACKET_ACTION_FORWARD)
        {
            /* Incase of blackhole host entry add, dont send the zero MAC as it's not accepted by the SAI */
            memset(&(nbr_entry.egress_data.neighbor_mac), 0xFF, HAL_RT_MAC_ADDR_LEN);
        }

        nbr_entry.npu_id = unit;
        nbr_entry.vrf_id = hal_vrf_obj_get(unit, vrf_id);
        nbr_entry.action = action;
        if (hal_rif_index_get_or_create(unit, p_fh->parent_vrf_id, p_fh->key.if_index,
                                        &nbr_entry.rif_id) != STD_ERR_OK) {
            HAL_RT_LOG_ERR("HOST-NDI", "RIF creation failed: VRF:%d host: %s mac_addr: %s, state: %d, port: %d "
                           "status:0x%x action: %d", p_fh->parent_vrf_id, FIB_IP_ADDR_TO_STR(&(p_fh->key.ip_addr)),
                           hal_rt_mac_to_str (&p_fh->p_arp_info->mac_addr, p_buf, HAL_RT_MAX_BUFSZ),
                           p_fh->p_arp_info->state, p_fh->p_arp_info->if_index, p_fh->p_arp_info->arp_status,
                           action);
            return DN_HAL_ROUTE_E_FAIL;
        }

        hal_dump_nbr_entry(&nbr_entry);
        if(!p_fh->a_is_written [unit]) {
            rc = ndi_route_neighbor_add(&nbr_entry);
            if(rc != STD_ERR_OK) {
                error_occured = true;
            } else {
                p_fh->a_is_written [unit] = true;
                hal_rt_rif_ref_inc(p_fh->parent_vrf_id, p_fh->key.if_index);
                HAL_RT_LOG_INFO("HOST-NDI", "VRF:%d(0x%lx) parent VRF :%d Host: %s mac_addr: %s, state: %d, port: %d "
                                "status:0x%x NPU status:%d unit:%d rif:0x%lx action: %s added successfully",
                                vrf_id, nbr_entry.vrf_id, p_fh->parent_vrf_id, FIB_IP_ADDR_TO_STR(&(p_fh->key.ip_addr)),
                                hal_rt_mac_to_str (&p_fh->p_arp_info->mac_addr, p_buf, HAL_RT_MAX_BUFSZ),
                                p_fh->p_arp_info->state, p_fh->p_arp_info->if_index, p_fh->p_arp_info->arp_status,
                                p_fh->a_is_written [unit], unit, nbr_entry.rif_id,
                                ((action == NDI_ROUTE_PACKET_ACTION_FORWARD) ? "Forward" :
                                 ((action == NDI_ROUTE_PACKET_ACTION_DROP) ? "Drop" : "TrapToCPU")));
            }
        } else {
            rc = ndi_route_neighbor_delete(&nbr_entry);
            if(rc != STD_ERR_OK) {
                HAL_RT_LOG_ERR("HOST-NDI", "VRF:%d(0x%lx) parent VRF:%d Host: %s mac_addr: %s, state: %d, port: %d "
                               "status:0x%x NPU status:%d unit:%d rif:0x%lx action: %s del failed",
                               vrf_id, nbr_entry.vrf_id, p_fh->parent_vrf_id, FIB_IP_ADDR_TO_STR(&(p_fh->key.ip_addr)),
                               hal_rt_mac_to_str (&p_fh->p_arp_info->mac_addr, p_buf, HAL_RT_MAX_BUFSZ),
                               p_fh->p_arp_info->state, p_fh->p_arp_info->if_index, p_fh->p_arp_info->arp_status,
                               p_fh->a_is_written [unit], unit, nbr_entry.rif_id,
                               ((action == NDI_ROUTE_PACKET_ACTION_FORWARD) ? "Forward" :
                                ((action == NDI_ROUTE_PACKET_ACTION_DROP) ? "Drop" : "TrapToCPU")));
            }
            rc = ndi_route_neighbor_add(&nbr_entry);
            if(rc != STD_ERR_OK) {
                error_occured = true;
            } else {
                HAL_RT_LOG_INFO("HOST-NDI", "vrf_id:%d(0x%lx) parent VRF:%d Host: %s mac_addr: %s, state: %d, port: %d "
                                "status:0x%x NPU status:%d unit:%d rif:0x%lx action: %s replaced successfully",
                                vrf_id, nbr_entry.vrf_id, p_fh->parent_vrf_id, FIB_IP_ADDR_TO_STR(&(p_fh->key.ip_addr)),
                                hal_rt_mac_to_str (&p_fh->p_arp_info->mac_addr, p_buf, HAL_RT_MAX_BUFSZ),
                                p_fh->p_arp_info->state, p_fh->p_arp_info->if_index, p_fh->p_arp_info->arp_status,
                                p_fh->a_is_written [unit], unit, nbr_entry.rif_id,
                                ((action == NDI_ROUTE_PACKET_ACTION_FORWARD) ? "Forward" :
                                 ((action == NDI_ROUTE_PACKET_ACTION_DROP) ? "Drop" : "TrapToCPU")));
            }
        }
        if (error_occured == true) {
            HAL_RT_LOG_ERR("HOST-NDI", "Failed to add : vrf:%d(0x%lx) parent VRF:%d host: %s mac_addr: %s, state: %d, port: %d "
                           "status:0x%x NPU status:%d unit:%d rif:0x%lx action: %s Err %d",
                           vrf_id, nbr_entry.vrf_id, p_fh->parent_vrf_id, FIB_IP_ADDR_TO_STR(&(p_fh->key.ip_addr)),
                           hal_rt_mac_to_str (&p_fh->p_arp_info->mac_addr, p_buf, HAL_RT_MAX_BUFSZ),
                           p_fh->p_arp_info->state, p_fh->p_arp_info->if_index, p_fh->p_arp_info->arp_status,
                           p_fh->a_is_written [unit], unit, nbr_entry.rif_id,
                           ((action == NDI_ROUTE_PACKET_ACTION_FORWARD) ? "Forward" :
                            ((action == NDI_ROUTE_PACKET_ACTION_DROP) ? "Drop" : "TrapToCPU")), rc);


            _hal_fib_host_del (vrf_id, p_fh);
            return DN_HAL_ROUTE_E_FAIL;
        } else {
            /* If the action is forward, consider this NH as resolved */
            nas_rt_handle_dest_change(NULL, p_fh,
                                      (action == NDI_ROUTE_PACKET_ACTION_FORWARD));
            fib_prg_nbr_to_leaked_vrfs_on_parent_nbr_update(p_fh, true);
        }
    }

    return DN_HAL_ROUTE_E_NONE;
}

dn_hal_route_err _hal_fib_host_del (uint32_t vrf_id, t_fib_nh *p_fh)
{
    npu_id_t       unit;
    t_std_error    rc = STD_ERR_OK;
    ndi_neighbor_t nbr_entry;

    HAL_RT_LOG_DEBUG("HOST-NDI", "VRF %d.", vrf_id);

    if ((FIB_IS_NH_LOOP_BACK (p_fh)) || (FIB_IS_NH_ZERO (p_fh))) {
        return (hal_fib_reserved_host_del (vrf_id, p_fh));
    }

    memset(&nbr_entry, 0, sizeof(ndi_neighbor_t));
    if (hal_form_nbr_entry(&nbr_entry, p_fh) != STD_ERR_OK) {
        HAL_RT_LOG_DEBUG("HOST-NDI", "NBR Entry zero!.");
    }

    for (unit = 0; unit < hal_rt_access_fib_config()->max_num_npu; unit++) {
        if (p_fh->a_is_written [unit] == false) {
            HAL_RT_LOG_INFO("HOST-NDI", "Host entry not present in "
                           "Unit %d, Vrf_id: %d.", unit, vrf_id);
            continue;
        }

        if (FIB_IS_NH_LOOP_BACK (p_fh) || (FIB_IS_NH_ZERO (p_fh))) {
            /* Loopback and Zero NHs will not be written in hardware */
            rc = STD_ERR_OK;
        } else {
            nbr_entry.npu_id = unit;
            nbr_entry.vrf_id = hal_vrf_obj_get(unit, vrf_id);
            nbr_entry.rif_id = hal_rif_id_get(unit, p_fh->parent_vrf_id, p_fh->key.if_index);
            if (nbr_entry.rif_id == 0) {
                HAL_RT_LOG_ERR("HOST-NDI", "RIF does not exist! Vrf_id: %d, "
                               "host: %s intf: %d Unit: %d", vrf_id,
                               FIB_IP_ADDR_TO_STR(&(p_fh->key.ip_addr)), p_fh->key.if_index,
                               unit);
            }
            hal_dump_nbr_entry(&nbr_entry);
            rc = ndi_route_neighbor_delete(&nbr_entry);
            if(rc != STD_ERR_OK) {
                HAL_RT_LOG_ERR("HOST-NDI", "Failed to delete Vrf_id: %d(0x%lx), "
                               "host: %s intf: %d rif:0x%lx Unit: %d. Err: %d ", vrf_id, nbr_entry.vrf_id,
                               FIB_IP_ADDR_TO_STR(&(p_fh->key.ip_addr)), p_fh->key.if_index, nbr_entry.rif_id,
                               unit, rc);
            } else {
                HAL_RT_LOG_INFO("HOST-NDI", "Vrf_id: %d (0x%lx), "
                                "host: %s intf: %d rif:0x%lx Unit: %d deleted successfully", vrf_id, nbr_entry.vrf_id,
                                FIB_IP_ADDR_TO_STR(&(p_fh->key.ip_addr)), p_fh->key.if_index, nbr_entry.rif_id,
                                unit);
                nas_rt_handle_dest_change(NULL, p_fh, false);
                fib_prg_nbr_to_leaked_vrfs_on_parent_nbr_update(p_fh, false);
            }

            if(!hal_rt_rif_ref_dec(p_fh->parent_vrf_id, p_fh->key.if_index))
                hal_rif_index_remove(unit, p_fh->parent_vrf_id, p_fh->key.if_index);
        }
        p_fh->a_is_written [unit] = false;
    }

    return DN_HAL_ROUTE_E_NONE;
}

dn_hal_route_err hal_fib_reserved_host_add (uint32_t vrf_id, t_fib_nh *p_fh)
{
    npu_id_t  unit;

    HAL_RT_LOG_DEBUG("HAL-RT-NDI", "VRF %d.", vrf_id);

    //@Todo reserved host addition

    for (unit = 0; unit < hal_rt_access_fib_config()->max_num_npu; unit++) {

        p_fh->a_is_written [unit] = true;
    }
    return (DN_HAL_ROUTE_E_NONE);
}

dn_hal_route_err hal_fib_reserved_host_del (uint32_t vrf_id, t_fib_nh *p_fh)
{
    npu_id_t  unit;

    HAL_RT_LOG_DEBUG("HAL-RT-NDI", "VRF %d.", vrf_id);

    //@Todo reserved host deletion

    for (unit = 0; unit < hal_rt_access_fib_config()->max_num_npu; unit++) {
        p_fh->a_is_written [unit] = false;
    }
    return DN_HAL_ROUTE_E_NONE;
}

dn_hal_route_err hal_fib_validate_tunnel_params (t_fib_nh *p_nh)
{
    if (!(FIB_IS_FH_IP_TUNNEL (p_nh))) {
        HAL_RT_LOG_ERR("HAL-RT-NDI", "%s (): Not a tunnel FH.", __FUNCTION__);
        return DN_HAL_ROUTE_E_PARAM;
    }

    /* Check if RTM has sent a route with the tunnel NH */
    if (!(FIB_IS_NH_OWNER_RTM (p_nh))) {
        HAL_RT_LOG_ERR("HAL-RT-NDI", "%s (): RTM not NH owner.", __FUNCTION__);
        return DN_HAL_ROUTE_E_PARAM;
    }

    if (FIB_IS_NH_ZERO (p_nh)) {
        /* receive-only tunnel */
        HAL_RT_LOG_ERR("HAL-RT-NDI", "%s (): Tunnel FH is receive-only type.",
                   __FUNCTION__);
        return DN_HAL_ROUTE_E_PARAM;
    }
    return DN_HAL_ROUTE_E_NONE;
}

dn_hal_route_err hal_fib_tunnel_remote_host_add (t_fib_nh *p_nh)
{
    void             *p_hal_nh_handle = NULL;
    t_fib_nh         *p_fh = NULL;
    t_fib_nh_holder   nh_holder;
    npu_id_t          unit;
    t_fib_tunnel_fh  *p_tunnel_fh = NULL;
    dn_hal_route_err  rc;

    HAL_RT_LOG_DEBUG("HAL-RT-NDI", "Interface: %d", p_nh->key.if_index);

    if((rc = hal_fib_validate_tunnel_params(p_nh)) != DN_HAL_ROUTE_E_NONE){
        return (rc);
    }

    for (unit = 0; unit < hal_rt_access_fib_config()->max_num_npu; unit++) {
        FIB_FOR_EACH_FH_FROM_TUNNEL_NH (p_nh, p_fh, nh_holder) {
            HAL_RT_LOG_DEBUG("HAL-RT-NDI", "FH Addr:  Interface: %d",
                         p_fh->key.if_index);
            p_tunnel_fh  = FIB_GET_TUNNEL_NHFH_NODE_FROM_NH_HOLDER (nh_holder);
            p_hal_nh_handle = (void *) p_tunnel_fh->p_hal_nh_handle;

            if (p_fh->tunnel_nh_ref_count == 0) {
                HAL_RT_LOG_ERR("HAL-RT-NDI", "%s () FH is marked for deletion.",
                           __FUNCTION__);
                continue;
            }
            if(p_hal_nh_handle) {
                // @TODO
                /* Handle tunnel Egress case */
            }
        }
    }/* End of for loop */

    return DN_HAL_ROUTE_E_NONE;
}

dn_hal_route_err hal_fib_tunnel_remote_host_del (t_fib_nh *p_nh)
{
    void            *p_hal_nh_handle = NULL;
    t_fib_nh        *p_fh = NULL;
    t_fib_nh_holder  nh_holder;
    npu_id_t         unit;
    t_fib_tunnel_fh *p_tunnel_fh = NULL;
    dn_hal_route_err  rc;

    HAL_RT_LOG_DEBUG("HAL-RT-NDI", "Addr: %s, Interface Index: %d",
                 FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index);

    if((rc = hal_fib_validate_tunnel_params(p_nh)) != DN_HAL_ROUTE_E_NONE){
        return (rc);
    }

    for (unit = 0; unit < hal_rt_access_fib_config()->max_num_npu; unit++) {
        FIB_FOR_EACH_FH_FROM_TUNNEL_NH (p_nh, p_fh, nh_holder) {
            HAL_RT_LOG_DEBUG("HAL-RT-NDI", "Interface: %d", p_fh->key.if_index);

            p_tunnel_fh  = FIB_GET_TUNNEL_NHFH_NODE_FROM_NH_HOLDER (nh_holder);
            p_hal_nh_handle = (void *) p_tunnel_fh->p_hal_nh_handle;

            if(p_hal_nh_handle) {
                // @TODO
                /* Handle tunnel Egress case */
            }
        }
    }   /* End of for loop */

    return DN_HAL_ROUTE_E_NONE;
}
