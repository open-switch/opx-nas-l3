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
        HAL_RT_LOG_ERR("HAL-RT-NDI", "%s () p_fh->p_arp_info is NULL. VrfId: %d.\r\n",
                   __FUNCTION__, vrf_id);
        return DN_HAL_ROUTE_E_FAIL;
    }

    return DN_HAL_ROUTE_E_NONE;
}

dn_hal_route_err hal_fib_host_add (uint32_t vrf_id, t_fib_nh *p_fh)
{
    dn_hal_route_err rc;

    HAL_RT_LOG_DEBUG("HAL-RT-NDI", "VRF %d. Addr: %s, Interface id: %d\r\n",
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

    HAL_RT_LOG_DEBUG("HAL-RT-NDI(NH-Add)","NH Add: Addr: %s, Interface: %d, nh_id %d\r\n",
                 FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index, p_nh->next_hop_id);

    for (npu_id = 0; npu_id < hal_rt_access_fib_config()->max_num_npu; npu_id++) {
        if(p_nh->next_hop_id == 0) {
            rif_id = hal_rif_index_get(npu_id, p_nh->vrf_id, p_nh->key.if_index);
            HAL_RT_LOG_DEBUG("HAL-RT-NDI",
                         "NH Group: RIF ID %d!" "Vrf_id: %d.\r\n",
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
            }
        }
    }

    return DN_HAL_ROUTE_E_NONE;
}


dn_hal_route_err hal_fib_next_hop_del(t_fib_nh *p_nh)
{
    t_std_error rc = STD_ERR_OK;
    npu_id_t    unit;

    HAL_RT_LOG_INFO("HAL-RT-NDI(ARP-END)",
                 "NH Del: Addr: %s, Interface: %d, nh_id %d\r\n",
                  FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index, p_nh->next_hop_id);

    for (unit = 0; unit < hal_rt_access_fib_config()->max_num_npu; unit++) {
        if(p_nh->next_hop_id) {
            rc = ndi_route_next_hop_delete(unit, p_nh->next_hop_id);
            if(rc != STD_ERR_OK) {
                HAL_RT_LOG_ERR("HAL-RT-NDI", "%s (): Failed to delete NH. "
                           "Unit: %d. Err: %d nh id %d\r\n",
                           __FUNCTION__, unit, rc, p_nh->next_hop_id);
                return DN_HAL_ROUTE_E_FAIL;
            }
            if(!hal_rt_rif_ref_dec(p_nh->key.if_index))
                hal_rif_index_remove(0, p_nh->vrf_id, p_nh->key.if_index);
        }
    }

    return DN_HAL_ROUTE_E_NONE;
}

dn_hal_route_err hal_fib_host_del (uint32_t vrf_id, t_fib_nh *p_fh)
{
    dn_hal_route_err   rc;

    HAL_RT_LOG_INFO("HAL-RT-NDI(ARP-END)", "NPU host del - VRF %d. Addr: %s, Interface: %d\r\n",
                    vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr), p_fh->key.if_index);

    if((rc = hal_fib_validate_nh_params(vrf_id, p_fh)) != DN_HAL_ROUTE_E_NONE){
        return (rc);
    }

    if (FIB_IS_FH_IP_TUNNEL (p_fh)) {
        /* This will handle the tunnel case specially */
        rc = hal_fib_tunnel_remote_host_del (p_fh);
        return (rc);
    }

    rc = _hal_fib_host_del (vrf_id, p_fh, false);
    return rc;
}

t_std_error hal_form_nbr_entry(ndi_neighbor_t *p_nbr_entry, t_fib_nh *p_nh)
{
    interface_ctrl_t intf_ctrl;

    if (p_nh->p_arp_info) {
        memcpy(&(p_nbr_entry->egress_data.neighbor_mac), &(p_nh->p_arp_info->mac_addr), HAL_RT_MAC_ADDR_LEN);
        p_nbr_entry->egress_data.vlan_id  = p_nh->p_arp_info->vlan_id;
        p_nbr_entry->state  = (uint32_t)p_nh->p_arp_info->state;
    }

    if(STD_IP_IS_ADDR_ZERO(&p_nh->key.ip_addr)) {
        return STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0);
    }

    if(p_nh->key.ip_addr.af_index == HAL_RT_V4_AFINDEX) {
        memcpy(&(p_nbr_entry->ip_addr.u.v4_addr), &(p_nh->key.ip_addr.u.v4_addr), HAL_RT_V4_ADDR_LEN);
    } else {
        memcpy(&(p_nbr_entry->ip_addr.u.v6_addr), &(p_nh->key.ip_addr.u.v6_addr), HAL_RT_V6_ADDR_LEN);
    }
    p_nbr_entry->ip_addr.af_index = p_nh->key.ip_addr.af_index;

    if (p_nh->p_arp_info) {
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
    HAL_RT_LOG_DEBUG( "HAL-RT-NDI", "VRF %d. Nbr Addr: %s "
                 "npu_id %d, port %d Rif %d MAC %s state %d action %d\r\n",
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
    cps_api_operation_types_t op = cps_api_oper_CREATE;

    if (p_fh->p_arp_info != NULL) {
        HAL_RT_LOG_INFO("HAL-RT-NDI", "NPU host add - nbr: %s p_arp_info - vlan_id: %d, mac_addr: %s, "
                        "state: %d, port: %d status:0x%x\r\n",
                        FIB_IP_ADDR_TO_STR(&(p_fh->key.ip_addr)), p_fh->p_arp_info->vlan_id,
                        hal_rt_mac_to_str (&p_fh->p_arp_info->mac_addr, p_buf, HAL_RT_MAX_BUFSZ),
                        p_fh->p_arp_info->state, p_fh->p_arp_info->if_index, p_fh->p_arp_info->arp_status);
        if(hal_rt_is_mac_address_zero((const hal_mac_addr_t *)p_fh->p_arp_info->mac_addr)) {
            if (p_fh->p_arp_info->arp_status & RT_NUD_INCOMPLETE) {
                /* ARP resolve in progress, drop the packets destined to this NH */
                action = NDI_ROUTE_PACKET_ACTION_DROP;
            } else {
                /* There is no ARP resolve triggered by kernel yet, delete the NH created */
                _hal_fib_host_del (vrf_id, p_fh, error_occured);
                return DN_HAL_ROUTE_E_NONE;
            }
        }
    } else {
        HAL_RT_LOG_DEBUG("HAL-RT-NDI", "VRF %d.Arp info null!\r\n", vrf_id);
        return rc;
    }

    if ((FIB_IS_NH_LOOP_BACK (p_fh)) || (FIB_IS_NH_ZERO (p_fh))) {
        rc = hal_fib_reserved_host_add (vrf_id, p_fh);
        return (rc);
    }

    memset(&nbr_entry, 0, sizeof(ndi_neighbor_t));

    if (hal_form_nbr_entry(&nbr_entry, p_fh) != STD_ERR_OK) {
        HAL_RT_LOG_DEBUG("HAL-RT-NDI", "NBR Entry zero!.\r\n");
        return DN_HAL_ROUTE_E_FAIL;
    }

    for (unit = 0; unit < hal_rt_access_fib_config()->max_num_npu; unit++) {
        if (action != NDI_ROUTE_PACKET_ACTION_FORWARD)
        {
            /* Incase of blackhole host entry add, dont send the zero MAC as it's not accepted by the SAI */
            memset(&(nbr_entry.egress_data.neighbor_mac), 0xFF, HAL_RT_MAC_ADDR_LEN);
        }

        nbr_entry.npu_id = unit;
        nbr_entry.action = action;
        nbr_entry.rif_id = hal_rif_index_get(unit, vrf_id, p_fh->key.if_index);
        hal_dump_nbr_entry(&nbr_entry);
        if(!p_fh->a_is_written [unit]) {
            rc = ndi_route_neighbor_add(&nbr_entry);
            if(rc != STD_ERR_OK) {
                error_occured = true;
            } else {
                p_fh->a_is_written [unit] = true;
                hal_rt_rif_ref_inc(p_fh->key.if_index);
                HAL_RT_LOG_INFO("HAL-RT-NDI", "Host: %s mac_addr: %s, state: %d, port: %d "
                                "status:0x%x NPU status:%d rif:%d unit:%d action: %s added successfully\r\n",
                                FIB_IP_ADDR_TO_STR(&(p_fh->key.ip_addr)),
                                hal_rt_mac_to_str (&p_fh->p_arp_info->mac_addr, p_buf, HAL_RT_MAX_BUFSZ),
                                p_fh->p_arp_info->state, p_fh->p_arp_info->if_index, p_fh->p_arp_info->arp_status,
                                p_fh->a_is_written [0], unit, nbr_entry.rif_id,
                                ((action == NDI_ROUTE_PACKET_ACTION_FORWARD) ? "Forward" :
                                 ((action == NDI_ROUTE_PACKET_ACTION_DROP) ? "Drop" : "TrapToCPU")));
            }
        } else {
            rc = ndi_route_neighbor_delete(&nbr_entry);
            if(rc != STD_ERR_OK) {
                HAL_RT_LOG_DEBUG("HAL-RT-NDI", "Nbr delete failed\r\n");
            }
            rc = ndi_route_neighbor_add(&nbr_entry);
            if(rc != STD_ERR_OK) {
                error_occured = true;
            } else {
                HAL_RT_LOG_INFO("HAL-RT-NDI", "Host: %s mac_addr: %s, state: %d, port: %d "
                                "status:0x%x NPU status:%d rif:%d unit:%d action: %s replaced successfully\r\n",
                                FIB_IP_ADDR_TO_STR(&(p_fh->key.ip_addr)),
                                hal_rt_mac_to_str (&p_fh->p_arp_info->mac_addr, p_buf, HAL_RT_MAX_BUFSZ),
                                p_fh->p_arp_info->state, p_fh->p_arp_info->if_index, p_fh->p_arp_info->arp_status,
                                p_fh->a_is_written [0], unit, nbr_entry.rif_id,
                                ((action == NDI_ROUTE_PACKET_ACTION_FORWARD) ? "Forward" :
                                 ((action == NDI_ROUTE_PACKET_ACTION_DROP) ? "Drop" : "TrapToCPU")));
            }
            op = cps_api_oper_SET;
        }
    }
    if (error_occured == true) {
        HAL_RT_LOG_ERR("HAL-RT-NDI", "Failed to add : host: %s mac_addr: %s, state: %d, port: %d "
                       "status:0x%x NPU status:%d action: %d Err %d\r\n", FIB_IP_ADDR_TO_STR(&(p_fh->key.ip_addr)),
                       hal_rt_mac_to_str (&p_fh->p_arp_info->mac_addr, p_buf, HAL_RT_MAX_BUFSZ),
                       p_fh->p_arp_info->state, p_fh->p_arp_info->if_index, p_fh->p_arp_info->arp_status,
                       p_fh->a_is_written [0], action, rc);
        /* Send error ocurred TRUE to publish the NPU program error to app */
        _hal_fib_host_del (vrf_id, p_fh, error_occured);
        return DN_HAL_ROUTE_E_FAIL;
    } else {
        if (action == NDI_ROUTE_PACKET_ACTION_FORWARD) {
            /* If the action is forward, consider this NH as resolved */
            nas_rt_handle_dest_change(NULL, p_fh, true);
        } else {
            nas_rt_handle_dest_change(NULL, p_fh, false);
        }
    }
    cps_api_object_t obj = nas_route_nh_to_arp_cps_object(p_fh, op);
    if(obj && (nas_route_publish_object(obj)!= STD_ERR_OK)){
        HAL_RT_LOG_ERR("HAL-RT-DR","Failed to publish neighbor entry");
    }

    return DN_HAL_ROUTE_E_NONE;
}

dn_hal_route_err _hal_fib_host_del (uint32_t vrf_id, t_fib_nh *p_fh, bool error_occured)
{
    npu_id_t       unit;
    t_std_error    rc = STD_ERR_OK;
    ndi_neighbor_t nbr_entry;

    HAL_RT_LOG_DEBUG("HAL-RT-NDI", "VRF %d.\r\n", vrf_id);

    if ((FIB_IS_NH_LOOP_BACK (p_fh)) || (FIB_IS_NH_ZERO (p_fh))) {
        return (hal_fib_reserved_host_del (vrf_id, p_fh));
    }

    memset(&nbr_entry, 0, sizeof(ndi_neighbor_t));
    if (hal_form_nbr_entry(&nbr_entry, p_fh) != STD_ERR_OK) {
        HAL_RT_LOG_DEBUG("HAL-RT-NDI", "NBR Entry zero!.\r\n");
    }

    for (unit = 0; unit < hal_rt_access_fib_config()->max_num_npu; unit++) {
        if (p_fh->a_is_written [unit] == false) {
            HAL_RT_LOG_DEBUG("HAL-RT-NDI", "Host entry not present in "
                       "Unit %d, Vrf_id: %d.", unit, vrf_id);
            continue;
        }

        if (FIB_IS_NH_LOOP_BACK (p_fh) || (FIB_IS_NH_ZERO (p_fh))) {
            /* Loopback and Zero NHs will not be written in hardware */
            rc = STD_ERR_OK;
        } else {
            nbr_entry.npu_id = unit;
            nbr_entry.rif_id = hal_rif_index_get(unit, vrf_id, p_fh->key.if_index);
            hal_dump_nbr_entry(&nbr_entry);
            rc = ndi_route_neighbor_delete(&nbr_entry);
            if(rc != STD_ERR_OK) {
                HAL_RT_LOG_ERR("HAL-RT-NDI", "Failed to delete Vrf_id: %d, "
                               "host: %s intf: %d Unit: %d. Err: %d \r\n", vrf_id,
                               FIB_IP_ADDR_TO_STR(&(p_fh->key.ip_addr)), p_fh->key.if_index,
                               unit, rc);
            } else {
                HAL_RT_LOG_INFO("HAL-RT-NDI", "Vrf_id: %d, "
                                "host: %s intf: %d Unit: %d deleted successfully\r\n", vrf_id,
                                FIB_IP_ADDR_TO_STR(&(p_fh->key.ip_addr)), p_fh->key.if_index,
                                unit);
                nas_rt_handle_dest_change(NULL, p_fh, false);
            }


            if(!hal_rt_rif_ref_dec(p_fh->key.if_index))
                hal_rif_index_remove(unit, vrf_id, p_fh->key.if_index);
        }
        p_fh->a_is_written [unit] = false;
    }
    /* If error occured is set, publish the ARP entry as op=create with npu-prg-done false */
    cps_api_object_t obj = nas_route_nh_to_arp_cps_object(p_fh,
                                                          (error_occured ? cps_api_oper_CREATE : cps_api_oper_DELETE));
    if(obj && (nas_route_publish_object(obj)!= STD_ERR_OK)){
        HAL_RT_LOG_ERR("HAL-RT-DR","Failed to publish neighbor entry");
    }

    return DN_HAL_ROUTE_E_NONE;
}

dn_hal_route_err hal_fib_reserved_host_add (uint32_t vrf_id, t_fib_nh *p_fh)
{
    npu_id_t  unit;

    HAL_RT_LOG_DEBUG("HAL-RT-NDI", "VRF %d.\r\n", vrf_id);

    //@Todo reserved host addition

    for (unit = 0; unit < hal_rt_access_fib_config()->max_num_npu; unit++) {

        p_fh->a_is_written [unit] = true;
    }
    return (DN_HAL_ROUTE_E_NONE);
}

dn_hal_route_err hal_fib_reserved_host_del (uint32_t vrf_id, t_fib_nh *p_fh)
{
    npu_id_t  unit;

    HAL_RT_LOG_DEBUG("HAL-RT-NDI", "VRF %d.\r\n", vrf_id);

    //@Todo reserved host deletion

    for (unit = 0; unit < hal_rt_access_fib_config()->max_num_npu; unit++) {
        p_fh->a_is_written [unit] = false;
    }
    return DN_HAL_ROUTE_E_NONE;
}

dn_hal_route_err hal_fib_validate_tunnel_params (t_fib_nh *p_nh)
{
    if (!(FIB_IS_FH_IP_TUNNEL (p_nh))) {
        HAL_RT_LOG_ERR("HAL-RT-NDI", "%s (): Not a tunnel FH.\r\n", __FUNCTION__);
        return DN_HAL_ROUTE_E_PARAM;
    }

    /* Check if RTM has sent a route with the tunnel NH */
    if (!(FIB_IS_NH_OWNER_RTM (p_nh))) {
        HAL_RT_LOG_ERR("HAL-RT-NDI", "%s (): RTM not NH owner.\r\n", __FUNCTION__);
        return DN_HAL_ROUTE_E_PARAM;
    }

    if (FIB_IS_NH_ZERO (p_nh)) {
        /* receive-only tunnel */
        HAL_RT_LOG_ERR("HAL-RT-NDI", "%s (): Tunnel FH is receive-only type.\r\n",
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

    HAL_RT_LOG_DEBUG("HAL-RT-NDI", "Interface: %ld\r\n", p_nh->key.if_index);

    if((rc = hal_fib_validate_tunnel_params(p_nh)) != DN_HAL_ROUTE_E_NONE){
        return (rc);
    }

    for (unit = 0; unit < hal_rt_access_fib_config()->max_num_npu; unit++) {
        FIB_FOR_EACH_FH_FROM_TUNNEL_NH (p_nh, p_fh, nh_holder) {
            HAL_RT_LOG_DEBUG("HAL-RT-NDI", "FH Addr:  Interface: %ld\r\n",
                         p_fh->key.if_index);
            p_tunnel_fh  = FIB_GET_TUNNEL_NHFH_NODE_FROM_NH_HOLDER (nh_holder);
            p_hal_nh_handle = (void *) p_tunnel_fh->p_hal_nh_handle;

            if (p_fh->tunnel_nh_ref_count == 0) {
                HAL_RT_LOG_ERR("HAL-RT-NDI", "%s () FH is marked for deletion.\r\n",
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

    HAL_RT_LOG_DEBUG("HAL-RT-NDI", "Addr: %s, Interface Index: %ld\r\n",
                 FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr), p_nh->key.if_index);

    if((rc = hal_fib_validate_tunnel_params(p_nh)) != DN_HAL_ROUTE_E_NONE){
        return (rc);
    }

    for (unit = 0; unit < hal_rt_access_fib_config()->max_num_npu; unit++) {
        FIB_FOR_EACH_FH_FROM_TUNNEL_NH (p_nh, p_fh, nh_holder) {
            HAL_RT_LOG_DEBUG("HAL-RT-NDI", "Interface: %ld\r\n", p_fh->key.if_index);

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
