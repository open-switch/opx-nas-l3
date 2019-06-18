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
 * \file   hal_rt_main.c
 * \brief  Hal Routing core functionality
 * \date   05-2014
 * \author Prince Sunny & Satish Mynam
 */

#define _GNU_SOURCE

#include "hal_rt_main.h"
#include "hal_rt_mem.h"
#include "hal_rt_route.h"
#include "hal_rt_api.h"
#include "hal_rt_debug.h"
#include "hal_rt_util.h"
#include "nas_rt_api.h"
#include "hal_rt_mpath_grp.h"
#include "hal_if_mapping.h"
#include "nas_switch.h"
#include "std_thread_tools.h"
#include "dell-base-if-linux.h"
#include "std_mac_utils.h"
#include "std_utils.h"
#include "nas_vrf_utils.h"

#include "event_log.h"
#include "cps_api_object_category.h"
#include "cps_api_operation.h"
#include "cps_api_events.h"
#include "cps_class_map.h"
#include "cps_api_object_key.h"
#include "dell-base-ip.h"
#include "os-routing-events.h"
#include "ietf-network-instance.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/**************************************************************************
 *                            GLOBALS
 **************************************************************************/
static std_thread_create_param_t hal_rt_dr_thr;
static std_thread_create_param_t hal_rt_nh_thr;
static std_thread_create_param_t hal_rt_msg_thr;
static std_thread_create_param_t hal_rt_offload_msg_thr;

static t_fib_config      g_fib_config;
static t_fib_gbl_info    g_fib_gbl_info;
static t_fib_vrf        *ga_fib_vrf [FIB_MAX_VRF];

static cps_api_operation_handle_t nas_rt_cps_handle;
static cps_api_operation_handle_t nas_rt_nht_cps_handle;

#define NUM_INT_NAS_RT_CPS_API_THREAD 1
#define NUM_INT_NAS_RT_NHT_CPS_API_THREAD 1

static std_mutex_lock_create_static_init_fast(nas_l3_mutex);

/***************************************************************************
 *                          Private Functions
 ***************************************************************************/

int hal_rt_config_init (void)
{
    /* Init the configs to default values */
    memset (&g_fib_config, 0, sizeof (g_fib_config));
    memset (&g_fib_gbl_info, 0, sizeof (g_fib_gbl_info));
    g_fib_config.max_num_npu          = nas_switch_get_max_npus();
    g_fib_config.ecmp_max_paths       = HAL_RT_MAX_ECMP_PATH;
    g_fib_config.ecmp_path_fall_back  = false;
    g_fib_config.ecmp_hash_sel        = FIB_DEFAULT_ECMP_HASH;

    return STD_ERR_OK;
}

const t_fib_config * hal_rt_access_fib_config(void)
{
    return(&g_fib_config);
}

t_fib_gbl_info * hal_rt_access_fib_gbl_info(void)
{
    return(&g_fib_gbl_info);
}

void nas_l3_lock()
{
    std_mutex_lock(&nas_l3_mutex);
}

void nas_l3_unlock()
{
    std_mutex_unlock(&nas_l3_mutex);
}

t_fib_vrf * hal_rt_access_fib_vrf(uint32_t vrf_id)
{
    return(ga_fib_vrf[vrf_id]);
}

t_fib_vrf_info * hal_rt_access_fib_vrf_info(uint32_t vrf_id, uint8_t af_index)
{
    return(&(ga_fib_vrf[vrf_id]->info[af_index]));
}

t_fib_vrf_cntrs * hal_rt_access_fib_vrf_cntrs(uint32_t vrf_id, uint8_t af_index)
{
    return(&(ga_fib_vrf[vrf_id]->cntrs[af_index]));
}

std_rt_table * hal_rt_access_fib_vrf_dr_tree(uint32_t vrf_id, uint8_t af_index)
{
    return(ga_fib_vrf[vrf_id]->info[af_index].dr_tree);
}

std_rt_table * hal_rt_access_fib_vrf_nh_tree(uint32_t vrf_id, uint8_t af_index)
{
    return(ga_fib_vrf[vrf_id]->info[af_index].nh_tree);
}

std_rt_table * hal_rt_access_fib_vrf_mp_md5_tree(uint32_t vrf_id, uint8_t af_index)
{
    return(ga_fib_vrf[vrf_id]->info[af_index].mp_md5_tree);
}

std_rt_table * hal_rt_access_fib_vrf_nht_tree(uint32_t vrf_id, uint8_t af_index)
{
    return(ga_fib_vrf[vrf_id]->info[af_index].nht_tree);
}


int hal_rt_vrf_init (hal_vrf_id_t vrf_id, const char *vrf_name)
{
    t_fib_vrf      *p_vrf = NULL;
    t_fib_vrf_info *p_vrf_info = NULL;
    uint8_t         af_index = 0;
    ndi_vrf_id_t    ndi_vr_id = 0;
    t_std_error     rc = STD_ERR_OK;

    p_vrf = hal_rt_access_fib_vrf(vrf_id);
    if (p_vrf != NULL) {
        HAL_RT_LOG_ERR("HAL-RT", "VRF %d(%s) already exists!", vrf_id, vrf_name);
        return STD_ERR(ROUTE, FAIL, rc);
    }
    t_fib_gbl_info *gbl_info =  hal_rt_access_fib_gbl_info();
    if (vrf_id != FIB_MGMT_VRF) {
        if (vrf_id == FIB_DEFAULT_VRF) {
            /* Get the BASE MAC only for default VRF initialisation, for all other VRFs, use the local cache. */
            /* Wait for the system MAC to become ready - will also provide trace logs to indicate issues if there are any*/
            nas_switch_wait_for_sys_base_mac(&gbl_info->base_mac_addr);
        }
        if(hal_rt_is_mac_address_zero((const hal_mac_addr_t *)&gbl_info->base_mac_addr)) {
            HAL_RT_LOG_ERR("HAL-RT", "The system MAC is zero, NAS Route VR init failed!");
            return STD_ERR(ROUTE, FAIL, rc);
        }

        if (nas_get_vrf_obj_id_from_vrf_name(vrf_name, &ndi_vr_id) != STD_ERR_OK) {
            HAL_RT_LOG_ERR("HAL-RT", "VRF oid get failed for default VRF!");
            return STD_ERR(ROUTE, FAIL, rc);
        }
    }
    HAL_RT_LOG_INFO("VRF-INIT","VRF:%s obj-id:0x%lx info get!", vrf_name, ndi_vr_id);
    if ((p_vrf = FIB_VRF_MEM_MALLOC ()) == NULL) {
        HAL_RT_LOG_ERR("HAL-RT", "Memory alloc failed.Vrf_id: %d", vrf_id);
        return STD_ERR(ROUTE, FAIL, rc);
    }

    memset (p_vrf, 0, sizeof (t_fib_vrf));
    p_vrf->vrf_id = vrf_id;
    p_vrf->vrf_obj_id = ndi_vr_id;

    memcpy(&p_vrf->router_mac, &gbl_info->base_mac_addr, HAL_MAC_ADDR_LEN);
    ga_fib_vrf[vrf_id] = p_vrf;

    hal_rt_vrf_update(vrf_id, true);

    for (af_index = FIB_MIN_AFINDEX; af_index < FIB_MAX_AFINDEX; af_index++) {
        p_vrf_info = hal_rt_access_fib_vrf_info(vrf_id, af_index);

        p_vrf_info->vrf_id = vrf_id;

        safestrncpy((char*)p_vrf_info->vrf_name, vrf_name, sizeof(p_vrf_info->vrf_name));
        p_vrf_info->af_index = af_index;

        /* Create the DR Tree */
        fib_create_dr_tree (p_vrf_info);

        HAL_RT_LOG_INFO("VRF-INIT", "DR tree for VRF:%d(%s) AF:%d init done", vrf_id, vrf_name, af_index);
        /* Create the NH Tree */
        fib_create_nh_tree (p_vrf_info);
        HAL_RT_LOG_INFO("VRF-INIT", "NH tree for VRF:%d(%s) AF:%d init done", vrf_id, vrf_name, af_index);

        /*
         *  Create the Multi-path MP MD5 Tree
         */
        fib_create_mp_md5_tree (p_vrf_info);

        /* Create the NHT Tree */
        fib_create_nht_tree (p_vrf_info);
        HAL_RT_LOG_INFO("VRF-INIT", "NHT tree for VRF:%d(%s) AF:%d init done", vrf_id, vrf_name, af_index);

        p_vrf_info->is_vrf_created = true;
        p_vrf_info->is_catch_all_disabled = false;
        memset (&p_vrf_info->dr_radical_marker, 0, sizeof (std_radical_ref_t));
        std_radical_walkconstructor (p_vrf_info->dr_tree,
                                     &p_vrf_info->dr_radical_marker);

        memset (&p_vrf_info->nh_radical_marker, 0, sizeof (std_radical_ref_t));
        std_radical_walkconstructor (p_vrf_info->nh_tree,
                                     &p_vrf_info->nh_radical_marker);
    }
    HAL_RT_LOG_INFO("VRF-INIT", "VRF:%d(%s) init done successfully!", vrf_id, vrf_name);
    if (vrf_id != FIB_MGMT_VRF) {
        fib_handle_default_link_local_route(vrf_id, true);
    }
    return STD_ERR_OK;
}

int hal_rt_vrf_de_init (hal_vrf_id_t vrf_id)
{
    t_fib_vrf      *p_vrf = NULL;
    t_fib_vrf_info *p_vrf_info = NULL;
    uint8_t         af_index = 0;
    t_std_error     rc = STD_ERR_OK;

    HAL_RT_LOG_DEBUG("HAL-RT", "Vrf de-initialize");

    p_vrf = hal_rt_access_fib_vrf(vrf_id);
    if (p_vrf == NULL) {
        HAL_RT_LOG_ERR("HAL-RT", "Vrf node NULL. Vrf_id: %d", vrf_id);
        return STD_ERR(ROUTE, FAIL, rc);
    }

    if (vrf_id != FIB_MGMT_VRF) {
        fib_handle_default_link_local_route(vrf_id, false);
    }
    HAL_RT_LOG_INFO("VRF-DEINIT", "Default LLA deleted for VRF-id:%d", vrf_id);
    for (af_index = FIB_MIN_AFINDEX; af_index < FIB_MAX_AFINDEX; af_index++) {
        p_vrf_info = hal_rt_access_fib_vrf_info(vrf_id, af_index);

        /* Destruct the DR radical walk */
        std_radical_walkdestructor(p_vrf_info->dr_tree, &p_vrf_info->dr_radical_marker);

        /* Destroy the DR Tree */
        fib_destroy_dr_tree (p_vrf_info);
        HAL_RT_LOG_INFO("VRF-DEINIT", "DR tree for VRF:%d AF:%d de-init done", vrf_id, af_index);

        /* Destruct the NH radical walk */
        std_radical_walkdestructor(p_vrf_info->nh_tree, &p_vrf_info->nh_radical_marker);
        HAL_RT_LOG_INFO("VRF-DEINIT", "NH tree for VRF:%d AF:%d de-init done NH tree root:%p",
                        vrf_id, af_index, p_vrf_info->nh_tree->rtt_root);

        /* Destroy the NH Tree */
        fib_destroy_nh_tree (p_vrf_info);
        HAL_RT_LOG_INFO("VRF-DEINIT", "NH tree for VRF:%d AF:%d destroyed", vrf_id, af_index);

        /* Destroy the MP MD5 Tree */
        fib_destroy_mp_md5_tree (p_vrf_info);

        /* Destroy the NHT Tree */
        fib_destroy_nht_tree (p_vrf_info);
    }
    nas_route_delete_vrf_peer_mac_config(vrf_id);
    nas_route_delete_vrf_virtual_routing_ip_config(vrf_id);

    memset (p_vrf, 0, sizeof (t_fib_vrf));
    FIB_VRF_MEM_FREE (p_vrf);
    ga_fib_vrf[vrf_id] = NULL;
    hal_rt_vrf_update(vrf_id, false);
    HAL_RT_LOG_INFO("VRF-DEINIT", "VRF-id:%d info. deleted successfully!", vrf_id);
    return STD_ERR_OK;
}

t_std_error hal_rt_process_peer_routing_config (uint32_t vrf_id, nas_rt_peer_mac_config_t*p_status, bool status) {

    t_fib_vrf      *p_vrf = NULL;
    ndi_vr_entry_t  vr_entry;
    ndi_vrf_id_t    ndi_vr_id = 0;
    ndi_rif_id_t        rif_id = 0;
    ndi_rif_entry_t     rif_entry;
    t_std_error     rc = STD_ERR_OK;
    npu_id_t        npu_id = 0;
    char            p_buf[HAL_RT_MAX_BUFSZ];

    if (p_status == NULL) {
        HAL_RT_LOG_ERR("HAL-RT", "Peer status information NULL for VRF:%d", vrf_id);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }
    p_vrf = hal_rt_access_fib_vrf(vrf_id);
    if (p_vrf == NULL) {
        HAL_RT_LOG_ERR("HAL-RT", "Vrf node NULL. Vrf_id: %d", vrf_id);
        return STD_ERR(ROUTE, FAIL, rc);
    }
    HAL_RT_LOG_INFO("HAL-RT", "Vrf:%d ndi-vr-id if name:%s peer-mac:%s status:%d ingress-only:%d",
                    vrf_id, p_status->if_name, hal_rt_mac_to_str(&p_status->mac, p_buf, HAL_RT_MAX_BUFSZ),
                    status, p_status->ingress_only);
    /* VR create is used if interface name is null and MAC present in the object, for VLT and Container cases,
     * wild-card VLAN with Router MAC is good enough for L3 termination.
     * RIF create is used if the if-name and router MAC attributes are present,
     * RIF create programs the My Station TCAM entry with Phy/VLAN and Router MAC (VMAC incase of VRRP).
     * now, the application for this RIF create is VRRP app */
    if (status) {
        if (nas_rt_peer_mac_get(p_status, NULL)) {
            /* If we are trying to delete an entry which does not exist, return */
            HAL_RT_LOG_ERR("HAL-RT", "Vrf:%d if-name:%s peer-mac:%s already exists",
                           vrf_id, p_status->if_name,
                           hal_rt_mac_to_str(&p_status->mac, p_buf, HAL_RT_MAX_BUFSZ));
            return STD_ERR_OK;
        }

        if (p_status->if_name[0] == '\0') {
            /* Create a virtual router entry and get vr_id (maps to fib vrf id) */
            memset (&vr_entry, 0, sizeof (ndi_vr_entry_t));
            vr_entry.npu_id = npu_id;

            memcpy(vr_entry.src_mac, &(p_status->mac), HAL_MAC_ADDR_LEN);
            vr_entry.flags |= NDI_VR_ATTR_SRC_MAC_ADDRESS;
            /* Create the VR entry for MAC */
            if ((rc = ndi_route_vr_create(&vr_entry, &ndi_vr_id))!= STD_ERR_OK) {
                HAL_RT_LOG_ERR("HAL-RT", "Vrf:%d peer-mac:%s creation failed!",
                               vrf_id, hal_rt_mac_to_str(&p_status->mac, p_buf, HAL_RT_MAX_BUFSZ));
                return STD_ERR(ROUTE, FAIL, rc);
            } else {
                p_status->vrf_obj_id = ndi_vr_id;
            }
        } else {
            memset (&rif_entry, 0, sizeof (ndi_rif_entry_t));
            rif_entry.npu_id = npu_id;
            rif_entry.vrf_id = hal_vrf_obj_get(npu_id, vrf_id);

            interface_ctrl_t intf_ctrl;
            memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
            intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;
            safestrncpy(intf_ctrl.if_name, (const char *)p_status->if_name, sizeof(intf_ctrl.if_name)-1);

            if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
                HAL_RT_LOG_ERR("HAL-RT",
                               "Invalid interface %s interface get failed ", p_status->if_name);
                return STD_ERR_OK;
            }
            if ((vrf_id != FIB_DEFAULT_VRF) && (intf_ctrl.int_type == nas_int_type_MACVLAN)) {
                if (hal_rt_get_parent_intf_ctrl(intf_ctrl.l3_intf_info.vrf_id,
                                                intf_ctrl.l3_intf_info.if_index, &intf_ctrl) != STD_ERR_OK) {
                    HAL_RT_LOG_ERR("RT-RIF-ADD",
                                   "Invalid interface VRF-id:%d if-index:%d. RIF ID get failed ",
                                   intf_ctrl.l3_intf_info.vrf_id,
                                   intf_ctrl.l3_intf_info.if_index);
                    return STD_ERR(ROUTE,FAIL,0);
                }
            }
            HAL_RT_LOG_INFO("HAL-RT", "RIF entry creation for intf:%s(%d) of type:%d",
                             intf_ctrl.if_name, intf_ctrl.if_index, intf_ctrl.int_type);
            if(intf_ctrl.int_type == nas_int_type_PORT) {
                rif_entry.rif_type = NDI_RIF_TYPE_PORT;
                rif_entry.attachment.port_id.npu_id = intf_ctrl.npu_id;
                rif_entry.attachment.port_id.npu_port = intf_ctrl.port_id;
            } else if(intf_ctrl.int_type == nas_int_type_LAG) {
                ndi_obj_id_t obj_id;
                rif_entry.rif_type = NDI_RIF_TYPE_LAG;
                if(hal_rt_lag_obj_id_get(intf_ctrl.if_index, &obj_id) == STD_ERR_OK) {
                    rif_entry.attachment.lag_id = obj_id;
                } else {
                    HAL_RT_LOG_ERR("HAL-RT", "LAG object id not present for rif-id:0x%lx intf:%s(%d) type:%d",
                                   rif_id, intf_ctrl.if_name, intf_ctrl.if_index, intf_ctrl.int_type);
                    return STD_ERR(ROUTE,FAIL,0);
                }
            } else if(intf_ctrl.int_type == nas_int_type_VLAN) {
                rif_entry.rif_type = NDI_RIF_TYPE_VLAN;
                rif_entry.attachment.vlan_id = intf_ctrl.vlan_id;
            } else if(intf_ctrl.int_type == nas_int_type_DOT1D_BRIDGE) {
                rif_entry.rif_type = NDI_RIF_TYPE_DOT1D_BRIDGE;
                rif_entry.attachment.bridge_id = intf_ctrl.bridge_id;
                HAL_RT_LOG_INFO("RT-RIF-ADD", "1D virtual bridge RIF entry creation for intf:%s(%d) type:%d bridge:%lu",
                                intf_ctrl.if_name, intf_ctrl.if_index, intf_ctrl.int_type, intf_ctrl.bridge_id);
            } else {
                HAL_RT_LOG_ERR("HAL-RT", "Invalid RIF entry creation ignored for rif-id:0x%lx intf:%s(%d) type:%d",
                               rif_id, intf_ctrl.if_name, intf_ctrl.if_index, intf_ctrl.int_type);
                return STD_ERR_OK;
            }

            rif_entry.flags = NDI_RIF_ATTR_SRC_MAC_ADDRESS;
            /* Virtual RIF is set only when we need to program ingress router MAC
               for ingress IP termination.
               if the config is only for ingress termination, then set the virtual rif flag.
             */
            if (p_status->ingress_only)
                rif_entry.flags |= NDI_RIF_ATTR_VIRTUAL;

            memcpy(&rif_entry.src_mac, &(p_status->mac), sizeof(hal_mac_addr_t));
            if ((rc = ndi_rif_create(&rif_entry, &rif_id)) != STD_ERR_OK) {
                HAL_RT_LOG_ERR("HAL-RT", "Vrf:%d if_name:%s peer-mac:%s is_virtual_rif:%s creation failed!",
                               vrf_id, p_status->if_name,
                               hal_rt_mac_to_str(&p_status->mac, p_buf, HAL_RT_MAX_BUFSZ),
                               ((rif_entry.flags & NDI_RIF_ATTR_VIRTUAL) ? "Yes":"No"));
                return (STD_ERR(ROUTE, FAIL, rc));
            } else {
                p_status->rif_obj_id = rif_id;

                HAL_RT_LOG_INFO ("HAL-RT-RIF", "Peer-routing RIF entry created successfully: "
                                 "0x%lx for if_index %d, is_virtual_rif:%s",
                                 rif_id, intf_ctrl.if_index,
                                 ((rif_entry.flags & NDI_RIF_ATTR_VIRTUAL) ? "Yes":"No"));
            }
        }

        nas_rt_peer_mac_db_add(p_status);
    } else {
        nas_rt_peer_mac_config_t cur_mac_info;
        if (!nas_rt_peer_mac_get(p_status, &cur_mac_info)) {
            /* If we are trying to delete an entry which does not exist, return */
            HAL_RT_LOG_ERR("HAL-RT", "Vrf:%d if-name:%s peer-mac:%s does not exist",
                           vrf_id, p_status->if_name,
                           hal_rt_mac_to_str(&p_status->mac, p_buf, HAL_RT_MAX_BUFSZ));
            return STD_ERR_OK;
        }
        HAL_RT_LOG_INFO("HAL-RT", "Vrf:%d if_name:%s peer-mac:%s vrf-obj-id:0x%lx rif-obj-id:0x%lx info",
                        vrf_id, cur_mac_info.if_name, hal_rt_mac_to_str(&cur_mac_info.mac, p_buf, HAL_RT_MAX_BUFSZ),
                        cur_mac_info.vrf_obj_id, cur_mac_info.rif_obj_id);
        if (cur_mac_info.vrf_obj_id) {
            /* Remove peer VLT MAC information */
            if ((rc = ndi_route_vr_delete(npu_id, cur_mac_info.vrf_obj_id))!= STD_ERR_OK) {
                HAL_RT_LOG_ERR("HAL-RT", "Vrf:%d peer-mac:%s deletion failed!",
                               vrf_id, hal_rt_mac_to_str(&p_status->mac, p_buf, HAL_RT_MAX_BUFSZ));
                return STD_ERR(ROUTE, FAIL, rc);
            }
        } else if (cur_mac_info.rif_obj_id) {
            if (ndi_rif_delete(npu_id, cur_mac_info.rif_obj_id) != STD_ERR_OK) {
                HAL_RT_LOG_ERR("HAL-RT", "Vrf:%d if_name:%s peer-mac:%s deletion failed!",
                               vrf_id, p_status->if_name,
                               hal_rt_mac_to_str(&p_status->mac, p_buf, HAL_RT_MAX_BUFSZ));
                return (STD_ERR(ROUTE, PARAM, 0));
            } else {
                HAL_RT_LOG_INFO ("HAL-RT-RIF", "Peer-routing RIF entry deleted successfully: 0x%lx for if_name %s",
                                 cur_mac_info.rif_obj_id, p_status->if_name);
            }
        }
        nas_rt_peer_mac_db_del(p_status);
    }
    return rc;
}

cps_api_object_t nas_route_peer_routing_config_to_cps_object(uint32_t vrf_id,
                                                             nas_rt_peer_mac_config_t *p_status){
    char buff[40];
    if(p_status == NULL){
        HAL_RT_LOG_ERR("HAL-RT","Null Peer Status pointer passed to convert it to cps object");
        return NULL;
    }

    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL){
        HAL_RT_LOG_ERR("HAL-RT","Failed to allocate memory to cps object");
        return NULL;
    }

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key, BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,
                                    cps_api_qualifier_TARGET);
    cps_api_object_set_key(obj,&key);

    cps_api_object_attr_add(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_NAME,
                            FIB_GET_VRF_NAME(vrf_id, HAL_INET4_FAMILY),
                            strlen((const char*)FIB_GET_VRF_NAME(vrf_id, HAL_INET4_FAMILY))+1);
    cps_api_object_attr_add(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_IFNAME,&p_status->if_name,strlen(p_status->if_name)+1);
    memset(buff, '\0', sizeof(buff));
    const char *_p = std_mac_to_string((const hal_mac_addr_t *)&p_status->mac, buff, sizeof(buff));
    cps_api_object_attr_add(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR,_p,strlen(_p)+1);

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_INGRESS_ONLY, p_status->ingress_only);
    return obj;
}

/* configure virtual routing ip for the given interface.
 */
t_std_error hal_rt_process_virtual_routing_ip_config (nas_rt_virtual_routing_ip_config_t *p_cfg, bool status) {
    t_fib_vrf      *p_vrf = NULL;
    t_std_error     rc = STD_ERR_OK;
    uint32_t        vrf_id = 0;

    if (p_cfg == NULL) {
        HAL_RT_LOG_ERR("HAL-RT", "Invalid Virtual routing IP cfg");
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    /* retrieve vrf-id for given vrf_name */
    if (!hal_rt_get_vrf_id(p_cfg->vrf_name, &vrf_id)) {
        HAL_RT_LOG_ERR("HAL-RT","Virtual routing IP cfg VRF(%s) not present.", p_cfg->vrf_name);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }
    p_cfg->vrf_id = vrf_id;

    p_vrf = hal_rt_access_fib_vrf(vrf_id);
    if (p_vrf == NULL) {
        HAL_RT_LOG_ERR("HAL-RT", "Virtual routing IP cfg Vrf node NULL. Vrf_id: %d", vrf_id);
        return STD_ERR(ROUTE, FAIL, rc);
    }

    HAL_RT_LOG_DEBUG ("HAL-RT", "Virtual routing IP cfg Vrf:%d if-name:%s IP:%s status:%d",
                      vrf_id, p_cfg->if_name, FIB_IP_ADDR_TO_STR(&p_cfg->ip_addr), status);

    interface_ctrl_t intf_ctrl;
    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;
    safestrncpy(intf_ctrl.if_name, (const char *)p_cfg->if_name, sizeof(intf_ctrl.if_name)-1);

    if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
        HAL_RT_LOG_DEBUG ("HAL-RT",
                          "Virtual routing IP cfg, interface %s not found",
                          p_cfg->if_name);
    }

    if (status) {
        if (nas_rt_virtual_routing_ip_get(p_cfg, NULL)) {
                /* If we are trying to create an entry which alreadt exist, return */
                HAL_RT_LOG_ERR("HAL-RT", "Vrf:%d if-name:%s IP:%s already exists",
                                             vrf_id, p_cfg->if_name,
                                             FIB_IP_ADDR_TO_STR(&p_cfg->ip_addr));
                return STD_ERR_OK;
        }

        /* Only one route/ip can exists across all interface in a given vrf.
         * On virtual routing ip add on an interface, create the entry in NDI
         * only for first interace create.
         */
        if (nas_rt_virtual_routing_ip_list_size (p_cfg) == 0) {
            /* create route entry in NDI for given IP only for first entry creation */
            rc = _hal_rt_virtual_routing_ip_cfg (p_cfg, status);
        }
        if (rc != STD_ERR_OK) {
                HAL_RT_LOG_ERR ("HAL-RT", "Virtual routing IP cfg create failed. Vrf:%d if-name:%s IP:%s ",
                                                p_cfg->vrf_id, p_cfg->if_name,
                                                FIB_IP_ADDR_TO_STR(&p_cfg->ip_addr));
        } else {
            nas_rt_virtual_routing_ip_db_add(p_cfg);

            HAL_RT_LOG_DEBUG ("HAL-RT-NDI", "Virtual routing IP config success. Route created successfully "
                                            "Vrf:%d if-name:%s IP:%s",
                                            vrf_id, p_cfg->if_name, FIB_IP_ADDR_TO_STR(&p_cfg->ip_addr));

        }
    } else {
        if (!nas_rt_virtual_routing_ip_get(p_cfg, NULL)) {
            /* If we are trying to delete an entry which does not exist, return */
            HAL_RT_LOG_ERR("HAL-RT", "Vrf:%d if-name:%s IP:%s does not exist",
                           vrf_id, p_cfg->if_name, FIB_IP_ADDR_TO_STR(&p_cfg->ip_addr));
            return STD_ERR(ROUTE, FAIL, rc);
        }

        /* Only one route/ip can exists across all interface in a given vrf.
         * On virtual routing ip del on an interface, delete the entry in NDI
         * only for last interace delete.
         */
        if (nas_rt_virtual_routing_ip_list_size (p_cfg) == 1) {
            /* delete route entry in NDI for given IP only for last entry removal */
            rc = _hal_rt_virtual_routing_ip_cfg (p_cfg, status);
        }

        if (rc != STD_ERR_OK) {
            HAL_RT_LOG_ERR ("HAL-RT", "Virtual routing IP cfg del failed. Vrf:%d if-name:%s IP:%s ",
                            p_cfg->vrf_id, p_cfg->if_name,
                            FIB_IP_ADDR_TO_STR(&p_cfg->ip_addr));
        } else {
            nas_rt_virtual_routing_ip_db_del(p_cfg);

            HAL_RT_LOG_DEBUG ("HAL-RT-NDI", "Virtual routing IP config success. Route deleted successfully "
                              "Vrf:%d if-name:%s IP:%s",
                             vrf_id, p_cfg->if_name, FIB_IP_ADDR_TO_STR(&p_cfg->ip_addr));

        }
    }

    return rc;
}

cps_api_object_t nas_route_virtual_routing_ip_config_to_cps_object(uint32_t vrf_id,
                                              nas_rt_virtual_routing_ip_config_t *p_status){
    if(p_status == NULL){
        HAL_RT_LOG_ERR("HAL-RT","Null Virtual routing Status pointer passed to convert it to cps object");
        return NULL;
    }

    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL){
        HAL_RT_LOG_ERR("HAL-RT","Failed to allocate memory to cps object");
        return NULL;
    }

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key, BASE_ROUTE_VIRTUAL_ROUTING_CONFIG_VIRTUAL_ROUTING_IP_CONFIG,
                                    cps_api_qualifier_TARGET);
    cps_api_object_set_key(obj,&key);

    cps_api_set_key_data (obj, BASE_ROUTE_VIRTUAL_ROUTING_CONFIG_VIRTUAL_ROUTING_IP_CONFIG_VRF_NAME,
                          cps_api_object_ATTR_T_BIN, p_status->vrf_name,
                          (strlen(p_status->vrf_name)+1));
    uint32_t af = p_status->ip_addr.af_index;
    cps_api_set_key_data (obj, BASE_ROUTE_VIRTUAL_ROUTING_CONFIG_VIRTUAL_ROUTING_IP_CONFIG_AF,
                          cps_api_object_ATTR_T_U32, &af, sizeof(af));
    cps_api_set_key_data (obj, BASE_ROUTE_VIRTUAL_ROUTING_CONFIG_VIRTUAL_ROUTING_IP_CONFIG_IFNAME,
                          cps_api_object_ATTR_T_BIN, p_status->if_name,
                          (strlen(p_status->if_name)+1));

    if(p_status->ip_addr.af_index == HAL_INET4_FAMILY){
        int addr_len = HAL_INET4_LEN;
        cps_api_set_key_data (obj, BASE_ROUTE_VIRTUAL_ROUTING_CONFIG_VIRTUAL_ROUTING_IP_CONFIG_IP,
                              cps_api_object_ATTR_T_BIN,
                              &(p_status->ip_addr.u.v4_addr), addr_len);
    } else {
        int addr_len = HAL_INET6_LEN;
        cps_api_set_key_data (obj, BASE_ROUTE_VIRTUAL_ROUTING_CONFIG_VIRTUAL_ROUTING_IP_CONFIG_IP,
                              cps_api_object_ATTR_T_BIN,
                              &(p_status->ip_addr.u.v6_addr), addr_len);
    }

    return obj;
}


t_std_error hal_rt_task_init (void)
{
    t_std_error rc = STD_ERR_OK;

    HAL_RT_LOG_DEBUG("HAL-RT", "Initializing HAL-Routing Core");

    hal_rt_config_init ();
    fib_dr_walker_init ();
    fib_nh_walker_init ();

    fib_create_intf_tree ();

    fib_create_leaked_rt_tree ();

    if ((rc = hal_rt_vrf_init (FIB_DEFAULT_VRF, FIB_DEFAULT_VRF_NAME)) != STD_ERR_OK) {
        HAL_RT_LOG_ERR( "HAL-RT", "VRF Init failed");
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    if ((rc = hal_rt_vrf_init (FIB_MGMT_VRF, FIB_MGMT_VRF_NAME)) != STD_ERR_OK) {
        HAL_RT_LOG_ERR( "HAL-RT", "VRF mgmt Init failed");
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    return rc;
}

void hal_rt_task_exit (void)
{
    hal_vrf_id_t vrf_id = 0;
    HAL_RT_LOG_DEBUG("HAL-RT", "Exiting HAL-Routing..");

    for (vrf_id = FIB_MIN_VRF; vrf_id < FIB_MAX_VRF; vrf_id ++) {
        hal_rt_vrf_de_init (vrf_id);
    }
    fib_destroy_intf_tree ();
    fib_destroy_leaked_rt_tree ();
    memset (&g_fib_config, 0, sizeof (g_fib_config));
    memset(&g_fib_gbl_info, 0, sizeof(g_fib_gbl_info));
    exit(0);

    return;
}

static bool hal_rt_process_msg(cps_api_object_t obj, void *param)
{
    t_fib_msg *p_msg = NULL;
    g_fib_gbl_info.num_tot_msg++;

    switch (cps_api_key_get_cat(cps_api_object_key(obj))) {
        case cps_api_obj_CAT_BASE_IF_LINUX:
            g_fib_gbl_info.num_int_msg++;
            t_fib_intf_entry intf;
            memset(&intf, 0, sizeof(t_fib_intf_entry));
            /* Enqueue the intf messages for further processing
             * only it has the admin attribute.*/
            if (hal_rt_cps_obj_to_intf(obj,&intf)) {
                p_msg = hal_rt_alloc_mem_msg();
                if (p_msg) {
                    p_msg->type = FIB_MSG_TYPE_NL_INTF;
                    memcpy(&(p_msg->intf), &intf, sizeof(intf));
                    nas_rt_process_msg(p_msg);
                }
            }
            break;
        case cps_api_obj_CAT_BASE_IP:
            g_fib_gbl_info.num_ip_msg++;
            /* Enqueue the IP address messages for further processing
             * it has the IPv4/IPv6 route attributes.
             */
            if (hal_rt_ip_addr_cps_obj_to_route (obj,&p_msg)) {
                nas_rt_process_msg(p_msg);
            }
            break;
        case cps_api_obj_CAT_OS_RE:
            g_fib_gbl_info.num_route_msg++;
            if (hal_rt_cps_obj_to_route(obj, &p_msg, false)) {
                nas_rt_process_msg(p_msg);
            }
            break;

        default:
            g_fib_gbl_info.num_unk_msg++;
            HAL_RT_LOG_DEBUG("HAL-RT", "msg sub_class unknown category:%d sub-cat:%d",
                             cps_api_key_get_cat(cps_api_object_key(obj)),
                             cps_api_key_get_subcat(cps_api_object_key(obj)));
            break;
    }
    return true;
}

t_std_error hal_rt_main(void)
{

    cps_api_event_reg_t reg;

    memset(&reg,0,sizeof(reg));
    const uint_t NUM_KEYS=4;
    cps_api_key_t key[NUM_KEYS];

    cps_api_key_from_attr_with_qual(&key[0], OS_RE_BASE_ROUTE_OBJ_ENTRY_OBJ,
                                    cps_api_qualifier_OBSERVED);
    // Register with NAS-Linux object for interface state change notifications
    cps_api_key_from_attr_with_qual(&key[1],
                                    BASE_IF_LINUX_IF_INTERFACES_INTERFACE_OBJ,
                                    cps_api_qualifier_OBSERVED);

    cps_api_key_from_attr_with_qual(&key[2],
                                    BASE_IP_IPV4_OBJ,
                                    cps_api_qualifier_OBSERVED);

    cps_api_key_from_attr_with_qual(&key[3],
                                    BASE_IP_IPV6_OBJ,
                                    cps_api_qualifier_OBSERVED);
    reg.priority = 0;
    reg.number_of_objects = NUM_KEYS;
    reg.objects = key;
    if (cps_api_event_thread_reg(&reg,hal_rt_process_msg,NULL)!=cps_api_ret_code_OK) {
        return STD_ERR(ROUTE,FAIL,0);
    }
    return STD_ERR_OK;
}

t_std_error hal_rt_cps_thread(void)
{
    t_std_error     rc = STD_ERR_OK;

    //Create a handle for CPS objects
    if (cps_api_operation_subsystem_init(&nas_rt_cps_handle,
            NUM_INT_NAS_RT_CPS_API_THREAD)!=cps_api_ret_code_OK) {
        return STD_ERR(CPSNAS,FAIL,0);
    }

    //Initialize CPS for Routing objects
    if((rc = nas_routing_cps_init(nas_rt_cps_handle)) != STD_ERR_OK) {
        HAL_RT_LOG_ERR( "HAL-RT","Initializing CPS for Routing failed");
        return rc;
    }

    return STD_ERR_OK;
}

t_std_error hal_rt_nht_cps_thread(void)
{
    t_std_error     rc = STD_ERR_OK;

    //Create a handle for CPS objects
    if (cps_api_operation_subsystem_init(&nas_rt_nht_cps_handle,
            NUM_INT_NAS_RT_NHT_CPS_API_THREAD)!=cps_api_ret_code_OK) {
        HAL_RT_LOG_ERR( "HAL-RT-NHT","Initializing CPS subsystem for Routing NHT failed");
        return STD_ERR(CPSNAS,FAIL,0);
    }

    //Initialize CPS for Routing NHT objects
    if((rc = nas_routing_nht_cps_init(nas_rt_nht_cps_handle)) != STD_ERR_OK) {
        HAL_RT_LOG_ERR( "HAL-RT-NHT","Initializing CPS for Routing NHT failed");
        return rc;
    }
    HAL_RT_LOG_DEBUG("HAL-RT-NHT","Initializing CPS subsystem for Routing NHT succeeded...");

    return STD_ERR_OK;
}

t_std_error hal_rt_init(void)
{
    t_std_error     rc = STD_ERR_OK;

    HAL_RT_LOG_DEBUG("HAL-RT", "Initializing HAL-Routing Threads");

    rc = hal_rt_task_init ();
    if (rc != STD_ERR_OK) {
        HAL_RT_LOG_ERR( "HAL-RT", "Initialization failed.");
        hal_rt_task_exit ();
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    /* CPS will spwan a thread in the name of local-event-thread
     * to handle the netlink messages from NAS-Linux */
    if (hal_rt_main() != STD_ERR_OK) {
        HAL_RT_LOG_ERR( "HAL-RT-THREAD", "Error creating thread");
        return STD_ERR(ROUTE,FAIL,0);
    }

    std_thread_init_struct(&hal_rt_dr_thr);
    hal_rt_dr_thr.name = "hal-rt-dr";
    hal_rt_dr_thr.thread_function = (std_thread_function_t)fib_dr_walker_main;
    if (std_thread_create(&hal_rt_dr_thr)!=STD_ERR_OK) {
        HAL_RT_LOG_ERR( "HAL-RT-THREAD", "Error creating dr thread");
        return STD_ERR(ROUTE,FAIL,0);
    }

    std_thread_init_struct(&hal_rt_nh_thr);
    hal_rt_nh_thr.name = "hal-rt-nh";
    hal_rt_nh_thr.thread_function = (std_thread_function_t)fib_nh_walker_main;
    if (std_thread_create(&hal_rt_nh_thr)!=STD_ERR_OK) {
        HAL_RT_LOG_ERR( "HAL-RT-THREAD", "Error creating nh thread");
        return STD_ERR(ROUTE,FAIL,0);
    }

    std_thread_init_struct(&hal_rt_msg_thr);
    hal_rt_msg_thr.name = "hal-rt-msg";
    hal_rt_msg_thr.thread_function = (std_thread_function_t)fib_msg_main;
    if (std_thread_create(&hal_rt_msg_thr)!=STD_ERR_OK) {
        HAL_RT_LOG_ERR( "HAL-RT-THREAD", "Error creating msg thread");
        return STD_ERR(ROUTE,FAIL,0);
    }

    std_thread_init_struct(&hal_rt_offload_msg_thr);
    hal_rt_offload_msg_thr.name = "hal-rt-off-msg";
    hal_rt_offload_msg_thr.thread_function = (std_thread_function_t)fib_offload_msg_main;
    if (std_thread_create(&hal_rt_offload_msg_thr)!=STD_ERR_OK) {
        HAL_RT_LOG_ERR( "HAL-RT-THREAD", "Error creating offload msg thread");
        return STD_ERR(ROUTE,FAIL,0);
    }

    /* CPS will spwan a CPS_API_Instance thread to handle the Route/Nbr
     * messages from north bound interfaces (RTM/AFS..etc) */
    if (hal_rt_cps_thread() != STD_ERR_OK) {
        HAL_RT_LOG_ERR( "HAL-RT-THREAD", "Error creating cps thread");
        return STD_ERR(ROUTE,FAIL,0);
    }
    if (hal_rt_nht_cps_thread() != STD_ERR_OK) {
        HAL_RT_LOG_ERR( "HAL-RT-THREAD", "Error creating cps thread");
        return STD_ERR(ROUTE,FAIL,0);
    }

    nas_rt_shell_debug_command_init ();
    return STD_ERR_OK;
}
