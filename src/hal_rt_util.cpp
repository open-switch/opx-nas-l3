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
 * \file   hal_rt_util.c
 * \brief  Hal Routing Utilities
 * \date   05-2014
 * \author Prince Sunny & Satish Mynam
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "hal_rt_main.h"
#include "hal_rt_util.h"
#include "hal_rt_debug.h"

#ifdef __cplusplus
}
#endif

#include <cstring>
#include <cstdio>
#include "event_log.h"
#include "hal_if_mapping.h"
#include "nas_if_utils.h"
#include <unordered_map>
#include <memory>
#include <deque>
#include <utility>
#include <mutex>
#include <sstream>
#include <set>
#include <condition_variable>
#include <algorithm>
#include "nas_ndi_obj_id_table.h"
#include "nas_ndi_common.h"
#include "nas_ndi_1d_bridge.h"
#include "dell-base-switch-element.h"
#include "std_utils.h"
#include "nas_vrf_utils.h"
#include "std_mac_utils.h"

#include "cps_api_object_category.h"
#include "cps_api_route.h"
#include "cps_api_operation.h"
#include "cps_class_map.h"

#include "std_utils.h"
#include "std_rw_lock.h"

using fib_msg_uptr_t = std::unique_ptr<t_fib_msg>;
static auto &hal_rt_msg_list = *new std::deque<fib_msg_uptr_t>;
static auto g_hal_rt_vrf_list = new std::set<hal_vrf_id_t>;
static std_rw_lock_t vrf_lock = PTHREAD_RWLOCK_INITIALIZER;
/* stats counter for hal_rt_msg_list queue on per msg type basis */
static auto hal_rt_msg_list_stats = new std::unordered_map<uint32_t,uint32_t> {
            { FIB_MSG_TYPE_NL_INTF, 0 },
            { FIB_MSG_TYPE_NBR_MGR_INTF, 0 },
            { FIB_MSG_TYPE_NL_ROUTE, 0 },
            { FIB_MSG_TYPE_NBR_MGR_NBR_INFO, 0 },
            { FIB_MSG_TYPE_NL_NBR, 0 },
            { FIB_MSG_TYPE_INTF_IP_UNREACH_CFG, 0 },
            { FIB_MSG_TYPE_INTF_IP_REDIRECTS_CFG, 0 },
            { FIB_MSG_TYPE_NEIGH_FLUSH, 0 },
};

uint_t hal_rt_msg_peak_cnt = 0;

#ifdef __cplusplus
extern "C" {
#endif

#define HAL_RT_INIT_ERR_TO_STR()                               \
        { { DN_HAL_ROUTE_E_NONE,           "Success"            },   \
          { DN_HAL_ROUTE_E_FAIL,           "Failure"            },   \
          { DN_HAL_ROUTE_E_FULL,           "Table full"         },   \
          { DN_HAL_ROUTE_E_HASH_COLLISION, "Hash collision"     },   \
          { DN_HAL_ROUTE_E_DEGEN,          "Route degeneration" },   \
          { DN_HAL_ROUTE_E_MEM,            "Out of memory"      },   \
          { DN_HAL_ROUTE_E_PARAM,          "Invalid parameters" },   \
          { DN_HAL_ROUTE_E_UNSUPPORTED,    "Not supported"      },   \
          { DN_HAL_ROUTE_E_END,            ""                   },   \
        }

static uint8_t   ga_fib_scratch_buf [FIB_NUM_SCRATCH_BUF][FIB_MAX_SCRATCH_BUFSZ];
static uint32_t  g_fib_scratch_buf_index = 0;

uint8_t  *fib_get_scratch_buf ()
{
    g_fib_scratch_buf_index++;

    if (g_fib_scratch_buf_index >= FIB_NUM_SCRATCH_BUF) {
        g_fib_scratch_buf_index = 0;
    }

    return ga_fib_scratch_buf [g_fib_scratch_buf_index];
}

t_std_error hal_rt_vrf_update (hal_vrf_id_t vrf_id, bool is_add) {

    HAL_RT_LOG_INFO("HAL-RT-VRF", "VRF update vrf_id:%d is_add:%d", vrf_id, is_add);
    std_rw_lock_write_guard l(&vrf_lock);
    auto it = g_hal_rt_vrf_list->find(vrf_id);
    if ((it == g_hal_rt_vrf_list->end()) && is_add) {
        g_hal_rt_vrf_list->insert(vrf_id);
    } else if ((it != g_hal_rt_vrf_list->end()) && (!is_add)) {
        g_hal_rt_vrf_list->erase(it);
    } else {
        HAL_RT_LOG_ERR("HAL-RT-VRF", "Invalid VRF update vrf_id:%d is_add:%d", vrf_id, is_add);
        return STD_ERR(ROUTE,FAIL,0);
    }
    return STD_ERR_OK;
}

t_std_error hal_rt_get_first_vrf_id(hal_vrf_id_t *p_vrf_id) {
    std_rw_lock_read_guard l(&vrf_lock);
    std::set<hal_vrf_id_t>::iterator it = g_hal_rt_vrf_list->begin();
    if (it != g_hal_rt_vrf_list->end()) {
        *p_vrf_id = *it;
        return STD_ERR_OK;
    }
    return STD_ERR(ROUTE,FAIL,0);
}

t_std_error hal_rt_get_next_vrf_id(hal_vrf_id_t vrf_id, hal_vrf_id_t *p_next_vrf_id) {
    std_rw_lock_read_guard l(&vrf_lock);
    auto it = g_hal_rt_vrf_list->upper_bound(vrf_id);
    if(it != g_hal_rt_vrf_list->end()) {
        *p_next_vrf_id = *it;
        return STD_ERR_OK;
    }
    return STD_ERR(ROUTE,FAIL,0);
}

t_std_error hal_rt_validate_intf(hal_vrf_id_t vrf_id, int if_index, bool *is_mgmt_intf)
{
    interface_ctrl_t intf_ctrl;
    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
    intf_ctrl.vrf_id = vrf_id;
    intf_ctrl.if_index = if_index;

    *is_mgmt_intf = false;
    if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
        return (STD_ERR_MK(e_std_err_NPU, e_std_err_code_PARAM, 0));
    }

    /* Add other invalid interfaces here, to skip the route/neighbor updates */
    /* skip events for manangement vlan */
    if ((intf_ctrl.int_type == nas_int_type_MGMT) ||
        ((intf_ctrl.int_type == nas_int_type_VLAN) &&
         (intf_ctrl.int_sub_type == BASE_IF_VLAN_TYPE_MANAGEMENT))) {
        *is_mgmt_intf = true;
        return STD_ERR_OK;
    }

    /* skip events for MAC VLAN interface in default VRF */
    if ((vrf_id == FIB_DEFAULT_VRF) && (intf_ctrl.int_type == nas_int_type_MACVLAN)) {
        return (STD_ERR_MK(e_std_err_NPU, e_std_err_code_PARAM, 0));
    }
    return STD_ERR_OK;
}

t_std_error hal_rt_get_intf_name(hal_vrf_id_t vrf_id, int if_index, char *p_if_name)
{
    interface_ctrl_t intf_ctrl;
    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));

    memset(p_if_name, '\0', HAL_IF_NAME_SZ);
    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
    intf_ctrl.vrf_id = vrf_id;
    intf_ctrl.if_index = if_index;

    if(dn_hal_get_interface_info(&intf_ctrl) != STD_ERR_OK) {
        return (STD_ERR_MK(e_std_err_NPU, e_std_err_code_PARAM, 0));
    }
    safestrncpy(p_if_name, intf_ctrl.if_name, HAL_IF_NAME_SZ);
    return STD_ERR_OK;
}


t_std_error hal_rt_get_if_index_from_if_name(char *if_name, hal_vrf_id_t *vrf_id, uint32_t *p_if_index) {
    interface_ctrl_t intf_ctrl;

    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF_NAME;
    safestrncpy(intf_ctrl.if_name, (const char *)if_name,
                sizeof(intf_ctrl.if_name)-1);

    if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
        HAL_RT_LOG_INFO("HAL-RT",
                       "Invalid interface %s interface get failed ", if_name);
        return (STD_ERR(ROUTE, PARAM, 0));
    }
    *p_if_index = intf_ctrl.if_index;
    *vrf_id = intf_ctrl.vrf_id;
    return STD_ERR_OK;
}

t_std_error hal_rt_get_parent_if_index_from_l3_intf(hal_vrf_id_t vrf_id, uint32_t if_index,
                                                    uint32_t *p_parent_if_index) {
    interface_ctrl_t intf_ctrl;
    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
    intf_ctrl.vrf_id = vrf_id;
    intf_ctrl.if_index = if_index;

    if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
        HAL_RT_LOG_INFO("HAL-RT-RIF",
                        "Invalid VRF:%d intf%d. RIF ID get failed ", vrf_id, if_index);
        return STD_ERR(ROUTE,FAIL,0);
    }
    *p_parent_if_index = intf_ctrl.l3_intf_info.if_index;
    return STD_ERR_OK;
}

uint8_t *hal_rt_get_hal_err_str(dn_hal_route_err _hal_err)
{
    static dn_hal_route_err_to_str g_hal_rt_err_str [HAL_RT_NUM_HAL_ERR] = HAL_RT_INIT_ERR_TO_STR ();
    uint8_t *p_str;

    p_str = ((((_hal_err) <= 0) && ((_hal_err) > DN_HAL_ROUTE_E_END))?
            (g_hal_rt_err_str [0 - (_hal_err)].err_str) :
            (g_hal_rt_err_str [0 - (DN_HAL_ROUTE_E_END)].err_str));

    return p_str;
}

char *hal_rt_mac_to_str (hal_mac_addr_t *mac_addr, char *p_buf, size_t len)
{
    snprintf (p_buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             (*mac_addr) [0], (*mac_addr) [1], (*mac_addr) [2],
             (*mac_addr) [3], (*mac_addr) [4], (*mac_addr) [5]);

    return p_buf;
}

static hal_mac_addr_t g_zero_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

bool hal_rt_is_mac_address_zero (const hal_mac_addr_t *p_mac)
{
    if (memcmp (p_mac, &g_zero_mac, sizeof (hal_mac_addr_t)))
    {
        return false;
    } else {
        return true;
    }
}

bool hal_rt_is_reserved_ipv4(hal_ip_addr_t *p_ip_addr)
{
    /* 127.x.x.x - reserved address range */
    if ((p_ip_addr->af_index == HAL_INET4_FAMILY) &&
        ((p_ip_addr->u.v4_addr & 0xff) == 0x7f))
        return true;

    return false;
}

bool hal_rt_is_reserved_ipv6(hal_ip_addr_t *p_ip_addr)
{
    if ((p_ip_addr->af_index == HAL_INET6_FAMILY) &&
        (((((p_ip_addr->u.v6_addr[0]) & (0xff)) == (0xff)) &&
          (((p_ip_addr->u.v6_addr[1]) & (0xf0)) == (0x00))) ||
         (STD_IP_IS_V6_ADDR_LOOP_BACK(p_ip_addr)))) {
        return true;
    }
    return false;
}

t_std_error hal_rt_lag_obj_id_get (hal_ifindex_t if_index, ndi_obj_id_t *obj_id)
{
    nas_obj_id_t lag_obj_id;

    if (nas_get_lag_id_from_if_index(if_index, &lag_obj_id) != STD_ERR_OK) {
        HAL_RT_LOG_DEBUG("HAL-RT-LAG", "Lag object get failed for %d", if_index);
        return (STD_ERR(ROUTE, PARAM, 0));
    }
    HAL_RT_LOG_INFO("HAL-RT-LAG", "LAG NDI object %lu retrieved for if_index %d",
                    lag_obj_id, if_index);
    // @Todo - Handle multiple npus
    *obj_id = lag_obj_id;

    return STD_ERR_OK;
}

uint32_t hal_rt_rif_ref_inc(hal_vrf_id_t vrf_id, hal_ifindex_t if_index)
{
    uint32_t ref_cnt = 0;
    t_fib_intf *p_intf = fib_get_intf(if_index, vrf_id, HAL_RT_V4_AFINDEX);
    if (p_intf == NULL) {
        HAL_RT_LOG_ERR("RT-RIF-INCR", "VRF:%d Intf:%d not created", vrf_id, if_index);
        return ref_cnt;
    }

    if (p_intf->rif_info.rif_id != 0) {
        ref_cnt = ++(p_intf->rif_info.ref_count);
        HAL_RT_LOG_INFO("RT-RIF-INCR", "Current Ref count for RIF id (0x%lx) VRF-id:%d if_index (%d)"
                        "is %d", p_intf->rif_info.rif_id, vrf_id, if_index, ref_cnt);
    } else {
        HAL_RT_LOG_INFO("RT-RIF-INCR", "Incr RIF not found for VRF-id:%d if_index (%d)", vrf_id, if_index);
    }
    return ref_cnt;
}

bool hal_rt_rif_ref_dec(hal_vrf_id_t vrf_id, hal_ifindex_t if_index)
{
    int32_t ref_cnt = -1;
    t_fib_intf *p_intf = fib_get_intf(if_index, vrf_id, HAL_RT_V4_AFINDEX);
    if (p_intf == NULL) {
        HAL_RT_LOG_ERR("RT-RIF-DECR", "VRF:%d Intf:%d not created", vrf_id, if_index);
        return true;
    }

    if (p_intf->rif_info.rif_id != 0) {
        if (p_intf->rif_info.ref_count == 0) {
            HAL_RT_LOG_ERR("RT-RIF-DECR", "Ref count reached zero already for RIF id (0x%lx)"
                           "VRF-id:%d if_index (%d)", p_intf->rif_info.rif_id, vrf_id, if_index);
        } else {
            ref_cnt = --(p_intf->rif_info.ref_count);
            HAL_RT_LOG_INFO("RT-RIF-DECR", "Current Ref count for RIF id (0x%lx) VRF-id:%d if_index (%d)"
                            "is %d", p_intf->rif_info.rif_id, vrf_id, if_index, ref_cnt);
        }
    } else {
        HAL_RT_LOG_INFO("RT-RIF-DECR", "Decr RIF not found for VRF-id:%d if_index (%d) ref-cnt:%d",
                        vrf_id, if_index, p_intf->rif_info.ref_count);
    }
    return ((ref_cnt == 0) ? false : true);
}

int hal_rt_rif_ref_get(hal_vrf_id_t vrf_id, hal_ifindex_t if_index)
{
    int32_t ref_cnt = -1;
    t_fib_intf *p_intf = fib_get_intf(if_index, vrf_id, HAL_RT_V4_AFINDEX);
    if (p_intf == NULL) {
        HAL_RT_LOG_INFO("RT-RIF-GET", "VRF:%d Intf:%d not created", vrf_id, if_index);
        return(ref_cnt);
    }

    if (p_intf->rif_info.rif_id != 0) {
        HAL_RT_LOG_INFO("RT-RIF-GET", "Get Ref count for RIF id (0x%lx) VRF-id:%d if_index (%d)"
                        "is %d", p_intf->rif_info.rif_id, vrf_id, if_index,
                        p_intf->rif_info.ref_count);
        return (p_intf->rif_info.ref_count);
    } else {
        HAL_RT_LOG_INFO("RT-RIF-GET", "Get RIF not found for VRF-id:%d if_index (%d)", vrf_id, if_index);
    }
    return(ref_cnt);
}


/* used by debug routines to retrieve rif information */
t_std_error hal_rif_info_get (hal_vrf_id_t vrf_id, hal_ifindex_t if_index, ndi_rif_id_t *rif_id, uint32_t *ref_count)
{
    t_fib_intf *p_intf = fib_get_intf(if_index, vrf_id, HAL_RT_V4_AFINDEX);
    if (p_intf == NULL) {
        HAL_RT_LOG_ERR("RIF-INFO-GET", "VRF:%d Intf:%d not created", vrf_id, if_index);
        return STD_ERR(ROUTE,FAIL,0);
    }

    if (p_intf->rif_info.rif_id != 0) {
        *rif_id   = p_intf->rif_info.rif_id;
        *ref_count = p_intf->rif_info.ref_count;
        return STD_ERR_OK;
    }
    return STD_ERR(ROUTE,FAIL,0);
}

bool hal_rif_update (hal_vrf_id_t vrf_id, t_fib_intf_entry *p_intf)
{
    ndi_rif_entry_t     rif_entry;
    npu_id_t npu_id = 0;

    ndi_rif_id_t rif_id = hal_rif_id_get(npu_id, vrf_id, p_intf->if_index);
    if (rif_id == 0) {
        /* return RIF entry if present in the RIF entry table */
        return true;
    }

    memset (&rif_entry, 0, sizeof (ndi_rif_entry_t));
    for (npu_id = 0; npu_id < (npu_id_t)hal_rt_access_fib_config()->max_num_npu;
         npu_id++) {

        rif_entry.npu_id = npu_id;
        rif_entry.vrf_id = hal_vrf_obj_get(npu_id, vrf_id);
        rif_entry.rif_id = rif_id;
        rif_entry.flags = NDI_RIF_ATTR_SRC_MAC_ADDRESS;
        memcpy(&rif_entry.src_mac, &p_intf->mac_addr, sizeof(hal_mac_addr_t));

        if (ndi_rif_set_attribute(&rif_entry)!= STD_ERR_OK) {
            HAL_RT_LOG_ERR("NAS-RT-RIF", "RIF id update "
                           " failed for if_index = %d",p_intf->if_index);
            return false;
        }
        HAL_RT_LOG_INFO("RT-RIF-UPD", "RIF id update "
                        " for if_index = %d",p_intf->if_index);
    }
    return true;
}

/* This function returns the RIF-id (non-zero) for the matching NPU-id, VRF-id and if-index,
 * if does not exist, returns 0 */
ndi_rif_id_t hal_rif_id_get (npu_id_t npu_id, hal_vrf_id_t vrf_id, hal_ifindex_t if_index)
{
    t_fib_intf *p_intf = fib_get_intf(if_index, vrf_id, HAL_RT_V4_AFINDEX);
    if (p_intf == NULL) {
        HAL_RT_LOG_ERR("RIF-ID-GET", "VRF:%d Intf:%d not created", vrf_id, if_index);
        return (0);
    }
    HAL_RT_LOG_DEBUG("RIF-ID-GET", "RIF id is 0x%lx for if_index %d refcnt %d",
                     p_intf->rif_info.rif_id, if_index, p_intf->rif_info.ref_count);
    return (p_intf->rif_info.rif_id);
}

bool hal_rt_is_intf_lpbk (hal_vrf_id_t vrf_id, hal_ifindex_t if_index)
{
    interface_ctrl_t    intf_ctrl;

    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
    intf_ctrl.vrf_id = vrf_id;
    intf_ctrl.if_index = if_index;

    if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
        return false;
    }
    /* Check if the MAC-VLAN created on the loopback interface, if yes, return true */
    if ((intf_ctrl.int_type == nas_int_type_MACVLAN) &&
        (intf_ctrl.l3_intf_info.if_index)) {
        hal_vrf_id_t parent_vrf_id = intf_ctrl.l3_intf_info.vrf_id;
        hal_ifindex_t parent_if_index = intf_ctrl.l3_intf_info.if_index;

        memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
        intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
        intf_ctrl.vrf_id = parent_vrf_id;
        intf_ctrl.if_index = parent_if_index;

        if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
            HAL_RT_LOG_ERR("RT-INTF-GET", "Invalid interface VRF-id:%d if-index:%d.",
                           parent_vrf_id, parent_if_index);
            return false;
        }
    }

    HAL_RT_LOG_DEBUG("HAL-RT-INTF", "intf:%s(%d) type:%d",
                     intf_ctrl.if_name, if_index, intf_ctrl.int_type);

    return (intf_ctrl.int_type == nas_int_type_LPBK);
}

bool hal_rt_is_intf_mgmt (hal_vrf_id_t vrf_id, hal_ifindex_t if_index)
{
    interface_ctrl_t    intf_ctrl;

    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
    intf_ctrl.vrf_id = vrf_id;
    intf_ctrl.if_index = if_index;

    if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
        return false;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-INTF", "intf:%s(%d) type:%d",
                     intf_ctrl.if_name, if_index, intf_ctrl.int_type);
    if ((intf_ctrl.int_type == nas_int_type_MGMT) ||
        ((intf_ctrl.int_type == nas_int_type_VLAN) &&
         (intf_ctrl.int_sub_type == BASE_IF_VLAN_TYPE_MANAGEMENT))) {
        return true;
    }
    return false;
}

bool hal_rt_is_intf_mac_vlan (hal_vrf_id_t vrf_id, hal_ifindex_t if_index)
{
    interface_ctrl_t    intf_ctrl;

    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
    intf_ctrl.vrf_id = vrf_id;
    intf_ctrl.if_index = if_index;

    if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
        return false;
    }

    HAL_RT_LOG_DEBUG("HAL-RT-INTF", "intf:%s(%d) type:%d",
                     intf_ctrl.if_name, if_index, intf_ctrl.int_type);

    /* For router interface in VRF context, return MAC-VLAN status as false. */
    if (intf_ctrl.l3_intf_info.if_index != 0) {
        return false;
    }
    return (intf_ctrl.int_type == nas_int_type_MACVLAN);
}

/*
 * This function gets the maximum mtu supported in the base switch configuration
 */
static uint_t hal_rt_get_max_mtu()
{
   cps_api_get_params_t   get_req;
   cps_api_object_t       obj;
   cps_api_object_attr_t  attr;
   cps_api_key_t          keys[1];
   size_t                 i, len = 0;
   static uint_t           mtu=0;


   if (mtu >= FIB_MIN_L3_MTU)
        return mtu;
   /*
    * Set mtu to minimum supported mtu, if anything fails
    * in getting base switch configuration
    */
   mtu = FIB_MIN_L3_MTU;

   if (cps_api_get_request_init (&get_req) != cps_api_ret_code_OK)
   {
       HAL_RT_LOG_INFO("HAL-RT",  "cps_api_get_request_init in base_switch failed");
       return mtu;
   }
   cps_api_key_from_attr_with_qual(keys, BASE_SWITCH_SWITCHING_ENTITIES_SWITCHING_ENTITY, cps_api_qualifier_TARGET);

    get_req.key_count = 1;
    get_req.keys=keys;

    if (cps_api_get(&get_req) != cps_api_ret_code_OK)
    {
        HAL_RT_LOG_INFO("HAL-RT", "cps_api_get in base_switch failed");
        cps_api_get_request_close (&get_req);
        return mtu;
    }

    len = cps_api_object_list_size(get_req.list);

    for (i=0; i < len; ++i)
    {
        obj = cps_api_object_list_get(get_req.list, i);
        if (cps_api_key_element_at(cps_api_object_key (obj),
                 CPS_OBJ_KEY_SUBCAT_POS) != BASE_SWITCH_SWITCHING_ENTITIES_OBJ)
        {
            HAL_RT_LOG_DEBUG("HAL-RT", "Invalid sub-cat received in base_switch cps get");
            continue;
        }

        attr = cps_api_object_attr_get (obj, BASE_SWITCH_SWITCHING_ENTITIES_SWITCHING_ENTITY_MAX_MTU);
        if (attr != NULL)
        {
            mtu = cps_api_object_attr_data_uint(attr);
            HAL_RT_LOG_DEBUG("HAL-RT", "Max MTU is %d", mtu);
        }
    }

    cps_api_get_request_close (&get_req);
    return mtu;
}

t_std_error hal_rt_get_parent_intf_ctrl(hal_vrf_id_t vrf_id, hal_ifindex_t if_index,
                                        interface_ctrl_t *p_intf_ctrl) {
    memset(p_intf_ctrl, 0, sizeof(interface_ctrl_t));
    p_intf_ctrl->q_type = HAL_INTF_INFO_FROM_IF;
    p_intf_ctrl->vrf_id = vrf_id;
    p_intf_ctrl->if_index = if_index;

    if ((dn_hal_get_interface_info(p_intf_ctrl)) != STD_ERR_OK) {
        HAL_RT_LOG_INFO("RT-RIF-ADD",
                        "Invalid interface VRF-id:%d if-index:%d. RIF ID get failed ", vrf_id,
                        if_index);
        return STD_ERR(ROUTE,FAIL,0);
    }

    HAL_RT_LOG_DEBUG("RT-RIF-ADD", "RIF entry creation for intf:%s(%d) type:%d "
                     "VRF context intf: VRF-id:%d intf:%d ",
                     p_intf_ctrl->if_name, p_intf_ctrl->if_index, p_intf_ctrl->int_type,
                     vrf_id, if_index);
    return STD_ERR_OK;
}

/*
 * This function gets the RIF index entry for a given if_index from the RIF entry table.
 * If entry us not present it creates a new RIF index in hardware via NDI and caches it
 * in the RIF entry table.
 */

t_std_error hal_rif_index_get_or_create (npu_id_t npu_id, hal_vrf_id_t vrf_id,
                                         hal_ifindex_t if_index, ndi_rif_id_t *rif_id)
{
    t_fib_intf         *p_intf = NULL, *p_temp_intf = NULL;
    ndi_rif_entry_t     rif_entry;
    interface_ctrl_t    intf_ctrl;
    char                buf[HAL_RT_MAX_BUFSZ];
    hal_ifindex_t       rt_if_index = if_index;
    hal_mac_addr_t      mac_addr;

    if (rif_id == NULL)
        return STD_ERR(ROUTE,FAIL,0);

    *rif_id = 0;
    bool is_intf_exist = false;
    p_intf = fib_get_or_create_intf(if_index, vrf_id, HAL_RT_V4_AFINDEX, &is_intf_exist);
    if (p_intf == NULL) {
        HAL_RT_LOG_ERR("RT-RIF-ADD", "VRF:%d Intf:%d not created", vrf_id, if_index);
        return STD_ERR(ROUTE,FAIL,0);
    }
    HAL_RT_LOG_INFO("RT-RIF-ADD", "VRF:%d Intf:%d intf-exist-already:%d",
                    vrf_id, if_index, is_intf_exist);
    if (p_intf->rif_info.rif_id != 0) {
        *rif_id = p_intf->rif_info.rif_id;
        HAL_RT_LOG_INFO("HAL-RT", "RIF id is 0x%lx for if_index %d refcnt %d",
                       *rif_id, if_index, p_intf->rif_info.ref_count);
        return STD_ERR_OK;
    }

    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
    intf_ctrl.vrf_id = vrf_id;
    intf_ctrl.if_index = if_index;

    if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
        HAL_RT_LOG_INFO("RT-RIF-ADD",
                        "Invalid interface %d. RIF ID get failed ", if_index);
        return STD_ERR(ROUTE,FAIL,0);
    }
    memset(&mac_addr, 0, sizeof(mac_addr));
    if(intf_ctrl.int_type == nas_int_type_MACVLAN) {
        std_string_to_mac(&(mac_addr), intf_ctrl.mac_addr, sizeof(intf_ctrl.mac_addr));
        hal_vrf_id_t parent_vrf_id = intf_ctrl.l3_intf_info.vrf_id;
        hal_ifindex_t parent_if_index = intf_ctrl.l3_intf_info.if_index;

        if (parent_if_index != 0) {
            memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
            intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
            intf_ctrl.vrf_id = parent_vrf_id;
            intf_ctrl.if_index = parent_if_index;

            if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
                HAL_RT_LOG_INFO("RT-RIF-ADD",
                                "Invalid interface VRF-id:%d if-index:%d. RIF ID get failed ", parent_vrf_id,
                                parent_if_index);
                return STD_ERR(ROUTE,FAIL,0);
            }

            HAL_RT_LOG_DEBUG("RT-RIF-ADD", "RIF entry creation for intf:%s(%d) type:%d VRF context intf: VRF-id:%d intf:%d ",
                             intf_ctrl.if_name, intf_ctrl.if_index, intf_ctrl.int_type, vrf_id, if_index);
            /* Use the parent interface for creating the RIF in NPU */
            if_index = intf_ctrl.if_index;
        }
    }

    memset (&rif_entry, 0, sizeof (ndi_rif_entry_t));
    rif_entry.npu_id = npu_id;

    HAL_RT_LOG_DEBUG("RT-RIF-ADD", "RIF entry creation for intf:%s(%d) type:%d",
                     intf_ctrl.if_name, intf_ctrl.if_index, intf_ctrl.int_type);
    if(intf_ctrl.int_type == nas_int_type_PORT) {
        rif_entry.rif_type = NDI_RIF_TYPE_PORT;
        rif_entry.attachment.port_id.npu_id = intf_ctrl.npu_id;
        rif_entry.attachment.port_id.npu_port = intf_ctrl.port_id;
    } else if(intf_ctrl.int_type == nas_int_type_LAG) {
        ndi_obj_id_t obj_id;
        rif_entry.rif_type = NDI_RIF_TYPE_LAG;
        if(hal_rt_lag_obj_id_get(intf_ctrl.if_index, &obj_id) == STD_ERR_OK)
            rif_entry.attachment.lag_id = obj_id;
        else
            return STD_ERR(ROUTE,FAIL,0);
    } else if(intf_ctrl.int_type == nas_int_type_VLAN) {
        rif_entry.rif_type = NDI_RIF_TYPE_VLAN;
        rif_entry.attachment.vlan_id = intf_ctrl.vlan_id;
    } else if(intf_ctrl.int_type == nas_int_type_DOT1D_BRIDGE) {
        rif_entry.rif_type = NDI_RIF_TYPE_DOT1D_BRIDGE;
        rif_entry.attachment.bridge_id = intf_ctrl.bridge_id;
        HAL_RT_LOG_INFO("RT-RIF-ADD", "1D bridge RIF entry creation for intf:%s(%d) type:%d bridge:%lu",
                       intf_ctrl.if_name, intf_ctrl.if_index, intf_ctrl.int_type, intf_ctrl.bridge_id);
    }  else if(intf_ctrl.int_type == nas_int_type_LPBK) {
        /* Loopback intf - valid L3 interface but RIF creation is not required as we dont use
         * the loopback MAC to lift the loopback address destined packets in the NPU */
        return STD_ERR_OK;
    } else {
        HAL_RT_LOG_ERR("RT-RIF-ADD", "Invalid RIF entry creation ignored for intf:%s(%d) type:%d",
                       intf_ctrl.if_name, intf_ctrl.if_index, intf_ctrl.int_type);
        return STD_ERR(ROUTE,FAIL,0);
    }

    rif_entry.vrf_id = hal_vrf_obj_get(npu_id, vrf_id);

    if (vrf_id != FIB_DEFAULT_VRF) {
        /* fib_intf is stored on a per af basis, so retrieve
         * the interface for first available family and use its mac.
         */
        p_temp_intf = fib_get_next_intf (rt_if_index, vrf_id, 0);

        rif_entry.flags = NDI_RIF_ATTR_SRC_MAC_ADDRESS;
        if (p_temp_intf && (p_temp_intf->key.vrf_id == vrf_id) && (p_temp_intf->key.if_index == rt_if_index)) {
            if (!hal_rt_is_mac_address_zero(&p_temp_intf->mac_addr)) {
                memcpy(&rif_entry.src_mac, &p_temp_intf->mac_addr, sizeof(hal_mac_addr_t));
            } else if (!hal_rt_is_mac_address_zero(&mac_addr)) {
                HAL_RT_LOG_INFO("RT-RIF-ADD", "VRF-id:%d MAC is zero in local intf:%d(%s) cache, using cmn intf. DB MAC",
                               vrf_id, rt_if_index, intf_ctrl.if_name);
                memcpy(&rif_entry.src_mac, &mac_addr, sizeof(hal_mac_addr_t));
            } else {
                HAL_RT_LOG_ERR("RT-RIF-ADD", "VRF-id:%d MAC is zero in intf:%d(%s)", vrf_id, rt_if_index,
                               intf_ctrl.if_name);
                return STD_ERR(ROUTE,FAIL,0);
            }
        } else {
            HAL_RT_LOG_ERR("RT-RIF-ADD", "VRF-id:%d intf:%d Mac is zero, using base MAC!", vrf_id, rt_if_index);
            t_fib_gbl_info *gbl_info = hal_rt_access_fib_gbl_info();
            memcpy(&rif_entry.src_mac, &gbl_info->base_mac_addr, sizeof(hal_mac_addr_t));
        }
        HAL_RT_LOG_INFO("RT-RIF-ADD", "VRF-id:%d RIF Mac is %s", vrf_id,
                        hal_rt_mac_to_str (&rif_entry.src_mac, buf, HAL_RT_MAX_BUFSZ));
    } else {
        /* fib_intf is stored on a per af basis, so retrieve
         * the interface for first available family and use its mac.
         */
        p_temp_intf = fib_get_next_intf (if_index, vrf_id, 0);

        if (p_temp_intf) {
            memcpy(&mac_addr, &p_temp_intf->mac_addr, sizeof(hal_mac_addr_t));
        }

        /* fetch the mac from nas interface only if local cache is not present,
         * call to dn_hal_get_interface_mac is a blocking call, hence to be
         * called only from l3 threads and not from cps handlers.
         */
        if((p_temp_intf && (!hal_rt_is_mac_address_zero(&p_temp_intf->mac_addr))) ||
           (dn_hal_get_interface_mac(if_index, mac_addr) == STD_ERR_OK)) {
            rif_entry.flags = NDI_RIF_ATTR_SRC_MAC_ADDRESS;
            memcpy(&rif_entry.src_mac, &mac_addr, sizeof(hal_mac_addr_t));
            HAL_RT_LOG_DEBUG("RT-RIF-ADD", "RIF Mac is %s",
                             hal_rt_mac_to_str (&mac_addr, buf, HAL_RT_MAX_BUFSZ));
        }
    }
    if (ndi_rif_create(&rif_entry, rif_id)!= STD_ERR_OK) {
        HAL_RT_LOG_ERR("NAS-RT-RIF", "RIF id creation "
                       " failed for if_index = %d bridge-id:%lu", if_index, intf_ctrl.bridge_id);
        return STD_ERR(ROUTE,FAIL,0);
    }
    /*
     * Configure RIF MTU
     */
    rif_entry.rif_id = *rif_id;
    rif_entry.flags = NDI_RIF_ATTR_MTU;
    rif_entry.mtu = hal_rt_get_max_mtu();
    HAL_RT_LOG_INFO("RT-RIF-ADD", "RIF MTU for rif-id:0x%lx if_index %d is %d",
                    *rif_id, if_index, rif_entry.mtu);
    if (ndi_rif_set_attribute(&rif_entry) != STD_ERR_OK) {
        HAL_RT_LOG_DEBUG("NAS-RT-RIF", "RIF update MTU failed for if_index = %d",
                         if_index);
    }
    /*
     * Configure RIF IP Redirect if enabled.
     */
    if (p_intf->is_ip_redirects_set) {
        rif_entry.npu_id = 0;
        rif_entry.rif_id = *rif_id;
        rif_entry.flags = NDI_RIF_ATTR_IP_REDIRECT;
        rif_entry.ip_redirect_state = true;

        HAL_RT_LOG_DEBUG("HAL-RT-RIF", "RIF attribute set for IP redirect config:%d, rif-id:0x%lx, if_index:%d",
                         p_intf->is_ip_redirects_set, *rif_id, if_index);
        if (ndi_rif_set_attribute(&rif_entry) != STD_ERR_OK) {
            HAL_RT_LOG_ERR ("NAS-RT-RIF",
                            "Failed! RIF attribute set for IP redirect config:%d, rif-id:0x%lx, if_index:%d",
                            p_intf->is_ip_redirects_set, *rif_id, if_index);
        }
    }

    /*
     * Save the RIF ID in the rif entry table
     */
    p_intf->rif_info.rif_id = *rif_id;
    p_intf->rif_info.ref_count = 0;

    HAL_RT_LOG_INFO("RT-RIF-ADD", "RIF entry created for vrf-obj-id:0x%lx rif-id:0x%lx VRF-id:%d intf:%s(%d) mac:%s type:%d",
                    rif_entry.vrf_id, *rif_id, vrf_id, intf_ctrl.if_name, if_index,
                    hal_rt_mac_to_str (&rif_entry.src_mac, buf, HAL_RT_MAX_BUFSZ), intf_ctrl.int_type);
    return STD_ERR_OK;
}

t_std_error hal_rif_index_remove (npu_id_t npu_id, hal_vrf_id_t vrf_id, hal_ifindex_t if_index)
{
    t_fib_intf *p_intf = fib_get_intf(if_index, vrf_id, HAL_RT_V4_AFINDEX);
    if (p_intf == NULL) {
        HAL_RT_LOG_ERR("RT-RIF-DEL", "VRF:%d Intf:%d not created", vrf_id, if_index);
        return STD_ERR(ROUTE,FAIL,0);
    }
    /*  RIF information is not present in the INTF-RIF able, return error */
    if (p_intf->rif_info.rif_id == 0) {
        HAL_RT_LOG_ERR("RT-RIF-DEL", "RIF id not present for if_index %d",
                       if_index);
        return (STD_ERR(ROUTE, PARAM, 0));
    }

    if (ndi_rif_delete(npu_id, p_intf->rif_info.rif_id) != STD_ERR_OK) {
        HAL_RT_LOG_ERR("RT-RIF-DEL", "RIF id Deletion failed for if_index = %d",
                       if_index);
        return (STD_ERR(ROUTE, PARAM, 0));
    }

    /*
     * Erase the RIF ID from the rif entry table
     */
    HAL_RT_LOG_INFO("RT-RIF-DEL", "RIF entry deleted successfully: 0x%lx for if_index %d",
                    p_intf->rif_info.rif_id, if_index);
    memset(&(p_intf->rif_info), 0, sizeof(nas_rif_info_t));
    return STD_ERR_OK;
}

//@Todo, have to take care of multi-npu scenario
ndi_vrf_id_t hal_vrf_obj_get (npu_id_t npu_id, hal_vrf_id_t vrf_id)
{
    return ((hal_rt_access_fib_vrf(vrf_id))->vrf_obj_id);
}

/*
 * Stub Routines - @TODO
 */
void fib_check_threshold_for_all_cams (int action)
{
    return;
}

unsigned long fib_tick_get( void )
{
    return (0);
}

int sys_clk_rate_get (void)
{
    return (50);
}

BASE_CMN_AF_TYPE_t nas_route_af_to_cps_af(unsigned short af){
    if(af == HAL_INET6_FAMILY){
        return BASE_CMN_AF_TYPE_INET6;
    }
    return BASE_CMN_AF_TYPE_INET;
}

t_std_error nas_rt_fill_opaque_data(cps_api_object_t obj, uint64_t attr, int npu_id, next_hop_id_t *p_ndi_id)
{
    nas::ndi_obj_id_table_t nh_opaque_data_table;
    nh_opaque_data_table[npu_id] = *p_ndi_id;
    cps_api_attr_id_t  attr_id_list[] = {attr};
    if (nas::ndi_obj_id_table_cps_serialize (nh_opaque_data_table, obj, attr_id_list,
                                             sizeof(attr_id_list)/sizeof(attr_id_list[0]))) {
        return STD_ERR_OK;
    }
    return (STD_ERR(ROUTE, PARAM, 0));
}

uint32_t nas_rt_get_clock_sec() {
    return(time(NULL));
}

std::mutex m_mtx;
std::condition_variable  m_data;

fib_msg_uptr_t nas_rt_read_msg () {
    std::unique_lock<std::mutex> l {m_mtx};
    if (hal_rt_msg_list.empty()) {
        m_data.wait (l, []{return !hal_rt_msg_list.empty();});
    }
    auto p_msg = std::move(hal_rt_msg_list.front());
    hal_rt_msg_list.pop_front();

    auto it = hal_rt_msg_list_stats->find(p_msg->type);
    if (it != hal_rt_msg_list_stats->end())
        it->second--;
    return p_msg;
}

uint32_t nas_rt_read_msg_list_stats (t_fib_msg_type msg_type)
{
    std::lock_guard<std::mutex> l {m_mtx};

    auto it = hal_rt_msg_list_stats->find(msg_type);
    if (it == hal_rt_msg_list_stats->end())
        return 0;
    return it->second;
}

int fib_msg_main(void) {
    uint32_t nas_num_route_msgs_in_queue = 0;
    /* Process the messages from queue */
    for(;;) {
        fib_msg_uptr_t p_msg_uptr = nas_rt_read_msg();
        if (!p_msg_uptr)
            continue;
        auto p_msg = p_msg_uptr.get();
        switch(p_msg->type) {
            case FIB_MSG_TYPE_NL_INTF:
            case FIB_MSG_TYPE_NBR_MGR_INTF:
                HAL_RT_LOG_DEBUG("HAL-RT-MSG-THREAD",
                                 "Interface msg processing type:%d", p_msg->type);
                nas_l3_lock();
                hal_rt_process_intf_state_msg(p_msg->type, &(p_msg->intf));
                nas_l3_unlock();
                break;
            case FIB_MSG_TYPE_NL_ROUTE:
                HAL_RT_LOG_DEBUG("HAL-RT-MSG-THREAD", "Route msg processing");
                nas_num_route_msgs_in_queue = nas_rt_read_msg_list_stats (p_msg->type);
                nas_l3_lock();
                fib_proc_dr_download(&(p_msg->route), nas_num_route_msgs_in_queue);
                nas_l3_unlock();
                break;
            case FIB_MSG_TYPE_NBR_MGR_NBR_INFO:
                HAL_RT_LOG_DEBUG("HAL-RT-MSG-THREAD", "Nbr msg processing");
                nas_l3_lock();
                fib_proc_nbr_download(&(p_msg->nbr));
                nas_l3_unlock();
                break;
            case FIB_MSG_TYPE_INTF_IP_UNREACH_CFG:
                HAL_RT_LOG_DEBUG("HAL-RT-MSG-THREAD", "IP unreachable config msg processing");
                nas_l3_lock();
                fib_proc_ip_unreach_config_msg(&(p_msg->ip_unreach_cfg));
                nas_l3_unlock();
                break;
            case FIB_MSG_TYPE_INTF_IP_REDIRECTS_CFG:
                HAL_RT_LOG_DEBUG("HAL-RT-MSG-THREAD", "IP redirects config msg processing");
                fib_proc_ip_redirects_config_msg(&(p_msg->ip_redirects_cfg));
                break;
            case FIB_MSG_TYPE_NEIGH_FLUSH:
                HAL_RT_LOG_DEBUG("HAL-RT-MSG-THREAD", "Neighbor flush msg processing");
                nas_l3_lock();
                fib_process_neigh_flush(&(p_msg->neigh_flush));
                nas_l3_unlock();
                break;
            default:
                break;
        }
    }
    return true;
}

int nas_rt_process_msg(t_fib_msg *p_msg) {
    bool hal_rt_msg_thr_wakeup = false;
    if (p_msg) {
        std::lock_guard<std::mutex> l {m_mtx};
        hal_rt_msg_thr_wakeup = hal_rt_msg_list.empty();
        hal_rt_msg_list.emplace_back(p_msg);

        auto it = hal_rt_msg_list_stats->find(p_msg->type);
        if (it != hal_rt_msg_list_stats->end())
            it->second++;

        if (hal_rt_msg_peak_cnt < hal_rt_msg_list.size())
            hal_rt_msg_peak_cnt = hal_rt_msg_list.size();
    }
    if (hal_rt_msg_thr_wakeup) m_data.notify_one ();
    return true;
}

t_fib_msg *hal_rt_alloc_mem_msg() {
    t_fib_msg *p_msg = new (std::nothrow) t_fib_msg;
    return p_msg;
}


/* allocate memory for the route message for given buffer size.
 * route message buffer size is calculated based on the nh_count
 * in the message.
 */
t_fib_msg *hal_rt_alloc_route_mem_msg(uint32_t buf_size) {
    char *p_msg = new (std::nothrow) char[buf_size];
    return (t_fib_msg *)p_msg;
}

void hal_rt_free_route_mem_msg(t_fib_msg *pmsg) {
    delete pmsg;
}

std::string hal_rt_queue_stats ()
{
    std::lock_guard<std::mutex> l {m_mtx};
    std::stringstream ss;
    ss << "Current:" << hal_rt_msg_list.size() << "Peak:" << hal_rt_msg_peak_cnt;
    return ss.str();
}

std::string hal_rt_queue_msg_type_stats ()
{
    std::lock_guard<std::mutex> l {m_mtx};
    std::stringstream ss;
    for (auto it = hal_rt_msg_list_stats->begin(); it != hal_rt_msg_list_stats->end(); ++it)
        ss << "MsgType:" << it->first << "Msg Count:" << it->second;
    return ss.str();
}

void hal_rt_sort_array(uint64_t data[], uint32_t count) {

    std::sort(data,data+count);
}

bool hal_rt_get_vrf_id(const char *vrf_name, hal_vrf_id_t *vrf_id) {
    if (strncmp(vrf_name, FIB_DEFAULT_VRF_NAME, sizeof(FIB_DEFAULT_VRF_NAME)) == 0) {
        *vrf_id = FIB_DEFAULT_VRF;
    } else if (strncmp(vrf_name, FIB_MGMT_VRF_NAME, sizeof(FIB_MGMT_VRF_NAME)) == 0) {
        *vrf_id = FIB_MGMT_VRF;
    } else if (nas_get_vrf_internal_id_from_vrf_name(vrf_name, vrf_id) != STD_ERR_OK) {
        return false;
    }
    return true;
}

bool hal_rt_get_vrf_name(hal_vrf_id_t vrf_id, char *vrf_name) {

    if (!FIB_IS_VRF_ID_VALID (vrf_id)) {
        HAL_RT_LOG_ERR("HAL-RT", "Invalid VRF: %d", vrf_id);
        return false;
    }

    t_fib_vrf_info *p_vrf_info = hal_rt_access_fib_vrf_info(vrf_id, HAL_INET4_FAMILY);

    if (p_vrf_info == NULL) {
        HAL_RT_LOG_ERR("HAL-RT-DB", "VRF information not populated for VRF-id:%d", vrf_id);
        return false;
    }
    safestrncpy(vrf_name, (char*)FIB_GET_VRF_NAME(vrf_id, HAL_RT_V4_AFINDEX),
                NAS_VRF_NAME_SZ);
    return true;
}

int nas_rt_get_mask (uint8_t af_index, uint8_t prefix_len, t_fib_ip_addr *mask) {
    if (!FIB_IS_AFINDEX_VALID(af_index)) {
        return false;
    }
    std_ip_get_mask_from_prefix_len (af_index, prefix_len, mask);
    /* @@TODO the above function is not giving the mask for IPv4 in the correct order, fix it */
    if (STD_IP_IS_AFINDEX_V4 (af_index)) {
        mask->u.v4_addr = htonl(mask->u.v4_addr);
    }
    return true;
}

bool hal_rt_is_local_ip_conflict(hal_vrf_id_t vrf_id, hal_ip_addr_t *nbr) {

    /* Check if there is an exact matching connected route for this neighbor,
     * if yes, ignore the programming of neighbor. */
    t_fib_dr *p_dr = fib_get_dr (vrf_id, nbr, FIB_AFINDEX_TO_PREFIX_LEN(nbr->af_index));
    if (p_dr) {
        t_fib_nh_holder nh_holder;
        t_fib_nh *p_dr_fh = FIB_GET_FIRST_NH_FROM_DR(p_dr, nh_holder);
        /* Check whether the route is connected route. */
        if ((p_dr->rt_type == RT_CACHE) || (p_dr_fh && (FIB_IS_NH_ZERO(p_dr_fh)))) {
            HAL_RT_LOG_INFO ("HAL-RT-NH-ADD",
                             "Local IP conflict - dont program nbr vrf_id: %d, ip_addr: %s",
                             vrf_id, FIB_IP_ADDR_TO_STR (nbr));
            return true;
        }
    }

    return false;
}

bool hal_rt_is_vrf_valid(hal_vrf_id_t vrf_id) {
    t_fib_vrf *p_vrf = hal_rt_access_fib_vrf(vrf_id);
    if (p_vrf) {
        return true;
    }
    return false;
}

void hal_rt_del_routes(hal_vrf_id_t vrf_id, uint8_t af_index) {
    t_fib_ip_addr prefix;
    uint32_t prefix_len = 0;

    memset(&prefix, 0, sizeof(prefix));
    prefix.af_index = af_index;
    t_fib_dr *p_dr = fib_get_first_dr(vrf_id, af_index);
    while (p_dr) {
        HAL_RT_LOG_INFO ("HAL-RT-DEL-ROUTE", "VRF:%d Prefix:%s/%d",
                         vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len);
        memcpy(&prefix, &p_dr->key.prefix, sizeof(prefix));
        prefix_len = p_dr->prefix_len;
        p_dr->status_flag |= FIB_DR_STATUS_DEL;
        fib_proc_dr_del (p_dr);
        p_dr = fib_get_next_dr (vrf_id, &prefix, prefix_len);
    }
}

bool hal_rt_flush_vrf_info(hal_vrf_id_t vrf_id) {

    t_fib_vrf *p_vrf = hal_rt_access_fib_vrf(vrf_id);
    if (p_vrf == NULL) {
        return true;
    }
    t_fib_intf *p_del_intf = NULL;
    t_fib_intf *p_intf = fib_get_next_intf(0, vrf_id, 0);
    while ((p_intf != NULL) && (p_intf->key.vrf_id == vrf_id)) {
        p_del_intf = p_intf;
        p_intf = fib_get_next_intf (p_intf->key.if_index,
                                    p_intf->key.vrf_id, p_intf->key.af_index);
        fib_process_route_del_on_intf_event (p_del_intf, FIB_INTF_FORCE_DEL);
        fib_process_link_local_address_del_on_intf_event (p_del_intf, FIB_INTF_FORCE_DEL);
        fib_process_nh_del_on_intf_event (p_del_intf, FIB_INTF_FORCE_DEL, false);

        fib_del_all_intf_ip(p_del_intf);
        p_del_intf->is_intf_delete_pending = true;
        p_del_intf->is_ipv4_unreachables_set =false;
        p_del_intf->is_ipv6_unreachables_set = false;
        fib_check_and_delete_intf(p_del_intf);
    }

    t_fib_nh * p_nh = fib_get_first_nh (vrf_id, HAL_RT_V4_AFINDEX);
    while (p_nh != NULL)
    {
        HAL_RT_LOG_ERR ("NH-DEL-ERR",
                        "NH not deleted - vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                        "owner_flag: 0x%x, status_flag: 0x%x",
                        p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                        p_nh->key.if_index, p_nh->owner_flag, p_nh->status_flag);

        p_nh = fib_get_next_nh (vrf_id, &p_nh->key.ip_addr, p_nh->key.if_index);
    }

    p_nh = fib_get_first_nh (vrf_id, HAL_RT_V6_AFINDEX);
    while (p_nh != NULL)
    {
        HAL_RT_LOG_ERR ("NH-DEL-ERR",
                        "NH not deleted - vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                        "owner_flag: 0x%x, status_flag: 0x%x",
                        p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                        p_nh->key.if_index, p_nh->owner_flag, p_nh->status_flag);

        p_nh = fib_get_next_nh (vrf_id, &p_nh->key.ip_addr, p_nh->key.if_index);
    }

    /* Since RIF-id is stored in the AF-IPv4 interface entry, it is possible that while deleting the IPv4 routes,
     * RIF-id should be retained since Ipv6 route delete comes next, loop thru interface DB again, to clean-up the interface DB. */
    p_intf = fib_get_next_intf(0, vrf_id, 0);
    while ((p_intf != NULL) && (p_intf->key.vrf_id == vrf_id)) {
        p_del_intf = p_intf;
        p_intf = fib_get_next_intf (p_intf->key.if_index,
                                    p_intf->key.vrf_id, p_intf->key.af_index);
        p_del_intf->is_intf_delete_pending = true;
        fib_check_and_delete_intf(p_del_intf);
    }

    /* Make sure all the interfaces associated with VRF is deleted */
    p_intf = fib_get_next_intf(0, vrf_id, 0);
    if ((p_intf != NULL) && (p_intf->key.vrf_id == vrf_id)) {
        HAL_RT_LOG_ERR("HAL-VRF-FLUSH", "VRF:%d intf:%d(%s) af:%d still exists after flush",
                       vrf_id, p_intf->key.if_index, p_intf->if_name, p_intf->key.af_index);
        HAL_RT_LOG_ERR("HAL-RT-INTF", "Intf delete not done: if_index: %d, vrf_id: %d, af_index: %d FH-list:%p "
                       "Pending-FH-list:%p IP-list:%p unreachble IPv4:%d IPv6:%d rif-id:0x%lx ref-cnt:%d",
                       p_intf->key.if_index, p_intf->key.vrf_id,
                       p_intf->key.af_index, std_dll_getfirst (&p_intf->fh_list),
                       std_dll_getfirst (&p_intf->pending_fh_list),
                       std_dll_getfirst (&p_intf->ip_list),
                       p_intf->is_ipv4_unreachables_set,
                       p_intf->is_ipv6_unreachables_set,
                       p_intf->rif_info.rif_id, p_intf->rif_info.ref_count);
    } else {
        HAL_RT_LOG_INFO("HAL-VRF-FLUSH", "VRF:%d interfaces deleted successfully", vrf_id);
    }
    /* Remove all non-interface associated routes i.e prohibit/blackhole/unreachable..etc
     * are deleted from VRF with AF-IPv4 and AF-IPv6 dr trees. */
    hal_rt_del_routes(vrf_id, HAL_INET4_FAMILY);
    hal_rt_del_routes(vrf_id, HAL_INET6_FAMILY);
    nas_rt_flush_nhts(vrf_id, HAL_INET4_FAMILY);
    nas_rt_flush_nhts(vrf_id, HAL_INET6_FAMILY);

    t_fib_dr *p_dr = fib_get_first_dr(vrf_id, HAL_INET4_FAMILY);
    while (p_dr) {
        HAL_RT_LOG_ERR("HAL-RT-DEL-ROUTE", "VRF:%d Prefix:%s/%d still present after clean-up",
                         vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len);
        p_dr = fib_get_next_dr (vrf_id, &p_dr->key.prefix, p_dr->prefix_len);
    }

    p_dr = fib_get_first_dr(vrf_id, HAL_INET6_FAMILY);
    while (p_dr) {
        HAL_RT_LOG_ERR("HAL-RT-DEL-ROUTE", "VRF:%d Prefix:%s/%d still present after clean-up",
                         vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix), p_dr->prefix_len);
        p_dr = fib_get_next_dr (vrf_id, &p_dr->key.prefix, p_dr->prefix_len);
    }

    HAL_RT_LOG_INFO("HAL-VRF-FLUSH", "VRF:%d flush completed successfully", vrf_id);
    return true;
}

/* This function handles all the pending routes to be resolved. */
t_std_error fib_process_pending_resolve_dr(int vrf_id, int af_index) {
    t_fib_vrf_info         *p_vrf_info = NULL;
    std_radix_version_t  max_walker_version = 0;
    int                  rc = STD_ERR_OK;

    if (hal_rt_access_fib_vrf(vrf_id) == NULL) {
        return STD_ERR_OK;
    }

    p_vrf_info = FIB_GET_VRF_INFO (vrf_id, af_index);
    if (p_vrf_info == NULL){
        HAL_RT_LOG_DEBUG("HAL-RT-DR", "Vrf info NULL. "
                         "vrf_id: %d, af_index: %d", vrf_id, af_index);
        return STD_ERR_OK;
    }

    p_vrf_info->num_dr_processed_by_walker = 0;

    if (p_vrf_info->dr_clear_on == true) {
        max_walker_version = p_vrf_info->dr_clear_max_radix_ver;
    }
    else if (p_vrf_info->dr_ha_on == true) {
        max_walker_version = p_vrf_info->dr_ha_max_radix_ver;
    }
    else {
        max_walker_version = std_radix_getversion (p_vrf_info->dr_tree);
    }

    std_radical_walkchangelist (p_vrf_info->dr_tree,
                                &p_vrf_info->dr_radical_marker,
                                fib_dr_walker_call_back,
                                0, 0,
                                max_walker_version,
                                &rc);

    return STD_ERR_OK;
}


#ifdef __cplusplus
}
#endif
