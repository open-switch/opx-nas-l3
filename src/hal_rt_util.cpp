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
#include <condition_variable>
#include "nas_ndi_obj_id_table.h"

typedef struct _nas_rif_info_t {
    ndi_rif_id_t rif_id;
    uint32_t     ref_count;
}nas_rif_info_t;

typedef std::unordered_map<hal_ifindex_t, nas_rif_info_t> nas_rt_rif_map_t;
using fib_msg_uptr_t = std::unique_ptr<t_fib_msg>;
static std::deque<fib_msg_uptr_t> hal_rt_msg_list;
static nas_rt_rif_map_t g_rif_entry_table;
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

t_std_error hal_rt_validate_intf(int if_index)
{
    interface_ctrl_t intf_ctrl;
    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
    intf_ctrl.if_index = if_index;

    if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
        return (STD_ERR_MK(e_std_err_NPU, e_std_err_code_PARAM, 0));
    }

    return STD_ERR_OK;
}

t_std_error hal_rt_get_intf_name(int if_index, char *p_if_name)
{
    interface_ctrl_t intf_ctrl;
    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));

    memset(p_if_name, '\0', HAL_IF_NAME_SZ);
    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
    intf_ctrl.if_index = if_index;

    if(dn_hal_get_interface_info(&intf_ctrl) != STD_ERR_OK) {
        return (STD_ERR_MK(e_std_err_NPU, e_std_err_code_PARAM, 0));
    }
    strncpy(p_if_name, intf_ctrl.if_name, sizeof(intf_ctrl.if_name));
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
    if (STD_IP_IS_ADDR_LINK_LOCAL(p_ip_addr))
        return true;
    else if ((p_ip_addr->af_index == HAL_INET6_FAMILY) &&
             (((((p_ip_addr->u.v6_addr[0]) & (0xff)) == (0xff)) &&
              (((p_ip_addr->u.v6_addr[1]) & (0xf0)) == (0x00))) ||
             (STD_IP_IS_V6_ADDR_LOOP_BACK(p_ip_addr)))) {
        return true;
    }
    return false;
}

t_std_error hal_rt_lag_obj_id_get (hal_ifindex_t if_index, ndi_obj_id_t& obj_id)
{
    nas::ndi_obj_id_table_t tmp_ndi_oid_tbl;
    if (dn_nas_lag_get_ndi_ids (if_index, &tmp_ndi_oid_tbl) != STD_ERR_OK) {
        HAL_RT_LOG_DEBUG("HAL-RT", "Lag object get failed for %d", if_index);
        return (STD_ERR(ROUTE, PARAM, 0));
    }

    // @Todo - Handle multiple npus
    obj_id = tmp_ndi_oid_tbl[0];
    return STD_ERR_OK;
}

uint32_t hal_rt_rif_ref_inc(hal_ifindex_t if_index)
{
    auto it = g_rif_entry_table.find(if_index);
    uint32_t ref_cnt = 0;

    /* return RIF entry if present in the RIF entry table */
    if (it != g_rif_entry_table.end()) {
        auto& rif_info = (it->second);
        ref_cnt = ++rif_info.ref_count;
        HAL_RT_LOG_DEBUG("HAL-RT", "Ref count for RIF id (%d) if_index (%d)"
                      "is %d", rif_info.rif_id, if_index, rif_info.ref_count);
    } else
        HAL_RT_LOG_DEBUG("HAL-RT", "RIF not found for if_index (%d)", if_index);

    return ref_cnt;
}

uint32_t hal_rt_rif_ref_dec(hal_ifindex_t if_index)
{
    auto it = g_rif_entry_table.find(if_index);
    uint32_t ref_cnt = 0;

    /* return RIF entry if present in the RIF entry table */
    if (it != g_rif_entry_table.end()) {
        auto& rif_info = (it->second);
        if(rif_info.ref_count != 0) {
            ref_cnt = --rif_info.ref_count;
        }
        HAL_RT_LOG_DEBUG("HAL-RT", "Ref count for RIF id (%d) if_index (%d)"
                      "is %d", rif_info.rif_id, if_index, rif_info.ref_count);
    } else
        HAL_RT_LOG_DEBUG("HAL-RT", "RIF not found for if_index (%d)", if_index);

    return ref_cnt;
}

/*
 * This function gets the RIF index entry for a given if_index from the RIF entry table.
 * If entry us not present it creates a new RIF index in hardware via NDI and caches it
 * in the RIF entry table.
 */

ndi_rif_id_t hal_rif_index_get (npu_id_t npu_id, hal_vrf_id_t vrf_id, hal_ifindex_t if_index)
{
    ndi_rif_id_t        rif_id = 0;
    nas_rif_info_t      rif_info;
    ndi_rif_entry_t     rif_entry;
    interface_ctrl_t    intf_ctrl;
    char                buf[HAL_RT_MAX_BUFSZ];

    auto it = g_rif_entry_table.find(if_index);

    /* return RIF entry if present in the RIF entry table */
    if (it != g_rif_entry_table.end()) {
        rif_info = (it->second);
        rif_id   = rif_info.rif_id;
        HAL_RT_LOG_DEBUG("HAL-RT", "RIF id is %d for if_index %d refcnt %d",
                      rif_id, if_index, rif_info.ref_count);
        return (rif_id);
    }

    memset(&intf_ctrl, 0, sizeof(interface_ctrl_t));
    intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
    intf_ctrl.if_index = if_index;

    if ((dn_hal_get_interface_info(&intf_ctrl)) != STD_ERR_OK) {
        HAL_RT_LOG_INFO("HAL-RT",
                    "Invalid interface %d. RIF ID get failed \r\n", if_index);
        return 0;
    }

    memset (&rif_entry, 0, sizeof (ndi_rif_entry_t));
    rif_entry.npu_id = npu_id;

    HAL_RT_LOG_DEBUG("HAL-RT", "RIF entry creation for intf:%s(%d) type:%d",
                     intf_ctrl.if_name, if_index, intf_ctrl.int_type);
    if(intf_ctrl.int_type == nas_int_type_PORT) {
        rif_entry.rif_type = NDI_RIF_TYPE_PORT;
        rif_entry.attachment.port_id.npu_id = intf_ctrl.npu_id;
        rif_entry.attachment.port_id.npu_port = intf_ctrl.port_id;
    } else if(intf_ctrl.int_type == nas_int_type_LAG) {
        ndi_obj_id_t obj_id;
        rif_entry.rif_type = NDI_RIF_TYPE_LAG;
        if(hal_rt_lag_obj_id_get(if_index, obj_id) == STD_ERR_OK)
            rif_entry.attachment.lag_id = obj_id;
        else
            return 0;
    } else if(intf_ctrl.int_type == nas_int_type_VLAN) {
        rif_entry.rif_type = NDI_RIF_TYPE_VLAN;
        rif_entry.attachment.vlan_id = intf_ctrl.vlan_id;
    } else if(intf_ctrl.int_type == nas_int_type_LPBK) {
        /* Loopback intf - valid L3 interface but RIF creation is not required as we dont use
         * the loopback MAC to lift the loopback address destined packets in the NPU */
        return 0;
    } else {
        HAL_RT_LOG_ERR("HAL-RT", "Invalid RIF entry creation ignored for rif-id:%d intf:%s(%d) type:%d",
                       rif_id, intf_ctrl.if_name, if_index, intf_ctrl.int_type);
        return 0;
    }

    rif_entry.vrf_id = hal_vrf_obj_get(npu_id, vrf_id);

    hal_mac_addr_t mac_addr;
    if(dn_hal_get_interface_mac(if_index, mac_addr) == STD_ERR_OK) {
        t_fib_vrf *p_vrf = NULL;
        if ((intf_ctrl.int_type == nas_int_type_VLAN) &&
            ((p_vrf = hal_rt_access_fib_vrf(vrf_id)) != NULL) &&
            (memcmp(&p_vrf->router_mac, &mac_addr, sizeof(hal_mac_addr_t)))) {
            ndi_vr_entry_t  vr_entry;
            memset (&vr_entry, 0, sizeof (ndi_vr_entry_t));
            vr_entry.npu_id = 0;

            memcpy(vr_entry.src_mac, &mac_addr, HAL_MAC_ADDR_LEN);
            memcpy(&p_vrf->router_mac, &mac_addr, HAL_MAC_ADDR_LEN);
            vr_entry.flags = NDI_VR_ATTR_SRC_MAC_ADDRESS;
            vr_entry.vrf_id = p_vrf->vrf_id;

            t_std_error     rc = STD_ERR_OK;
            /* Create default VRF and other vrfs as per FIB_MAX_VRF */
            if ((rc = ndi_route_vr_set_attribute(&vr_entry))!= STD_ERR_OK) {
                HAL_RT_LOG_ERR("HAL-RT", "VR set for router MAC:%s change failed rc:%d",
                               hal_rt_mac_to_str (&mac_addr, buf, HAL_RT_MAX_BUFSZ), rc);
            } else {
                HAL_RT_LOG_INFO("HAL-RT", "RIF Mac is %s set as Router MAC",
                                hal_rt_mac_to_str (&mac_addr, buf, HAL_RT_MAX_BUFSZ));
            }
        }
        rif_entry.flags = NDI_RIF_ATTR_SRC_MAC_ADDRESS;
        memcpy(&rif_entry.src_mac, &mac_addr, sizeof(hal_mac_addr_t));
        HAL_RT_LOG_DEBUG("HAL-RT", "RIF Mac is %s",
                      hal_rt_mac_to_str (&mac_addr, buf, HAL_RT_MAX_BUFSZ));
    }

    if (ndi_rif_create(&rif_entry, &rif_id)!= STD_ERR_OK) {
        HAL_RT_LOG_ERR("NAS-ROUTE", "%s ():RIF id creation "
                " failed for if_index = %d", __FUNCTION__, if_index);
        return (0);
    }

    /*
     * Save the RIF ID in the rif entry table
     */
    rif_info.rif_id = rif_id;
    rif_info.ref_count = 0;
    g_rif_entry_table.insert(std::make_pair(if_index, rif_info));

    HAL_RT_LOG_DEBUG("HAL-RT-RIF", "RIF entry created for rif-id:%d intf:%s(%d) mac:%s type:%d",
                     rif_id, intf_ctrl.if_name, if_index,
                     hal_rt_mac_to_str (&mac_addr, buf, HAL_RT_MAX_BUFSZ), intf_ctrl.int_type);
    return (rif_id);
}

t_std_error hal_rif_index_remove (npu_id_t npu_id, hal_vrf_id_t vrf_id, hal_ifindex_t if_index)
{
    ndi_rif_id_t        rif_id = 0;

    auto it = g_rif_entry_table.find(if_index);

    /*  RIF entry if not present in the RIF able, return error */
    if (it == g_rif_entry_table.end()) {
        HAL_RT_LOG_DEBUG("HAL-RT", "RIF id not present for if_index %d",
                      if_index);
        return (STD_ERR(ROUTE, PARAM, 0));
    }

    rif_id = (it->second).rif_id;

    if (ndi_rif_delete(npu_id, rif_id) != STD_ERR_OK) {
        HAL_RT_LOG_ERR("NAS-ROUTE", "%s ():RIF id Deletion "
                " failed for if_index = %d", __FUNCTION__, if_index);
        return (STD_ERR(ROUTE, PARAM, 0));
    }

    /*
     * Erase the RIF ID from the rif entry table
     */
    g_rif_entry_table.erase(if_index);
    HAL_RT_LOG_DEBUG("HAL-RT", "RIF entry deleted: %d for if_index %d",
                 rif_id, if_index);
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
    return p_msg;
}

int fib_msg_main(void) {
    /* Process the messages from queue */
    for(;;) {
        fib_msg_uptr_t p_msg_uptr = nas_rt_read_msg();
        if (!p_msg_uptr)
            continue;
        auto p_msg = p_msg_uptr.get();
        switch(p_msg->type) {
            case FIB_MSG_TYPE_INTF:
                HAL_RT_LOG_DEBUG("HAL-RT-MSG-THREAD", "Interface msg processing");
                hal_rt_process_intf_state_msg(&(p_msg->intf));
                break;
            case FIB_MSG_TYPE_ROUTE:
                HAL_RT_LOG_DEBUG("HAL-RT-MSG-THREAD", "Route msg processing");
                fib_proc_dr_download(&(p_msg->route));
                break;
            case FIB_MSG_TYPE_NBR:
                HAL_RT_LOG_DEBUG("HAL-RT-MSG-THREAD", "Nbr msg processing");
                fib_proc_nbr_download(&(p_msg->nbr));
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
std::string hal_rt_queue_stats ()
{
    std::lock_guard<std::mutex> l {m_mtx};
    std::stringstream ss;
    ss << "Current:" << hal_rt_msg_list.size() << "Peak:" << hal_rt_msg_peak_cnt;
    return ss.str();
}

#ifdef __cplusplus
}
#endif
