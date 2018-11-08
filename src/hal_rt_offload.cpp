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
 * \file   hal_rt_offload.c
 * \brief  Hal Routing Offload functionality
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
#include <algorithm>
#include "std_utils.h"

#include "cps_api_object_category.h"
#include "cps_api_route.h"
#include "cps_api_operation.h"
#include "cps_api_object_tools.h"
#include "cps_api_operation_tools.h"
#include "cps_class_map.h"
#include "dell-base-neighbor.h"

#include "std_utils.h"
#include "std_rw_lock.h"

using fib_offload_msg_uptr_t = std::unique_ptr<t_fib_offload_msg>;
static auto &hal_rt_offload_msg_list = *new std::deque<fib_offload_msg_uptr_t>;
/* stats counter for hal_rt_offload_msg_list queue on per msg type basis */
static auto hal_rt_offload_msg_list_stats = new std::unordered_map<uint32_t,uint32_t> {
            { FIB_OFFLOAD_MSG_TYPE_NEIGH_FLUSH, 0 },
};

uint_t hal_rt_offload_msg_peak_cnt = 0;

#ifdef __cplusplus
extern "C" {
#endif

std::mutex m_offload_mtx;
std::condition_variable  m_offload_data;

fib_offload_msg_uptr_t nas_rt_read_offload_msg () {
    std::unique_lock<std::mutex> l {m_offload_mtx};
    if (hal_rt_offload_msg_list.empty()) {
        m_offload_data.wait (l, []{return !hal_rt_offload_msg_list.empty();});
    }
    auto p_offload_msg = std::move(hal_rt_offload_msg_list.front());
    hal_rt_offload_msg_list.pop_front();

    auto it = hal_rt_offload_msg_list_stats->find(p_offload_msg->type);
    if (it != hal_rt_offload_msg_list_stats->end())
        it->second--;
    return p_offload_msg;
}

int fib_offload_msg_main(void) {
    /* Process the offload messages from queue */
    for(;;) {
        fib_offload_msg_uptr_t p_offload_msg_uptr = nas_rt_read_offload_msg();
        if (!p_offload_msg_uptr)
            continue;
        auto p_offload_msg = p_offload_msg_uptr.get();
        switch(p_offload_msg->type) {
            case FIB_OFFLOAD_MSG_TYPE_NEIGH_FLUSH:
                HAL_RT_LOG_DEBUG("HAL-RT-OFFLOAD-MSG-THREAD",
                                 "Neigh flush msg processing type:%d", p_offload_msg->type);
                hal_rt_process_neigh_flush_offload_msg (&p_offload_msg->neigh_flush_msg);
                break;
            default:
                break;
        }
    }
    return true;
}


int nas_rt_process_offload_msg(t_fib_offload_msg *p_offload_msg) {
    bool hal_rt_offload_msg_thr_wakeup = false;
    if (p_offload_msg) {
        std::lock_guard<std::mutex> l {m_offload_mtx};
        hal_rt_offload_msg_thr_wakeup = hal_rt_offload_msg_list.empty();
        hal_rt_offload_msg_list.emplace_back(p_offload_msg);

        auto it = hal_rt_offload_msg_list_stats->find(p_offload_msg->type);
        if (it != hal_rt_offload_msg_list_stats->end())
            it->second++;

        if (hal_rt_offload_msg_peak_cnt < hal_rt_offload_msg_list.size())
            hal_rt_offload_msg_peak_cnt = hal_rt_offload_msg_list.size();
    }
    if (hal_rt_offload_msg_thr_wakeup) m_offload_data.notify_one ();
    return true;
}


t_fib_offload_msg *hal_rt_alloc_offload_msg() {
    t_fib_offload_msg *p_offload_msg = new (std::nothrow) t_fib_offload_msg;
    return p_offload_msg;
}

std::string hal_rt_offload_queue_stats ()
{
    std::lock_guard<std::mutex> l {m_offload_mtx};
    std::stringstream ss;
    ss << "Current:" << hal_rt_offload_msg_list.size() << " Peak:" << hal_rt_offload_msg_peak_cnt;
    return ss.str();
}

std::string hal_rt_offload_queue_msg_type_stats ()
{
    std::lock_guard<std::mutex> l {m_offload_mtx};
    std::stringstream ss;
    ss << "Offload Msg Type Stats";
    for (auto it = hal_rt_offload_msg_list_stats->begin(); it != hal_rt_offload_msg_list_stats->end(); ++it)
        ss << "MsgType:" << it->first << " Msg Count:" << it->second;
    return ss.str();
}

bool hal_rt_process_neigh_flush_offload_msg(t_fib_offload_msg_neigh_flush *p_flush_msg) {
    hal_vrf_id_t  vrf_id = 0;

    if (hal_rt_get_vrf_id(p_flush_msg->vrf_name, &vrf_id) == false) {
        /* possibly vrf is deleted before the offload message is processed. skip this msg. */
        HAL_RT_LOG_DEBUG ("HAL-RT-OFF", "VRF-name:%s is not valid!", p_flush_msg->vrf_name);
        return true;
    }

    cps_api_object_guard obj_g (cps_api_obj_tool_create(cps_api_qualifier_TARGET,
                                 BASE_NEIGHBOR_FLUSH_OBJ, false));

    if (obj_g.get() == nullptr)
    {
        HAL_RT_LOG_ERR ("HAL-RT-OFF", " CPS object create failed ");
        return false;
    }

    cps_api_object_attr_add(obj_g.get(), BASE_NEIGHBOR_FLUSH_INPUT_VRF_NAME, p_flush_msg->vrf_name,
                            strlen(p_flush_msg->vrf_name)+1);
    cps_api_object_attr_add_u32(obj_g.get(),BASE_NEIGHBOR_FLUSH_INPUT_AF, p_flush_msg->prefix.af_index);

    size_t addr_len = (p_flush_msg->prefix.af_index == AF_INET) ? HAL_INET4_LEN:HAL_INET6_LEN;
    cps_api_attr_id_t ids[1] = {BASE_NEIGHBOR_FLUSH_INPUT_IP};
    cps_api_object_e_add(obj_g.get(), ids, 1, cps_api_object_ATTR_T_BIN,
                         p_flush_msg->prefix.u.v6_addr, addr_len);

    cps_api_object_attr_add_u32(obj_g.get(),BASE_NEIGHBOR_FLUSH_INPUT_PREFIX_LEN, p_flush_msg->prefix_len);

    if (p_flush_msg->is_neigh_flush_with_intf) {
        interface_ctrl_t   intf_ctrl;
        memset(&intf_ctrl, 0, sizeof(intf_ctrl));

        intf_ctrl.q_type = HAL_INTF_INFO_FROM_IF;
        intf_ctrl.vrf_id = p_flush_msg->vrf_id;
        intf_ctrl.if_index = p_flush_msg->if_index;

        if (dn_hal_get_interface_info(&intf_ctrl) == STD_ERR_OK) {
            cps_api_object_attr_add(obj_g.get(), BASE_NEIGHBOR_FLUSH_INPUT_IFNAME, intf_ctrl.if_name,
                                    strlen(intf_ctrl.if_name)+1);
            HAL_RT_LOG_DEBUG ("HAL-RT-OFF", " Processing Neigh flush message for "
                             "vrf: %s(%d), prefix: %s, prefix_len: %d "
                             "flush_with_intf: %s, if_name: %s(%d)",
                             p_flush_msg->vrf_name, p_flush_msg->vrf_id,
                             FIB_IP_ADDR_TO_STR (&p_flush_msg->prefix), p_flush_msg->prefix_len,
                             (p_flush_msg->is_neigh_flush_with_intf ? "true":"false"),
                             intf_ctrl.if_name, p_flush_msg->if_index);

            if((cps_api_commit_one(cps_api_oper_ACTION, obj_g.get(), 1,0)) != cps_api_ret_code_OK){
                HAL_RT_LOG_ERR ("HAL-RT-OFF", "CPS commit failed ");
                return false;
            }
            HAL_RT_LOG_INFO ("HAL-RT-OFF", "IP neigh flush CPS commit success");
        }
    } else {

        HAL_RT_LOG_DEBUG ("HAL-RT-OFF", " Processing Neigh flush message for "
                         "vrf_id: %s(%d), prefix: %s, prefix_len: %d "
                         "flush_with_intf: %s, if_name: %s(%d)",
                         p_flush_msg->vrf_name, p_flush_msg->vrf_id,
                         FIB_IP_ADDR_TO_STR (&p_flush_msg->prefix), p_flush_msg->prefix_len,
                         (p_flush_msg->is_neigh_flush_with_intf ? "true":"false"),
                         "N/A", p_flush_msg->if_index);
        if((cps_api_commit_one(cps_api_oper_ACTION, obj_g.get(), 1,0)) != cps_api_ret_code_OK){
            HAL_RT_LOG_ERR ("HAL-RT-OFF", "CPS commit failed ");
            return false;
        }
        HAL_RT_LOG_INFO ("HAL-RT-OFF", "IP neigh flush CPS commit success");
    }

    return true;
}
#ifdef __cplusplus
}
#endif
