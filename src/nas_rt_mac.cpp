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
 * \file   nas_rt_mac.c
 * \brief  NAS peer MAC handling
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

#include "event_log.h"
#include "std_mac_utils.h"
#include <unordered_map>
#include <iostream>
#include <memory>
#include <string>

static constexpr size_t MAC_STR_LEN = 20;

inline std::string nas_rt_make_string (const hal_mac_addr_t& mac)
{
    char str [MAC_STR_LEN];
    return {std_mac_to_string (&mac, str, MAC_STR_LEN)};
}

static std_mutex_lock_create_static_init_rec(nas_rt_mac_mutex);
using nas_rt_mac_uptr_t = std::unique_ptr<nas_rt_peer_mac_config_t>;

/* Vrf, Peer MAC based map*/
using nas_rt_mac_addr_list_t = std::unordered_map <std::string, nas_rt_mac_uptr_t>;
static std::unordered_map <hal_vrf_id_t, nas_rt_mac_addr_list_t> peer_mac_list;

#ifdef __cplusplus
extern "C" {
#endif

static bool nas_rt_db_add_peer_mac_list(nas_rt_mac_uptr_t &mac_uptr)
{
    std::string str = mac_uptr->if_name + nas_rt_make_string(mac_uptr->mac);
    peer_mac_list[mac_uptr->vrf_id][str] = std::move (mac_uptr);
    return true;
}

bool nas_rt_peer_mac_get (const nas_rt_peer_mac_config_t* req,
                          nas_rt_peer_mac_config_t* reply_p)
{
    std_mutex_simple_lock_guard l(&nas_rt_mac_mutex);

    auto vrf_it = peer_mac_list.find(req->vrf_id);
    if(vrf_it == peer_mac_list.end()) return false;

    auto& mac_list = vrf_it->second;
    std::string str = req->if_name + nas_rt_make_string(req->mac);
    auto mac_it = mac_list.find(str);
    if(mac_it == mac_list.end()) return false;

    if (reply_p != nullptr) *reply_p = *(mac_it->second);
    return true;
}

bool nas_rt_peer_mac_db_add (nas_rt_peer_mac_config_t* mac_info)
{
    std_mutex_simple_lock_guard l(&nas_rt_mac_mutex);

    nas_rt_peer_mac_config_t old_mac;
    char p_buf[MAC_STR_LEN];
    if (nas_rt_peer_mac_get(mac_info, &old_mac)) {
        HAL_RT_LOG_ERR("HAL-RT", "Vrf:%d if-name:%s peer-mac:%s already exists",
                       mac_info->vrf_id, mac_info->if_name,
                       hal_rt_mac_to_str(&mac_info->mac, p_buf, MAC_STR_LEN));
        return false;
    }

    nas_rt_mac_uptr_t mac_uptr (new nas_rt_peer_mac_config_t (*mac_info));
    nas_rt_db_add_peer_mac_list (mac_uptr);

    HAL_RT_LOG_INFO("HAL-RT", "Vrf:%d if-name:%s peer-mac:%s vrf obj:0x%x rif obj:0x%x "
                    "added successfully", mac_info->vrf_id, mac_info->if_name,
                    hal_rt_mac_to_str(&mac_info->mac, p_buf, MAC_STR_LEN),
                    mac_info->vrf_obj_id, mac_info->rif_obj_id);
    return true;
}

static bool nas_rt_peer_mac_db_del_mac_list(const nas_rt_peer_mac_config_t& mac_info)
{
    auto vrf_it = peer_mac_list.find(mac_info.vrf_id);
    if(vrf_it == peer_mac_list.end()) return false;
    auto &mac_list = vrf_it->second;

    std::string str = mac_info.if_name + nas_rt_make_string(mac_info.mac);
    auto erased = mac_list.erase(str);

    if (mac_list.empty())
        peer_mac_list.erase(mac_info.vrf_id);

    return (erased > 0);
}

bool nas_rt_peer_mac_db_del (nas_rt_peer_mac_config_t* mac_info)
{
    std_mutex_simple_lock_guard l(&nas_rt_mac_mutex);

    char p_buf[MAC_STR_LEN];
    if (!nas_rt_peer_mac_db_del_mac_list(*mac_info)) {
        HAL_RT_LOG_ERR("HAL-RT", "Could not find vrf:%d if-name:%s peer-mac:%s in the list",
                       mac_info->vrf_id, mac_info->if_name,
                       hal_rt_mac_to_str(&mac_info->mac, p_buf, MAC_STR_LEN));
        return false;
    }

    HAL_RT_LOG_INFO("HAL-RT", "Vrf:%d if-name:%s peer-mac:%s deleted successfully",
                   mac_info->vrf_id, mac_info->if_name,
                   hal_rt_mac_to_str(&mac_info->mac, p_buf, MAC_STR_LEN));
    return true;
}


void fib_dump_peer_mac_db_get_all_with_vrf(hal_vrf_id_t vrf_id)
{
    std_mutex_simple_lock_guard l(&nas_rt_mac_mutex);

    auto vrf_it = peer_mac_list.find(vrf_id);
    if(vrf_it == peer_mac_list.end()) {
        std::cout << "VRF does not exist" << std::endl;
        return;
    }
    auto &mac_list = vrf_it->second;

    char str [MAC_STR_LEN];
    for(auto& x: mac_list){
        nas_rt_peer_mac_config_t *ptr = x.second.get();
        std_mac_to_string (&ptr->mac, str, MAC_STR_LEN);
        std::cout << "Peer MAC Info VRF:" << ptr->vrf_id <<"IF_NAME:"
            << ptr->if_name <<" MAC:"<< str << std::endl;
    }
    return;
}

t_std_error nas_route_get_all_peer_routing_config(cps_api_object_list_t list){

    t_fib_vrf      *p_vrf = NULL;
    uint32_t       vrf_id = 0;

    for (vrf_id = FIB_MIN_VRF; vrf_id < FIB_MAX_VRF; vrf_id ++) {
        p_vrf = hal_rt_access_fib_vrf(vrf_id);
        if (p_vrf == NULL) {
            HAL_RT_LOG_ERR("HAL-RT", "Vrf node NULL. Vrf_id: %d", vrf_id);
            continue;
        }

        std_mutex_simple_lock_guard l(&nas_rt_mac_mutex);
        auto vrf_it = peer_mac_list.find(vrf_id);
        if(vrf_it == peer_mac_list.end()) return STD_ERR_OK;
        auto &mac_list = vrf_it->second;

        for(auto& x: mac_list){
            nas_rt_peer_mac_config_t *ptr = x.second.get();
            cps_api_object_t obj = nas_route_peer_routing_config_to_cps_object(vrf_id, ptr);
            if(obj == NULL)
                continue;

            if (!cps_api_object_list_append(list,obj)) {
                cps_api_object_delete(obj);
                HAL_RT_LOG_ERR("HAL-RT","Failed to append peer routing object to object list");
                return STD_ERR(ROUTE,FAIL,0);
            }
        }
    }
    return STD_ERR_OK;
}

t_std_error nas_route_delete_vrf_peer_mac_config(uint32_t vrf_id) {

    std_mutex_simple_lock_guard l(&nas_rt_mac_mutex);
    t_std_error rc = STD_ERR_OK;

    auto vrf_it = peer_mac_list.find(vrf_id);
    if(vrf_it == peer_mac_list.end()) return STD_ERR_OK;
    auto &mac_list = vrf_it->second;

    char p_buf[MAC_STR_LEN];
    for(auto& x: mac_list){
        nas_rt_peer_mac_config_t *ptr = x.second.get();
        HAL_RT_LOG_DEBUG("HAL-RT", "Vrf:%d if_name:%s peer-mac:%s vrf:0x%x rif:0x%x info",
                         vrf_id, ptr->if_name,
                         hal_rt_mac_to_str(&ptr->mac, p_buf, MAC_STR_LEN),
                         ptr->vrf_obj_id, ptr->rif_obj_id);
        if (ptr->vrf_obj_id) {
            /* Remove peer VLT MAC information */
            if ((rc = ndi_route_vr_delete(0, ptr->vrf_obj_id))!= STD_ERR_OK) {
                HAL_RT_LOG_ERR("HAL-RT", "Vrf:%d if_name:%s peer-mac:%s obj-id:0x%x deletion failed!",
                               vrf_id, ptr->if_name,
                               hal_rt_mac_to_str(&ptr->mac, p_buf, HAL_RT_MAX_BUFSZ),
                               ptr->vrf_obj_id);
                return STD_ERR(ROUTE, FAIL, rc);
            }
        } else if (ptr->rif_obj_id) {
            if (ndi_rif_delete(0, ptr->rif_obj_id) != STD_ERR_OK) {
                HAL_RT_LOG_ERR("HAL-RT", "Vrf:%d if_name:%s peer-mac:%s obj-id:0x%x deletion failed!",
                               vrf_id, ptr->if_name,
                               hal_rt_mac_to_str(&ptr->mac, p_buf, HAL_RT_MAX_BUFSZ),
                               ptr->rif_obj_id);
                return (STD_ERR(ROUTE, PARAM, 0));
            }
        }
    }
    mac_list.clear();
    peer_mac_list.erase(vrf_id);
    return STD_ERR_OK;
}

#ifdef __cplusplus
}
#endif
template <typename LIST_TYPE>
static void nas_rt_print_peer_mac_stats (const LIST_TYPE& list)
{
    std::cout << "Count: " << list.size() << std::endl;
    std::cout << "Load factor: " << list.load_factor() << std::endl;
    std::cout << "Bucket Count: " << list.bucket_count() << std::endl;

    std::unordered_map <size_t, size_t> sizes;
    for (auto& entry: list) {
        auto bucket = list.bucket(entry.first);
        ++sizes[list.bucket_size (bucket)];
    }
    uint_t total = 0;
    for (auto size: sizes) {
        std::cout << "# Buckets with size " << size.first << ": " << size.second << std::endl;
        total += size.second;
    }
    std::cout << "# Buckets with size 0 " << ": " << list.bucket_count() - total << std::endl;
}

bool nas_rt_peer_mac_list_stats (uint_t vrf_id)
{
    std_mutex_simple_lock_guard l(&nas_rt_mac_mutex);
    try {
        nas_rt_print_peer_mac_stats(peer_mac_list.at (vrf_id));
    } catch (...) {
        return false;
    }
    return true;
}

