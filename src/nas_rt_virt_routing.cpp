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
 * \file   nas_rt_virt_routing.cpp
 * \brief  NAS virtual routing handling
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "hal_rt_main.h"
#include "hal_rt_util.h"

#ifdef __cplusplus
}
#endif

#include "event_log.h"
#include <unordered_map>
#include <iostream>
#include <memory>
#include <string>

inline std::string nas_rt_make_ip_string (const hal_ip_addr_t & ip_addr)
{
    char str [INET6_ADDRSTRLEN] = {0};
    return {std_ip_to_string (&ip_addr, str, INET6_ADDRSTRLEN)};
}

static std_mutex_lock_create_static_init_rec(nas_rt_ip_mutex);
using nas_rt_ip_uptr_t = std::unique_ptr<nas_rt_virtual_routing_ip_config_t>;

/* ifname based map of type nas_rt_virtual_routing_ip_config_t */
using nas_rt_if_ip_addr_list_t = std::unordered_map <std::string, nas_rt_ip_uptr_t>;
/* Vrf, Peer ip based map */
using nas_rt_ip_addr_list_t = std::unordered_map <std::string, nas_rt_if_ip_addr_list_t>;
static auto &virtual_routing_ip_list = *new std::unordered_map <hal_vrf_id_t, nas_rt_ip_addr_list_t>;

#ifdef __cplusplus
extern "C" {
#endif

static bool nas_rt_db_add_virtual_routing_ip_list(nas_rt_ip_uptr_t &ip_uptr)
{
    std::string if_name_str = ip_uptr->if_name;
    std::string ip_str = nas_rt_make_ip_string(ip_uptr->ip_addr);
    virtual_routing_ip_list[ip_uptr->vrf_id][ip_str][if_name_str] = std::move (ip_uptr);
    return true;
}

uint32_t nas_rt_virtual_routing_ip_list_size (const nas_rt_virtual_routing_ip_config_t * req)
{
    std_mutex_simple_lock_guard l(&nas_rt_ip_mutex);

    auto vrf_it = virtual_routing_ip_list.find(req->vrf_id);
    if(vrf_it == virtual_routing_ip_list.end()) return 0;

    auto& ip_list = vrf_it->second;
    std::string ip_str = nas_rt_make_ip_string(req->ip_addr);
    auto ip_it = ip_list.find(ip_str);
    if(ip_it == ip_list.end()) return 0;

    auto& if_ip_list = ip_it->second;
    return if_ip_list.size();
}

bool nas_rt_virtual_routing_ip_get (const nas_rt_virtual_routing_ip_config_t * req,
                                    nas_rt_virtual_routing_ip_config_t* reply_p)
{
    std_mutex_simple_lock_guard l(&nas_rt_ip_mutex);

    auto vrf_it = virtual_routing_ip_list.find(req->vrf_id);
    if(vrf_it == virtual_routing_ip_list.end()) return false;

    auto& ip_list = vrf_it->second;
    std::string ip_str = nas_rt_make_ip_string(req->ip_addr);
    auto ip_it = ip_list.find(ip_str);
    if(ip_it == ip_list.end()) return false;

    auto& if_ip_list = ip_it->second;
    std::string if_name_str = req->if_name;
    auto if_name_it = if_ip_list.find(if_name_str);
    if(if_name_it == if_ip_list.end()) return false;

    if (reply_p != nullptr) *reply_p = *(if_name_it->second);
    return true;
}

bool nas_rt_virtual_routing_ip_db_add (nas_rt_virtual_routing_ip_config_t * ip_info)
{
    std_mutex_simple_lock_guard l(&nas_rt_ip_mutex);

    nas_rt_virtual_routing_ip_config_t old_ip;
    if (nas_rt_virtual_routing_ip_get (ip_info, &old_ip)) {
        HAL_RT_LOG_ERR("HAL-RT", "Virtual routing Vrf:%d if-name:%s IP:%s already exists",
                       ip_info->vrf_id, ip_info->if_name,
                       FIB_IP_ADDR_TO_STR(&ip_info->ip_addr));
        return false;
    }

    nas_rt_ip_uptr_t ip_uptr (new nas_rt_virtual_routing_ip_config_t (*ip_info));
    nas_rt_db_add_virtual_routing_ip_list (ip_uptr);

    HAL_RT_LOG_DEBUG ("HAL-RT", "Virtual routing Vrf:%d if-name:%s IP:%s  "
                      "added successfully", ip_info->vrf_id, ip_info->if_name,
                      FIB_IP_ADDR_TO_STR(&ip_info->ip_addr));
    return true;
}

static bool nas_rt_virtual_routing_ip_db_del_ip_list(const nas_rt_virtual_routing_ip_config_t & ip_info)
{
    auto vrf_it = virtual_routing_ip_list.find(ip_info.vrf_id);
    if(vrf_it == virtual_routing_ip_list.end()) return false;
    auto &ip_list = vrf_it->second;


    std::string ip_str = nas_rt_make_ip_string(ip_info.ip_addr);
    auto ip_it = ip_list.find(ip_str);
    if(ip_it == ip_list.end()) return false;

    auto& if_ip_list = ip_it->second;

    std::string if_name_str = ip_info.if_name;
    auto if_name_it = if_ip_list.find(if_name_str);
    if(if_name_it == if_ip_list.end()) return false;

    auto erased = if_ip_list.erase(if_name_str);

    if (if_ip_list.empty()) {
        ip_list.erase(ip_str);
        if (ip_list.empty())
            virtual_routing_ip_list.erase(ip_info.vrf_id);
    }

    return (erased > 0);
}

bool nas_rt_virtual_routing_ip_db_del (nas_rt_virtual_routing_ip_config_t * ip_info)
{
    std_mutex_simple_lock_guard l(&nas_rt_ip_mutex);

    if (!nas_rt_virtual_routing_ip_db_del_ip_list(*ip_info)) {
        HAL_RT_LOG_ERR("HAL-RT", "Virtual routing Could not find vrf:%d if-name:%s IP:%s in the list",
                       ip_info->vrf_id, ip_info->if_name,
                       FIB_IP_ADDR_TO_STR(&ip_info->ip_addr));
        return false;
    }

    return true;
}

t_std_error nas_route_get_all_virtual_routing_ip_config (cps_api_object_list_t list,
                                                         bool show_all,
                                                         nas_rt_virtual_routing_ip_config_t *p_cfg) {
    t_fib_vrf      *p_vrf = NULL;
    uint32_t       vrf_id = 0;

    if (show_all) {
        for (vrf_id = FIB_MIN_VRF; vrf_id < FIB_MAX_VRF; vrf_id ++) {
            p_vrf = hal_rt_access_fib_vrf(vrf_id);
            if (p_vrf == NULL) {
                HAL_RT_LOG_ERR("HAL-RT", "Virtual Routing Vrf node NULL. Vrf_id: %d", vrf_id);
                continue;
            }

            std_mutex_simple_lock_guard l(&nas_rt_ip_mutex);
            auto vrf_it = virtual_routing_ip_list.find(vrf_id);
            if(vrf_it == virtual_routing_ip_list.end()) { continue; }
            auto &ip_list = vrf_it->second;

            for(auto& ip_it: ip_list){
                auto& if_ip_list  = ip_it.second;
                for(auto& x: if_ip_list){
                    nas_rt_virtual_routing_ip_config_t *ptr = x.second.get();
                    cps_api_object_t obj = nas_route_virtual_routing_ip_config_to_cps_object (vrf_id, ptr);
                    if(obj == NULL)
                        continue;

                    if (!cps_api_object_list_append(list,obj)) {
                        cps_api_object_delete(obj);
                        HAL_RT_LOG_ERR("HAL-RT","Failed to append virtual routing IP object to object list");
                        return STD_ERR(ROUTE,FAIL,0);
                    }
                }
            }
        }
    } else {
        vrf_id = p_cfg->vrf_id;
        p_vrf = hal_rt_access_fib_vrf(vrf_id);
        if (p_vrf == NULL) {
            return STD_ERR_OK;
        }

        std_mutex_simple_lock_guard l(&nas_rt_ip_mutex);
        auto vrf_it = virtual_routing_ip_list.find(vrf_id);
        if(vrf_it == virtual_routing_ip_list.end()) return STD_ERR_OK;
        auto &ip_list = vrf_it->second;


        std::string ip_str = nas_rt_make_ip_string(p_cfg->ip_addr);
        auto ip_it = ip_list.find(ip_str);
        if(ip_it == ip_list.end()) return STD_ERR_OK;

        auto& if_ip_list = ip_it->second;
        std::string if_name_str(p_cfg->if_name);
        auto if_name_it = if_ip_list.find(if_name_str);
        if(if_name_it == if_ip_list.end()) return STD_ERR_OK;

        nas_rt_virtual_routing_ip_config_t *ptr = if_name_it->second.get();
        cps_api_object_t obj = nas_route_virtual_routing_ip_config_to_cps_object (vrf_id, ptr);
        if(obj == NULL) return STD_ERR_OK;

        if (!cps_api_object_list_append(list,obj)) {
            cps_api_object_delete(obj);
            HAL_RT_LOG_ERR("HAL-RT","Failed to append virtual routing IP object to object list");
            return STD_ERR(ROUTE,FAIL,0);
        }
    }

    return STD_ERR_OK;
}

t_std_error nas_route_delete_vrf_virtual_routing_ip_config(uint32_t vrf_id) {

    std_mutex_simple_lock_guard l(&nas_rt_ip_mutex);

    auto vrf_it = virtual_routing_ip_list.find(vrf_id);
    if(vrf_it == virtual_routing_ip_list.end()) return STD_ERR_OK;
    auto &ip_list = vrf_it->second;

    for(auto& ip_it: ip_list){
        auto& if_ip_list  = ip_it.second;
        for(auto& x: if_ip_list){
            nas_rt_virtual_routing_ip_config_t *ptr = x.second.get();

            HAL_RT_LOG_DEBUG ("HAL-RT", "Virtual routing Vrf:%d if-name:%s IP:%s ",
                              ptr->vrf_id, ptr->if_name,
                              FIB_IP_ADDR_TO_STR(&ptr->ip_addr));

            if (_hal_rt_virtual_routing_ip_cfg(ptr, false) != STD_ERR_OK) {
                HAL_RT_LOG_ERR ("HAL-RT", "Virtual routing cfg del failed. Vrf:%d if-name:%s IP:%s ",
                                ptr->vrf_id, ptr->if_name,
                                FIB_IP_ADDR_TO_STR(&ptr->ip_addr));
            }
        }
        if_ip_list.clear();
    }
    ip_list.clear();
    virtual_routing_ip_list.erase(vrf_id);

    return STD_ERR_OK;
}

void fib_dump_virtual_routing_ip_db_get_all_with_vrf(hal_vrf_id_t vrf_id)
{
    std_mutex_simple_lock_guard l(&nas_rt_ip_mutex);

    auto vrf_it = virtual_routing_ip_list.find(vrf_id);
    if(vrf_it == virtual_routing_ip_list.end()) {
        std::cout << "VRF list empty" << std::endl;
        return;
    }
    auto &ip_list = vrf_it->second;

    char str [INET6_ADDRSTRLEN] = {0};

    for(auto& ip_it: ip_list){
        auto& if_ip_list  = ip_it.second;
        for(auto& x: if_ip_list){
            nas_rt_virtual_routing_ip_config_t *ptr = x.second.get();
            std_ip_to_string (&ptr->ip_addr, str, INET6_ADDRSTRLEN);
            std::cout << "Virtual Routing IP Info VRF:" << ptr->vrf_id <<" IF_NAME:"
                << ptr->if_name <<" IP:"<< str << std::endl;
        }
    }
    return;
}

#ifdef __cplusplus
}
#endif

template <typename LIST_TYPE>
static void nas_rt_print_virtual_routing_ip_stats (const LIST_TYPE& list)
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

bool nas_rt_virtual_routing_ip_list_stats (uint_t vrf_id)
{
    std_mutex_simple_lock_guard l(&nas_rt_ip_mutex);
    try {
        nas_rt_print_virtual_routing_ip_stats (virtual_routing_ip_list.at (vrf_id));
    } catch (...) {
        return false;
    }
    return true;
}

