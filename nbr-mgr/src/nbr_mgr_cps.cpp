/*
 * Copyright (c) 2018 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * THIS CODE IS PROVIDED ON AN  *AS IS* BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 * LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 * FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
 *
 * See the Apache Version 2.0 License for specific language governing
 * permissions and limitations under the License.
 */

/*
 * filename: nbr_mgr_cps.cpp
 */

#include "cps_api_object_key.h"
#include "cps_api_node.h"

#include "ds_common_types.h"
#include "cps_api_interface_types.h"
#include "cps_api_operation.h"
#include "cps_api_events.h"
#include "cps_class_map.h"
#include "cps_api_db_interface.h"
#include "cps_api_object_tools.h"
#include "cps_api_object.h"
#include "cps_api_operation_tools.h"
#include "dell-base-routing.h"
#include "dell-base-neighbor.h"
#include "dell-base-if.h"
#include "dell-base-if-linux.h"
#include "hal_if_mapping.h"
#include "std_ip_utils.h"
#include "std_utils.h"
#include "std_mac_utils.h"
#include "dell-base-l2-mac.h"
#include "os-routing-events.h"
#include "vrf-mgmt.h"

#include "nbr_mgr_main.h"
#include "nbr_mgr_cache.h"
#include "nbr_mgr_msgq.h"
#include "nbr_mgr_log.h"
#include "nbr_mgr_utils.h"

#include <string>
#include <mutex>
#include <unordered_map>

static void* cps_evt_handle = nullptr;
static std::mutex _auto_refresh_mutex;
static auto& _nbr_auto_refresh_status = *new std::unordered_map<std::string, nbr_mgr_auto_refresh_t> ;

bool nbr_mgr_process_flush_cps_msg(cps_api_object_t obj, void *param);
/* Note: Dont return false from CPS event handler */
bool nbr_mgr_process_nas_cps_msg(cps_api_object_t obj, void *param)
{
    cps_api_object_it_t it;
    cps_api_attr_id_t id = 0;
    nbr_mgr_msg_t *p_msg = nullptr;

    if (obj == NULL){
        NBR_MGR_LOG_ERR ("NBR-MGR-CPS", "Invalid object sent from NAS");
        return true;
    }

    nbr_mgr_msg_uptr_t p_msg_uptr = nbr_mgr_alloc_unique_msg(&p_msg);
    if (p_msg == NULL) {
        NBR_MGR_LOG_ERR ("NBR-MGR-CPS", "Memory alloc failed for NAS message");
        return true;
    }
    memset(p_msg, 0, sizeof(nbr_mgr_msg_t));
    p_msg->type = NBR_MGR_NAS_NBR_MSG;
    p_msg->nbr.msg_type = NBR_MGR_NBR_ADD;

    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    switch (op) {
        case cps_api_oper_CREATE:
        case cps_api_oper_SET:
            p_msg->nbr.msg_type = NBR_MGR_NBR_ADD;
            break;
        case cps_api_oper_DELETE:
            p_msg->nbr.msg_type = NBR_MGR_NBR_DEL;
            break;
        default:
            break;
    }

    const char *vrf_name = (const char*)cps_api_object_get_data(obj, BASE_ROUTE_OBJ_VRF_NAME);
    cps_api_object_it_begin(obj,&it);

    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {
        id = cps_api_object_attr_id(it.attr);

        switch (id) {
            case BASE_ROUTE_OBJ_NBR_VRF_ID:
                p_msg->nbr.vrfid = cps_api_object_attr_data_uint(it.attr);
                break;
            case BASE_ROUTE_OBJ_NBR_AF:
                p_msg->nbr.nbr_addr.af_index = cps_api_object_attr_data_uint(it.attr);
                p_msg->nbr.family = p_msg->nbr.nbr_addr.af_index;
                break;
            case BASE_ROUTE_OBJ_NBR_IFINDEX:
                p_msg->nbr.if_index = cps_api_object_attr_data_uint(it.attr);
                break;
            case BASE_ROUTE_OBJ_NBR_FLAGS:
                p_msg->nbr.flags = cps_api_object_attr_data_uint(it.attr);
                break;
            case BASE_ROUTE_OBJ_NBR_ADDRESS:
                memcpy(&p_msg->nbr.nbr_addr.u, cps_api_object_attr_data_bin(it.attr),
                       cps_api_object_attr_len (it.attr));
                break;
            case OS_RE_BASE_ROUTE_OBJ_NBR_LOWER_LAYER_IF:
                p_msg->nbr.parent_if = cps_api_object_attr_data_uint(it.attr);
                break;
        }
    }
    if (vrf_name) {
        safestrncpy(p_msg->nbr.vrf_name, vrf_name, sizeof(p_msg->nbr.vrf_name));
    }
    char buff[HAL_INET6_TEXT_LEN + 1];
    NBR_MGR_LOG_INFO("NAS-MSG", "Nbr resolution request for vrf:%lu(%s) type:%d family:%d ip:%s if-index:%d parent-if:%d flags:%d",
                     p_msg->nbr.vrfid, (vrf_name ? vrf_name : " "), p_msg->nbr.msg_type, p_msg->nbr.family,
                     std_ip_to_string(&(p_msg->nbr.nbr_addr), buff, HAL_INET6_TEXT_LEN),
                     p_msg->nbr.if_index, p_msg->nbr.parent_if, p_msg->nbr.flags);
    if (p_msg->nbr.flags == NBR_MGR_NBR_FLAGS_TRIGGER_RESOLVE) {
        p_msg->nbr.flags = NBR_MGR_NBR_TRIGGER_RESOLVE;
    } else if (p_msg->nbr.flags == NBR_MGR_NBR_FLAGS_DISABLE_AGE_OUT_1D_BRIDGE_REMOTE_MAC) {
        p_msg->nbr.flags = NBR_MGR_NBR_DISABLE_AGE_OUT_1D_REMOTE_MAC;
    } else if (p_msg->nbr.flags == NBR_MGR_NBR_FLAGS_ENABLE_AGE_OUT) {
        p_msg->nbr.flags = NBR_MGR_NBR_ENABLE_AGE_OUT;
    } else if (p_msg->nbr.flags == NBR_MGR_NBR_FLAGS_UPDATE_PARENT_IF) {
        p_msg->nbr.flags = NBR_MGR_NBR_UPDATE_PARENT_IF;
    } else {
        /* Proactive resolution request from NAS-L3 if not already resolved */
        p_msg->nbr.flags = NBR_MGR_NBR_RESOLVE;
    }
    nbr_mgr_enqueue_netlink_nas_msg(std::move(p_msg_uptr));
    return true;
}

bool nbr_mgr_nas_nl_cps_init() {
    cps_api_event_reg_t reg;

    memset(&reg,0,sizeof(reg));
    const uint_t NUM_KEYS=3;
    cps_api_key_t key[NUM_KEYS];

    cps_api_key_from_attr_with_qual(&key[0], OS_RE_BASE_ROUTE_OBJ_NBR_OBJ,
                                    cps_api_qualifier_OBSERVED);
    // Register with NAS-Linux object for interface state change notifications
    cps_api_key_from_attr_with_qual(&key[1], BASE_IF_LINUX_IF_INTERFACES_INTERFACE_OBJ,
                                    cps_api_qualifier_OBSERVED);
    cps_api_key_from_attr_with_qual(&key[2], VRF_MGMT_NI_NETWORK_INSTANCES_NETWORK_INSTANCE_OBJ,
                                    cps_api_qualifier_OBSERVED);
    reg.priority = 0;
    reg.number_of_objects = NUM_KEYS;
    reg.objects = key;
    if (cps_api_event_thread_reg(&reg,nbr_mgr_process_nl_msg,NULL)!=cps_api_ret_code_OK) {
        return false;
    }
    return true;
}
static cps_api_object_t nbr_mgr_auto_refresh_status_to_cps_obj(const char * vrf_name,
                                                               uint32_t af, uint32_t enable) {
    cps_api_object_t obj = cps_api_object_create();
    if(obj == NULL){
        NBR_MGR_LOG_ERR("NBR-MGR-CPS", "Failed to allocate memory to cps object");
        return NULL;
    }

    cps_api_key_t key;
    cps_api_key_from_attr_with_qual(&key, BASE_NEIGHBOR_AUTO_NBR_REFRESH_OBJ,
                                    cps_api_qualifier_TARGET);
    cps_api_object_set_key(obj,&key);

    cps_api_set_key_data (obj, BASE_NEIGHBOR_AUTO_NBR_REFRESH_VRF_NAME, cps_api_object_ATTR_T_BIN, vrf_name,
                          strlen(vrf_name)+1);
    cps_api_set_key_data (obj, BASE_NEIGHBOR_AUTO_NBR_REFRESH_AF, cps_api_object_ATTR_T_U32, &af,
                          sizeof(af));
    cps_api_object_attr_add_u32(obj, BASE_NEIGHBOR_AUTO_NBR_REFRESH_ENABLE,
                                (enable == NBR_MGR_AUTO_REFRESH_ENABLE) ? true : false);
    return obj;
}

static cps_api_return_code_t nbr_mgr_cps_auto_refresh_get_func(void * ctx,
                                                               cps_api_get_params_t * param,
                                                               size_t ix) {
    cps_api_object_t filt = cps_api_object_list_get(param->filters,ix);
    if (filt == NULL) {
        NBR_MGR_LOG_ERR("NBR-MGR-CPS","Neighbor refresh config. object is not present");
        return cps_api_ret_code_ERR;
    }
    std::lock_guard<std::mutex> lock(_auto_refresh_mutex);
    cps_api_object_t obj = nullptr;
    for (auto itr = _nbr_auto_refresh_status.begin();
         itr != _nbr_auto_refresh_status.end(); itr++) {
        if ((itr->second).ipv4_nbr_auto_refresh_status != NBR_MGR_AUTO_REFRESH_INIT) {
            obj = nbr_mgr_auto_refresh_status_to_cps_obj((itr->first).c_str(), HAL_INET4_FAMILY,
                                                         (itr->second).ipv4_nbr_auto_refresh_status);
            if(obj != NULL){
                if (!cps_api_object_list_append(param->list, obj)) {
                    cps_api_object_delete(obj);
                    return cps_api_ret_code_ERR;
                }
            }
        }
        if ((itr->second).ipv6_nbr_auto_refresh_status != NBR_MGR_AUTO_REFRESH_INIT) {
            obj = nbr_mgr_auto_refresh_status_to_cps_obj((itr->first).c_str(), HAL_INET6_FAMILY,
                                                         (itr->second).ipv6_nbr_auto_refresh_status);
            if(obj != NULL){
                if (!cps_api_object_list_append(param->list, obj)) {
                    cps_api_object_delete(obj);
                    return cps_api_ret_code_ERR;
                }
            }
        }
    }
    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nbr_mgr_cps_auto_refresh_rollback_func(void * ctx,
                                                                    cps_api_transaction_params_t * param,
                                                                    size_t ix) {
    NBR_MGR_LOG_DEBUG("NBR-MGR-CPS", "Auto refresh rollback function");
    return cps_api_ret_code_OK;
}

bool nbr_mgr_get_auto_refresh_status (const char *vrf_name, uint32_t family) {
    std::lock_guard<std::mutex> lock(_auto_refresh_mutex);

    auto it = _nbr_auto_refresh_status.find(std::string(vrf_name));
    if(it != _nbr_auto_refresh_status.end()) {
        auto& status = it->second;
        if (family == HAL_INET4_FAMILY) {
            if (status.ipv4_nbr_auto_refresh_status != NBR_MGR_AUTO_REFRESH_INIT) {
                return ((status.ipv4_nbr_auto_refresh_status
                         == NBR_MGR_AUTO_REFRESH_ENABLE) ? true : false);
            }
        } else if (status.ipv6_nbr_auto_refresh_status != NBR_MGR_AUTO_REFRESH_INIT) {
            return ((status.ipv6_nbr_auto_refresh_status
                     == NBR_MGR_AUTO_REFRESH_ENABLE) ? true : false);
        }
    }

    return true;
}

bool nbr_mgr_handle_auto_refresh_config(cps_api_operation_types_t op, const char *vrf_name,
                                        uint32_t af, uint32_t enable) {
    uint32_t enable_status = enable ? NBR_MGR_AUTO_REFRESH_ENABLE : NBR_MGR_AUTO_REFRESH_DISABLE;
    std::lock_guard<std::mutex> lock(_auto_refresh_mutex);
    auto it = _nbr_auto_refresh_status.find(std::string(vrf_name));
    if(it == _nbr_auto_refresh_status.end()) {
        if ((op == cps_api_oper_CREATE) || (op == cps_api_oper_SET)) {
            nbr_mgr_auto_refresh_t status;
            memset(&status, 0, sizeof(status));
            if(af == HAL_INET4_FAMILY)
                status.ipv4_nbr_auto_refresh_status = enable_status;
            else if(af == HAL_INET6_FAMILY)
                status.ipv6_nbr_auto_refresh_status = enable_status;

            NBR_MGR_LOG_INFO("NBR-MGR-CPS", "op:%d VRF:%s af:%d enable:%d "
                            "DB enable status - ipv4:%d ipv6:%d", op, vrf_name, af, enable,
                            status.ipv4_nbr_auto_refresh_status, status.ipv6_nbr_auto_refresh_status);
            _nbr_auto_refresh_status[std::string(vrf_name)] = status;
        }else return false;
    } else {
        auto& curr_status = it->second;
        NBR_MGR_LOG_INFO("NBR-MGR-CPS", "entry exists - op:%d VRF:%s af:%d enable:%d "
                        "DB enable status - ipv4:%d ipv6:%d", op, vrf_name, af, enable,
                        curr_status.ipv4_nbr_auto_refresh_status, curr_status.ipv6_nbr_auto_refresh_status);
        if ((op == cps_api_oper_CREATE) || (op == cps_api_oper_SET)) {
            if(af == HAL_INET4_FAMILY)
                curr_status.ipv4_nbr_auto_refresh_status = enable_status;
            else if(af == HAL_INET6_FAMILY)
                curr_status.ipv6_nbr_auto_refresh_status = enable_status;
        } else if (op == cps_api_oper_DELETE) {
            if(af == HAL_INET4_FAMILY) {
                curr_status.ipv4_nbr_auto_refresh_status = NBR_MGR_AUTO_REFRESH_INIT;
                if (curr_status.ipv6_nbr_auto_refresh_status != NBR_MGR_AUTO_REFRESH_INIT)
                    return true;
            } else {
                curr_status.ipv6_nbr_auto_refresh_status = NBR_MGR_AUTO_REFRESH_INIT;
                if (curr_status.ipv4_nbr_auto_refresh_status != NBR_MGR_AUTO_REFRESH_INIT) {
                    return true;
                }
            }
            NBR_MGR_LOG_INFO("NBR-MGR-CPS", "DB DEL - op:%d VRF:%s af:%d enable:%d "
                            "DB enable status - ipv4:%d ipv6:%d", op, vrf_name, af, enable,
                            curr_status.ipv4_nbr_auto_refresh_status, curr_status.ipv6_nbr_auto_refresh_status);
            _nbr_auto_refresh_status.erase(std::string(vrf_name));
        }
    }
    return true;
}

static cps_api_return_code_t nbr_mgr_cps_auto_refresh_set_func(void * ctx,
                                                               cps_api_transaction_params_t * param,
                                                               size_t ix) {
    if(param == NULL){
        NBR_MGR_LOG_ERR("NBR-MGR-CPS", "Auto refresh set with no param:");
        return cps_api_ret_code_ERR;
    }

    cps_api_object_t obj = cps_api_object_list_get (param->change_list, ix);
    if (obj == NULL) {
        NBR_MGR_LOG_ERR("NBR-MGR-CPS", "Auto refresh set with no object");
        return cps_api_ret_code_ERR;
    }

    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));
    const char *vrf_name = (const char*)cps_api_object_get_data(obj, BASE_NEIGHBOR_AUTO_NBR_REFRESH_VRF_NAME);
    cps_api_object_attr_t af_attr = cps_api_object_attr_get(obj, BASE_NEIGHBOR_AUTO_NBR_REFRESH_AF);
    cps_api_object_attr_t enable_attr = cps_api_object_attr_get(obj, BASE_NEIGHBOR_AUTO_NBR_REFRESH_ENABLE);

    if ((vrf_name == nullptr) || (af_attr == nullptr)) {
        NBR_MGR_LOG_ERR("NBR-MGR-CPS", "Missing VRF-name/af attributes");
        return cps_api_ret_code_ERR;
    }

    uint32_t enable = true;
    cps_api_return_code_t rc = cps_api_ret_code_OK;
    uint32_t af = cps_api_object_attr_data_u32(af_attr);
    if (enable_attr) {
        enable = cps_api_object_attr_data_u32(enable_attr);
        if ((enable != true) && (enable != false))
            return cps_api_ret_code_ERR;
    }

    NBR_MGR_LOG_INFO("NBR-MGR-CPS", "op:%d VRF:%s af:%d enable:%d", op, vrf_name, af, enable);
    if (!nbr_mgr_handle_auto_refresh_config(op, vrf_name, af, enable)) {
        NBR_MGR_LOG_ERR("NBR-MGR-CPS", "op:%d VRF:%s af:%d enable:%d failed!", op, vrf_name, af, enable);
        return cps_api_ret_code_ERR;
    }
    rc =  cps_api_db_commit_one(op, obj, NULL, false);
    if (rc != cps_api_ret_code_OK) {
        NBR_MGR_LOG_ERR("NBR-MGR-CPS", "op:%d VRF:%s af:%d enable:%d DB commit failed", op, vrf_name, af, enable);
    } else {
        NBR_MGR_LOG_INFO("NBR-MGR-CPS", "op:%d VRF:%s af:%d enable:%d DB commit success", op, vrf_name, af, enable);
    }
    return rc;
}

bool nbr_mgr_refresh_status_db_read() {
    cps_api_object_t obj = cps_api_object_create();
    cps_api_object_list_t list = cps_api_object_list_create();

    cps_api_object_guard obj_g (obj);
    cps_api_object_list_guard list_g (list);
    if ((obj == NULL) || (list == NULL)) {
        NBR_MGR_LOG_ERR("NBR-MGR-CPS-DB", "CPS object creation failed!");
        return false;
    }

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_NEIGHBOR_AUTO_NBR_REFRESH_OBJ,
                                    cps_api_qualifier_TARGET);
    cps_api_filter_wildcard_attrs(obj, true);

    cps_api_return_code_t rc = cps_api_ret_code_OK;
    rc = cps_api_db_get(obj, list);

    size_t len = cps_api_object_list_size(list);
    NBR_MGR_LOG_INFO("NBR-MGR-CPS-DB", "DB-get rc:%d len:%lu", rc, len);
    size_t ix = 0;

    for (ix=0; ix < len; ++ix)
    {
        cps_api_object_t cps_obj = cps_api_object_list_get(list, ix);
        cps_api_object_it_t it;

        if(cps_obj == NULL) {
            NBR_MGR_LOG_ERR("NBR-MGR-CPS-DB", "CPS object get failed!");
            return false;
        }
        cps_api_object_it_begin(cps_obj,&it);

        char  vrf_name[NAS_VRF_NAME_SZ + 1];
        memset (vrf_name,0,sizeof(vrf_name));
        uint32_t af = HAL_INET4_FAMILY, enable = true;

        for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) )
        {
            int id = (int) cps_api_object_attr_id(it.attr);
            switch (id)
            {
                case BASE_NEIGHBOR_AUTO_NBR_REFRESH_VRF_NAME:
                    safestrncpy(vrf_name, (const char *)cps_api_object_attr_data_bin(it.attr),
                                sizeof(vrf_name));
                    break;
                case BASE_NEIGHBOR_AUTO_NBR_REFRESH_AF:
                    af = cps_api_object_attr_data_uint(it.attr);
                    break;
                case BASE_NEIGHBOR_AUTO_NBR_REFRESH_ENABLE:
                    enable = cps_api_object_attr_data_uint(it.attr);
                    break;
                default:
                    break;
            }
        }
        NBR_MGR_LOG_INFO("NBR-MGR-CPS-DB", "VRF:%s af:%d enable:%d", vrf_name, af, enable);
        if (!nbr_mgr_handle_auto_refresh_config(cps_api_oper_CREATE, vrf_name, af, enable)) {
            NBR_MGR_LOG_ERR("NBR-MGR-CPS-DB", "VRF:%s af:%d enable:%d failed!", vrf_name, af, enable);
            return cps_api_ret_code_ERR;
        }
    }
    return true;
}

bool nbr_mgr_cps_init()
{
    if (cps_api_event_service_init() != cps_api_ret_code_OK) {
        NBR_MGR_LOG_ERR("CPS-INIT", "CPS Event Service Init failed");
        return false;
    }

    /* Handle all CPS events in a separate thread */
    if (cps_api_event_thread_init() != cps_api_ret_code_OK) {
        NBR_MGR_LOG_ERR("CPS_INIT", "CPS Event thread Init failed");
        return false;
    }

    /* initialize to the CPS event forwarding service for to handle events.  */
    if (cps_api_event_client_connect(&cps_evt_handle) != cps_api_ret_code_OK) {
        NBR_MGR_LOG_ERR("CPS-INIT", "CPS Event Client Connect failed");
        return false;
    }

    /* Subscribe for intf and neighbor events from NAS-Linux */
    nbr_mgr_nas_nl_cps_init ();

    cps_api_event_reg_t reg;
    cps_api_key_t key;

    /* Subscribe for NAS-L3 events */
    memset(&reg,0,sizeof(reg));
    memset(key, 0, sizeof(key));
    cps_api_key_from_attr_with_qual(&key, BASE_NEIGHBOR_BASE_ROUTE_OBJ_NBR_OBJ,
                                    cps_api_qualifier_OBSERVED);
    reg.number_of_objects = 1;
    reg.objects = &key;
    if (cps_api_event_thread_reg(&reg,nbr_mgr_process_nas_cps_msg,NULL)!=cps_api_ret_code_OK) {
        NBR_MGR_LOG_ERR("CPS-INIT", "CPS neighbor event subscription failed!");
        return false;
    }

    memset(&reg,0,sizeof(reg));
    memset(key, 0, sizeof(key));
    cps_api_key_from_attr_with_qual(&key,BASE_MAC_FLUSH_EVENT_OBJ,
                                    cps_api_qualifier_OBSERVED);
    reg.number_of_objects = 1;
    reg.objects = &key;
    if (cps_api_event_thread_reg(&reg,nbr_mgr_process_flush_cps_msg,NULL)!=cps_api_ret_code_OK) {
        NBR_MGR_LOG_ERR("CPS-INIT", "CPS flush event subscription failed!");
        return false;
    }

    cps_api_operation_handle_t handle;
    cps_api_return_code_t ret_val = cps_api_operation_subsystem_init(&handle, 1);
    if (ret_val != cps_api_ret_code_OK) {
        NBR_MGR_LOG_ERR("CPS-INIT", "CPS handle init failed!");
        return false;
    }
    cps_api_registration_functions_t f;
    memset(&f,0,sizeof(f));

    f.handle                 = handle;
    f._read_function         = nbr_mgr_cps_auto_refresh_get_func;
    f._write_function        = nbr_mgr_cps_auto_refresh_set_func;
    f._rollback_function     = nbr_mgr_cps_auto_refresh_rollback_func;

    if (!cps_api_key_from_attr_with_qual(&f.key, BASE_NEIGHBOR_AUTO_NBR_REFRESH_OBJ,
                                         cps_api_qualifier_TARGET)) {
        NBR_MGR_LOG_ERR("CPS-INIT", "CPS auto refresh config. object key filling failed!");
        return false;
    }

    if (cps_api_register(&f) != cps_api_ret_code_OK) {
        NBR_MGR_LOG_ERR("CPS-INIT", "CPS auto refresh config. object registration failed!");
        return false;
    }
    /* Read the DB for stored auto refresh status if any */
    nbr_mgr_refresh_status_db_read();
    return true;
}

bool nbr_mgr_program_npu(nbr_mgr_op_t op, const nbr_mgr_nbr_entry_t& entry) {

    NBR_MGR_LOG_DEBUG("NAS-NBR-UPD", "Program NPU");
    auto cps_obj = cps_api_object_create();
    if (cps_obj == nullptr)
    {
        NBR_MGR_LOG_ERR("NAS-NBR-UPD","CPS Object Create failed");
        return false;
    }
    cps_api_object_guard obj_g (cps_obj);

    if(cps_api_key_from_attr_with_qual(cps_api_object_key(cps_obj),
                                       BASE_NEIGHBOR_BASE_ROUTE_OBJ_NBR_OBJ,cps_api_qualifier_TARGET) != true)
    {
        NBR_MGR_LOG_ERR("NAS-NBR-UPD","Key extraction from Attribute ID %d failed",
                        BASE_NEIGHBOR_BASE_ROUTE_OBJ_NBR_OBJ);
        return false;
    }

    cps_api_object_attr_add_u32 (cps_obj,BASE_ROUTE_OBJ_NBR_AF, entry.family);

    /* Fill the CPS object attributes*/
    if(entry.family == HAL_INET4_FAMILY){
        cps_api_object_attr_add (cps_obj,BASE_ROUTE_OBJ_NBR_ADDRESS,
                                 (void*) &entry.nbr_addr.u.ipv4.s_addr, HAL_INET4_LEN);
    }else{
        cps_api_object_attr_add (cps_obj,BASE_ROUTE_OBJ_NBR_ADDRESS,
                                 (void *) entry.nbr_addr.u.ipv6.s6_addr,HAL_INET6_LEN);
    }
    char mac_addr[NBR_MGR_MAC_STR_LEN];
    std_mac_to_string (&(entry.nbr_hwaddr), mac_addr, NBR_MGR_MAC_STR_LEN);
    cps_api_object_attr_add(cps_obj, BASE_ROUTE_OBJ_NBR_MAC_ADDR, (const void *)mac_addr,
                            strlen(mac_addr)+1);
    cps_api_object_attr_add(cps_obj, BASE_ROUTE_OBJ_VRF_NAME, (const void *)entry.vrf_name,
                            strlen(entry.vrf_name)+1);

    cps_api_object_attr_add_u32(cps_obj,BASE_ROUTE_OBJ_NBR_VRF_ID, entry.vrfid);
    //cps_api_object_attr_add_u32(cps_obj,BASE_ROUTE_OBJ_NBR_TYPE,m_rt_type);
    cps_api_object_attr_add_u32(cps_obj,BASE_ROUTE_OBJ_NBR_STATE, entry.status);
    //cps_api_object_attr_add(cps_obj, BASE_ROUTE_OBJ_NBR_IFNAME, ifname.c_str(), ifname.size()+1);
    cps_api_object_attr_add_u32(cps_obj,BASE_ROUTE_OBJ_NBR_IFINDEX, entry.if_index);
    cps_api_object_attr_add_u32(cps_obj,OS_RE_BASE_ROUTE_OBJ_NBR_LOWER_LAYER_IF, entry.parent_if);
    cps_api_object_attr_add_u32(cps_obj,BASE_NEIGHBOR_BASE_ROUTE_OBJ_NBR_PHY_IFINDEX,
                                    entry.mbr_if_index);

    /** Transaction Init */
    cps_api_transaction_params_t tran;
    cps_api_return_code_t err_code = cps_api_ret_code_ERR;
    if ((err_code = cps_api_transaction_init(&tran)) != cps_api_ret_code_OK)
    {
        NBR_MGR_LOG_ERR("NAS-NBR-UPD","CPS Transaction Init failed %d", err_code);
        return false;
    }
    cps_api_transaction_guard tr_g (&tran);

    NBR_MGR_LOG_DEBUG("NAS-NBR-UPD","CPS Transaction Init Success. Operation %d", op);

    switch (op)
    {
        /** API Create */
        case NBR_MGR_OP_CREATE:
            if ((err_code = cps_api_create(&tran, cps_obj)) != cps_api_ret_code_OK)
            {
                NBR_MGR_LOG_ERR("NAS-NBR-UPD","Failed to add CREATE Object to Transaction");
                return false;
            }
            break;

        case NBR_MGR_OP_DELETE:
            if ((err_code = cps_api_delete(&tran, cps_obj)) != cps_api_ret_code_OK)
            {
                NBR_MGR_LOG_ERR("NAS-NBR-UPD","Failed to add DELETE Object to Transaction");
                return false;
            }
            break;

        case NBR_MGR_OP_UPDATE:
                if ((err_code = cps_api_set (&tran, cps_obj)) != cps_api_ret_code_OK)
                {
                    NBR_MGR_LOG_ERR("NAS-NBR-UPD","Failed to add SET Object to Transaction");
                    return false;
                }
            break;
        default:
            NBR_MGR_LOG_ERR("NAS-NBR-UPD","Invalid CPS Operation %d", op);
            return false;
    }

    obj_g.release ();

    /** API Commit */
    if ((err_code = cps_api_commit(&tran)) != cps_api_ret_code_OK)
    {
        NBR_MGR_LOG_ERR("NAS-NBR-UPD","CPS API Commit failed %d", err_code);
        return false;
    }

    NBR_MGR_LOG_DEBUG("NAS-NBR-UPD", "Transaction Successfully completed. Exit");

    return true;
}

bool nbr_mgr_notify_intf_status(nbr_mgr_op_t op, const nbr_mgr_intf_entry_t& entry) {

    NBR_MGR_LOG_DEBUG("NAS-INTF-UPD", "Program NPU");
    auto cps_obj = cps_api_object_create();
    if (cps_obj == nullptr)
    {
        NBR_MGR_LOG_ERR("NAS-INTF-UPD","CPS Object Create failed");
        return false;
    }
    cps_api_object_guard obj_g (cps_obj);

    if(cps_api_key_from_attr_with_qual(cps_api_object_key(cps_obj),
                                       BASE_NEIGHBOR_IF_INTERFACES_STATE_INTERFACE_OBJ,
                                       cps_api_qualifier_TARGET) != true)
    {
        NBR_MGR_LOG_ERR("NAS-INTF-UPD","Key extraction from Attribute ID %d failed",
                        BASE_NEIGHBOR_IF_INTERFACES_STATE_INTERFACE_OBJ);
        return false;
    }

    cps_api_object_attr_add_u32(cps_obj, VRF_MGMT_NI_IF_INTERFACES_INTERFACE_VRF_ID, entry.vrfid);
    cps_api_object_attr_add_u32(cps_obj, BASE_NEIGHBOR_IF_INTERFACES_STATE_INTERFACE_IF_INDEX,
                                entry.if_index);
    cps_api_object_attr_add_u32(cps_obj, IF_INTERFACES_INTERFACE_ENABLED, entry.is_admin_up);

    /** Transaction Init */
    cps_api_transaction_params_t tran;
    cps_api_return_code_t err_code = cps_api_ret_code_ERR;
    if ((err_code = cps_api_transaction_init(&tran)) != cps_api_ret_code_OK)
    {
        NBR_MGR_LOG_ERR("NAS-INTF-UPD","CPS Transaction Init failed %d", err_code);
        return false;
    }
    cps_api_transaction_guard tr_g (&tran);

    NBR_MGR_LOG_DEBUG("NAS-INTF-UPD","CPS Transaction Init Success. Operation %d", op);

    switch (op)
    {
        /** API Create */
        case NBR_MGR_OP_CREATE:
            if ((err_code = cps_api_create(&tran, cps_obj)) != cps_api_ret_code_OK)
            {
                NBR_MGR_LOG_ERR("NAS-INTF-UPD","Failed to add CREATE Object to Transaction");
                return false;
            }
            break;

        case NBR_MGR_OP_DELETE:
            if ((err_code = cps_api_delete(&tran, cps_obj)) != cps_api_ret_code_OK)
            {
                NBR_MGR_LOG_ERR("NAS-INTF-UPD","Failed to add DELETE Object to Transaction");
                return false;
            }
            break;

        case NBR_MGR_OP_UPDATE:
            if ((err_code = cps_api_set (&tran, cps_obj)) != cps_api_ret_code_OK)
            {
                NBR_MGR_LOG_ERR("NAS-INTF-UPD","Failed to add SET Object to Transaction");
                return false;
            }
            break;
        default:
            NBR_MGR_LOG_ERR("NAS-INTF-UPD","Invalid CPS Operation %d", op);
            return false;
    }

    obj_g.release ();

    /** API Commit */
    if ((err_code = cps_api_commit(&tran)) != cps_api_ret_code_OK)
    {
        NBR_MGR_LOG_ERR("NAS-INTF-UPD","CPS API Commit failed %d", err_code);
        return false;
    }

    NBR_MGR_LOG_INFO("NAS-INTF-UPD", "VRF:%lu if-index:%d is_admin_up:%d Transaction Successfully completed", entry.vrfid,
                     entry.if_index, entry.is_admin_up);
    return true;
}

bool nbr_mgr_get_all_nh(uint8_t af) {
    cps_api_get_params_t get_req;

    if (cps_api_ret_code_OK != cps_api_get_request_init (&get_req)) {
        NBR_MGR_LOG_ERR("NBR-GET","NAS Get all NH request init failed!");
        return false;
    }

    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(get_req.filters);
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),BASE_NEIGHBOR_BASE_ROUTE_OBJ_NBR_OBJ,
                                    cps_api_qualifier_TARGET);
    cps_api_set_key_data(obj,BASE_ROUTE_OBJ_NBR_AF,cps_api_object_ATTR_T_U16,
                         &af,sizeof(af));

    if (cps_api_get(&get_req) == cps_api_ret_code_OK) {
        size_t total_msgs = cps_api_object_list_size(get_req.list);

        for ( size_t itr = 0 ; itr < total_msgs ; ++itr ) {
            obj = cps_api_object_list_get(get_req.list, itr);
            if (NULL == obj) return false;

            nbr_mgr_process_nas_cps_msg(obj, nullptr);
        }
    }

    cps_api_get_request_close(&get_req);

    return true;
}

bool nbr_mgr_is_mac_present_in_hw(hal_mac_addr_t mac, hal_ifindex_t if_index,
                                  bool& is_mac_present_in_hw) {
    cps_api_get_params_t get_req;

    nbr_mgr_intf_entry_t intf;
    if(nbr_get_if_data(0, if_index, intf)== false) {
        NBR_MGR_LOG_ERR("NBR-GET","NAS MAC get from HW, unable to get intf info!");
        return false;
    }
    /* If the interface type is not .1D or .1Q, return from here  */
    if ((intf.type != NBR_MGR_INTF_TYPE_1Q_BRIDGE) && (intf.type != NBR_MGR_INTF_TYPE_1D_BRIDGE)) {
        NBR_MGR_LOG_INFO("NBR-GET","NAS MAC get from HW,"
                        "VLAN id is not present for:%d", if_index);
        return false;
    }

    if (cps_api_ret_code_OK != cps_api_get_request_init (&get_req)) {
        NBR_MGR_LOG_ERR("NBR-GET","NAS MAC get from HW CPS init failed!");
        return false;
    }

    NBR_MGR_LOG_INFO("NBR-MAC-GET","NAS MAC get from HW, intf:%d type:%d vlan-id:%d if-name:%s",
                     if_index, intf.type, intf.vlan_id, intf.if_name);
    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(get_req.filters);
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),BASE_MAC_QUERY_OBJ,
                                    cps_api_qualifier_TARGET);
    cps_api_object_attr_add(obj,BASE_MAC_QUERY_MAC_ADDRESS, mac,
                            sizeof(hal_mac_addr_t));
    if (intf.type == NBR_MGR_INTF_TYPE_1Q_BRIDGE) {
        cps_api_object_attr_add_u16(obj,BASE_MAC_QUERY_VLAN, intf.vlan_id);
    } else {
        cps_api_object_attr_add(obj,BASE_MAC_QUERY_BR_NAME, intf.if_name,
                                strlen(intf.if_name)+1);
    }

    cps_api_return_code_t rc = cps_api_get(&get_req);
    if (rc == cps_api_ret_code_OK) {
        size_t total_msgs = cps_api_object_list_size(get_req.list);

        for ( size_t itr = 0 ; itr < total_msgs ; ++itr ) {
            obj = cps_api_object_list_get(get_req.list, itr);
            if (NULL == obj) return false;

            cps_api_object_attr_t if_index_attr = cps_api_object_attr_get(obj,BASE_MAC_QUERY_IFINDEX);
            cps_api_object_attr_t actions_attr = cps_api_object_attr_get(obj,BASE_MAC_QUERY_ACTIONS);
            cps_api_object_attr_t static_attr = cps_api_object_attr_get(obj,BASE_MAC_QUERY_STATIC);

            uint32_t mbr_if_index = 0, action = 0, is_static = 0;
            if (if_index_attr)
                mbr_if_index = cps_api_object_attr_data_u32(if_index_attr);
            if (actions_attr)
                action = cps_api_object_attr_data_u32(actions_attr);
            if (static_attr)
                is_static = cps_api_object_attr_data_u32(static_attr);

            NBR_MGR_LOG_INFO("NBR-MAC-GET","NAS MAC get from HW MAC vlan:%d bridge:%d(%s) mbr:%d action:%d static:%d",
                             intf.vlan_id, intf.if_index, intf.if_name, mbr_if_index, action, is_static);
        }
    }


    cps_api_get_request_close(&get_req);

    /* MAC is not present in the HW */
    if (rc != cps_api_ret_code_OK) {
        is_mac_present_in_hw = false;
    } else {
        is_mac_present_in_hw = true;
    }
    return true;
}

static void nbr_mgr_process_flush_obj_embed_attr(cps_api_object_t obj, const cps_api_object_it_t & it){
    uint32_t if_index = 0;
    cps_api_object_it_t it_lvl_1 = it;

    for (cps_api_object_it_inside (&it_lvl_1); cps_api_object_it_valid (&it_lvl_1);
         cps_api_object_it_next (&it_lvl_1)) {

        cps_api_object_it_t it_lvl_2 = it_lvl_1;
        for (cps_api_object_it_inside (&it_lvl_2); cps_api_object_it_valid (&it_lvl_2);
             cps_api_object_it_next (&it_lvl_2)) {

            switch(cps_api_object_attr_id(it_lvl_2.attr)){
                case BASE_MAC_FLUSH_EVENT_FILTER_MEMBER_IFINDEX:
                    if_index = cps_api_object_attr_data_u32(it_lvl_2.attr);
                    /* Refresh the VLAN associated neighbors */
                    NBR_MGR_LOG_INFO("NAS_FLUSH","Nbr refresh for VLAN:%d", if_index);
                    nbr_mgr_enqueue_flush_msg(if_index, 0);
                    break;
                case BASE_MAC_FLUSH_EVENT_FILTER_ALL:
                    /* Refresh all the VLAN associated neighbors */
                    NBR_MGR_LOG_INFO("NAS_FLUSH","Nbr refresh all VLAN associated neighbors");
                    nbr_mgr_enqueue_flush_msg(0, 0);
                    break;
                default:
                    break;
            }
        }
    }
}

/* Note: Dont return false from CPS event handler */
bool nbr_mgr_process_flush_cps_msg(cps_api_object_t obj, void *param) {
    cps_api_object_it_t it;
    cps_api_object_it_begin(obj,&it);

    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {

        int id = (int) cps_api_object_attr_id(it.attr);
        switch (id) {
            case BASE_MAC_FLUSH_EVENT_FILTER:
                nbr_mgr_process_flush_obj_embed_attr(obj, it);
                break;
            default:
                break;
        }
    }
    return true;
}

bool nbr_mgr_os_neigh_flush(const char *vrf_name, uint32_t family, const char *if_name) {

    cps_api_object_guard obj_g (cps_api_obj_tool_create(cps_api_qualifier_TARGET,
                                                        BASE_NEIGHBOR_FLUSH_OBJ, false));
    if (obj_g.get() == nullptr)
    {
        NBR_MGR_LOG_ERR("NAS_OS_FLUSH", "CPS object create failed!");
        return false;
    }

    cps_api_object_attr_add(obj_g.get(), BASE_NEIGHBOR_FLUSH_INPUT_VRF_NAME, vrf_name,
                            strlen(vrf_name)+1);
    cps_api_object_attr_add_u32(obj_g.get(),BASE_NEIGHBOR_FLUSH_INPUT_AF, family);

    cps_api_object_attr_add(obj_g.get(), BASE_NEIGHBOR_FLUSH_INPUT_IFNAME, if_name,
                            strlen(if_name)+1);
    if((cps_api_commit_one(cps_api_oper_ACTION, obj_g.get(), 1,0)) != cps_api_ret_code_OK){
        NBR_MGR_LOG_ERR("NAS_OS_FLUSH", "CPS commit failed for VRF:%s af:%d if-name:%s!",
                        vrf_name, family, if_name);
        return false;
    }
    NBR_MGR_LOG_INFO("NAS_OS_FLUSH", "IP neigh flush CPS commit success for VRF:%s af:%d if-name:%s!",
                     vrf_name, family, if_name);
    return true;
}

