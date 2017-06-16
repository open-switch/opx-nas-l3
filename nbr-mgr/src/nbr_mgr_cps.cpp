/*
 * Copyright (c) 2016 Dell Inc.
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
#include "cps_api_route.h"
#include "cps_api_operation.h"
#include "cps_api_events.h"
#include "cps_class_map.h"
#include "dell-base-routing.h"
#include "dell-base-neighbor.h"
#include "dell-base-if.h"
#include "dell-base-if-linux.h"
#include "hal_if_mapping.h"
#include "std_ip_utils.h"
#include "std_mac_utils.h"
#include "dell-base-l2-mac.h"

#include "nbr_mgr_main.h"
#include "nbr_mgr_msgq.h"
#include "nbr_mgr_log.h"
#include "nbr_mgr_utils.h"

static void* cps_evt_handle = nullptr;
cps_api_key_t linux_if_obj_key;

bool nbr_mgr_process_flush_cps_msg(cps_api_object_t obj, void *param);
bool nbr_mgr_process_nas_cps_msg(cps_api_object_t obj, void *param)
{
    cps_api_object_it_t it;
    cps_api_attr_id_t id = 0;
    nbr_mgr_msg_t *p_msg = nullptr;

    if (obj == NULL){
        NBR_MGR_LOG_ERR ("Invalid object sent from NAS");
        return false;
    }

    nbr_mgr_msg_uptr_t p_msg_uptr = nbr_mgr_alloc_unique_msg(&p_msg);
    if (p_msg == NULL) {
        NBR_MGR_LOG_ERR ("Memory alloc failed for NAS message");
        return false;
    }
    memset(p_msg, 0, sizeof(nbr_mgr_msg_t));
    p_msg->type = NBR_MGR_NAS_NBR_MSG;
    p_msg->nbr.msg_type = NBR_MGR_NBR_ADD;

    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    switch (op) {
        case cps_api_oper_CREATE:
            break;
        case cps_api_oper_DELETE:
            break;
        case cps_api_oper_SET:
            break;
        default:
            break;
    }

    cps_api_object_it_begin(obj,&it);

    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {
#if 0
        id = cps_api_object_attr_id(it.attr);

        switch (id) {
            case BASE_ROUTE_OBJ_NBR_VRF_ID:
                //nbr_mgr_msg->vrf_id = cps_api_object_attr_data_uint(it.attr);
                break;
            case BASE_ROUTE_OBJ_NBR_AF:
                p_msg->nbr.nbr_addr.af_index = cps_api_object_attr_data_uint(it.attr);
                p_msg->nbr.family = p_msg->nbr.nbr_addr.af_index;
                break;
            case BASE_ROUTE_OBJ_NBR_IFINDEX:
                p_msg->nbr.if_index = cps_api_object_attr_data_uint(it.attr);
                break;
            case BASE_ROUTE_OBJ_NBR_ADDRESS:
                //memcpy(&nbr_mgr_msg->ip_addr.u, cps_api_object_attr_data_bin(it.attr),
                //       cps_api_object_attr_len (it.attr));
                break;
        }
#endif
    }
    char buff[HAL_INET6_TEXT_LEN + 1];
    NBR_MGR_LOG_DEBUG("NAS-MSG", "Nbr resolution request for vrf:%d type:%d family:%d ip:%s if-index:%d",
                    p_msg->nbr.vrfid, p_msg->nbr.msg_type, p_msg->nbr.family,
                    std_ip_to_string(&(p_msg->nbr.nbr_addr), buff, HAL_INET6_TEXT_LEN),
                    p_msg->nbr.if_index);
    /* Proactive resolution request from NAS-L3 if not already resolved */
    p_msg->nbr.flags = NBR_MGR_NBR_RESOLVE;
    nbr_mgr_enqueue_netlink_nas_msg(std::move(p_msg_uptr));
    return true;
}

bool nbr_mgr_nas_nl_cps_init() {
    cps_api_event_reg_t reg;

    memset(&reg,0,sizeof(reg));
    const uint_t NUM_KEYS=2;
    cps_api_key_t key[NUM_KEYS];

    cps_api_key_init(&key[0],cps_api_qualifier_TARGET, cps_api_obj_cat_ROUTE,
                     cps_api_route_obj_NEIBH,0);
    // Register with NAS-Linux object for interface state change notifications
    cps_api_key_from_attr_with_qual(&key[1], BASE_IF_LINUX_IF_INTERFACES_INTERFACE_OBJ,
                                    cps_api_qualifier_OBSERVED);
    memcpy(&linux_if_obj_key, &key[1], sizeof(cps_api_key_t));

    reg.number_of_objects = NUM_KEYS;
    reg.objects = key;
    if (cps_api_event_thread_reg(&reg,nbr_mgr_process_nl_msg,NULL)!=cps_api_ret_code_OK) {
        return false;
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

    cps_api_object_attr_add_u32(cps_obj,BASE_ROUTE_OBJ_NBR_VRF_ID, entry.vrfid);
    //cps_api_object_attr_add_u32(cps_obj,BASE_ROUTE_OBJ_NBR_TYPE,m_rt_type);
    cps_api_object_attr_add_u32(cps_obj,BASE_ROUTE_OBJ_NBR_STATE, entry.status);
    //cps_api_object_attr_add(cps_obj, BASE_ROUTE_OBJ_NBR_IFNAME, ifname.c_str(), ifname.size()+1);
    cps_api_object_attr_add_u32(cps_obj,BASE_ROUTE_OBJ_NBR_IFINDEX, entry.if_index);
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

    NBR_MGR_LOG_DEBUG("NAS-INTF-UPD", "Transaction Successfully completed. Exit");

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
                    nbr_mgr_enqueue_flush_msg(if_index);
                    break;
                case BASE_MAC_FLUSH_EVENT_FILTER_ALL:
                    /* Refresh all the VLAN associated neighbors */
                    NBR_MGR_LOG_INFO("NAS_FLUSH","Nbr refresh all VLAN associated neighbors");
                    nbr_mgr_enqueue_flush_msg(0);
                    break;
                default:
                    break;
            }
        }
    }
}

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
