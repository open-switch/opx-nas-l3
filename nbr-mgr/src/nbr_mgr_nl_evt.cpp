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
 * filename: nbr_mgr_nl_evt.cpp
 */

#include <unistd.h>
#include <iostream>
#include "nbr_mgr_main.h"
#include "nbr_mgr_msgq.h"
#include "nbr_mgr_utils.h"
#include "nbr_mgr_log.h"
#include "std_mac_utils.h"
#include "std_ip_utils.h"
#include "ds_common_types.h"

#include "dell-base-if.h"
#include "dell-base-if-linux.h"
#include "dell-base-routing.h"
#include "cps_api_route.h"

extern cps_api_key_t linux_if_obj_key;
char *nbr_mgr_nl_neigh_state_to_str (int state) {
    static char str[18];
        if (state == NBR_MGR_NUD_INCOMPLETE)
            snprintf (str, sizeof(str), "Incomplete");
        else if (state == NBR_MGR_NUD_REACHABLE)
            snprintf (str, sizeof(str), "Reachable");
        else if (state == NBR_MGR_NUD_STALE)
            snprintf (str, sizeof(str), "Stale");
        else if (state == NBR_MGR_NUD_DELAY)
            snprintf (str, sizeof(str), "Delay");
        else if (state == NBR_MGR_NUD_PROBE)
            snprintf (str, sizeof(str), "Probe");
        else if (state == NBR_MGR_NUD_FAILED)
            snprintf (str, sizeof(str), "Failed");
        else if (state == NBR_MGR_NUD_NOARP)
            snprintf (str, sizeof(str), "NoArp");
        else if (state == NBR_MGR_NUD_PERMANENT)
            snprintf (str, sizeof(str), "Static");
        else
            snprintf (str, sizeof(str), "None");

    return str;
}

bool nbr_mgr_cps_obj_to_intf(cps_api_object_t obj, nbr_mgr_intf_entry_t *p_intf) {
    bool is_admin_up = false;
    bool is_op_del = false;
    bool is_bridge = false;
    uint32_t type = 0;

    NBR_MGR_LOG_DEBUG("CPS-INTF","Interface admin status change notification");

    /* Get the IfIndex and admin status attributes */
    cps_api_object_attr_t ifix_attr = cps_api_object_attr_get(obj,DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX);
    if (ifix_attr == NULL) {
        NBR_MGR_LOG_ERR("CPS-INTF","If-Index is not present");
        return false;
    }
    hal_ifindex_t index = cps_api_object_attr_data_u32(ifix_attr);

    /* If the interface VLAN/LAG deleted, flush all the neighbors and routes associated with it */
    if (cps_api_object_type_operation(cps_api_object_key(obj)) != cps_api_oper_DELETE) {
        cps_api_object_attr_t admin_attr = cps_api_object_attr_get(obj,IF_INTERFACES_INTERFACE_ENABLED);

        if(admin_attr == NULL){
            NBR_MGR_LOG_DEBUG("CPS-INTF","admin status is not present for intf:%d",index);
            return false;
        }

        is_admin_up = cps_api_object_attr_data_u32(admin_attr);
        NBR_MGR_LOG_DEBUG("CPS-INTF","Intf:%d status:%s",
                          index, (is_admin_up ? "Up" : "Down"));
    } else {
        is_op_del = true;
    }
    /* Removing the member port from the logical intf(VLAN/LAG) should not be
     * considered as the logical intf delete, allow only the L2/L3/LAG intfs */
    cps_api_object_attr_t intf_type =
        cps_api_object_attr_get(obj, BASE_IF_LINUX_IF_INTERFACES_INTERFACE_DELL_TYPE);
    if (intf_type) {
        type = cps_api_object_attr_data_u32(intf_type);
        NBR_MGR_LOG_INFO("CPS-INTF","Intf:%d status:%s type:%d",
                         index, (is_admin_up ? "Up" : "Down"), type);
        /* Allow only the L2 (bridge) and L3 ports for L3 operations */
        if ((type != BASE_CMN_INTERFACE_TYPE_L2_PORT) && (type != BASE_CMN_INTERFACE_TYPE_L3_PORT) &&
            (type != BASE_CMN_INTERFACE_TYPE_LAG)) {
            return false;
        }
        cps_api_object_attr_t intf_member_port =
            cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_MEMBER_PORTS_NAME);
        /* Incase of LAG member delete, ignore it, allow only LAG intf admin down/up and delete */
        if (is_op_del && intf_member_port && (type == BASE_CMN_INTERFACE_TYPE_LAG)) {
            return false;
        }
        if (type == BASE_CMN_INTERFACE_TYPE_L2_PORT)
            is_bridge = true;
    }

    p_intf->if_index = index;
    p_intf->is_admin_up = is_admin_up;
    p_intf->is_bridge = is_bridge;
    p_intf->is_op_del = is_op_del;

    NBR_MGR_LOG_INFO("CPS-INTF","Intf:%d status:%s type:%d bridge:%d is_op_del:%d",
                     index, (is_admin_up ? "Up" : "Down"), type, is_bridge, is_op_del);
    return true;
}

bool nbr_mgr_cps_obj_to_neigh(cps_api_object_t obj, nbr_mgr_nbr_entry_t *n) {
    cps_api_object_attr_t list[cps_api_if_NEIGH_A_MAX];
    cps_api_object_attr_fill_list(obj,0,list,sizeof(list)/sizeof(*list));

    memset(n,0,sizeof(*n));

    if (list[cps_api_if_NEIGH_A_FAMILY]!=NULL)
        n->family = cps_api_object_attr_data_u32(list[cps_api_if_NEIGH_A_FAMILY]);
    if (list[cps_api_if_NEIGH_A_OPERATION]!=NULL)
        n->msg_type = (db_nbr_event_type_t)cps_api_object_attr_data_u32(list[cps_api_if_NEIGH_A_OPERATION]);
    if (list[cps_api_if_NEIGH_A_NBR_ADDR]!=NULL)
        memcpy(&n->nbr_addr,
               cps_api_object_attr_data_bin(list[cps_api_if_NEIGH_A_NBR_ADDR]),
               sizeof(n->nbr_addr));
    if (list[cps_api_if_NEIGH_A_NBR_MAC]!=NULL)
        memcpy(n->nbr_hwaddr,
               cps_api_object_attr_data_bin(list[cps_api_if_NEIGH_A_NBR_MAC]),
               sizeof(n->nbr_hwaddr));
    if (list[cps_api_if_NEIGH_A_IFINDEX]!=NULL)
        n->if_index = cps_api_object_attr_data_u32(list[cps_api_if_NEIGH_A_IFINDEX]);
    if (list[cps_api_if_NEIGH_A_PHY_IFINDEX]!=NULL)
        n->mbr_if_index = cps_api_object_attr_data_u32(list[cps_api_if_NEIGH_A_PHY_IFINDEX]);
    if (list[cps_api_if_NEIGH_A_VRF]!=NULL)
        n->vrfid = cps_api_object_attr_data_u32(list[cps_api_if_NEIGH_A_VRF]);
    if (list[cps_api_if_NEIGH_A_EXPIRE]!=NULL)
        n->expire= cps_api_object_attr_data_u32(list[cps_api_if_NEIGH_A_EXPIRE]);
    if (list[cps_api_if_NEIGH_A_FLAGS]!=NULL)
        n->flags = cps_api_object_attr_data_u32(list[cps_api_if_NEIGH_A_FLAGS]);
    if (list[cps_api_if_NEIGH_A_STATE]!=NULL)
        n->status = cps_api_object_attr_data_u32(list[cps_api_if_NEIGH_A_STATE]);
    return true;
}

bool nbr_mgr_process_nl_msg(cps_api_object_t obj, void *param)
{
    nbr_mgr_msg_t *p_msg = nullptr;
    nbr_mgr_msg_uptr_t p_msg_uptr;
    char str[NBR_MGR_MAC_STR_LEN];
    char buff[HAL_INET6_TEXT_LEN + 1];

   // g_fib_gbl_info.num_tot_msg++;

    if (cps_api_key_matches (&linux_if_obj_key, cps_api_object_key(obj), true) == 0) {
        //g_fib_gbl_info.num_int_msg++;
        nbr_mgr_intf_entry_t intf;
        /* Enqueue the intf messages for further processing
         * only it has the admin attribute.*/
        if (nbr_mgr_cps_obj_to_intf(obj,&intf)) {
            p_msg_uptr = nbr_mgr_alloc_unique_msg(&p_msg);
            if (p_msg) {
                p_msg->type = NBR_MGR_NL_INTF_EVT;
                memcpy(&(p_msg->intf), &intf, sizeof(nbr_mgr_intf_entry_t));
                nbr_mgr_enqueue_netlink_nas_msg(std::move(p_msg_uptr));
            }
        }
        return true;
    }

    if (cps_api_key_get_cat(cps_api_object_key(obj)) != cps_api_obj_cat_ROUTE) {
     //   g_fib_gbl_info.num_err_msg++;
        return true;
    }

    switch (cps_api_key_get_subcat(cps_api_object_key(obj))) {
        case cps_api_route_obj_NEIBH:
            //g_fib_gbl_info.num_neigh_msg++;
            p_msg_uptr = nbr_mgr_alloc_unique_msg(&p_msg);
            if (p_msg) {
                if (nbr_mgr_cps_obj_to_neigh(obj, &(p_msg->nbr))) {
                    NBR_MGR_LOG_DEBUG("NETLINK-EVT", "type:%d family:%d ip:%s mac:%s if-index:%d/phy:%d state:%s(0x%x) processing",
                                    p_msg->nbr.msg_type, p_msg->nbr.family,
                                    std_ip_to_string(&(p_msg->nbr.nbr_addr), buff, HAL_INET6_TEXT_LEN),
                                    std_mac_to_string (&(p_msg->nbr.nbr_hwaddr), str, NBR_MGR_MAC_STR_LEN),
                                    p_msg->nbr.if_index, p_msg->nbr.mbr_if_index,
                                    nbr_mgr_nl_neigh_state_to_str(p_msg->nbr.status), p_msg->nbr.status);

                    /* If AF_INET/AF_INET6 are set, IP nbr otherwise AF_BRIDGE nbr */
                    if ((p_msg->nbr.family == HAL_INET4_FAMILY) || (p_msg->nbr.family == HAL_INET6_FAMILY)) {
                        if (p_msg->nbr.status == NBR_MGR_NUD_NOARP) {
                            /* Ignore the No ARP message @@TODO Is this free correct? */
                            p_msg = p_msg_uptr.release();
                            delete p_msg;
                            return true;
                        }
                        p_msg->type = NBR_MGR_NL_NBR_EVT;
                    } else {
                        p_msg->type = NBR_MGR_NL_MAC_EVT;
                    }
                    p_msg->nbr.flags = 0;
                    nbr_mgr_enqueue_netlink_nas_msg(std::move(p_msg_uptr));
                }
            }
            break;

        default:
            break;
    }

    return true;
}

