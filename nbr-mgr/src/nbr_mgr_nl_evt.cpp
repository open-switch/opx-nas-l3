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
#include "std_utils.h"
#include "ds_common_types.h"

#include "dell-base-if.h"
#include "dell-base-if-linux.h"
#include "dell-base-routing.h"
#include "os-routing-events.h"
#include "dell-base-if-vlan.h"
#include "vrf-mgmt.h"

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

char *nbr_mgr_nl_intf_msg_to_str (int type) {
    static char str[18];
        if (type == NBR_MGR_INTF_VLAN_MSG)
            snprintf (str, sizeof(str), "Vlan");
        else if (type == NBR_MGR_INTF_ADMIN_MSG)
            snprintf (str, sizeof(str), "Admin");
        else if (type == NBR_MGR_INTF_OPER_MSG)
            snprintf (str, sizeof(str), "Oper");
        else if (type == (NBR_MGR_INTF_VLAN_MSG | NBR_MGR_INTF_ADMIN_MSG))
            snprintf (str, sizeof(str), "VLAN and Admin");
        else if (type == (NBR_MGR_INTF_VLAN_MSG | NBR_MGR_INTF_OPER_MSG))
            snprintf (str, sizeof(str), "VLAN and Oper");
        else if (type == (NBR_MGR_INTF_ADMIN_MSG | NBR_MGR_INTF_OPER_MSG))
            snprintf (str, sizeof(str), "Admin and Oper");
        else
            snprintf (str, sizeof(str), "Unknown");

    return str;
}

bool nbr_mgr_cps_obj_to_intf(cps_api_object_t obj, nbr_mgr_intf_entry_t *p_intf) {
    bool is_admin_up = false;
    bool is_oper_up = false;
    bool is_op_del = false;
    bool is_bridge = false;
    uint32_t type = 0, vlan_id = 0, mbr_if_index = 0;

    NBR_MGR_LOG_DEBUG("CPS-INTF","Interface admin status change notification");

    /* Get the IfIndex and admin status attributes */
    cps_api_object_attr_t ifix_attr = cps_api_object_attr_get(obj,DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX);
    if (ifix_attr == NULL) {
        NBR_MGR_LOG_ERR("CPS-INTF","If-Index is not present");
        return false;
    }
    const char *vrf_name = (const char *) cps_api_object_get_data(obj, NI_IF_INTERFACES_INTERFACE_BIND_NI_NAME);
    if (vrf_name) {
        safestrncpy(p_intf->vrf_name, vrf_name, sizeof(p_intf->vrf_name));
    }
    hal_ifindex_t index = cps_api_object_attr_data_u32(ifix_attr);

    cps_api_object_attr_t vrfid_attr = cps_api_object_attr_get(obj, VRF_MGMT_NI_IF_INTERFACES_INTERFACE_VRF_ID);
    if (vrfid_attr) {
        p_intf->vrfid = cps_api_object_attr_data_u32(vrfid_attr);
    }
    const char *if_name = (const char *) cps_api_object_get_data(obj, IF_INTERFACES_INTERFACE_NAME);
    if (if_name) {
        safestrncpy(p_intf->if_name, if_name, sizeof(p_intf->if_name));
    } else {
        memset(p_intf->if_name, '\0', sizeof(p_intf->if_name));
    }

    /* If the interface VLAN/LAG deleted, flush all the neighbors and routes associated with it */
    if (cps_api_object_type_operation(cps_api_object_key(obj)) != cps_api_oper_DELETE) {
        cps_api_object_attr_t admin_attr = cps_api_object_attr_get(obj,IF_INTERFACES_INTERFACE_ENABLED);
        cps_api_object_attr_t flags_attr = cps_api_object_attr_get(obj,BASE_IF_LINUX_IF_INTERFACES_INTERFACE_IF_FLAGS);

        if(admin_attr != NULL){
            is_admin_up = cps_api_object_attr_data_u32(admin_attr);
            p_intf->flags |= NBR_MGR_INTF_ADMIN_MSG;
            NBR_MGR_LOG_DEBUG("CPS-INTF","Intf:%d status:%s",
                              index, (is_admin_up ? "Up" : "Down"));
        } else {
            NBR_MGR_LOG_DEBUG("CPS-INTF","admin status is not present for intf:%d",index);
        }
        if (flags_attr) {
            is_oper_up = (NBR_MGR_INTF_OPER_UP & cps_api_object_attr_data_u32(flags_attr));
            p_intf->flags |= NBR_MGR_INTF_OPER_MSG;
        }
    } else {
        is_op_del = true;
    }
    /* Removing the member port from the logical intf(VLAN/LAG) should not be
     * considered as the logical intf delete, allow only the L2/L3/LAG intfs */
    cps_api_object_attr_t intf_type =
        cps_api_object_attr_get(obj, BASE_IF_LINUX_IF_INTERFACES_INTERFACE_DELL_TYPE);
    if (intf_type) {
        type = cps_api_object_attr_data_u32(intf_type);
        NBR_MGR_LOG_INFO("CPS-INTF","Intf:%d is_del:%d admin:%s oper:%s type:%d", index, is_op_del,
                         ((p_intf->flags & NBR_MGR_INTF_ADMIN_MSG) ? (is_admin_up ? "Up" : "Down") : "NA"),
                         ((p_intf->flags & NBR_MGR_INTF_OPER_MSG) ? (is_oper_up ? "Up" : "Down") : "NA"), type);
        /* Allow only the L2 (bridge) and L3 ports for L3 operations */
        if ((type != BASE_CMN_INTERFACE_TYPE_BRIDGE) && (type != BASE_CMN_INTERFACE_TYPE_L3_PORT) &&
            (type != BASE_CMN_INTERFACE_TYPE_LAG) && (type != BASE_CMN_INTERFACE_TYPE_L2_PORT) &&
            (type != BASE_CMN_INTERFACE_TYPE_MACVLAN) && (type != BASE_CMN_INTERFACE_TYPE_MANAGEMENT) &&
            (type != BASE_CMN_INTERFACE_TYPE_VXLAN)) {
            return false;
        }
        p_intf->type = NBR_MGR_INTF_TYPE_PHY;
        /* Incase of LAG/VLAN member delete, ignore it,
         * allow only LAG/VLAN intf admin down/up and delete */
        if (type == BASE_CMN_INTERFACE_TYPE_LAG) {
            cps_api_object_attr_t intf_member_port =
                cps_api_object_attr_get(obj, DELL_IF_IF_INTERFACES_INTERFACE_MEMBER_PORTS_NAME);
            if (intf_member_port) {
                NBR_MGR_LOG_INFO("CPS-INTF","LAG member Intf:%d is_del:%d admin:%s oper:%s type:%d mbr:%s", index, is_op_del,
                                 ((p_intf->flags & NBR_MGR_INTF_ADMIN_MSG) ? (is_admin_up ? "Up" : "Down") : "NA"),
                                 ((p_intf->flags & NBR_MGR_INTF_OPER_MSG) ? (is_oper_up ? "Up" : "Down") : "NA"), type,
                                 ((char*)cps_api_object_attr_data_bin(intf_member_port)));
                return false;
            }
            p_intf->type = NBR_MGR_INTF_TYPE_LAG;
        }
        if (type == BASE_CMN_INTERFACE_TYPE_L2_PORT) {
            NBR_MGR_LOG_INFO("CPS-INTF","VLAN member Intf:%d is_del:%d admin:%s oper:%s type:%d", index, is_op_del,
                             ((p_intf->flags & NBR_MGR_INTF_ADMIN_MSG) ? (is_admin_up ? "Up" : "Down") : "NA"),
                             ((p_intf->flags & NBR_MGR_INTF_OPER_MSG) ? (is_oper_up ? "Up" : "Down") : "NA"), type);
            if (is_op_del) {
                return false;
            }
        }
        if (type == BASE_CMN_INTERFACE_TYPE_BRIDGE) {
            is_bridge = true;
            p_intf->type = NBR_MGR_INTF_TYPE_1Q_BRIDGE;
        } else if (type == BASE_CMN_INTERFACE_TYPE_L2_PORT) {
            /* Make sure only the VLAN flag is set since this event handled
             * only for VLAN-id update not for admin/oper status update for VLAN interface. */
            p_intf->flags = 0;
            p_intf->type = NBR_MGR_INTF_TYPE_1Q_BRIDGE;
            cps_api_object_attr_t vlan_id_attr =
                cps_api_object_attr_get(obj, BASE_IF_VLAN_IF_INTERFACES_INTERFACE_ID);
            if (vlan_id_attr) {
                vlan_id = cps_api_object_attr_data_u32(vlan_id_attr);
                p_intf->flags |= NBR_MGR_INTF_VLAN_MSG;
            }
            cps_api_object_attr_t if_mbr_attr =
                cps_api_object_attr_get(obj, BASE_IF_LINUX_IF_INTERFACES_INTERFACE_MBR_IFINDEX);
            if (if_mbr_attr) {
                mbr_if_index = cps_api_object_attr_data_u32(if_mbr_attr);
            }
        } else if (type == BASE_CMN_INTERFACE_TYPE_MACVLAN) {
            p_intf->type = NBR_MGR_INTF_TYPE_MACVLAN;
        } else if (type == BASE_CMN_INTERFACE_TYPE_VXLAN) {
            p_intf->type = NBR_MGR_INTF_TYPE_VXLAN;
        }
    }
    /* If add/update case, if none of the flags set, return false */
    if ((is_op_del == false) && (p_intf->flags == 0) && (mbr_if_index == 0)) {
        return false;
    }
    p_intf->if_index = index;
    p_intf->is_admin_up = is_admin_up;
    p_intf->is_oper_up = is_oper_up;
    p_intf->is_bridge = is_bridge;
    p_intf->vlan_id = vlan_id;
    p_intf->is_op_del = is_op_del;
    p_intf->mbr_if_index = mbr_if_index;

    NBR_MGR_LOG_INFO("CPS-INTF","msg:%s VRF-id:%lu Intf:%d(%s) type:%d flags:0x%x status admin:%s oper:%s type:%d "
                     "bridge:%d is_op_del:%d vlan-id:%d mbr-intf:%d", nbr_mgr_nl_intf_msg_to_str(p_intf->flags),
                     p_intf->vrfid, index, (if_name ? p_intf->if_name : ""), p_intf->type, p_intf->flags,
                     ((p_intf->flags & NBR_MGR_INTF_ADMIN_MSG) ? (is_admin_up ? "Up" : "Down") : "NA"),
                     ((p_intf->flags & NBR_MGR_INTF_OPER_MSG) ? (is_oper_up ? "Up" : "Down") : "NA"),
                     type, is_bridge, is_op_del, vlan_id, mbr_if_index);
    return true;
}

bool nbr_mgr_cps_obj_to_neigh(cps_api_object_t obj, nbr_mgr_nbr_entry_t *n) {

    memset(n, 0, sizeof(nbr_mgr_nbr_entry_t));
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    switch (op) {
        case cps_api_oper_CREATE:
            n->msg_type = NBR_MGR_NBR_ADD;
            break;
        case cps_api_oper_SET:
            n->msg_type = NBR_MGR_NBR_UPD;
            break;
        case cps_api_oper_DELETE:
            n->msg_type = NBR_MGR_NBR_DEL;
            break;
        default:
            break;
    }
    cps_api_object_it_t it;
    cps_api_attr_id_t id = 0;
    cps_api_object_it_begin(obj,&it);
    bool is_fdb_remote_ip_present = false;

    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {
        id = cps_api_object_attr_id(it.attr);

        switch (id) {
            case BASE_ROUTE_OBJ_VRF_NAME:
                safestrncpy((char*)n->vrf_name, (const char*)cps_api_object_attr_data_bin(it.attr),
                            sizeof(n->vrf_name));
                break;
            case OS_RE_BASE_ROUTE_OBJ_NBR_VRF_ID:
                n->vrfid = cps_api_object_attr_data_uint(it.attr);
                break;
            case BASE_ROUTE_OBJ_NBR_FLAGS:
                n->flags = cps_api_object_attr_data_uint(it.attr);
                break;
            case BASE_ROUTE_OBJ_NBR_AF:
                n->family = cps_api_object_attr_data_uint(it.attr);
                n->nbr_addr.af_index = n->family;
                break;
            case BASE_ROUTE_OBJ_NBR_ADDRESS:
                is_fdb_remote_ip_present = true;
                memcpy(&n->nbr_addr.u, cps_api_object_attr_data_bin(it.attr),
                       cps_api_object_attr_len (it.attr));
                break;
            case BASE_ROUTE_OBJ_NBR_MAC_ADDR:
                std_string_to_mac(&n->nbr_hwaddr, (char*)cps_api_object_attr_data_bin(it.attr),
                                  cps_api_object_attr_len(it.attr));
                break;
            case BASE_ROUTE_OBJ_NBR_IFINDEX:
                n->if_index = cps_api_object_attr_data_uint(it.attr);
                break;
            case OS_RE_BASE_ROUTE_OBJ_NBR_LOWER_LAYER_IF:
                n->parent_if = cps_api_object_attr_data_uint(it.attr);
                break;
            case OS_RE_BASE_ROUTE_OBJ_NBR_MBR_IFINDEX:
                n->mbr_if_index= cps_api_object_attr_data_uint(it.attr);
                break;
            case BASE_ROUTE_OBJ_NBR_STATE:
                n->status = cps_api_object_attr_data_uint(it.attr);
                break;
        }
    }
    if ((n->family == HAL_INET4_FAMILY) || (n->family == HAL_INET6_FAMILY)) {
        if (n->status == NBR_MGR_NUD_STALE) {
            n->auto_refresh_on_stale_enabled = nbr_mgr_get_auto_refresh_status((char*)n->vrf_name,
                                                                               n->family);
        }
    } else if (is_fdb_remote_ip_present) {
        /* Set the remote IP family */
        n->nbr_addr.af_index = HAL_INET4_FAMILY;
    }
    return true;
}

/* Note: Dont return false from CPS event handler */
bool nbr_mgr_process_nl_msg(cps_api_object_t obj, void *param)
{
    nbr_mgr_msg_t *p_msg = nullptr;
    nbr_mgr_msg_uptr_t p_msg_uptr;
    char str[NBR_MGR_MAC_STR_LEN];
    char buff[HAL_INET6_TEXT_LEN + 1];

    switch (cps_api_key_get_cat(cps_api_object_key(obj))) {
        case cps_api_obj_CAT_BASE_IF_LINUX:
            nbr_mgr_intf_entry_t intf;
            /* Enqueue the intf messages for further processing
             * only it has the admin attribute.*/
            memset(&intf, 0, sizeof(intf));
            if (nbr_mgr_cps_obj_to_intf(obj,&intf)) {
                p_msg_uptr = nbr_mgr_alloc_unique_msg(&p_msg);
                if (p_msg) {
                    p_msg->type = NBR_MGR_NL_INTF_EVT;
                    memcpy(&(p_msg->intf), &intf, sizeof(nbr_mgr_intf_entry_t));
                    nbr_mgr_enqueue_netlink_nas_msg(std::move(p_msg_uptr));
                }
            }
            break;

        case cps_api_obj_CAT_OS_RE:
            //g_fib_gbl_info.num_neigh_msg++;
            p_msg_uptr = nbr_mgr_alloc_unique_msg(&p_msg);
            if (p_msg) {
                if (nbr_mgr_cps_obj_to_neigh(obj, &(p_msg->nbr))) {
                    std::string q_stats = nbr_mgr_netlink_q_stats();
                    NBR_MGR_LOG_DEBUG("NETLINK-EVT", "Q:%s type:%d family:%d ip:%s mac:%s if-index:%d/phy:%d "
                                      "state:%s(0x%lx) processing", q_stats.c_str(),
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
        case cps_api_obj_CAT_VRF_MGMT:
            if (cps_api_object_type_operation(cps_api_object_key(obj)) == cps_api_oper_DELETE) {
                cps_api_object_attr_t vrfid_attr =
                    cps_api_object_attr_get(obj, VRF_MGMT_NI_NETWORK_INSTANCES_NETWORK_INSTANCE_VRF_ID);
                if (vrfid_attr) {
                    nbr_mgr_enqueue_flush_msg(0, cps_api_object_attr_data_u32(vrfid_attr));
                }
            }
            break;

        default:
            break;
    }

    return true;
}

