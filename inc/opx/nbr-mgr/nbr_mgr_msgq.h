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
 * filename: nbr_mgr_msgq.h
 *
 */

#ifndef _NBR_MGR_MSGQ_H_
#define _NBR_MGR_MSGQ_H_

#include "cps_api_interface_types.h"
#include "ds_common_types.h"
#include "std_type_defs.h"
#include "cps_api_interface_types.h"
#include "nas_vrf_utils.h"

#include <deque>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <utility>

typedef enum {
    NBR_MGR_OP_CREATE = 1,
    NBR_MGR_OP_UPDATE,
    NBR_MGR_OP_DELETE
}nbr_mgr_op_t;

typedef enum {
    NBR_MGR_NL_INTF_EVT = 1,
    NBR_MGR_NL_NBR_EVT,
    NBR_MGR_NL_MAC_EVT,
    NBR_MGR_NAS_NBR_MSG,
    NBR_MGR_NL_RESOLVE_MSG,
    NBR_MGR_NL_REFRESH_MSG,
    NBR_MGR_NAS_FLUSH_MSG,
    NBR_MGR_NL_DELAY_REFRESH_MSG,
    NBR_MGR_DUMP_MSG,
    NBR_MGR_NL_DELAY_RESOLVE_MSG,
    NBR_MGR_NL_INSTANT_REFRESH_MSG,
    NBR_MGR_NL_SET_NBR_STATE_MSG
} nbr_mgr_msg_type_t;

typedef enum {
    NBR_MGR_NBR_ADD =1 ,
    NBR_MGR_NBR_DEL,
    NBR_MGR_NBR_UPD
}nbr_mgr_evt_type_t;

typedef enum {
    NBR_MGR_DUMP_NBR = 1,
    NBR_MGR_DUMP_NBRS,
    NBR_MGR_DUMP_MACS,
    NBR_MGR_DUMP_INTF,
    NBR_MGR_DUMP_GBL_STATS,
    NBR_MGR_DUMP_GBL_STATS_CLEAR,
    NBR_MGR_DUMP_DETAIL_NBR_STATS,
    NBR_MGR_DUMP_DETAIL_NBR_STATS_CLEAR,
}nbr_mgr_dump_type_t;

#define NBR_MGR_NBR_RESOLVE      0x1
#define NBR_MGR_NBR_REFRESH      0x2
#define NBR_MGR_MAC_NOT_PRESENT  0x4
#define NBR_MGR_NBR_MAC_CHANGE   0x8
#define NBR_MGR_NBR_REFRESH_FOR_MAC_LEARN           0x10
#define NBR_MGR_NBR_TRIGGER_RESOLVE                 0x20
#define NBR_MGR_NBR_DISABLE_AGE_OUT_1D_REMOTE_MAC   0x40
#define NBR_MGR_NBR_ENABLE_AGE_OUT                  0x80
#define NBR_MGR_NBR_RESOLUTION_IN_PRGS              0x100
#define NBR_MGR_NBR_UPDATE_PARENT_IF                0x200

typedef struct  {
    unsigned short        family;
    nbr_mgr_evt_type_t    msg_type;
    hal_ip_addr_t         nbr_addr;
    hal_mac_addr_t        nbr_hwaddr;
    hal_ifindex_t         if_index;
    hal_ifindex_t         parent_if;
    hal_ifindex_t         mbr_if_index;
    unsigned long         vrfid;
    char                  vrf_name[NAS_VRF_NAME_SZ + 1];
    unsigned long         expire;
    unsigned long         flags;
    unsigned long         status;
    bool                  auto_refresh_on_stale_enabled;
} nbr_mgr_nbr_entry_t;

typedef struct {
    hal_ifindex_t if_index;
    bool is_admin_up;
    bool is_oper_up;
    bool is_op_del;
    bool is_bridge;
    uint32_t vlan_id;
    uint32_t flags;
    uint32_t type; /* Interface type */
    unsigned long vrfid;
    hal_ifindex_t parent_or_child_if_index; /* If-index of the router interface in VRF context (child intf)
                                               or parent interface */
    unsigned long parent_or_child_vrfid; /* VRF-id of the router interface in VRF context (child VRF-id or
                                            parent VRF-id */
    hal_ifindex_t mbr_if_index;
    char vrf_name[NAS_VRF_NAME_SZ + 1];
    char if_name[HAL_IF_NAME_SZ + 1]; /* interface name */
    bool is_parent_and_child_in_same_vrf; /* This is set to TRUE when parent and
                                             MAC VLAN interfaces are in the same VRF. */
    bool is_child_intf; /* This is the child interface on parent intf (parent_or_child_if_index). */
} nbr_mgr_intf_entry_t;

typedef struct {
    hal_ifindex_t if_index; /* VLAN interface index */
    unsigned long vrfid; /* Flush the interfaces and neighbors that are associated with the VRF */
} nbr_mgr_flush_entry_t;

typedef struct {
    nbr_mgr_dump_type_t type;
    uint32_t af;
    unsigned long vrf_id;
    char nbr_ip[HAL_INET6_TEXT_LEN + 1];
    hal_ifindex_t if_index;
    bool is_dump_all;
} nbr_mgr_dump_entry_t;

typedef struct {
    nbr_mgr_msg_type_t type;
    union {
        nbr_mgr_nbr_entry_t nbr;
        nbr_mgr_intf_entry_t intf;
        nbr_mgr_flush_entry_t flush;
        nbr_mgr_dump_entry_t dump;
    };
} nbr_mgr_msg_t;

using nbr_mgr_msg_uptr_t = std::unique_ptr<nbr_mgr_msg_t>;

/* Function to allocate a new message based on the type of pointer passed in */
template <typename NBR_MSG_TYPE, typename... Ts>
nbr_mgr_msg_uptr_t nbr_mgr_alloc_unique_msg (NBR_MSG_TYPE** ptr, Ts&&... params)
{
    *ptr = new (std::nothrow) NBR_MSG_TYPE (std::forward<Ts>(params)...);
    return nbr_mgr_msg_uptr_t(*ptr);
}

typedef bool (*burst_resolvefunc)(nbr_mgr_msg_t*);

class nbr_mgr_msgq_t {
    public:
        nbr_mgr_msgq_t(){};
        bool enqueue(nbr_mgr_msg_uptr_t msg);
        nbr_mgr_msg_uptr_t dequeue ();
        std::string  queue_stats();
        friend bool nbr_mgr_dequeue_and_handle_burst_resolve_msg(nbr_mgr_msgq_t *hdl, burst_resolvefunc cb,
                                                                 uint32_t burst_delay, uint32_t *resolve_delay);
    private:
        std::deque<nbr_mgr_msg_uptr_t>  m_msgq;
        std::mutex m_mtx;
        std::condition_variable  m_data;
        uint_t  m_high = 0;
};
using nbr_mgr_msgq_handle_t = nbr_mgr_msgq_t*;

bool nbr_mgr_msgq_create ();

bool nbr_mgr_enqueue_netlink_nas_msg(nbr_mgr_msg_uptr_t msg);
nbr_mgr_msg_uptr_t nbr_mgr_dequeue_netlink_nas_msg ();
bool nbr_mgr_enqueue_burst_resolve_msg(nbr_mgr_msg_uptr_t msg);
bool nbr_mgr_enqueue_instant_resolve_msg(nbr_mgr_msg_uptr_t msg);
bool nbr_mgr_process_burst_resolve_msg(burst_resolvefunc cb);
bool nbr_mgr_process_instant_resolve_msg(burst_resolvefunc cb);
bool nbr_mgr_process_delay_resolve_msg(burst_resolvefunc cb);
bool nbr_mgr_enqueue_delay_resolve_msg(nbr_mgr_msg_uptr_t msg);
bool nbr_mgr_process_nl_msg(cps_api_object_t obj, void *param);
std::string nbr_mgr_netlink_q_stats();
std::string nbr_mgr_burst_q_stats();
std::string nbr_mgr_delay_q_stats();
std::string nbr_mgr_instant_q_stats();
#endif
