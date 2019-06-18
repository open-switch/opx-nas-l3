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
 * filename: nbr_mgr_debug.cpp
 */

#include "nbr_mgr_main.h"
#include "nbr_mgr_cache.h"
#include "nbr_mgr_log.h"
#include "std_utils.h"
#include <exception>
#include <sstream>

extern nbr_process* p_nbr_process_hdl;
extern char *nbr_mgr_nl_neigh_state_to_str (int state);

void nbr_process::nbr_mgr_dump_process_stats() {
    NBR_MGR_LOG_ERR("DUMP", " NBR_MGR Stats INTF add:%d,del:%d,NBR add:%d,incomplete:%d,reachable:%d,stale:%d,"
                    "delay:%d,probe:%d,failed:%d,permanent:%d,del:%d, RESOLVE add:%d del%d FDB add:%d del:%d"
                    " FLUSH:%d trig_refresh:%d,dup_trig_nbr:%d Q netlink:%s burst:%s delay:%s instant:%s",
                    stats.intf_add_msg_cnt,  stats.intf_del_msg_cnt, stats.nbr_add_msg_cnt,
                    stats.nbr_add_incomplete_msg_cnt, stats.nbr_add_reachable_msg_cnt, stats.nbr_add_stale_msg_cnt,
                    stats.nbr_add_delay_msg_cnt, stats.nbr_add_probe_msg_cnt, stats.nbr_add_failed_msg_cnt,
                    stats.nbr_add_permanaent_cnt, stats.nbr_del_msg_cnt,
                    stats.nbr_rslv_add_msg_cnt, stats.nbr_rslv_del_msg_cnt,
                    stats.fdb_add_msg_cnt, stats.fdb_del_msg_cnt, stats.flush_msg_cnt,
                    stats.flush_trig_refresh_cnt, stats.flush_nbr_cnt, nbr_mgr_netlink_q_stats().c_str(),
                    nbr_mgr_burst_q_stats().c_str(), nbr_mgr_delay_q_stats().c_str(), nbr_mgr_instant_q_stats().c_str());
}

static void _nbr_mgr_dump_nbr_data_stats(nbr_data const * ptr) {
    NBR_MGR_LOG_ERR("DUMP", "Neighbor STATS vrf-id:%d Nbr:%s refresh:%d instant refresh:%d delay refresh:%d "
                    "delay resolve:%d resolve:%d retry:%d mac_np:%d fail_trig_resolve:%d stale_ref:%d "
                    "hw_mac_lrn_refresh:%d mac_trig_ref:%d mac_trig_skip_oper:%d mac_inst_trig_on_oper_down:%d "
                    "FLUSH skip:%d fail_resolve:%d refresh:%d "
                    "mac add resolve:%d refresh:%d delay-state-failed-resolve:%d refresh_for_more_flushes:%d",
                    ptr->get_vrf_id(), ptr->get_ip_addr().c_str(),
                    ptr->nbr_stats.refresh_cnt, ptr->nbr_stats.instant_refresh_cnt, ptr->nbr_stats.delay_refresh_cnt,
                    ptr->nbr_stats.delay_resolve_cnt, ptr->nbr_stats.resolve_cnt,
                    ptr->nbr_stats.retry_cnt, ptr->nbr_stats.mac_not_present_cnt,
                    ptr->nbr_stats.failed_trig_resolve_cnt, ptr->nbr_stats.stale_trig_refresh_cnt,
                    ptr->nbr_stats.hw_mac_learn_refresh_cnt, ptr->nbr_stats.mac_trig_refresh,
                    ptr->nbr_stats.oper_down_mac_trig_instant_refresh, ptr->nbr_stats.failed_handle_skip_oper_down,
                    ptr->nbr_stats.flush_skip_refresh, ptr->nbr_stats.flush_failed_resolve,
                    ptr->nbr_stats.flush_refresh, ptr->nbr_stats.mac_add_trig_resolve,
                    ptr->nbr_stats.mac_add_trig_refresh, ptr->nbr_stats.delay_trig_refresh,
                    ptr->nbr_stats.refresh_for_more_flushes);
}

static void _nbr_mgr_dump_nbr_data_ref_stats(nbr_data_ptr &ptr) {
    NBR_MGR_LOG_ERR("DUMP", "Neighbor STATS vrf-id:%d Nbr:%s refresh:%d instant refresh:%d delay refresh:%d "
                    "delay resolve:%d resolve:%d retry:%d mac_np:%d fail_trig_resolve:%d stale_ref:%d "
                    "hw_mac_lrn_refresh:%d mac_trig_ref:%d mac_inst_trig_on_oper_down:%d "
                    "FLUSH skip:%d fail_resolve:%d refresh:%d mac add resolve:%d refresh:%d delay-state-failed-resolve:%d"
                    " refresh_for_more_flushes:%d",
                    ptr->get_vrf_id(), ptr->get_ip_addr().c_str(),
                    ptr->nbr_stats.refresh_cnt, ptr->nbr_stats.instant_refresh_cnt, ptr->nbr_stats.delay_refresh_cnt,
                    ptr->nbr_stats.delay_resolve_cnt, ptr->nbr_stats.resolve_cnt,
                    ptr->nbr_stats.retry_cnt, ptr->nbr_stats.mac_not_present_cnt,
                    ptr->nbr_stats.failed_trig_resolve_cnt, ptr->nbr_stats.stale_trig_refresh_cnt,
                    ptr->nbr_stats.hw_mac_learn_refresh_cnt, ptr->nbr_stats.mac_trig_refresh,
                    ptr->nbr_stats.oper_down_mac_trig_instant_refresh, ptr->nbr_stats.failed_handle_skip_oper_down,
                    ptr->nbr_stats.flush_skip_refresh, ptr->nbr_stats.flush_failed_resolve,
                    ptr->nbr_stats.flush_refresh, ptr->nbr_stats.mac_add_trig_resolve,
                    ptr->nbr_stats.mac_add_trig_refresh, ptr->nbr_stats.delay_trig_refresh, ptr->nbr_stats.refresh_for_more_flushes);
}

static nbr_mgr_nbr_stats gbl_nbr_stats;
static void nbr_mgr_dump_all_nbr_data_stats(nbr_data const * ptr) {
    gbl_nbr_stats.refresh_cnt += ptr->nbr_stats.refresh_cnt;
    gbl_nbr_stats.instant_refresh_cnt += ptr->nbr_stats.instant_refresh_cnt;
    gbl_nbr_stats.delay_refresh_cnt += ptr->nbr_stats.delay_refresh_cnt;
    gbl_nbr_stats.delay_resolve_cnt += ptr->nbr_stats.delay_resolve_cnt;
    gbl_nbr_stats.resolve_cnt += ptr->nbr_stats.resolve_cnt;
    gbl_nbr_stats.retry_cnt += ptr->nbr_stats.retry_cnt;
    gbl_nbr_stats.mac_not_present_cnt += ptr->nbr_stats.mac_not_present_cnt;
    gbl_nbr_stats.failed_trig_resolve_cnt += ptr->nbr_stats.failed_trig_resolve_cnt;
    gbl_nbr_stats.stale_trig_refresh_cnt += ptr->nbr_stats.stale_trig_refresh_cnt;
    gbl_nbr_stats.hw_mac_learn_refresh_cnt += ptr->nbr_stats.hw_mac_learn_refresh_cnt;
    gbl_nbr_stats.failed_handle_skip_oper_down += ptr->nbr_stats.failed_handle_skip_oper_down;
    gbl_nbr_stats.mac_trig_refresh += ptr->nbr_stats.mac_trig_refresh;
    gbl_nbr_stats.oper_down_mac_trig_instant_refresh+= ptr->nbr_stats.oper_down_mac_trig_instant_refresh;
    gbl_nbr_stats.flush_skip_refresh += ptr->nbr_stats.flush_skip_refresh;
    gbl_nbr_stats.flush_failed_resolve += ptr->nbr_stats.flush_failed_resolve;
    gbl_nbr_stats.flush_refresh += ptr->nbr_stats.flush_refresh;
    gbl_nbr_stats.delay_trig_refresh += ptr->nbr_stats.delay_trig_refresh;
    gbl_nbr_stats.refresh_for_more_flushes += ptr->nbr_stats.refresh_for_more_flushes;

}

void _nbr_mgr_dump_all_nbr_stats() {
    memset(&gbl_nbr_stats, 0, sizeof(gbl_nbr_stats));
    p_nbr_process_hdl->nbr_db_walk(nbr_mgr_dump_all_nbr_data_stats);
    NBR_MGR_LOG_ERR("DUMP", "All neighbor STATS refresh:%d instant refresh:%d delay refresh:%d delay resolve:%d resolve:%d "
                    "retry:%d mac_np:%d fail_trig:%d stale_ref:%d mac_lrn_ref:%d mac_trig_ref:%d mac_trig_ref_oper_skip:%d "
                    " mac_inst_trig_on_oper_down:%d"
                    " FLUSH skip:%d fail_resolve:%d refresh:%d delay-state-failed-resolve:%d refresh_for_more_flushes:%d",
                    gbl_nbr_stats.refresh_cnt, gbl_nbr_stats.instant_refresh_cnt, gbl_nbr_stats.delay_refresh_cnt,
                    gbl_nbr_stats.delay_resolve_cnt, gbl_nbr_stats.resolve_cnt,
                    gbl_nbr_stats.retry_cnt, gbl_nbr_stats.mac_not_present_cnt,
                    gbl_nbr_stats.failed_trig_resolve_cnt, gbl_nbr_stats.stale_trig_refresh_cnt,
                    gbl_nbr_stats.hw_mac_learn_refresh_cnt, gbl_nbr_stats.mac_trig_refresh,
                    gbl_nbr_stats.failed_handle_skip_oper_down,
                    gbl_nbr_stats.oper_down_mac_trig_instant_refresh,
                    gbl_nbr_stats.flush_skip_refresh, gbl_nbr_stats.flush_failed_resolve,
                    gbl_nbr_stats.flush_refresh, gbl_nbr_stats.delay_trig_refresh, gbl_nbr_stats.refresh_for_more_flushes);
}

void _nbr_mgr_dump_all_nbr_stats_clear(nbr_data const * ptr) {
    memset(&(ptr->nbr_stats), 0, sizeof(ptr->nbr_stats));
}

void nbr_mgr_dump_mac_data(mac_data_ptr ptr) {
    NBR_MGR_LOG_ERR("DUMP", "MAC entry MAC:%s, ifindex:%d, mbr_if_index:%d, FDB type:%d valid:%d learnt-first:%d "
                    " add-cnt:%d add-no-mbr-cnt:%d del-cnt:%d IP:%s",
                    ptr->get_mac_addr().c_str(), ptr->get_mac_intf(),
                    ptr->get_mac_phy_if(), static_cast<int>(ptr->get_fdb_type()), ptr->is_valid(),
                    ptr->get_mac_learnt_flag(), ptr->fdb_get_msg_cnt(true), ptr->fdb_get_msg_no_mbr_cnt(),
                    ptr->fdb_get_msg_cnt(false),
                    ((ptr->get_mac_remote_ip().af_index == HAL_INET4_FAMILY) ?
                     nbr_ip_addr_string (ptr->get_mac_remote_ip()).c_str() : ""));
}


void _nbr_mgr_dump_macs(nbr_mgr_dump_entry_t &dump) {
    if (p_nbr_process_hdl) {
        if (dump.if_index) {
            p_nbr_process_hdl->mac_if_db_walk(dump.if_index, nbr_mgr_dump_mac_data);
        } else {
            p_nbr_process_hdl->mac_db_walk(nbr_mgr_dump_mac_data);
        }
    }
}

void nbr_mgr_dump_intf_data(nbr_mgr_intf_entry_t intf) {
    NBR_MGR_LOG_ERR("DUMP", "Intf entry VRF-id:%d ifindex:%d, is_admin_up:%d, is_oper_up:%d VlanId:%d, "
                    "flags:0x%x hlayer VRF:%d if-index:%d",
                    intf.vrfid, intf.if_index, intf.is_admin_up, intf.is_oper_up, intf.vlan_id, intf.flags,
                    intf.parent_or_child_vrfid, intf.parent_or_child_if_index);
}

void _nbr_mgr_dump_intf(nbr_mgr_dump_entry_t &dump) {
    if (p_nbr_process_hdl == nullptr) return;

    if (dump.is_dump_all) {
        p_nbr_process_hdl->nbr_if_list_walk(nbr_mgr_dump_intf_data);
    } else {
        p_nbr_process_hdl->nbr_if_list_entry_walk(dump.vrf_id, dump.if_index, nbr_mgr_dump_intf_data);
    }
}

/* Dump global stats */
void _nbr_mgr_dump_stats() {
    if (p_nbr_process_hdl == nullptr) {
        printf("Process is not spawned");
        return;
    }
    p_nbr_process_hdl->nbr_mgr_dump_process_stats();
    _nbr_mgr_dump_all_nbr_stats();
}

/* Clears global stats */
void _nbr_mgr_stats_clear() {
    if (p_nbr_process_hdl) {
        memset(&(p_nbr_process_hdl->stats), 0, sizeof(nbr_mgr_stats));
        p_nbr_process_hdl->nbr_db_walk(_nbr_mgr_dump_all_nbr_stats_clear);
    }
}

void _nbr_mgr_dump_nbr_stats(nbr_mgr_dump_entry_t &dump) {
    if (p_nbr_process_hdl == nullptr) return;

    if (dump.is_dump_all) {
        p_nbr_process_hdl->nbr_db_walk(_nbr_mgr_dump_nbr_data_stats);
    } else {
        p_nbr_process_hdl->nbr_if_db_walk(dump.vrf_id, dump.if_index, _nbr_mgr_dump_nbr_data_stats);
    }
}

void _nbr_mgr_dump_nbr_stats_clear(nbr_mgr_dump_entry_t &dump) {
    if (p_nbr_process_hdl == nullptr) return;

    if (dump.is_dump_all) {
        p_nbr_process_hdl->nbr_db_walk(_nbr_mgr_dump_all_nbr_stats_clear);
    } else {
        p_nbr_process_hdl->nbr_if_db_walk(dump.vrf_id, dump.if_index, _nbr_mgr_dump_all_nbr_stats_clear);
    }
}

static void _nbr_mgr_dump_nbr_data(nbr_data const * ptr) {
    NBR_MGR_LOG_ERR("DUMP", "Neighbor VRF:%s(%d) family:%d Nbr:%s, MAC:%s, ifindex:%d, llayer-index:%d status:%s(0x%x)"
                    " flags:0x%x published:%d failed_cnt:%d retry_cnt:%d refresh_cnt:%d "
                    "refresh_cnt_for_mac_learn prev:%d curr:%d npu_prg_msg_cnt:%d last_status_pub:%s(%x)",
                    ptr->get_vrf_name().c_str(), ptr->get_vrf_id(), ptr->get_family(), ptr->get_ip_addr().c_str(),
                    ((ptr->get_mac_ptr()) ? ptr->get_mac_ptr()->get_mac_addr().c_str() : nullptr),
                    ptr->get_if_index(), ptr->get_parent_if_index(), nbr_mgr_nl_neigh_state_to_str (ptr->get_status()),
                    ptr->get_status(), ptr->get_flags(), ptr->get_published(),
                    ptr->get_failed_cnt(), ptr->get_retry_cnt(), ptr->get_refresh_cnt(),
                    ptr->get_prev_refresh_for_mac_learn_retry_cnt(),
                    ptr->get_refresh_for_mac_learn_retry_cnt(), ptr->nbr_stats.npu_prg_msg_cnt,
                    nbr_mgr_nl_neigh_state_to_str(ptr->get_last_pub_status()), ptr->get_last_pub_status());
    _nbr_mgr_dump_nbr_data_stats(ptr);
    if (p_nbr_process_hdl) {
        p_nbr_process_hdl->nbr_if_list_entry_walk(ptr->get_vrf_id(), ptr->get_if_index(), nbr_mgr_dump_intf_data);
        if (ptr->get_if_index() != ptr->get_parent_if_index()) {
            p_nbr_process_hdl->nbr_if_list_entry_walk(NBR_MGR_DEFAULT_VRF_ID, ptr->get_parent_if_index(), nbr_mgr_dump_intf_data);
        }
        try {
            std::string mac = ptr->get_mac_ptr()->get_mac_addr().c_str();
            nbr_mgr_dump_mac_data(p_nbr_process_hdl->mac_db_get(ptr->get_parent_if_index(), mac));
        } catch(std::invalid_argument& e) {
            NBR_MGR_LOG_ERR("DUMP", "MAC is not present");
        }
        p_nbr_process_hdl->nbr_mgr_dump_process_stats();
    }
}

static void _nbr_mgr_dump_nbr_ref(nbr_data_ptr &ptr) {
    NBR_MGR_LOG_ERR("DUMP", "Neighbor VRF:%s(%d) family:%d Nbr:%s, MAC:%s, ifindex:%d, llayer-index:%d status:%s(0x%x)"
                    " flags:0x%x published:%d failed_cnt:%d retry_cnt:%d refresh_cnt:%d "
                    "refresh_cnt_for_mac_learn prev:%d curr:%d npu_prg_msg_cnt:%d last_status_pub:%s(%x)",
                    ptr->get_vrf_name().c_str(), ptr->get_vrf_id(), ptr->get_family(), ptr->get_ip_addr().c_str(),
                    ((ptr->get_mac_ptr()) ? ptr->get_mac_ptr()->get_mac_addr().c_str() : nullptr),
                    ptr->get_if_index(), ptr->get_parent_if_index(), nbr_mgr_nl_neigh_state_to_str (ptr->get_status()),
                    ptr->get_status(), ptr->get_flags(), ptr->get_published(),
                    ptr->get_failed_cnt(), ptr->get_retry_cnt(), ptr->get_refresh_cnt(),
                    ptr->get_prev_refresh_for_mac_learn_retry_cnt(),
                    ptr->get_refresh_for_mac_learn_retry_cnt(), ptr->nbr_stats.npu_prg_msg_cnt,
                    nbr_mgr_nl_neigh_state_to_str(ptr->get_last_pub_status()), ptr->get_last_pub_status());
    _nbr_mgr_dump_nbr_data_ref_stats(ptr);
    if (p_nbr_process_hdl) {
        p_nbr_process_hdl->nbr_if_list_entry_walk(ptr->get_vrf_id(), ptr->get_if_index(), nbr_mgr_dump_intf_data);
        if (ptr->get_if_index() != ptr->get_parent_if_index()) {
            p_nbr_process_hdl->nbr_if_list_entry_walk(NBR_MGR_DEFAULT_VRF_ID, ptr->get_parent_if_index(), nbr_mgr_dump_intf_data);
        }
        try {
            std::string mac = ptr->get_mac_ptr()->get_mac_addr().c_str();
            nbr_mgr_dump_mac_data(p_nbr_process_hdl->mac_db_get(ptr->get_parent_if_index(), mac));
        } catch(std::invalid_argument& e) {
            NBR_MGR_LOG_ERR("DUMP", "MAC is not present");
        }
        p_nbr_process_hdl->nbr_mgr_dump_process_stats();
    }
}

void nbr_mgr_dump_all() {
    if (p_nbr_process_hdl == nullptr) return;

    p_nbr_process_hdl->nbr_db_walk(_nbr_mgr_dump_nbr_data);
    p_nbr_process_hdl->nbr_mgr_dump_process_stats();
    _nbr_mgr_dump_all_nbr_stats();
    p_nbr_process_hdl->nbr_db_walk(_nbr_mgr_dump_nbr_data_stats);
}

/* ARP/Neighbor dump, pass if-index 0 to dump all neighbors */
void _nbr_mgr_dump_nbrs(nbr_mgr_dump_entry_t &dump) {
    if (p_nbr_process_hdl == nullptr) return;

    if (dump.is_dump_all) {
        p_nbr_process_hdl->nbr_db_walk(_nbr_mgr_dump_nbr_data);
    } else {
        p_nbr_process_hdl->nbr_if_db_walk(dump.vrf_id, dump.if_index, _nbr_mgr_dump_nbr_data);
    }
}

inline std::string nbr_get_nbr_dump_key(hal_ifindex_t ifix, const std::string& ip) {
    return (std::to_string(ifix) + "-" + ip);
}

static void _nbr_mgr_dump_nbr(nbr_mgr_dump_entry_t &dump) {

    NBR_MGR_LOG_ERR("DUMP", "af:%d vrf-id:%d intf:%d Nbr:%s ", dump.af, dump.vrf_id,
                    dump.if_index, dump.nbr_ip);
    if (p_nbr_process_hdl == nullptr) {
        return;
    }

    std::string ip(dump.nbr_ip);
    std::string key = nbr_get_nbr_dump_key(dump.if_index, ip);

    try {
        nbr_ip_db_type& nbr_db = p_nbr_process_hdl->neighbor_db(dump.af);
        auto &ptr = p_nbr_process_hdl->nbr_db_get(nbr_db, dump.vrf_id, key);
        _nbr_mgr_dump_nbr_ref(ptr);

    } catch (std::invalid_argument& e){
        NBR_MGR_LOG_ERR("DUMP", "Nbr:%s does not exist! %s", dump.nbr_ip, e.what());
        return;
    }
}



bool nbr_process::nbr_proc_dump_msg(nbr_mgr_dump_entry_t& dump) {
    NBR_MGR_LOG_INFO("PROC", "DUMP AF:%d VRF-id:%d Nbr-ip:%s Intf:%d type:%d is_dump_all:%d",
                     dump.af, dump.vrf_id, dump.nbr_ip, dump.if_index, dump.type, dump.is_dump_all);

    switch(dump.type) {
        case NBR_MGR_DUMP_NBR:
            _nbr_mgr_dump_nbr(dump);
            break;
        case NBR_MGR_DUMP_NBRS:
            _nbr_mgr_dump_nbrs(dump);
            break;
        case NBR_MGR_DUMP_MACS:
            _nbr_mgr_dump_macs(dump);
            break;
        case NBR_MGR_DUMP_INTF:
            _nbr_mgr_dump_intf(dump);
            break;
        case NBR_MGR_DUMP_GBL_STATS:
            _nbr_mgr_dump_stats();
            break;
        case NBR_MGR_DUMP_GBL_STATS_CLEAR:
            _nbr_mgr_stats_clear();
            break;
        case NBR_MGR_DUMP_DETAIL_NBR_STATS:
            _nbr_mgr_dump_nbr_stats(dump);
            break;
        case NBR_MGR_DUMP_DETAIL_NBR_STATS_CLEAR:
            _nbr_mgr_dump_nbr_stats_clear(dump);
            break;
        default:
            break;

    }
    return true;
}

bool nbr_mgr_dump_info(nbr_mgr_dump_entry_t *dump) {
    nbr_mgr_msg_t *p_msg = nullptr;

    NBR_MGR_LOG_INFO ("NAS_DUMP","DUMP msg to be enqueued for type:%d vrf-id:%d if-index:%d is_dump_all:%d",
                      dump->type, dump->vrf_id, dump->if_index, dump->is_dump_all);
    nbr_mgr_msg_uptr_t p_msg_uptr = nbr_mgr_alloc_unique_msg(&p_msg);
    if (p_msg == NULL) {
        NBR_MGR_LOG_ERR ("NAS_DUMP","Memory alloc failed for NAS dump message");
        return false;
    }
    memset(p_msg, 0, sizeof(nbr_mgr_msg_t));
    p_msg->type = NBR_MGR_DUMP_MSG;
    memcpy(&p_msg->dump, dump, sizeof(nbr_mgr_dump_entry_t));

    nbr_mgr_enqueue_netlink_nas_msg(std::move(p_msg_uptr));
    return true;
}

/*
char *nbr_mgr_dump_help() {
    std::stringstream ss;
    ss << "nbr_mgr_dump_nbr(af,vrf_id,nbr_ip,if_index), nbr_mgr_dump_nbrs(vrf_id,if_index), \
        nbr_mgr_dump_mac(vrf_id,if_index), nbr_mgr_dump_intf(vrf_id, if_index), \
        nbr_mgr_dump_stats(), nbr_mgr_dump_stats_clear(), nbr_mgr_dump_nbr_stats(vrf_id, if_index), \
        nbr_mgr_dump_nbr_stats_clear(vrf_id,if_index)";
    return ss.str().c_str();
}
*/

/* Use the following functions for dumping the neighbor information and stats */
void nbr_mgr_dump_nbr(uint32_t af, uint32_t vrf_id, const char *nbr_ip, uint32_t if_index) {
    if (nbr_ip == nullptr) {
        return;
    }
    nbr_mgr_dump_entry_t dump;
    memset(&dump, 0, sizeof(dump));
    dump.af = af;
    dump.vrf_id = vrf_id;
    safestrncpy(dump.nbr_ip, nbr_ip, sizeof(dump.nbr_ip));
    dump.if_index = if_index;
    dump.type = NBR_MGR_DUMP_NBR;
    nbr_mgr_dump_info(&dump);
}
void nbr_mgr_dump_nbrs(bool is_dump_all, uint32_t vrf_id, uint32_t if_index) {
    nbr_mgr_dump_entry_t dump;
    memset(&dump, 0, sizeof(dump));
    dump.vrf_id = vrf_id;
    dump.if_index = if_index;
    dump.is_dump_all = is_dump_all;
    dump.type = NBR_MGR_DUMP_NBRS;
    nbr_mgr_dump_info(&dump);
}
void nbr_mgr_dump_mac(uint32_t if_index) {
    nbr_mgr_dump_entry_t dump;
    memset(&dump, 0, sizeof(dump));
    dump.if_index = if_index;
    dump.type = NBR_MGR_DUMP_MACS;
    nbr_mgr_dump_info(&dump);
}
void nbr_mgr_dump_intf(bool is_dump_all, uint32_t vrf_id, uint32_t if_index) {
    nbr_mgr_dump_entry_t dump;
    memset(&dump, 0, sizeof(dump));
    dump.vrf_id = vrf_id;
    dump.if_index = if_index;
    dump.is_dump_all = is_dump_all;
    dump.type = NBR_MGR_DUMP_INTF;
    nbr_mgr_dump_info(&dump);
}
void nbr_mgr_dump_stats() {
    nbr_mgr_dump_entry_t dump;
    memset(&dump, 0, sizeof(dump));
    dump.type = NBR_MGR_DUMP_GBL_STATS;
    nbr_mgr_dump_info(&dump);
}
void nbr_mgr_dump_stats_clear() {
    nbr_mgr_dump_entry_t dump;
    memset(&dump, 0, sizeof(dump));
    dump.type = NBR_MGR_DUMP_GBL_STATS_CLEAR;
    nbr_mgr_dump_info(&dump);
}
void nbr_mgr_dump_nbr_stats(bool is_dump_all, uint32_t vrf_id, uint32_t if_index) {
    nbr_mgr_dump_entry_t dump;
    memset(&dump, 0, sizeof(dump));
    dump.vrf_id = vrf_id;
    dump.if_index = if_index;
    dump.is_dump_all = is_dump_all;
    dump.type = NBR_MGR_DUMP_DETAIL_NBR_STATS;
    nbr_mgr_dump_info(&dump);
}
void nbr_mgr_dump_nbr_stats_clear(bool is_dump_all, uint32_t vrf_id, uint32_t if_index) {
    nbr_mgr_dump_entry_t dump;
    memset(&dump, 0, sizeof(dump));
    dump.vrf_id = vrf_id;
    dump.if_index = if_index;
    dump.is_dump_all = is_dump_all;
    dump.type = NBR_MGR_DUMP_DETAIL_NBR_STATS_CLEAR;
    nbr_mgr_dump_info(&dump);
}

