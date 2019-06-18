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
 * filename: nbr_mgr_cache.h
 *
 */

#ifndef _NBR_MGR_CACHE_H_
#define _NBR_MGR_CACHE_H_

#include "ds_common_types.h"
#include "std_type_defs.h"
#include "nbr_mgr_msgq.h"
#include "nbr_mgr_utils.h"

#include <memory>
#include <utility>
#include <thread>

#include <iostream>
#include <memory>
#include <string>
#include <set>
#include <unordered_set>
#include <unordered_map>
#include <map>
#include <utility>
#include <functional>


template<typename T>
class nbr_key {
public:
    nbr_key(hal_ifindex_t ifx, std::string& str) {
        k_ifdx = ifx;
        k_str  = str;
    }
    bool operator== (const nbr_key<T>& rhs) const
    {
        if (k_ifdx != rhs.k_ifdx || k_str != rhs.k_str) return false;
        else return true;
    }

    hal_ifindex_t k_ifdx=0;
    std::string   k_str="";
};

template<typename T>
class nbr_key_hash
{
public:
    inline std::size_t operator() (T const& src) const;
};

template<>
inline std::size_t nbr_key_hash<std::string>::operator() (std::string const& src) const {
    return std::hash<std::string>() (src);
}

template<>
inline std::size_t nbr_key_hash<int>::operator() (int const& src) const {
    return std::hash<uint_t>() (src);
}

// Forward declaration
class nbr_data;

using nbr_data_list = std::set<nbr_data const *>;
enum class FDB_TYPE: std::uint32_t { FDB_INCOMPLETE, FDB_LEARNED, FDB_IGNORE};
bool nbr_get_if_data(hal_vrf_id_t vrfid, hal_ifindex_t idx, nbr_mgr_intf_entry_t& intf);

typedef struct {
    uint32_t intf_add_msg_cnt;
    uint32_t intf_del_msg_cnt;
    uint32_t nbr_add_msg_cnt;
    uint32_t nbr_add_incomplete_msg_cnt;
    uint32_t nbr_add_reachable_msg_cnt;
    uint32_t nbr_add_stale_msg_cnt;
    uint32_t nbr_add_delay_msg_cnt;
    uint32_t nbr_add_probe_msg_cnt;
    uint32_t nbr_add_failed_msg_cnt;
    uint32_t nbr_add_permanaent_cnt;
    uint32_t nbr_del_msg_cnt;
    uint32_t nbr_rslv_add_msg_cnt;
    uint32_t nbr_rslv_del_msg_cnt;
    uint32_t fdb_add_msg_cnt;
    uint32_t fdb_del_msg_cnt;
    uint32_t flush_msg_cnt;
    uint32_t flush_trig_refresh_cnt;
    uint32_t flush_nbr_cnt;
}nbr_mgr_stats;

typedef struct {
    uint32_t retry_cnt;
    uint32_t mac_not_present_cnt;
    uint32_t failed_trig_resolve_cnt;
    uint32_t stale_trig_refresh_cnt;
    uint32_t resolve_cnt;
    uint32_t hw_mac_learn_refresh_cnt;
    uint32_t refresh_cnt;
    uint32_t instant_refresh_cnt;
    uint32_t delay_resolve_cnt;
    uint32_t delay_refresh_cnt;
    uint32_t flush_skip_refresh;
    uint32_t flush_failed_resolve;
    uint32_t flush_refresh;
    uint32_t mac_trig_refresh;
    uint32_t npu_prg_msg_cnt;
    uint32_t mac_add_trig_refresh;
    uint32_t mac_add_trig_resolve;
    uint32_t delay_trig_refresh;
    uint32_t oper_down_mac_trig_instant_refresh;
    uint32_t refresh_for_more_flushes;
    uint32_t failed_handle_skip_oper_down;
    uint32_t set_state_cnt;
}nbr_mgr_nbr_stats;

typedef struct {
    /* Auto refresh on stale state is enabled by default for both IPv4 and IPv6 neighbors */
    uint32_t ipv4_nbr_auto_refresh_status;
    uint32_t ipv6_nbr_auto_refresh_status;
} nbr_mgr_auto_refresh_t;

class mac_data {

public:
    mac_data(const nbr_mgr_nbr_entry_t& mac_entry);
    mac_data(const hal_mac_addr_t&, hal_ifindex_t);
    bool update_mac_addr(hal_mac_addr_t& src) { return true; }
    bool update_mac_addr(std::string& src) { return true; }
    void update_mac_if(hal_ifindex_t port) noexcept;
    void update_mac_remote_ip(const hal_ip_addr_t& ip) noexcept;
    const std::string& get_mac_addr() const { return m_mac_addr; }
    /* The member intf could be physical or port-channel in the VLAN */
    hal_ifindex_t get_mac_phy_if() noexcept { return m_mbr_index; }
    const hal_ip_addr_t& get_mac_remote_ip() noexcept { return m_ip_addr; }
    hal_ifindex_t get_mac_intf() noexcept { return m_if_index; }
    FDB_TYPE get_fdb_type() noexcept { return m_fdb_type; }

    ~mac_data() { };

    void nbr_list_add(nbr_data const* ptr) {
        nbr_list.insert(ptr);
    }

    void nbr_list_del(nbr_data const* ptr) {
        nbr_list.erase(ptr);
    }

    bool nbr_list_empty() const {
        return nbr_list.empty();
    }

    void set_mac_learnt_flag(bool val) noexcept {
        m_mac_learnt = val;
    }

    bool get_mac_learnt_flag() noexcept {
        return m_mac_learnt;
    }

    void set_fdb_type(FDB_TYPE ft) noexcept {
        m_fdb_type = ft;
    }

    void fdb_msg_cnt(bool is_add) noexcept {
        if (is_add) {
            m_fdb_add_cnt++;
        } else {
            m_fdb_del_cnt++;
        }
    }

    void fdb_add_msg_no_mbr_cnt() noexcept {
        m_fdb_add_no_mbr_cnt++;
    }

    uint32_t fdb_get_msg_no_mbr_cnt() noexcept {
        return m_fdb_add_no_mbr_cnt;
    }

    uint32_t fdb_get_msg_cnt(bool is_add) noexcept {
        if (is_add) {
            return m_fdb_add_cnt;
        }
        return m_fdb_del_cnt;
    }

    void fdb_set_1d_remote_mac_status(bool val) noexcept {
        m_is_1d_remote_mac = val;
    }

    uint32_t fdb_get_1d_remote_mac_status() noexcept {
        return m_is_1d_remote_mac;
    }
    void display() const;

    void for_each_nbr_list(std::function <void (nbr_data const *, std::string)> fn) {
        for (auto ix: nbr_list)
            fn(ix, m_mac_addr);
    }

    //Mac entry is valid if learned from kernel or belongs to a layer 3 physical intf
    bool is_valid() {
        if(m_fdb_type == FDB_TYPE::FDB_LEARNED ||
           m_fdb_type == FDB_TYPE::FDB_IGNORE) return true;
        nbr_mgr_intf_entry_t intf;
        if(nbr_get_if_data(NBR_MGR_DEFAULT_VRF_ID, m_if_index, intf) && !intf.is_bridge) return true;

        return false;
    }

private:

    std::string     m_mac_addr;
    hal_ifindex_t   m_if_index;
    hal_ifindex_t   m_mbr_index; /* VLAN member port - physical/LAG */
    FDB_TYPE        m_fdb_type = FDB_TYPE::FDB_INCOMPLETE;
    bool            m_mac_learnt = false; /* If the MAC is learnt in the kernel first time,
                                             it will be set to true after that
                                             it will not be re-set on MAC delete. */
    uint32_t        m_fdb_add_cnt = 0;
    uint32_t        m_fdb_add_no_mbr_cnt = 0;
    uint32_t        m_fdb_del_cnt = 0;
    bool            m_is_1d_remote_mac = false;
    hal_ip_addr_t   m_ip_addr; /* Store the IP for VXLAN remote MAC case. */

    //List of associated neighbor entries. Any change in mac info can trigger a walk of this list
    nbr_data_list   nbr_list;
};

using mac_data_ptr = std::shared_ptr<mac_data>;
bool nbr_list_if_update(hal_vrf_id_t vrf_id, hal_ifindex_t router_intf, hal_ifindex_t parent_intf, const nbr_data*, bool=true);

class nbr_data {

public:
    nbr_data(const nbr_mgr_nbr_entry_t& entry, std::shared_ptr<mac_data> ptr=nullptr):
        m_vrf_id(entry.vrfid), m_ip_addr(entry.nbr_addr), m_ifindex(entry.if_index), m_parent_if(entry.parent_if),
        m_status(entry.status), m_family(entry.family), m_vrf_name(entry.vrf_name), m_mac_data_ptr(ptr) {
        if (m_mac_data_ptr)
            m_mac_data_ptr->nbr_list_add(this);
        nbr_list_if_update(entry.vrfid, entry.if_index, entry.parent_if, this);
        m_failed_cnt = 0;
        memset(&nbr_stats, 0, sizeof(nbr_stats));
        display();
    }

    ~nbr_data() {
        if (m_mac_data_ptr)
            m_mac_data_ptr->nbr_list_del(this);
        nbr_list_if_update(m_vrf_id, m_ifindex, m_parent_if, this, false);
    }

    void set_status(uint8_t status) { };
    void set_owner(uint32_t owner) { };
    /* This refresh count is incremented when the nbr is in
     * process of refreshing nbr and the flush is received for
     * this nbr associated VLAN */
    void set_refresh_cnt() { m_refresh_cnt++; };
    void reset_refresh_cnt() { m_refresh_cnt=0; };

    uint16_t get_family() const {
        return m_family;
    }

    void set_flags(uint32_t flags) {
        m_flags |= flags;
    }

    uint32_t get_flags() const {
        return m_flags;
    }

    uint32_t get_status() const {
        return m_status;
    }

    uint32_t get_last_pub_status() const {
        return m_last_status_published;
    }

    std::string get_ip_addr() const {
        return nbr_ip_addr_string(m_ip_addr);
    }

    hal_vrf_id_t get_vrf_id() const {
        return m_vrf_id;
    }

    std::string get_vrf_name() const {
        return m_vrf_name;
    }

    hal_ifindex_t get_if_index() const {
        return m_ifindex;
    }

    hal_ifindex_t get_parent_if_index() const {
        return m_parent_if;
    }

    hal_ifindex_t get_published() const {
        return m_published;
    }

    uint32_t get_failed_cnt() const {
        return m_failed_cnt;
    }

    uint32_t get_retry_cnt() const {
        return m_retry_cnt;
    }

    uint32_t get_refresh_cnt() const {
        return m_refresh_cnt;
    }

    uint32_t get_refresh_for_mac_learn_retry_cnt() const {
        return m_refresh_for_mac_learn_retry_cnt;
    }
    uint32_t get_prev_refresh_for_mac_learn_retry_cnt() const {
        return m_prev_refresh_for_mac_learn_retry_cnt;
    }

    bool trigger_resolve() const;
    bool trigger_refresh(bool track_refresh = true) const;
    bool trigger_instant_refresh() const;
    bool trigger_delay_resolve() const;
    bool trigger_delay_refresh() const;
    bool trigger_refresh_for_mac_learn() const;
    bool trigger_set_nbr_state(uint32_t state) const;
    bool publish_entry(nbr_mgr_op_t op, const nbr_mgr_nbr_entry_t&) const;
    void populate_nbr_entry(nbr_mgr_nbr_entry_t& entry) const;

    void display() const;
    bool process_nbr_data(nbr_mgr_nbr_entry_t& entry);

    bool handle_fdb_change(nbr_mgr_evt_type_t, unsigned long status, bool is_mac_moved) const;
    bool handle_if_state_change(nbr_mgr_intf_entry_t&);
    bool handle_mac_change(nbr_mgr_nbr_entry_t& entry);

    const mac_data_ptr& get_mac_ptr() const noexcept {
        return m_mac_data_ptr;
    }

    void reset_mac_ptr() noexcept {
        m_mac_data_ptr = nullptr;
    }

    void update_mac_ptr(std::shared_ptr<mac_data> ptr) noexcept {
        m_mac_data_ptr = ptr;
        m_mac_data_ptr->nbr_list_add(this);
    }

    void delete_mac_ptr() noexcept {
        if (m_mac_data_ptr) {
            m_mac_data_ptr->nbr_list_del(this);
        }
    }
    /* Neighbor statistics */
    mutable nbr_mgr_nbr_stats nbr_stats;

private:
    hal_vrf_id_t   m_vrf_id;
    hal_ip_addr_t  m_ip_addr;
    hal_ifindex_t  m_ifindex;
    hal_ifindex_t  m_parent_if;
    uint8_t        m_status = 0;
    uint32_t       m_owner = 0;
    uint16_t       m_family;
    mutable uint32_t m_flags = 0;
    mutable bool   m_published = false;
    mutable uint8_t m_last_status_published = 0;
    mutable bool   m_del_published = false;
    uint8_t        m_failed_cnt = 0; /* This helps to resolve
                                        the nbr atleast few times
                                        before give up */
    mutable uint8_t m_retry_cnt = 0; /* This helps to refresh
                                        the nbr atleast few times
                                        to learn the MAC before give up */
    uint32_t m_refresh_cnt = 0; /* This tracks the no. of refreshes being
                                        triggered so as to trigger the refresh again
                                        when the current refresh in progress is done */
    uint8_t m_refresh_for_mac_learn_retry_cnt = 0; /* This helps to refresh
                                        the nbr atleast few times
                                        to learn the MAC in the HW before give up */
    uint8_t m_prev_refresh_for_mac_learn_retry_cnt = 0; /* This helps for the statistics */
    std::string     m_vrf_name = "default";

    //Each neighbor object contains a pointer to its associated mac data object
    std::shared_ptr<mac_data> m_mac_data_ptr;
};

using nbr_data_ptr = std::unique_ptr<nbr_data>;
using nbr_ip_list = std::unordered_map<std::string, nbr_data_ptr, nbr_key_hash<std::string>>;
using nbr_ip_db_type = std::unordered_map<hal_vrf_id_t, nbr_ip_list>;
using nbr_ip_db_iter = nbr_ip_db_type::iterator;
using nbr_mac_list = std::unordered_map<std::string, mac_data_ptr, nbr_key_hash<std::string>>;
using nbr_mac_db_type = std::unordered_map<hal_ifindex_t, nbr_mac_list>;
using nbr_mac_db_iter = nbr_mac_db_type::iterator;
// IF based neighbor cache
using nbr_if_nbr_list = std::unordered_map<hal_ifindex_t, nbr_data_list, nbr_key_hash<int>>;
// INTF cache
using nbr_if_list = std::unordered_map<hal_ifindex_t, nbr_mgr_intf_entry_t, nbr_key_hash<int>>;

class nbr_process {

public:
    nbr_process() { memset(&stats, 0, sizeof(stats));};

    //Prevent copy construction and assignment operations
    nbr_process(const nbr_process& src) = delete;
    nbr_process& operator= (const nbr_process& rhs) = delete;

    //FDB related functions
    bool nbr_proc_fdb_msg(const nbr_mgr_nbr_entry_t&);
    mac_data_ptr create_mac_instance(std::string&, const nbr_mgr_nbr_entry_t&);
    mac_data_ptr create_mac_instance(std::string&, const hal_mac_addr_t&, hal_ifindex_t);
    bool delete_mac_instance(const std::string&, hal_ifindex_t);
    bool delete_mac_instance(const hal_mac_addr_t&, hal_ifindex_t);

    mac_data_ptr mac_db_get(hal_ifindex_t, std::string&);
    mac_data_ptr mac_db_get(hal_ifindex_t, const hal_mac_addr_t&);
    mac_data_ptr mac_db_get_w_create(hal_ifindex_t, const hal_mac_addr_t&);
    mac_data_ptr mac_db_update(hal_ifindex_t, std::string&, mac_data_ptr&);
    bool mac_db_remove(hal_ifindex_t, const std::string&);
    void mac_if_db_walk(hal_ifindex_t, std::function <void (mac_data_ptr )> fn);
    void mac_db_walk(std::function <void (mac_data_ptr )> fn);

    //Intf related functions
    bool nbr_proc_intf_msg(nbr_mgr_intf_entry_t& intf);
    bool nbr_update_intf_info(nbr_mgr_intf_entry_t& intf);
    bool nbr_proc_flush_msg(nbr_mgr_flush_entry_t& flush);
    bool nbr_list_if_add(hal_vrf_id_t, hal_ifindex_t, const nbr_data*);
    bool nbr_list_if_del(hal_vrf_id_t, hal_ifindex_t, const nbr_data*);
    bool nbr_proc_dump_msg(nbr_mgr_dump_entry_t& dump);
    void nbr_if_list_entry_walk(hal_vrf_id_t vrf_id, hal_ifindex_t,
                                std::function <void (nbr_mgr_intf_entry_t )> fn);
    void nbr_if_list_walk(std::function <void (nbr_mgr_intf_entry_t )> fn);

    //ARP/ND related functions
    bool nbr_proc_nbr_msg(nbr_mgr_nbr_entry_t&);
    nbr_data_ptr& create_nbr_instance(nbr_ip_db_type&, std::string&, const nbr_mgr_nbr_entry_t&);
    bool delete_nbr_instance(nbr_ip_db_type&, hal_vrf_id_t, std::string);
    nbr_data_ptr& nbr_db_get(nbr_ip_db_type&, hal_vrf_id_t, std::string&);
    nbr_data_ptr& nbr_db_get_w_create(const nbr_mgr_nbr_entry_t&);
    nbr_data_ptr& nbr_db_update(nbr_ip_db_type&,
                                hal_vrf_id_t, std::string&, std::unique_ptr<nbr_data>& );
    bool nbr_db_remove(nbr_ip_db_type&, hal_vrf_id_t, std::string&);

    void nbr_if_db_walk(hal_vrf_id_t, hal_ifindex_t, std::function <void (nbr_data const *)> fn);

    nbr_ip_db_type& neighbor_db(unsigned short) noexcept;

    void nbr_db4_walk(std::function <void (nbr_data const *)> fn, hal_vrf_id_t vrf=0);
    void nbr_db6_walk(std::function <void (nbr_data const *)> fn, hal_vrf_id_t vrf=0);

    void nbr_db_walk(std::function <void (nbr_data const *)> fn);
    void nbr_mgr_dump_process_stats();
    /* Neighbor Stats */
    nbr_mgr_stats stats;

protected:
    //Process thread main function
    friend void nbr_proc_thread_main(void *ctx);

    friend bool nbr_list_if_update(hal_vrf_id_t vrfid, hal_ifindex_t router_intf, hal_ifindex_t parent_intf,
                                   const nbr_data*, bool);

    friend bool nbr_get_if_data(hal_vrf_id_t, hal_ifindex_t idx, nbr_mgr_intf_entry_t& intf);

private:
    // Function running in background to process neigbhor entries
    void process_nbr_entries(void);

    std::thread m_thread;

    // MAC cache
    std::unordered_map<hal_ifindex_t, nbr_mac_list> mac_db;

    // IPv4 neighbor(ARP) cache
    std::unordered_map<hal_vrf_id_t, nbr_ip_list> neighbor_db4;

    // IPv6 neighbor cache
    std::unordered_map<hal_vrf_id_t, nbr_ip_list> neighbor_db6;

    // IF based neighbor cache
    std::unordered_map<hal_vrf_id_t, nbr_if_nbr_list> neighbor_if_nbr_db;

    // INTF cache
    std::unordered_map<hal_vrf_id_t, nbr_if_list> neighbor_if_db;
};

#endif
