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
 * filename: nbr_mgr_msgq.cpp
 */

#include "nbr_mgr_main.h"
#include "nbr_mgr_msgq.h"
#include "nbr_mgr_log.h"
#include <unistd.h>

#include <sstream>

nbr_mgr_msgq_handle_t p_msgq_nl_nas_msg_hdl; /* This Q handles the message
                                                        from netlink (kernel) and NAS-L3 */
nbr_mgr_msgq_handle_t p_msgq_burst_rslv_hdl; /* This Q handles the Nbr to be resolved/refreshed
                                                      in a burst every x(say. 1) second*/
nbr_mgr_msgq_handle_t p_msgq_delay_rslv_hdl; /* This Q handles the Nbr to be resolved after
                                                      some time (say. 20 secs) to control the DoS attack
                                                      after N (say. 5, each try 5x2 = 10 secs, after ~50 secs of retries)
                                                      of ARP resolution attempts */

bool nbr_mgr_msgq_create ()
{
    /* This Q handles the message from netlink (kernel) and NAS-L3 */
    p_msgq_nl_nas_msg_hdl = new (std::nothrow) nbr_mgr_msgq_t;
    if (!p_msgq_nl_nas_msg_hdl) {
        return false;
    }
    /* This Q handles the Nbr to be resolved/refreshed
     * in a burst every x(say. 1) second to avoid the tap intf. tx buffer overflow */
    p_msgq_burst_rslv_hdl = new (std::nothrow) nbr_mgr_msgq_t;
    if (!p_msgq_burst_rslv_hdl) {
        delete p_msgq_nl_nas_msg_hdl;
        return false;
    }
    /* This Q handles the Nbr to be resolved after some time (say. 20 secs)
     * to control the DoS attack after N (say. 5, each try 5x2 = 10 secs,
     * after ~50 secs of retries) of ARP resolution attempts */
    p_msgq_delay_rslv_hdl = new (std::nothrow) nbr_mgr_msgq_t;
    if (!p_msgq_delay_rslv_hdl) {
        delete p_msgq_burst_rslv_hdl;
        delete p_msgq_nl_nas_msg_hdl;
        return false;
    }
    return true;
}

nbr_mgr_msg_uptr_t nbr_mgr_msgq_t::dequeue ()
{
    std::unique_lock<std::mutex> l {m_mtx};
    /* If the message queue is empty, wait */
    if (m_msgq.empty()) {
        m_data.wait (l, [&] {return !m_msgq.empty();});
    }
    /* Move the message ownership from msgq*/
    auto ret = std::move (m_msgq.front());
    m_msgq.pop_front ();
    return ret;
}

bool nbr_mgr_msgq_t::enqueue (nbr_mgr_msg_uptr_t msg)
{
    bool wake =  false;
    {
        std::lock_guard<std::mutex> l {m_mtx};
        /* If the message queue is empty, push the message back and
         * wakeup the receiving thread to read the message from the queue */
        wake = m_msgq.empty();
        /* Move the unique pointer ownership to message queue */
        m_msgq.push_back(std::move (msg));
        /* set the peak count (no. of messages present in the queue for pending processing) of the queue */
        if (m_high < m_msgq.size()) m_high = m_msgq.size();
    }
    /* Signal the message receiving thread to process the message from the queue */
    if (wake) m_data.notify_one ();
    return true;
}

std::string nbr_mgr_msgq_t::queue_stats ()
{
    std::lock_guard<std::mutex> l {m_mtx};
    std::stringstream ss;
    ss << "Current:" << m_msgq.size() << "Peak:" << m_high;
    return ss.str();
}

std::string nbr_mgr_netlink_q_stats() {
    return (p_msgq_nl_nas_msg_hdl->queue_stats());
}

bool nbr_mgr_enqueue_netlink_nas_msg(nbr_mgr_msg_uptr_t msg)
{
    return (p_msgq_nl_nas_msg_hdl->enqueue(std::move(msg)));
}

nbr_mgr_msg_uptr_t nbr_mgr_dequeue_netlink_nas_msg ()
{
    return (p_msgq_nl_nas_msg_hdl->dequeue());
}

bool nbr_mgr_enqueue_burst_resolve_msg(nbr_mgr_msg_uptr_t msg)
{
    return (p_msgq_burst_rslv_hdl->enqueue(std::move(msg)));
}

bool nbr_mgr_enqueue_delay_resolve_msg(nbr_mgr_msg_uptr_t msg)
{
    return (p_msgq_delay_rslv_hdl->enqueue(std::move(msg)));
}

bool nbr_mgr_process_burst_resolve_msg(burst_resolvefunc callbk_func) {
    static uint32_t resolve_cnt = 0;
    return (nbr_mgr_dequeue_and_handle_burst_resolve_msg(p_msgq_burst_rslv_hdl, callbk_func,
                                                         NBR_MGR_BURST_RESOLVE_DELAY, &resolve_cnt));
}

bool nbr_mgr_process_delay_resolve_msg(burst_resolvefunc callbk_func) {
    static uint32_t delay_resolve_cnt = 0;
    return (nbr_mgr_dequeue_and_handle_burst_resolve_msg(p_msgq_delay_rslv_hdl, callbk_func,
                                                         NBR_MGR_DELAY_BURST_RESOLVE_DELAY, &delay_resolve_cnt));
}

bool nbr_mgr_dequeue_and_handle_burst_resolve_msg(nbr_mgr_msgq_t *hdl, burst_resolvefunc callbk_func,
                                                  uint32_t burst_delay, uint32_t *resolve_cnt)
{
    nbr_mgr_msg_uptr_t uptr;
    {
        std::unique_lock<std::mutex> l {hdl->m_mtx};
        /* If the message queue is empty, wait */
        if (hdl->m_msgq.empty()) {
            if (burst_delay == NBR_MGR_BURST_RESOLVE_DELAY)
                *resolve_cnt = 0;
            hdl->m_data.wait (l, [&] {return !hdl->m_msgq.empty();});
        }
        /* Move the message ownership from msgq*/
        uptr = std::move (hdl->m_msgq.front());
        hdl->m_msgq.pop_front ();
    }
    if (uptr)
    {
        callbk_func(uptr.get());
        (*resolve_cnt)++;
    }

    if (*resolve_cnt > NBR_MGR_BURST_RESOLVE_CNT) {
        /* Once the max. threshold count reached, wait for few sec(s).
         * to avoid the kernel load with lot of nbr resolve/refresh messages,
         * also NPU CPU-Q Rx rate is 400 PPS for ARP reply, if we send more than
         * 400 ARP requests per second, we will get more than 400 ARP replies
         * from the peer but only 400 ARP replies will be lifted to CPU,
         * so, we will end up re-transmitting the ARP requests for the missed ARP replies */
        sleep(burst_delay);
        *resolve_cnt = 0;
    }
    return true;
}


