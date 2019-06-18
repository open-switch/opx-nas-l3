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
 * filename: hal_rt_intf_util.c
 */
#include "hal_rt_util.h"
#include "nas_rt_api.h"
#include "std_utils.h"

const char *hal_rt_intf_mode_to_str (uint32_t mode) {

    if (mode == BASE_IF_MODE_MODE_NONE)
        return "None";
    else if (mode == BASE_IF_MODE_MODE_L2)
        return "L2";
    else if (mode == BASE_IF_MODE_MODE_L2HYBRID)
        return "L2HYBRID";
    else if (mode == BASE_IF_MODE_MODE_L3)
        return "L3";
    else if (mode == BASE_IF_MODE_MODE_L2DISABLED)
        return "L2DISABLED";
    else
        return "Unknown";
}

const char *hal_rt_intf_admin_status_to_str (uint32_t admin) {

    if (admin == RT_INTF_ADMIN_STATUS_NONE)
        return "None";
    else if (admin == RT_INTF_ADMIN_STATUS_UP)
        return "Up";
    else if (admin == RT_INTF_ADMIN_STATUS_DOWN)
        return "Down";
    else
        return "Unknown";
}


int fib_nbr_del_on_intf_down (int if_index, int vrf_id, int af_index) {
    t_fib_nh       *p_fh = NULL;
    t_fib_nh_holder nh_holder;
    t_fib_intf  *p_intf = NULL;

    HAL_RT_LOG_INFO ("HAL-RT-NBR", "Admin status if_index: %d, vrf_id: %d, af_index: %d",
                     if_index, vrf_id, af_index);
    /* Get the L3 interface and delete all the associated routes*/
    p_intf = fib_get_intf (if_index, vrf_id, af_index);
    if (p_intf == NULL) {
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    /* Loop for all the FH and associated routes for deletion */
    FIB_FOR_EACH_FH_FROM_INTF (p_intf, p_fh, nh_holder) {
        fib_proc_nh_delete (p_fh, FIB_NH_OWNER_TYPE_ARP, 0);
    }
    return STD_ERR_OK;
}

int fib_process_route_add_on_intf_event (t_fib_intf *p_intf, t_fib_intf_event_type intf_event) {

    t_fib_nh       *p_fh = NULL, *p_nh = NULL;
    t_fib_nh_holder nh_holder, nh_holder1;
    t_fib_nh_dep_dr   *p_nh_dep_dr = NULL;
    t_fib_dr *p_add_dr = NULL;
    bool is_fib_route_add = false;

    /* Loop for all the FH and associated routes for download */
    FIB_FOR_EACH_FH_FROM_INTF (p_intf, p_fh, nh_holder) {
        p_nh_dep_dr = fib_get_first_nh_dep_dr (p_fh);
        while (p_nh_dep_dr != NULL) {
            if (p_nh_dep_dr->p_dr == NULL) {
                p_nh_dep_dr = fib_get_next_nh_dep_dr (p_fh, p_nh_dep_dr->key.vrf_id,
                                                      &p_nh_dep_dr->key.dr_key.prefix,
                                                      p_nh_dep_dr->prefix_len);
                continue;
            }
            /* Init the FIB route add to true first,
             * if there aren't any valid path found in the ECMP,
             * then don't add the FIB route
             */
            is_fib_route_add = true;

            HAL_RT_LOG_DEBUG("HAL-RT-DR-ADD",
                             "DR: vrf_id: %d, prefix: %s, prefix_len: %d, rt_type: %d, "
                             "Dep NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x status:0x%x",
                             p_nh_dep_dr->p_dr->vrf_id,
                             FIB_IP_ADDR_TO_STR (&p_nh_dep_dr->p_dr->key.prefix),
                             p_nh_dep_dr->p_dr->prefix_len, p_nh_dep_dr->p_dr->rt_type,
                             p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                             p_fh->key.if_index, p_fh->status_flag);
            /* If all the multipaths are dead for the ECMP route, delete the route, otherwise continue for next route */
            if (p_nh_dep_dr->p_dr->num_nh > 1) {
                FIB_FOR_EACH_NH_FROM_DR (p_nh_dep_dr->p_dr, p_nh, nh_holder1)
                {
                    HAL_RT_LOG_DEBUG("HAL-RT-DR-ADD",
                                     "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
                                     "Dep NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x status:0x%x is_nh_dead:%s",
                                     p_nh_dep_dr->p_dr->vrf_id,
                                     FIB_IP_ADDR_TO_STR (&p_nh_dep_dr->p_dr->key.prefix),
                                     p_nh_dep_dr->p_dr->prefix_len, p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                                     p_nh->key.if_index, p_nh->status_flag,
                                     ((p_nh->status_flag & FIB_NH_STATUS_DEAD) ? "yes": "no"));
                    if (!(p_nh->status_flag & FIB_NH_STATUS_DEAD)) {
                        is_fib_route_add = true;
                        break;
                    }
                    /* Valid NH is not found, dont add the ECMP route */
                    is_fib_route_add = false;
                }
            }
            /* copy the route to be deleted and then get the next dependent dr,
             * to avoid accessing the invalid dep-dr after route deletion */
            p_add_dr = p_nh_dep_dr->p_dr;
            p_nh_dep_dr = fib_get_next_nh_dep_dr (p_fh, p_nh_dep_dr->key.vrf_id,
                                                  &p_nh_dep_dr->key.dr_key.prefix,
                                                  p_nh_dep_dr->prefix_len);
            /* Dont delete the link local route on admin down,
             * wait for explicit route del from kernel thru netlink
             * The reason - let's say LAG(bond) has only one member and
             * upon removing the bond member, bond admin down
             * and then bond admin up is received from the NAS-linux
             * though the bond is intact with link local address, to avoid this issue,
             * link local route is deleted on explicit route del from kernel */

            if (is_fib_route_add && p_add_dr &&
                !(STD_IP_IS_ADDR_LINK_LOCAL(&p_add_dr->key.prefix))) {

                /* @@TODO - kerel specific event handling.
                 * on admin up, kernel notifies of ROUTE events for
                 * /prefix-length and the full length routes (for the address)
                 * are not notified again. They are notified only during
                 * IP address assignment.
                 * Hence on admin down, local routes will only be deleted from NPU
                 * and retained in nas. They will be configured in NPU again on
                 * admin UP. So don't set FIB_DR_STATUS_DEL for RT_LOCAL routes.
                 */
                /* if event is mode change to L3, then reprogram
                 * all routes from cache to NPU, irrespective of rt_type.
                 */
                if ((intf_event == FIB_INTF_MODE_CHANGE_EVENT) || (p_add_dr->rt_type == RT_LOCAL)) {
                    p_add_dr->status_flag &= ~FIB_DR_STATUS_DEL;
                    HAL_RT_LOG_INFO ("HAL-RT-DR-ADD",
                                     "Intf event: %d, DR: vrf_id: %d, prefix: %s, prefix_len: %d, rt_type: %d ",
                                     intf_event, p_add_dr->vrf_id,
                                     FIB_IP_ADDR_TO_STR (&p_add_dr->key.prefix),
                                     p_add_dr->prefix_len, p_add_dr->rt_type);

                    /* set ADD flag to trigger route download to walker */
                    p_add_dr->status_flag |= FIB_DR_STATUS_ADD;
                    fib_mark_dr_for_resolution (p_add_dr);
                }
            }
        }
    }
    return STD_ERR_OK;
}

int fib_process_link_local_address_add_on_intf_event (t_fib_intf *p_intf, t_fib_intf_event_type intf_event) {

    t_fib_dr         *p_add_dr = NULL;
    t_fib_ip_addr    *p_temp_ip = NULL;
    t_fib_ip_holder   ip_holder;
    hal_ifindex_t     if_index;

    if (!p_intf)
    {
        HAL_RT_LOG_ERR("HAL-RT-LLA-ADD", "Invalid input param");
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    /* if mode is not L3, then link local routes
     * should not be programmed to NDI.
     */
    if (!FIB_IS_INTF_MODE_L3 (p_intf->mode)) {
        return STD_ERR_OK;
    }

    if_index = p_intf->key.if_index;

    FIB_FOR_EACH_IP_FROM_INTF (p_intf, p_temp_ip, ip_holder)
    {
        HAL_RT_LOG_INFO("HAL-RT-LLA-ADD", "vrf:%d, if_index:%d, ip_addr: %s, RIF-ref-cnt:%d",
                        p_intf->key.vrf_id, if_index,
                        FIB_IP_ADDR_TO_STR (p_temp_ip),
                        hal_rt_rif_ref_get(p_intf->key.vrf_id, if_index));

        if (!STD_IP_IS_ADDR_LINK_LOCAL(p_temp_ip)) {
            continue;
        }

        p_add_dr = fib_get_dr (p_intf->key.vrf_id, p_temp_ip, HAL_RT_V6_PREFIX_LEN);

        if (!p_add_dr) {
            continue;
        }
        HAL_RT_LOG_INFO ("HAL-RT-LLA-ADD",
                         "Intf event: %d, DR: vrf_id: %d, prefix: %s/%d, "
                         "link_local_cnt: %d, RIF link_local_cnt: %d  rt_type: %d ",
                         intf_event, p_add_dr->vrf_id,
                         FIB_IP_ADDR_TO_STR (&p_add_dr->key.prefix),
                         p_add_dr->prefix_len, p_add_dr->num_ipv6_link_local,
                         p_add_dr->num_ipv6_rif_link_local, p_add_dr->rt_type);

        /* if num_ipv6_rif_link_local is > 1, then there are multiple interfaces
         * using same link local route.
         * so DR num_rif_ipv6_link_local value 1 indicates this is the only
         * interface on which this link local route
         * is configured; hence configure the LLA in NDI.
         */
        ndi_rif_id_t rif_id = 0;
        if (hal_rif_index_get_or_create(0, p_add_dr->vrf_id, if_index, &rif_id) == STD_ERR_OK) {
            hal_rt_rif_ref_inc(p_add_dr->vrf_id, if_index);
            p_add_dr->num_ipv6_rif_link_local++;
        } else {
            HAL_RT_LOG_ERR("HAL-RT-LLA-ADD", " RIF get failed for Route add vrf_id: %d, prefix: %s/%d,"
                           " proto: %d out-if:%d link-local-cnt:%d RIF-ref-cnt:%d",
                           p_add_dr->vrf_id, FIB_IP_ADDR_TO_STR (&p_add_dr->key.prefix),
                           p_add_dr->prefix_len, p_add_dr->proto, if_index,
                           p_add_dr->num_ipv6_link_local, hal_rt_rif_ref_get(p_intf->key.vrf_id, if_index));
        }

        if (p_add_dr->num_ipv6_rif_link_local > 1) {
            continue;
        }

        /* For interface mode change event,
         * add link local route from cache to NDI.
         */
        p_add_dr->status_flag &= ~FIB_DR_STATUS_DEL;
        HAL_RT_LOG_INFO ("HAL-RT-LLA-ADD",
                         "DR: vrf_id: %d, prefix: %s/%d, "
                         "link_local_cnt: %d, RIF link_local_cnt: %d",
                         p_add_dr->vrf_id,
                         FIB_IP_ADDR_TO_STR (&p_add_dr->key.prefix),
                         p_add_dr->prefix_len, p_add_dr->num_ipv6_link_local,
                         p_add_dr->num_ipv6_rif_link_local);

        /* set ADD flag to trigger route download to walker */
        p_add_dr->status_flag |= FIB_DR_STATUS_ADD;
        fib_mark_dr_for_resolution (p_add_dr);
    }
    return STD_ERR_OK;
}

int fib_process_nh_add_on_intf_event (t_fib_intf *p_intf, t_fib_intf_event_type intf_event) {

    t_fib_nh       *p_fh = NULL;
    t_fib_nh_holder nh_holder;

    /* Loop for all the FH associated on that interface */
    FIB_FOR_EACH_FH_FROM_INTF (p_intf, p_fh, nh_holder) {
        p_fh->status_flag &= ~FIB_NH_STATUS_DEAD;

        HAL_RT_LOG_INFO ("HAL-RT-NH-ADD",
                         "vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                         "owner_flag: 0x%x, status_flag: 0x%x",
                         p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                         p_fh->key.if_index, p_fh->owner_flag, p_fh->status_flag);

        if (hal_rt_is_local_ip_conflict (p_fh->vrf_id, &p_fh->key.ip_addr)) {
            continue;
        }

        /* restore this NH only if its not already marked for deletion */
        if (!(p_fh->status_flag & FIB_NH_STATUS_DEL)) {
            /* For admin event and L2 mode change event,
             * reset the FIB_NH_STATUS_DEAD flag and
             * restore all NH retained in cache.
             */
            p_fh->status_flag |= FIB_NH_STATUS_ADD;

            fib_mark_nh_for_resolution (p_fh);
        }
    }

    return STD_ERR_OK;
}

int fib_route_add_on_intf_up (t_fib_intf *p_intf) {
    return (fib_process_route_add_on_intf_event (p_intf, FIB_INTF_ADMIN_EVENT));
}

int fib_process_route_del_on_intf_event (t_fib_intf *p_intf, t_fib_intf_event_type intf_event) {

    t_fib_nh       *p_fh = NULL, *p_nh = NULL;
    t_fib_nh_holder nh_holder, nh_holder1;
    t_fib_nh_dep_dr   *p_nh_dep_dr = NULL;
    t_fib_dr_nh       *p_dr_nh = NULL;
    t_fib_dr *p_del_dr = NULL;
    bool is_fib_route_del = true;

    /* Loop for all the FH and associated routes for deletion */
    FIB_FOR_EACH_FH_FROM_INTF (p_intf, p_fh, nh_holder) {
        p_fh->status_flag |= FIB_NH_STATUS_DEAD;
        p_nh_dep_dr = fib_get_first_nh_dep_dr (p_fh);
        while (p_nh_dep_dr != NULL) {
            if (p_nh_dep_dr->p_dr == NULL) {
                p_nh_dep_dr = fib_get_next_nh_dep_dr (p_fh, p_nh_dep_dr->key.vrf_id,
                                                      &p_nh_dep_dr->key.dr_key.prefix,
                                                      p_nh_dep_dr->prefix_len);
                continue;
            }
            /* Init the FIB route del to true first, if any valid path found in the ECMP, dont delete the FIB route */
            is_fib_route_del = true;
            HAL_RT_LOG_DEBUG("HAL-RT-DR-DEL",
                             "DR: vrf_id: %d, prefix: %s, prefix_len: %d, rt_type: %d, "
                             "Dep NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x status:0x%x",
                             p_nh_dep_dr->p_dr->vrf_id,
                             FIB_IP_ADDR_TO_STR (&p_nh_dep_dr->p_dr->key.prefix),
                             p_nh_dep_dr->p_dr->prefix_len, p_nh_dep_dr->p_dr->rt_type,
                             p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                             p_fh->key.if_index, p_fh->status_flag);
            /* If all the multipaths are dead for the ECMP route, delete the route, otherwise continue for next route */
            if (p_nh_dep_dr->p_dr->num_nh > 1) {
                if (intf_event == FIB_INTF_FORCE_DEL) {
                    p_dr_nh = fib_get_dr_nh(p_nh_dep_dr->p_dr, p_fh);
                    if (p_dr_nh) {
                        fib_del_dr_nh (p_nh_dep_dr->p_dr, p_dr_nh);
                        p_nh_dep_dr->p_dr->status_flag |= FIB_DR_STATUS_ADD;
                        fib_mark_dr_for_resolution (p_nh_dep_dr->p_dr);
                    }
                }
                FIB_FOR_EACH_NH_FROM_DR (p_nh_dep_dr->p_dr, p_nh, nh_holder1)
                {
                    HAL_RT_LOG_DEBUG("HAL-RT-DR-DEL",
                                     "DR: vrf_id: %d, prefix: %s, prefix_len: %d, "
                                     "Dep NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x status:0x%x is_nh_dead:%s",
                                     p_nh_dep_dr->p_dr->vrf_id,
                                     FIB_IP_ADDR_TO_STR (&p_nh_dep_dr->p_dr->key.prefix),
                                     p_nh_dep_dr->p_dr->prefix_len, p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_nh->key.ip_addr),
                                     p_nh->key.if_index, p_nh->status_flag,
                                     ((p_nh->status_flag & FIB_NH_STATUS_DEAD) ? "yes": "no"));
                    if (p_nh->status_flag & FIB_NH_STATUS_DEAD) {
                        continue;
                    }
                    /* Valid NH is found, dont delete the ECMP route */
                    is_fib_route_del = false;
                    break;
                }
            }
            /* copy the route to be deleted and then get the next dependent dr,
             * to avoid accessing the invalid dep-dr after route deletion */
            p_del_dr = p_nh_dep_dr->p_dr;
            p_nh_dep_dr = fib_get_next_nh_dep_dr (p_fh, p_nh_dep_dr->key.vrf_id,
                                                  &p_nh_dep_dr->key.dr_key.prefix,
                                                  p_nh_dep_dr->prefix_len);
            /* Dont delete the link local route on admin down,
             * wait for explicit route del from kernel thru netlink
             * The reason - let's say LAG(bond) has only one member and
             * upon removing the bond member, bond admin down
             * and then bond admin up is received from the NAS-linux
             * though the bond is intact with link local address, to avoid this issue,
             * link local route is deleted on explicit route del from kernel */

            if (is_fib_route_del && p_del_dr &&
                !(STD_IP_IS_ADDR_LINK_LOCAL(&p_del_dr->key.prefix))) {

                /* For admin event,
                 * delete all routes except from both NPU & in cache.
                 * For L2 mode change event,
                 * irrespective of rt_type delete all routes from NPU only
                 * and retain in cache.
                 */
                if (((intf_event == FIB_INTF_ADMIN_EVENT) && (p_del_dr->rt_type != RT_LOCAL))
                    || (intf_event == FIB_INTF_FORCE_DEL)) {
                    p_del_dr->status_flag |= FIB_DR_STATUS_DEL;
                }
                HAL_RT_LOG_INFO ("HAL-RT-DR-DEL",
                                 "Intf event: %d, DR: vrf_id: %d, prefix: %s, prefix_len: %d, rt_type: %d ",
                                 intf_event, p_del_dr->vrf_id,
                                 FIB_IP_ADDR_TO_STR (&p_del_dr->key.prefix),
                                 p_del_dr->prefix_len, p_del_dr->rt_type);

                /* @@TODO Delete the leaked route and the associated NHs */
                fib_proc_dr_del (p_del_dr);
            }
        }
    }
    return STD_ERR_OK;
}

int fib_process_link_local_address_del_on_intf_event (t_fib_intf *p_intf, t_fib_intf_event_type intf_event) {

    t_fib_dr         *p_del_dr = NULL;
    t_fib_ip_addr    *p_temp_ip = NULL;
    t_fib_ip_holder   ip_holder;
    hal_ifindex_t     if_index;

    if (!p_intf) {
        HAL_RT_LOG_ERR("HAL-RT-LLA-DEL", "Invalid input param");
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }

    /* on admin down if mode is not L3, then link local routes
     * would have been deleted already when mode changed to L3.
     */
    if ((intf_event == FIB_INTF_ADMIN_EVENT) &&
        !FIB_IS_INTF_MODE_L3 (p_intf->mode)) {
        return STD_ERR_OK;
    }

    if_index = p_intf->key.if_index;

    FIB_FOR_EACH_IP_FROM_INTF (p_intf, p_temp_ip, ip_holder)
    {
        HAL_RT_LOG_INFO("HAL-RT-LLA-DEL", "vrf:%d, if_index:%d, ip_addr: %s, RIF-ref-cnt:%d",
                        p_intf->key.vrf_id, if_index,
                        FIB_IP_ADDR_TO_STR (p_temp_ip),
                        hal_rt_rif_ref_get(p_intf->key.vrf_id, if_index));

        if (!STD_IP_IS_ADDR_LINK_LOCAL(p_temp_ip)) {
            continue;
        }

        p_del_dr = fib_get_dr (p_intf->key.vrf_id, p_temp_ip, HAL_RT_V6_PREFIX_LEN);

        if (!p_del_dr) {
            continue;
        }

        HAL_RT_LOG_INFO ("HAL-RT-LLA-DEL",
                         "Intf event: %d, DR: vrf_id: %d, prefix: %s/%d, "
                         "link_local_cnt: %d, RIF link_local_cnt: %d  rt_type: %d ",
                         intf_event, p_del_dr->vrf_id,
                         FIB_IP_ADDR_TO_STR (&p_del_dr->key.prefix),
                         p_del_dr->prefix_len, p_del_dr->num_ipv6_link_local,
                         p_del_dr->num_ipv6_rif_link_local, p_del_dr->rt_type);
        if (p_del_dr->num_ipv6_rif_link_local)
            p_del_dr->num_ipv6_rif_link_local--;

        /* Don't delete the LLA route from NDI if the DR's
         * num_ipv6_link_local is > 1,
         * DR num_ipv6_link_local value 1 indicates this is the only
         * interface on which this link local route
         * is configured; hence delete the LLA from NDI.
         */
        if (p_del_dr->num_ipv6_rif_link_local >= 1) {
            if (!hal_rt_rif_ref_dec(p_intf->key.vrf_id, if_index))
                hal_rif_index_remove(0, p_intf->key.vrf_id, if_index);
            continue;
        }

        if (intf_event == FIB_INTF_FORCE_DEL) {
            p_del_dr->status_flag |= FIB_DR_STATUS_DEL;
        }
        /* For interface mode change event,
         * delete link local route from NDI only.
         * link local routes will be retained in cache and deleted
         * only on kernel notification.
         */
        fib_proc_dr_del (p_del_dr);

        /* update/remove rif */
        if (!hal_rt_rif_ref_dec(p_intf->key.vrf_id, if_index))
            hal_rif_index_remove(0, p_intf->key.vrf_id, if_index);
    }
    return STD_ERR_OK;
}

static t_std_error hal_rt_intf_check_lla_dep_nh(t_fib_nh *p_nh) {
    t_fib_nh_dep_dr   *p_nh_dep_dr = NULL;
    t_fib_dr *p_dr = NULL;
    if (FIB_IS_NH_ZERO(p_nh)) {
        p_nh_dep_dr = fib_get_first_nh_dep_dr (p_nh);
        if (p_nh_dep_dr) {
            p_dr = p_nh_dep_dr->p_dr;
            if (p_dr && (STD_IP_IS_ADDR_LINK_LOCAL(&p_dr->key.prefix))) {
                HAL_RT_LOG_INFO ("HAL-RT-NH-DEL",
                                 "LLA NH skipping - vrf_id: %d, dep-dr: %s, if_index: 0x%x, "
                                 "owner_flag: 0x%x, status_flag: 0x%x",
                                 p_nh->vrf_id, FIB_IP_ADDR_TO_STR (&p_dr->key.prefix),
                                 p_nh->key.if_index, p_nh->owner_flag, p_nh->status_flag);
                return STD_ERR_OK;
            }
        }
    }
    return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
}

static t_std_error hal_rt_pub_nbr_evt(t_fib_nh *p_fh, cps_api_operation_types_t op) {

    cps_api_object_t obj = nas_route_nh_to_arp_cps_object(p_fh, op);
    if(obj && (nas_route_publish_object(obj)!= STD_ERR_OK)){
        HAL_RT_LOG_ERR ("HAL-RT-NH-PUB",
                        "Failed to publish - op:%d vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                        "owner_flag: 0x%x, status_flag: 0x%x", op,
                        p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                        p_fh->key.if_index, p_fh->owner_flag, p_fh->status_flag);
        return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
    }
    return STD_ERR_OK;
}

int fib_process_nh_del_on_intf_event (t_fib_intf *p_intf, t_fib_intf_event_type intf_event, bool is_intf_del) {

    t_fib_nh       *p_fh = NULL, *p_fh_del = NULL;
    t_fib_nh_holder nh_holder;

    /* Loop for all the FH associated on that interface */
    FIB_FOR_EACH_FH_FROM_INTF (p_intf, p_fh, nh_holder) {
        if (intf_event == FIB_INTF_FORCE_DEL) {
            if (p_fh_del) {
                /* If the NH is associated with LLA, dont delete it, since this NH could be associated with LLA,
                 * if we delete this NH now, it will lead to radix assert when the dependent NH is deleted
                 * and route reaches the lla count reaches zero. */
                if (hal_rt_intf_check_lla_dep_nh(p_fh_del) == STD_ERR_OK) {
                    continue;
                }

                hal_rt_pub_nbr_evt(p_fh_del, cps_api_oper_DELETE);
                fib_nh_del_nh(p_fh_del, true);
            }
            p_fh_del = p_fh;
        } else {
            p_fh->status_flag |= FIB_NH_STATUS_DEAD;

            HAL_RT_LOG_INFO ("HAL-RT-NH-DEL",
                             "vrf_id: %d, ip_addr: %s, if_index: 0x%x, "
                             "owner_flag: 0x%x, status_flag: 0x%x",
                             p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                             p_fh->key.if_index, p_fh->owner_flag, p_fh->status_flag);


            /* For admin/L2 mode change event, set the FIB_NH_STATUS_DEAD flag,
             * delete the nh in NPU only and retain it in cache.
             * NH will be deleted only via explicit triggers from ARP delete.
             */
            fib_proc_nh_dead (p_fh);
            hal_rt_pub_nbr_evt(p_fh, cps_api_oper_DELETE);
            /* Interface del will not delete the NH if NH is associated with LLA route,
             * make sure to remove the DEAD status if present so that LLA programming for other
             * same LLAs (e.g multiple port-channels have same MAC i.e same LLA) wont be affected. */
            if (is_intf_del && (hal_rt_intf_check_lla_dep_nh(p_fh) == STD_ERR_OK)) {
                p_fh->status_flag &= ~FIB_NH_STATUS_DEAD;
            }
        }
    }

    if (p_fh_del) {
        /* If the NH is associated with LLA, dont delete it, since this NH could be associated with LLA,
         * if we delete this NH now, it will lead to radix assert when the dependent NH is deleted
         * and route reaches the lla count reaches zero. */
        if (hal_rt_intf_check_lla_dep_nh(p_fh_del) != STD_ERR_OK) {
            hal_rt_pub_nbr_evt(p_fh_del, cps_api_oper_DELETE);
            fib_nh_del_nh(p_fh_del, true);
        }
    }
    return STD_ERR_OK;
}

int fib_route_del_on_intf_down (t_fib_intf *p_intf) {
    return (fib_process_route_del_on_intf_event (p_intf, FIB_INTF_ADMIN_EVENT));
}

int fib_handle_intf_admin_status_change(int vrf_id, int af_index, t_fib_intf_entry *p_intf_chg) {

    t_fib_intf  *p_intf = NULL;
    t_fib_nh    *p_fh = NULL;
    t_fib_nh_holder nh_holder;
    bool is_intf_present = false;

    if (p_intf_chg->is_op_del) {
        p_intf = fib_get_intf (p_intf_chg->if_index, vrf_id, af_index);
        if (p_intf == NULL)
            return STD_ERR_OK;
    } else {
        /* Get the L3 interface and delete all the associated routes*/
        p_intf = fib_get_or_create_intf(p_intf_chg->if_index, vrf_id, af_index, &is_intf_present);
        if (p_intf == NULL) {
            HAL_RT_LOG_ERR ("HAL-RT-DR", "Handling Failed - Admin status if_index: %d, vrf_id: %d, af_index: %d "
                            "admin status:%s is_del:%d p_intf:%p", p_intf_chg->if_index, vrf_id, af_index,
                            hal_rt_intf_admin_status_to_str(p_intf_chg->admin_status),
                            p_intf_chg->is_op_del, p_intf);

            return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
        }
        safestrncpy(p_intf->if_name, p_intf_chg->if_name, sizeof(p_intf->if_name));
    }
    HAL_RT_LOG_INFO ("HAL-RT-DR", "Admin status if_index: %d, vrf_id: %d, af_index: %d admin status:%s "
                     "is_del:%d name:%s p_intf:%p", p_intf_chg->if_index, vrf_id, af_index,
                     hal_rt_intf_admin_status_to_str(p_intf_chg->admin_status),
                     p_intf_chg->is_op_del, p_intf_chg->if_name, p_intf);
    /* if interface notification is received for the first time,
     * just update the admin status from kernel.
     */
    if ((p_intf_chg->is_op_del == false) && (!is_intf_present)) {
        memcpy(&p_intf->mac_addr, &p_intf_chg->mac_addr, sizeof(hal_mac_addr_t));
        p_intf->admin_status = p_intf_chg->admin_status;
        return STD_ERR_OK;
    } else if ((p_intf->admin_status == RT_INTF_ADMIN_STATUS_NONE) &&
               (p_intf_chg->admin_status == RT_INTF_ADMIN_STATUS_DOWN)) {
        HAL_RT_LOG_INFO ("HAL-RT-DR", "if_index: %d admin_up:%d curr:%d is_del:%d",
                         p_intf_chg->if_index, p_intf_chg->admin_status,
                         p_intf->admin_status, p_intf_chg->is_op_del);

        /* Bootup time, interface creation with admin down notification,
         * this will clear the existing routes, ignore it */
        p_intf->admin_status = p_intf_chg->admin_status;
        /* reset intf delete pending flag since this is a new update */
        p_intf->is_intf_delete_pending = false;
        return STD_ERR_OK;
    }

    /* simply return, if we are receiving duplicate status notification */
    /* On bootup, admin down event for master interface on interface create
     * from kernel might be processed after processing connected route add.
     * in this scenario we may end up in a state where
     * where connected route will never get installed after that.
     * To avoid this issue, skip out of order duplicate state notifications.
     */
    if ((p_intf_chg->admin_status != RT_INTF_ADMIN_STATUS_NONE) &&
        (p_intf->admin_status != p_intf_chg->admin_status)) {

        p_intf->admin_status = p_intf_chg->admin_status;

        if (p_intf->admin_status == RT_INTF_ADMIN_STATUS_UP) {

            /* If admin is up, clear the NH dead status flag */
            FIB_FOR_EACH_FH_FROM_INTF (p_intf, p_fh, nh_holder) {
                HAL_RT_LOG_DEBUG("HAL-RT-DR",
                                 "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x status:0x%x is_nh_dead:%s",
                                 p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                                 p_fh->key.if_index, p_fh->status_flag,
                                 ((p_fh->status_flag & FIB_NH_STATUS_DEAD) ? "yes" : "no"));
                p_fh->status_flag &= ~FIB_NH_STATUS_DEAD;
            }
            /* on interface admin up,
             * download the cached route configurations to hardware.
             */
            fib_route_add_on_intf_up(p_intf);
            fib_process_link_local_address_add_on_intf_event (p_intf, FIB_INTF_ADMIN_EVENT);
        } else {
            fib_route_del_on_intf_down(p_intf);
            fib_process_link_local_address_del_on_intf_event (p_intf, FIB_INTF_ADMIN_EVENT);
            fib_process_nh_del_on_intf_event (p_intf, FIB_INTF_ADMIN_EVENT, false);
        }
    } else if (p_intf_chg->is_op_del) {
        fib_route_del_on_intf_down(p_intf);
        fib_process_link_local_address_del_on_intf_event (p_intf, FIB_INTF_ADMIN_EVENT);
        fib_process_nh_del_on_intf_event (p_intf, FIB_INTF_ADMIN_EVENT, true);
    }
    /* reset intf delete pending flag since this is a new update */
    p_intf->is_intf_delete_pending = false;

    fib_resume_nh_walker_thread(af_index);
    fib_resume_dr_walker_thread(af_index);
    /* If there are any Nbr/route reference to this interface, update the RIF MAC in the NPU */
    if ((p_intf_chg->is_op_del == false) &&
        (!hal_rt_is_mac_address_zero((const hal_mac_addr_t *)&p_intf_chg->mac_addr)) &&
        (memcmp(&p_intf->mac_addr, &p_intf_chg->mac_addr, sizeof(hal_mac_addr_t)) != 0)) {

        memcpy(&p_intf->mac_addr, &p_intf_chg->mac_addr, sizeof(hal_mac_addr_t));
        /* If RIF is already created for this interface, update the RIF if MAC is changed */
        if (hal_rif_update (vrf_id, p_intf_chg) == false) {
            char p_buf[HAL_RT_MAX_BUFSZ];
            HAL_RT_LOG_ERR ("HAL-RT-DR",
                            "MAC update failed for "
                            "vrf_id: %d, if_index: 0x%x, af: %d MAC:%s",
                            vrf_id, p_intf_chg->if_index, af_index,
                            hal_rt_mac_to_str (&(p_intf->mac_addr), p_buf, HAL_RT_MAX_BUFSZ));
        }
    }

    /* When is_op_del is true,
     * check & delete interface if there are no routes/NH associated with it.
     */
    if (p_intf_chg->is_op_del == true) {
        p_intf->is_intf_delete_pending = true;
        fib_check_and_delete_intf (p_intf);
    }
    return STD_ERR_OK;
}

/* This function will perform the following on interface mode change:
 * 1) When mode changes from none to L2,
 *    delete all the routes from NPU only and retain it in cache;
 *    routes will be deleted in cache when the kernel deletes the routes.
 * 2) When mode changes from L2 to none,
 *    program all the routes from cache to NPU.
 */
t_std_error fib_process_intf_mode_change (int vrf_id, int af_index, uint32_t if_index, uint32_t mode) {

    t_fib_intf       *p_intf = NULL;
    t_fib_nh         *p_fh = NULL;
    t_fib_nh_holder   nh_holder;

    /* Get the L3 interface and delete all the associated routes*/
    p_intf = fib_get_intf (if_index, vrf_id, af_index);
    HAL_RT_LOG_INFO ("HAL-RT-INTF", "Intf Mode if_index: %d, vrf_id: %d, af_index: %d Mode:%s ",
                     if_index, vrf_id, af_index, hal_rt_intf_mode_to_str(mode));

    /* if mode change notification is received for the first time,
     * just update the mode in cache and return.
     */
    if (p_intf == NULL)
    {
        if ((p_intf = fib_add_intf (if_index, vrf_id, af_index)) == NULL)
        {
            HAL_RT_LOG_ERR ("HAL-RT-INTF",
                            "%s (): Intf addition failed. "
                            "if_index: %d, vrf_id: %d, af_index: %d",
                            __FUNCTION__, if_index, vrf_id, af_index);

            return (STD_ERR_MK(e_std_err_ROUTE, e_std_err_code_FAIL, 0));
        }

        std_dll_init (&p_intf->fh_list);
        std_dll_init (&p_intf->pending_fh_list);
        std_dll_init (&p_intf->ip_list);
        p_intf->admin_status = RT_INTF_ADMIN_STATUS_DOWN;
        p_intf->mode = mode;
        return STD_ERR_OK;
    }
    HAL_RT_LOG_INFO ("HAL-RT-INTF", "vrf_id:%d af_index:%d if_index:%d admin status:%s curr mode:%s new mode:%s",
                     vrf_id, af_index, if_index, hal_rt_intf_admin_status_to_str(p_intf->admin_status),
                     hal_rt_intf_mode_to_str(p_intf->mode), hal_rt_intf_mode_to_str(mode));

    if (p_intf->mode == mode) {
        /* if same mode, then simply return */
        return STD_ERR_OK;
    }

    p_intf->mode = mode;

    if (p_intf->admin_status == RT_INTF_ADMIN_STATUS_UP) {
        if (FIB_IS_INTF_MODE_L3 (mode)) {
            FIB_FOR_EACH_FH_FROM_INTF (p_intf, p_fh, nh_holder) {
                HAL_RT_LOG_DEBUG("HAL-RT-DR",
                                 "NH: vrf_id: %d, ip_addr: %s, if_index: 0x%x status:0x%x is_nh_dead:%s",
                                 p_fh->vrf_id, FIB_IP_ADDR_TO_STR (&p_fh->key.ip_addr),
                                 p_fh->key.if_index, p_fh->status_flag,
                                 ((p_fh->status_flag & FIB_NH_STATUS_DEAD) ? "yes" : "no"));
                p_fh->status_flag &= ~FIB_NH_STATUS_DEAD;
            }
            /* on mode change from L2 to L3,
             * download the cached route/nh configurations to hardware.
             */
            fib_process_nh_add_on_intf_event (p_intf, FIB_INTF_MODE_CHANGE_EVENT);

            fib_process_route_add_on_intf_event (p_intf, FIB_INTF_MODE_CHANGE_EVENT);

            /* on mode change from L2 to L3,
             * download the cached LLA route configurations to hardware.
             */
            fib_process_link_local_address_add_on_intf_event (p_intf, FIB_INTF_MODE_CHANGE_EVENT);

        } else {
            /* mode  BASE_IF_MODE_MODE_L2 or any other mode
             * is handled as L2 mode.
             */

            /* On L2 mode change, disable ICMP redirect. */
            p_intf->is_ip_redirects_set = false;

            /* on mode change from L3 to L2,
             * delete all route/nh configurations from hardware only
             * and retain it in cache. Route/nh information in cache will be
             * deleted only when the kernel deletes it.
             */

            fib_process_route_del_on_intf_event (p_intf, (vrf_id ? FIB_INTF_FORCE_DEL : FIB_INTF_MODE_CHANGE_EVENT));

            /* on mode change from L3 to L2,
             * delete LLA route configurations from hardware only
             * and retain it in cache. Route information in cache will be
             * deleted only when the kernel deletes it.
             */
            fib_process_link_local_address_del_on_intf_event (p_intf, (vrf_id ? FIB_INTF_FORCE_DEL : FIB_INTF_MODE_CHANGE_EVENT));

            /* It is possible that the routes that are associated with this interface would have moved to different NH
             * and in the change list for pending resolution to program into the HW, process all the pending routes now
             * so that in the fib_process_nh_del_on_intf_event function,
             * next-hop delete will be successful if we remove the HW binding for those routes. */
            fib_process_pending_resolve_dr(vrf_id, af_index);
            fib_process_nh_del_on_intf_event (p_intf, (vrf_id ? FIB_INTF_FORCE_DEL : FIB_INTF_MODE_CHANGE_EVENT), false);
            if (vrf_id) {
                fib_del_all_intf_ip(p_intf);
                p_intf->is_intf_delete_pending = true;
                fib_check_and_delete_intf(p_intf);
            }
        }
        /* resume NH/DR walker to process nh/route programming */
        fib_resume_nh_walker_thread(HAL_RT_V4_AFINDEX);
        fib_resume_dr_walker_thread(HAL_RT_V4_AFINDEX);

        fib_resume_nh_walker_thread(HAL_RT_V6_AFINDEX);
        fib_resume_dr_walker_thread(HAL_RT_V6_AFINDEX);
    }

    return STD_ERR_OK;
}

int fib_process_route_del_on_ip_del_event (hal_ifindex_t if_index, hal_vrf_id_t vrf_id,
                                           t_fib_ip_addr *prefix, uint8_t prefix_len) {
    t_fib_nh        *p_nh = NULL;
    t_fib_nh_holder nh_holder;
    t_fib_nh_dep_dr   *p_nh_dep_dr = NULL;
    t_fib_intf *p_intf = NULL;
    t_fib_ip_addr mask;
    t_fib_dr *p_dr = NULL;

    HAL_RT_LOG_INFO("IP-RT-DEL", "intf:%d vrf_id: %d, prefix: %s, prefix_len: %d",
                   if_index, vrf_id, FIB_IP_ADDR_TO_STR (prefix), prefix_len);
    p_intf = fib_get_intf (if_index, vrf_id, prefix->af_index);
    if (p_intf == NULL) {
        HAL_RT_LOG_ERR("IP-RT-DEL", "intf:%d not present for vrf_id: %d, prefix: %s, prefix_len: %d",
                       if_index, vrf_id, FIB_IP_ADDR_TO_STR (prefix), prefix_len);
        return STD_ERR_OK;
    }
    memset (&mask, 0, sizeof (t_fib_ip_addr));
    if (nas_rt_get_mask (prefix->af_index, prefix_len, &mask) == false) {
        HAL_RT_LOG_ERR("IP-RT-DEL", "intf:%d vrf_id: %d, prefix: %s, prefix_len: %d get mask failed",
                       if_index, vrf_id, FIB_IP_ADDR_TO_STR (prefix), prefix_len);
        return STD_ERR_OK;
    }

    /* Loop for all the FH and associated routes for deletion */
    FIB_FOR_EACH_FH_FROM_INTF (p_intf, p_nh, nh_holder) {
        if (FIB_IS_NH_ZERO(p_nh)) {
            HAL_RT_LOG_INFO("IP-RT-DEL", "intf:%d vrf_id: %d, prefix: %s, prefix_len: %d NH zero",
                            if_index, vrf_id, FIB_IP_ADDR_TO_STR (prefix), prefix_len);
            continue;
        }
        if (FIB_IS_IP_ADDR_IN_PREFIX(&p_nh->key.ip_addr, &mask, prefix)) {
            p_nh_dep_dr = fib_get_first_nh_dep_dr (p_nh);
            while ((p_nh_dep_dr != NULL) && (p_nh_dep_dr->p_dr != NULL)) {
                HAL_RT_LOG_INFO("IP-RT-DEL", "intf:%d vrf_id: %d, prefix: %s, prefix_len: %d NH:%s num_nh:%d",
                                if_index, vrf_id, FIB_IP_ADDR_TO_STR (&p_nh_dep_dr->p_dr->key.prefix),
                                p_nh_dep_dr->p_dr->prefix_len, FIB_IP_ADDR_TO_STR(&p_nh->key.ip_addr),
                                p_nh_dep_dr->p_dr->num_nh);
                p_dr = p_nh_dep_dr->p_dr;
                p_nh_dep_dr = fib_get_next_nh_dep_dr (p_nh, p_nh_dep_dr->key.vrf_id,
                                                      &p_nh_dep_dr->key.dr_key.prefix,
                                                      p_nh_dep_dr->prefix_len);
                if (p_dr->num_nh == 1) {
                    p_dr->status_flag |= FIB_DR_STATUS_DEL;
                    fib_proc_dr_del (p_dr);
                }
            }
        }
    }
    return STD_ERR_OK;
}

