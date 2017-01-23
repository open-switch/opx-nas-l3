/*
 * Copyright (c) 2016 Dell Inc.
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
 * \file   hal_rt_route.h
 * \brief  Hal Routing functionality
 * \date   05-2014
 * \author Prince Sunny & Satish Mynam
 */

#ifndef __HAL_RT_ROUTE_H__
#define __HAL_RT_ROUTE_H__

#include "stddef.h"
#include "cps_api_object.h"
#include "cps_api_operation.h"

#include "std_error_codes.h"
#include "hal_rt_main.h"
#include "nas_ndi_router_interface.h"
#include "nas_ndi_route.h"

#define FIB_RDX_DR_KEY_LEN             (8 * (sizeof (t_fib_dr_key)))
#define FIB_RDX_NH_KEY_LEN             (8 * (sizeof (t_fib_nh_key)))
#define FIB_RDX_NH_DEP_DR_KEY_LEN      (8 * (sizeof (t_fib_nh_dep_dr_key)))
#define FIB_RDX_TNL_DEST_KEY_LEN       (8 * (sizeof (t_fib_tnl_key)))

#define FIB_DR_WALKER_COUNT            100
#define FIB_NH_WALKER_COUNT            100
#define FIB_DEFAULT_DR_OWNER_FIB       1
#define FIB_DEFAULT_DR_OWNER_RTM       2

#define FIB_DR_STATUS_REQ_RESOLVE      0x0001
#define FIB_DR_STATUS_WRITTEN          0x0002
#define FIB_DR_STATUS_DEGENERATED      0x0004
#define FIB_DR_STATUS_ADD              0x0008
#define FIB_DR_STATUS_DEL              0x0010

#define FIB_IS_FH_IP_TUNNEL(_p_fh)     false

#define FIB_GET_NH_FROM_LINK_NODE_GLUE(_p_dll) \
        ((t_fib_nh *) (((t_fib_link_node *)(((char *) (_p_dll)) - offsetof (t_fib_link_node, glue)))->self))

/* FH node and the NH node typedefs are the same. */
#define FIB_GET_FH_FROM_LINK_NODE_GLUE(_p_dll) \
        FIB_GET_NH_FROM_LINK_NODE_GLUE (_p_dll)

#define FIB_GET_DR_TUNNEL_FH_FROM_LINK_NODE_GLUE(_p_dll) \
        ((t_fib_tunnel_fh *) (((t_fib_link_node *)(((char *) (_p_dll)) - offsetof (t_fib_link_node, glue)))->self))

#define FIB_GET_NH_TUNNEL_FH_FROM_LINK_NODE_GLUE(_p_dll) \
        ((t_fib_nh *) (((t_fib_link_node *)(((char *) (_p_dll)) - offsetof (t_fib_link_node, glue)))->self))

/*
 * Following macros:
 *
 * FIB_GET_LINK_NODE_FROM_NH_HOLDER
 * FIB_GET_DRNH_NODE_FROM_NH_HOLDER
 * FIB_GET_DRFH_NODE_FROM_NH_HOLDER
 *
 * should NOT be used as a stand alone macro. It should be used
 * only with the Fib traversal macros.
 */
#define FIB_GET_LINK_NODE_FROM_NH_HOLDER(_nh_holder) \
        ((t_fib_link_node *)(_nh_holder).p_dll)

#define FIB_GET_DRNH_NODE_FROM_NH_HOLDER(_nh_holder) \
        ((t_fib_dr_nh *)((_nh_holder).p_dll))

#define FIB_GET_DRFH_NODE_FROM_NH_HOLDER(_nh_holder) \
        ((t_fib_dr_fh *)((_nh_holder).p_dll))

#define FIB_GET_FH_FROM_DRFH(_p_dr_fh) \
        (t_fib_nh *)((_p_dr_fh)->link_node.self)

#define FIB_GET_TUNNEL_NHFH_NODE_FROM_NH_HOLDER(_nh_holder) \
        ((t_fib_tunnel_fh *)((_nh_holder).p_dll))

#define FIB_GET_TUNNEL_DRFH_NODE_FROM_NH_HOLDER(_nh_holder) \
        ((t_fib_tunnel_dr_fh *)((_nh_holder).p_dll))

#define FIB_GET_FH_FROM_TUNNEL_FH(_p_tunnel_fh) \
        ((_p_tunnel_fh != NULL) ? ((t_fib_nh *)((_p_tunnel_fh)->link_node.self)) : \
          NULL)

#define FIB_GET_FIRST_DEP_NH_FROM_DR(_p_dr, _nh_holder) \
        (((_nh_holder.p_dll = FIB_DLL_GET_FIRST (&((_p_dr)->dep_nh_list))) != NULL) \
         ? FIB_GET_NH_FROM_LINK_NODE_GLUE (_nh_holder.p_dll) : NULL)

/*
 * FIB_GET_NEXT_DEP_NH_FROM_DR should NOT be used without using
 * FIB_GET_FIRST_DEP_NH_FROM_DR
 */
#define FIB_GET_NEXT_DEP_NH_FROM_DR(_p_dr, _nh_holder) \
        (((_nh_holder.p_next_dll \
           = FIB_DLL_GET_NEXT (&((_p_dr)->dep_nh_list), _nh_holder.p_dll)) != NULL) \
         ? FIB_GET_NH_FROM_LINK_NODE_GLUE (_nh_holder.p_next_dll) : NULL)

#define FIB_GET_FIRST_NH_FROM_DR(_p_dr, _nh_holder) \
        (((_nh_holder.p_dll = FIB_DLL_GET_FIRST (&((_p_dr)->nh_list))) != NULL) \
         ? FIB_GET_NH_FROM_LINK_NODE_GLUE (_nh_holder.p_dll) : NULL)

/*
 * FIB_GET_NEXT_NH_FROM_DR should NOT be used without using
 * FIB_GET_FIRST_NH_FROM_DR
 */
#define FIB_GET_NEXT_NH_FROM_DR(_p_dr, _nh_holder) \
        (((_nh_holder.p_next_dll \
           = FIB_DLL_GET_NEXT (&((_p_dr)->nh_list), _nh_holder.p_dll)) != NULL) \
         ? FIB_GET_NH_FROM_LINK_NODE_GLUE (_nh_holder.p_next_dll) : NULL)

#define FIB_GET_FIRST_FH_FROM_DR(_p_dr, _nh_holder) \
        ((((_nh_holder).p_dll = FIB_DLL_GET_FIRST (&((_p_dr)->fh_list))) != NULL) \
         ? FIB_GET_FH_FROM_LINK_NODE_GLUE ((_nh_holder).p_dll) : NULL)

/*
 * FIB_GET_NEXT_FH_FROM_DR should NOT be used without using
 * FIB_GET_FIRST_FH_FROM_DR
 */
#define FIB_GET_NEXT_FH_FROM_DR(_p_dr, _nh_holder) \
        ((((_nh_holder).p_next_dll \
           = FIB_DLL_GET_NEXT (&((_p_dr)->fh_list), (_nh_holder).p_dll)) != NULL) \
         ? FIB_GET_FH_FROM_LINK_NODE_GLUE ((_nh_holder).p_next_dll) : NULL)

#define FIB_GET_FIRST_FH_FROM_NH(_p_nh, _nh_holder) \
        (((_nh_holder.p_dll = FIB_DLL_GET_FIRST (&((_p_nh)->fh_list))) != NULL) \
         ? FIB_GET_FH_FROM_LINK_NODE_GLUE (_nh_holder.p_dll) : NULL)

/*
 * FIB_GET_NEXT_FH_FROM_NH should NOT be used without using
 * FIB_GET_FIRST_FH_FROM_NH
 */
#define FIB_GET_NEXT_FH_FROM_NH(_p_nh, _nh_holder) \
        (((_nh_holder.p_next_dll \
           = FIB_DLL_GET_NEXT (&((_p_nh)->fh_list), _nh_holder.p_dll)) != NULL) \
         ? FIB_GET_FH_FROM_LINK_NODE_GLUE (_nh_holder.p_next_dll) : NULL)

#define FIB_GET_FIRST_FH_FROM_INTF(_p_intf, _nh_holder) \
        ((((_nh_holder).p_dll = \
           FIB_DLL_GET_FIRST (&((_p_intf)->fh_list))) != NULL) \
         ? FIB_GET_FH_FROM_LINK_NODE_GLUE ((_nh_holder).p_dll) : NULL)

/*
 * FIB_GET_NEXT_FH_FROM_INTF should NOT be used without using
 * FIB_GET_FIRST_FH_FROM_INTF
 */
#define FIB_GET_NEXT_FH_FROM_INTF(_p_intf, _nh_holder) \
        ((((_nh_holder).p_next_dll \
           = FIB_DLL_GET_NEXT (&((_p_intf)->fh_list), (_nh_holder).p_dll)) != NULL) \
         ? FIB_GET_FH_FROM_LINK_NODE_GLUE ((_nh_holder).p_next_dll) : NULL)

#define FIB_GET_FIRST_PENDING_FH_FROM_INTF(_p_intf, _nh_holder) \
        ((((_nh_holder).p_dll = \
           FIB_DLL_GET_FIRST (&((_p_intf)->pending_fh_list))) != NULL) \
         ? FIB_GET_FH_FROM_LINK_NODE_GLUE ((_nh_holder).p_dll) : NULL)

/*
 * FIB_GET_NEXT_PENDING_FH_FROM_INTF should NOT be used without using
 * FIB_GET_FIRST_PENDING_FH_FROM_INTF
 */
#define FIB_GET_NEXT_PENDING_FH_FROM_INTF(_p_intf, _nh_holder) \
        ((((_nh_holder).p_next_dll \
           = FIB_DLL_GET_NEXT (&((_p_intf)->pending_fh_list), \
                            (_nh_holder).p_dll)) != NULL) \
         ? FIB_GET_FH_FROM_LINK_NODE_GLUE ((_nh_holder).p_next_dll) : NULL)

#define FIB_GET_FIRST_TUNNEL_FH_FROM_DRFH(_p_dr_fh, _nh_holder) \
        ((((_nh_holder).p_dll = FIB_DLL_GET_FIRST (&((_p_dr_fh)->tunnel_fh_list))) != NULL) \
         ? FIB_GET_DR_TUNNEL_FH_FROM_LINK_NODE_GLUE ((_nh_holder).p_dll) : NULL)

/*
 * FIB_GET_NEXT_TUNNEL_FH_FROM_DRFH should NOT be used without using
 * FIB_GET_FIRST_TUNNEL_FH_FROM_DRFH
 */
#define FIB_GET_NEXT_TUNNEL_FH_FROM_DRFH(_p_dr_fh, _nh_holder) \
        ((((_nh_holder).p_next_dll \
           = FIB_DLL_GET_NEXT (&((_p_dr_fh)->tunnel_fh_list), (_nh_holder).p_dll)) != NULL) \
         ? FIB_GET_DR_TUNNEL_FH_FROM_LINK_NODE_GLUE ((_nh_holder).p_next_dll) : NULL)

#define FIB_GET_FIRST_TUNNEL_FH_FROM_NH(_p_nh, _nh_holder) \
        ((((_nh_holder).p_dll = FIB_DLL_GET_FIRST (&((_p_nh)->tunnel_fh_list))) != NULL) \
         ? FIB_GET_NH_TUNNEL_FH_FROM_LINK_NODE_GLUE ((_nh_holder).p_dll) : NULL)

/*
 * FIB_GET_NEXT_TUNNEL_FH_FROM_NH should NOT be used without using
 * FIB_GET_FIRST_TUNNEL_FH_FROM_NH
 */
#define FIB_GET_NEXT_TUNNEL_FH_FROM_NH(_p_nh, _nh_holder) \
        ((((_nh_holder).p_next_dll \
           = FIB_DLL_GET_NEXT (&((_p_nh)->tunnel_fh_list), (_nh_holder).p_dll)) != NULL) \
         ? FIB_GET_NH_TUNNEL_FH_FROM_LINK_NODE_GLUE ((_nh_holder).p_next_dll) : NULL)

#define FIB_FOR_EACH_DEP_NH_FROM_DR(_p_dr, _p_nh, _nh_holder) \
        for ((_p_nh) = FIB_GET_FIRST_DEP_NH_FROM_DR ((_p_dr), _nh_holder), \
             _nh_holder.p_next_nh = ((_p_nh != NULL) ? \
                  FIB_GET_NEXT_DEP_NH_FROM_DR (_p_dr, _nh_holder) : NULL); \
             (_p_nh) != NULL; \
             (_p_nh) = _nh_holder.p_next_nh, \
             (_nh_holder).p_dll = (_nh_holder).p_next_dll, \
             _nh_holder.p_next_nh = ((_p_nh != NULL) ? \
                  FIB_GET_NEXT_DEP_NH_FROM_DR (_p_dr, _nh_holder) : NULL))

#define FIB_FOR_EACH_NH_FROM_DR(_p_dr, _p_nh, _nh_holder) \
        for ((_p_nh) = FIB_GET_FIRST_NH_FROM_DR ((_p_dr), _nh_holder), \
             _nh_holder.p_next_nh = ((_p_nh != NULL) ? \
                  FIB_GET_NEXT_NH_FROM_DR (_p_dr, _nh_holder) : NULL); \
             (_p_nh) != NULL; \
             (_p_nh) = _nh_holder.p_next_nh, \
             (_nh_holder).p_dll = (_nh_holder).p_next_dll, \
             _nh_holder.p_next_nh = ((_p_nh != NULL) ? \
                  FIB_GET_NEXT_NH_FROM_DR (_p_dr, _nh_holder) : NULL))

#define FIB_FOR_EACH_FH_FROM_DR(_p_dr, _p_fh, _nh_holder) \
        for ((_p_fh) = FIB_GET_FIRST_FH_FROM_DR ((_p_dr), (_nh_holder)), \
             (_nh_holder).p_next_fh = (((_p_fh) != NULL) ? \
                  FIB_GET_NEXT_FH_FROM_DR ((_p_dr), (_nh_holder)) : NULL); \
             (_p_fh) != NULL; \
             (_p_fh) = (_nh_holder).p_next_fh, \
             (_nh_holder).p_dll = (_nh_holder).p_next_dll, \
             (_nh_holder).p_next_fh = (((_p_fh) != NULL) ? \
                  FIB_GET_NEXT_FH_FROM_DR ((_p_dr), (_nh_holder)) : NULL))

#define FIB_FOR_EACH_FH_FROM_NH(_p_nh, _p_fh, _nh_holder) \
        for ((_p_fh) = FIB_GET_FIRST_FH_FROM_NH (_p_nh, _nh_holder), \
             _nh_holder.p_next_fh = (((_p_fh) != NULL) ? \
                  FIB_GET_NEXT_FH_FROM_NH (_p_nh, _nh_holder) : NULL); \
             (_p_fh) != NULL; \
             (_p_fh) = _nh_holder.p_next_fh, \
             (_nh_holder).p_dll = (_nh_holder).p_next_dll, \
             _nh_holder.p_next_fh = (((_p_fh) != NULL) ? \
                 FIB_GET_NEXT_FH_FROM_NH (_p_nh, _nh_holder) : NULL))

#define FIB_FOR_EACH_FH_FROM_INTF(_p_intf, _p_fh, _nh_holder) \
        for ((_p_fh) = \
             FIB_GET_FIRST_FH_FROM_INTF ((_p_intf), (_nh_holder)), \
             (_nh_holder).p_next_fh = (((_p_fh) != NULL) ? \
               FIB_GET_NEXT_FH_FROM_INTF ((_p_intf), (_nh_holder)) : NULL); \
             (_p_fh) != NULL; \
             (_p_fh) = (_nh_holder).p_next_fh, \
             (_nh_holder).p_dll = (_nh_holder).p_next_dll, \
             _nh_holder.p_next_fh = (((_p_fh) != NULL) ? \
               FIB_GET_NEXT_FH_FROM_INTF ((_p_intf), (_nh_holder)) : NULL))

#define FIB_FOR_EACH_PENDING_FH_FROM_INTF(_p_intf, _p_fh, _nh_holder) \
        for ((_p_fh) = \
             FIB_GET_FIRST_PENDING_FH_FROM_INTF ((_p_intf), (_nh_holder)), \
             (_nh_holder).p_next_fh = (((_p_fh) != NULL) ? \
               FIB_GET_NEXT_PENDING_FH_FROM_INTF ((_p_intf), \
                                                  (_nh_holder)) : NULL); \
             (_p_fh) != NULL; \
             (_p_fh) = (_nh_holder).p_next_fh, \
             (_nh_holder).p_dll = (_nh_holder).p_next_dll, \
             _nh_holder.p_next_fh = (((_p_fh) != NULL) ? \
               FIB_GET_NEXT_PENDING_FH_FROM_INTF ((_p_intf), (_nh_holder)) : NULL))

#define FIB_FOR_EACH_FH_FROM_TUNNEL_DRFH(_p_dr_fh, _p_tunnel_fh, _nh_holder) \
        for ((_p_tunnel_fh) = FIB_GET_FIRST_TUNNEL_FH_FROM_DRFH ((_p_dr_fh), (_nh_holder)), \
             (_nh_holder).p_next_tunnel_fh = (((_p_tunnel_fh) != NULL) ? \
                  FIB_GET_NEXT_TUNNEL_FH_FROM_DRFH ((_p_dr_fh), (_nh_holder)) : NULL); \
             (_p_tunnel_fh) != NULL; \
             (_p_tunnel_fh) = (_nh_holder).p_next_tunnel_fh, \
             (_nh_holder).p_dll = (_nh_holder).p_next_dll, \
             (_nh_holder).p_next_tunnel_fh = (((_p_tunnel_fh) != NULL) ? \
                  FIB_GET_NEXT_TUNNEL_FH_FROM_DRFH ((_p_dr_fh), (_nh_holder)) : NULL))

#define FIB_FOR_EACH_FH_FROM_TUNNEL_NH(_p_nh, _p_fh, _nh_holder) \
        for ((_p_fh) = FIB_GET_FIRST_TUNNEL_FH_FROM_NH ((_p_nh), (_nh_holder)), \
             (_nh_holder).p_next_fh = (((_p_fh) != NULL) ? \
                  FIB_GET_NEXT_TUNNEL_FH_FROM_NH ((_p_nh), (_nh_holder)) : NULL); \
             (_p_fh) != NULL; \
             (_p_fh) = (_nh_holder).p_next_fh, \
             (_nh_holder).p_dll = (_nh_holder).p_next_dll, \
             (_nh_holder).p_next_fh = (((_p_fh) != NULL) ? \
                  FIB_GET_NEXT_TUNNEL_FH_FROM_NH ((_p_nh), (_nh_holder)) : NULL))

/* Values of 'state' in 't_fib_dr_fh' */
#define FIB_DRFH_STATUS_WRITTEN      0x1
#define FIB_DRFH_STATUS_UNWRITTEN    0x2

/* Values of 'status_flag' in 't_fib_nh' */
#define FIB_NH_STATUS_ADD            0x0001
#define FIB_NH_STATUS_DEL            0x0002
#define FIB_NH_STATUS_REQ_RESOLVE    0x0004
#define FIB_NH_STATUS_PENDING        0x0008
#define FIB_NH_STATUS_WRITTEN        0x0010
#define FIB_NH_STATUS_DEAD           0x0020 /* NH is declared dead because the
                                               interface thru which this NH is reachable is down*/

/* Values of 'state' in 't_fib_arp_info' */
#define FIB_ARP_RESOLVING            1
#define FIB_ARP_RESOLVED             2
#define FIB_ARP_UNRESOLVED           3

#define FIB_IS_NH_OWNER(_p_nh, _owner_type, _owner_value)                       \
        ((_p_nh)->owner_flag &                                                 \
         (0x1 << (FIB_NH_OWNER_TYPE_TO_NUM ((_owner_type), (_owner_value)))))

#define FIB_IS_NH_FH(_p_nh)                                                   \
        (((((_p_nh)->key.if_index) != 0) || (FIB_IS_NH_LOOP_BACK((_p_nh)))) &&  \
         (((_p_nh)->p_arp_info) != NULL))

#define FIB_IS_NH_LOOP_BACK(_p_nh)                                            \
        STD_IP_IS_ADDR_LOOP_BACK ((&((_p_nh)->key.ip_addr)))

#define FIB_IS_NH_ZERO(_p_nh)                                                 \
        STD_IP_IS_ADDR_ZERO ((&((_p_nh)->key.ip_addr)))


#define FIB_GET_RDX_DR_KEY_LEN(_p_prefix, _prefix_len) \
        (((sizeof ((_p_prefix)->af_index)) * 8) + (_prefix_len))

#define FIB_GET_RDX_NH_DEP_DR_KEY_LEN(_p_nh_dep_dr_key, _prefix_len)        \
        (((sizeof ((_p_nh_dep_dr_key)->vrf_id)) * 8) +                      \
         ((sizeof ((_p_nh_dep_dr_key)->dr_key.prefix.af_index)) * 8) +      \
         (_prefix_len))

#define FIB_IS_DR_DEFAULT(_p_)                                              \
        ((STD_IP_IS_ADDR_ZERO (&((_p_)->key.prefix))) && ((_p_)->prefix_len == 0))

#define FIB_IS_DR_WRITTEN(_p_)                                              \
        ((((_p_)->status_flag) & FIB_DR_STATUS_WRITTEN))

#define FIB_IS_DEFAULT_DR_OWNER_RTM(_p_)                                    \
        ((_p_)->default_dr_owner == FIB_DEFAULT_DR_OWNER_RTM)

#define FIB_IS_DEFAULT_DR_OWNER_FIB(_p_)                                    \
        ((_p_)->default_dr_owner == FIB_DEFAULT_DR_OWNER_FIB)

#define FIB_IS_CATCH_ALL_ROUTE_DISABLED(_vrf_id, _af_index)                 \
        (((hal_rt_access_fib_vrf_info(_vrf_id, _af_index))->is_catch_all_disabled) == true)

#define FIB_IS_DR_REQ_RESOLVE(_p_)                                          \
        ((((_p_)->status_flag) & FIB_DR_STATUS_REQ_RESOLVE))

#define FIB_IS_NH_RESERVED(_p_nh)                                             \
        ((FIB_IS_NH_LOOP_BACK ((_p_nh))) ||                                   \
         (FIB_IS_NH_ZERO ((_p_nh))))

#define FIB_IS_NH_OWNER_RTM(_p_nh)                                            \
        FIB_IS_NH_OWNER ((_p_nh), FIB_NH_OWNER_TYPE_RTM, 0)

#define FIB_IS_NH_OWNER_ARP(_p_nh)                                            \
        FIB_IS_NH_OWNER ((_p_nh), FIB_NH_OWNER_TYPE_ARP, 0)

#define FIB_IS_NH_REQ_RESOLVE(_p_nh)                                          \
        ((((_p_nh)->status_flag) & FIB_NH_STATUS_REQ_RESOLVE))

#define FIB_IS_NH_PENDING(_p_nh)                                              \
        ((((_p_nh)->status_flag) & FIB_NH_STATUS_PENDING))

#define FIB_IS_NH_WRITTEN(_p_nh)                                              \
        ((((_p_nh)->status_flag) & FIB_NH_STATUS_WRITTEN))

#define FIB_IS_FH_PENDING(_p_fh)                                              \
        (FIB_IS_NH_PENDING ((_p_fh)))

#define FIB_IS_FH_VALID_ECMP(_p_fh, _ecmp_count)                               \
        (((FIB_IS_NH_WRITTEN ((_p_fh))) &&                                    \
          ((_p_fh)->p_arp_info->state == FIB_ARP_RESOLVED) &&                   \
          ((_ecmp_count) < HAL_RT_MAX_ECMP_PATH)))

#define FIB_IS_L2_FH(_p_fh)                                         \
        ((_p_fh)->p_arp_info->is_l3_fh)

/* Macros related to NH */

#define FIB_NH_OWNER_RTM_VAL_START     0
#define FIB_NH_OWNER_RTM_VAL_END       FIB_NH_OWNER_RTM_VAL_START

#define FIB_NH_OWNER_ARP_VAL_START     (FIB_NH_OWNER_RTM_VAL_END + 1)
#define FIB_NH_OWNER_ARP_VAL_END       FIB_NH_OWNER_ARP_VAL_START

#define FIB_NH_OWNER_CLIENT_VAL_START  (FIB_NH_OWNER_ARP_VAL_END + 1)
#define FIB_NH_OWNER_CLIENT_VAL_END    (FIB_NH_OWNER_CLIENT_VAL_START +      \
                                        (FIB_MAX_CLIENTS - 1))

#define FIB_NH_OWNER_TYPE_TO_NUM(_owner_type, _owner_value)                    \
        (((_owner_type) == FIB_NH_OWNER_TYPE_RTM) ?                           \
         (FIB_NH_OWNER_RTM_VAL_START + (_owner_value)) :                      \
         (((_owner_type) == FIB_NH_OWNER_TYPE_ARP) ?                          \
          (FIB_NH_OWNER_ARP_VAL_START  + (_owner_value)) :                    \
          ((FIB_NH_OWNER_CLIENT_VAL_START + (_owner_value)))))

#define FIB_SET_NH_OWNER(_p_nh, _owner_type, _owner_value)                      \
        ((_p_nh)->owner_flag |=                                                \
         (0x1 << (FIB_NH_OWNER_TYPE_TO_NUM ((_owner_type), (_owner_value)))))

#define FIB_RESET_NH_OWNER(_p_nh, _owner_type, _owner_value)                    \
        ((_p_nh)->owner_flag &=                                                \
         ~(0x1 << (FIB_NH_OWNER_TYPE_TO_NUM ((_owner_type), (_owner_value)))))

/* Data Structure */
typedef enum _t_fib_nh_owner_type {
    FIB_NH_OWNER_TYPE_RTM,
    FIB_NH_OWNER_TYPE_ARP,
    FIB_NH_OWNER_TYPE_CLIENT
} t_fib_nh_owner_type;

typedef struct _t_fib_tunnel_fh {
    t_fib_link_node  link_node;
    /*
     * Incremented when a Tunnel FH is added to the tunnel_fh List
     * of a DR.
     */
    uint32_t         dr_ref_count;
    /* Set when a Tunnel FH is included in the NH's tunnel_fh List */
    uint8_t          is_nh_ref;
    next_hop_id_t    next_hop_id;
    void            *p_hal_nh_handle; /* Lower NPU Handle */
} t_fib_tunnel_fh;

typedef struct _t_fib_arp_info {
    hal_vlan_id_t vlan_id;
    uint8_t       mac_addr [HAL_RT_MAC_ADDR_LEN];
    uint8_t       state; /* FIB_ARP_RESOLVED/FIB_ARP_RESOLVING/FIB_ARP_UNRESOLVED */
    hal_ifindex_t if_index;
    uint8_t       is_l2_fh;
    uint8_t       arp_status; /* various ARP/ND status i.e RT_NUD_REACHABLE/RT_NUD_PERMANENT etc...*/
} t_fib_arp_info;

typedef struct _t_fib_dr_key {
    t_fib_ip_addr     prefix;
} t_fib_dr_key;

typedef struct _t_fib_dr_fh {
     t_fib_link_node link_node;
     uint8_t         status;
     std_dll_head    tunnel_fh_list;
     uint32_t        ecmp_weight_count; /* count the number of occurrences of same FH in the DR */
} t_fib_dr_fh;

typedef struct _t_fib_nht_key {
    t_fib_ip_addr  dest_addr; /* Route/Next-Hop address */
} t_fib_nht_key;

typedef struct _t_fib_nht {
    std_rt_head      rt_head;
    t_fib_nht_key    key; /* Client given route/nexthop is present in the key */
    hal_vrf_id_t     vrf_id;
    t_fib_ip_addr    fib_match_dest_addr; /* Best match Route/Next-Hop in the FIB */
    uint8_t          prefix_len; /* Prefix len of the route, incase of exact match in NH,
                                    it has the value /32(IPv4) or /128 (IPv6)*/
    uint32_t         ref_count; /* no. of clients interested in the route/next hop */
}t_fib_nht;

typedef struct _t_fib_dr {
    std_radical_head_t radical;
    t_fib_dr_key       key;
    uint8_t            prefix_len;
    hal_vrf_id_t       vrf_id;
    rt_proto           proto;
    uint32_t           default_dr_owner;
    uint32_t           status_flag;
    uint32_t           num_nh;
    uint32_t           num_fh;
    uint32_t           nh_count;  /* ECMP NH count */
    std_dll_head       nh_list;
    std_dll_head       fh_list;
    std_dll_head       dep_nh_list;
    t_fib_dr_fh        degen_dr_fh;
    uint64_t           last_update_time;
    uint8_t            a_is_written [HAL_RT_MAX_INSTANCE];
    next_hop_id_t      nh_handle;  /* nh_handle or ECMP group_handle */
    next_hop_id_t      onh_handle;  /* old nh_handle or ECMP group_handle */
    bool               remove_old_handle;
    bool               ecmp_handle_created; /* true if ecmp handle is present */
    bool               is_nh_resolved; /* true if ARP is resolved for this route */
    uint32_t           ofh_cnt; /* Old fh list count to detect the Non-ECMP to ECMP route */
    void              *p_hal_dr_handle; /* mp_obj details per SAI instance */
} t_fib_dr;

typedef struct _t_fib_nh_key {
    t_fib_ip_addr      ip_addr;
    hal_ifindex_t      if_index;
} t_fib_nh_key;

/*
 * t_fib_nh will either be a First Hop node or a Next Hope node. If 'key.if_index'
 * is non NULL, then it is a First hop node, else it is a next hop node.
 */
typedef struct _t_fib_nh {
    std_radical_head_t radical;
    t_fib_nh_key       key;
    hal_vrf_id_t       vrf_id;
    next_hop_id_t      next_hop_id;
    t_fib_dr          *p_best_fit_dr;
    uint32_t           num_fh;
    std_dll_head       fh_list;
    /* Incremented when a FH is added to the Tunnel FH list of a NH */
    uint32_t           tunnel_nh_ref_count;
    std_dll_head       tunnel_fh_list;
    t_fib_arp_info    *p_arp_info;
    uint32_t           owner_flag;
    uint32_t           status_flag;
    /* Incremented when a DR refers to this NH */
    uint32_t           rtm_ref_count;
    /*
     * Incremented when a NH is added either to the DRNH list
     * or DRFH list of a DR.
     */
    uint32_t           dr_ref_count;
    /* Incremented when a NH is added to the FH list of a NH */
    uint32_t           nh_ref_count;
    std_rt_table      *dep_dr_tree;
    uint64_t           arp_last_update_time;
    uint8_t            is_cam_host_count_incremented;
    uint8_t            is_audit_egr_info_matched;
    uint8_t            is_audit_egr_id_in_hw;
    uint8_t            is_audit_egr_id_corrupt;
    uint8_t            a_is_written [HAL_RT_MAX_INSTANCE];
    void              *p_hal_nh_handle; /* Lower NPU Handle */
    uint32_t           reachable_state_time_stamp; /* Reachable state received
                                                      from the kernel */
} t_fib_nh;

/*
 * t_fib_nh_holder is a nh_holder structure used in the following macros:
 *    FIB_GET_FIRST_NH_FROM_DR
 *    FIB_GET_NEXT_NH_FROM_DR
 *    FIB_GET_FIRST_FH_FROM_NH
 *    FIB_GET_NEXT_FH_FROM_NH
 * It serves to provide local variable usage in the above macros.
 */
typedef struct _t_fib_nh_holder {
    std_dll         *p_dll;
    std_dll         *p_next_dll;
    t_fib_nh        *p_next_nh;
    t_fib_nh        *p_next_fh;
    t_fib_tunnel_fh *p_next_tunnel_fh;
    uint32_t         ecmp_count;
} t_fib_nh_holder;

typedef struct _t_fib_dr_nh {
    t_fib_link_node  link_node;
    /* Add any new fields above this */
    uint32_t         tlv_info_len;
    uint8_t          tlv_info [0];
} t_fib_dr_nh;

typedef struct _t_fib_tunnel_dr_fh {
    t_fib_link_node  link_node;
    uint8_t          status;
} t_fib_tunnel_dr_fh;

typedef struct _t_fib_nh_dep_dr_key {
    hal_vrf_id_t     vrf_id;
    t_fib_dr_key     dr_key;
} t_fib_nh_dep_dr_key;

typedef struct _t_fib_nh_dep_dr {
    std_rt_head         rt_head;
    t_fib_nh_dep_dr_key key;
    uint8_t             prefix_len;
    t_fib_dr           *p_dr;
} t_fib_nh_dep_dr;

typedef struct _t_fib_intf_key {
    hal_ifindex_t if_index;
    hal_vrf_id_t  vrf_id;
    uint8_t       af_index;
} t_fib_intf_key;

typedef struct _t_fib_intf {
    std_rt_head    rt_head;
    t_fib_intf_key key;
    /*
     * Each node in the list is of type 't_fib_link_node'.
     * The 'self' field of 't_fib_link_node' points to t_fib_nh node.
     */
    std_dll_head   fh_list;
    /*
     * Each node in the list is of type 't_fib_link_node'.
     * The 'self' field of 't_fib_link_node' points to t_fib_nh node.
     */
    std_dll_head   pending_fh_list;

    /* admin status of the interface; true - up, false - down */
    bool admin_status; /* this status is received from the kernel directly */
} t_fib_intf;

/* Function signatures for route.c - Start */

void hal_form_route_entry(ndi_route_t *p_route_entry, t_fib_dr *p_dr,
        uint8_t is_l3_terminated);
void hal_dump_route_entry(ndi_route_t *p_route_entry);

/* Function signatures for dr.c - Start */
int fib_create_dr_tree (t_fib_vrf_info *p_vrf_info);

int fib_destroy_dr_tree (t_fib_vrf_info *p_vrf_info);

int fib_proc_dr_download (t_fib_route_entry *p_route_msg);

int fib_proc_add_msg (uint8_t af_index, void *p_rtm_fib_cmd, int *p_nh_bytes);

int fib_proc_del_msg (uint8_t af_index, void *p_rtm_fib_cmd);

int fib_proc_del (t_fib_dr *p_dr);

int fib_proc_dr_nh_add (t_fib_dr *p_dr, void *p_rtm_fib_cmd, int *p_nh_bytes);

int fib_proc_dr_nh_del (t_fib_dr *p_dr, void *p_rtm_fib_cmd);

int fib_form_dr_msg_info (uint8_t af_index, void *p_rtm_fib_cmd, t_fib_dr_msg_info *p_fib_dr_msg_info);

int fib_form_nh_msg_info (uint8_t af_index, void *p_rtm_nh_key, t_fib_nh_msg_info *p_fib_nh_msg_info,
                            size_t nh_index);
int fib_proc_dr_add_msg (uint8_t af_index, void *p_rtm_fib_cmd, int *p_nh_info_size, bool is_rt_replace);

int fib_form_tnl_nh_msg_info (t_fib_tnl_dest *p_tnl_dest, t_fib_nh_msg_info *p_fib_nh_msg_info);

int fib_add_default_dr (uint32_t vrf_id, uint8_t af_index);

t_fib_dr *fib_add_dr (uint32_t vrf_id, t_fib_ip_addr *p_prefix, uint8_t prefix_len);

t_fib_dr *fib_get_dr (uint32_t vrf_id, t_fib_ip_addr *p_prefix, uint8_t prefix_len);

t_fib_dr *fib_get_first_dr (uint32_t vrf_id, uint8_t af_index);

t_fib_dr *fib_get_next_dr(uint32_t vrf_id, t_fib_ip_addr *prefix, uint8_t prefix_len);

int fib_del_dr (t_fib_dr *p_dr);

t_fib_dr_nh *fib_add_dr_nh (t_fib_dr *p_dr, t_fib_nh *p_nh, uint8_t *p_cur_nh_tlv, uint32_t nh_tlv_len);

t_fib_dr_nh *fib_get_dr_nh (t_fib_dr *p_dr, t_fib_nh *p_nh);

int fib_del_dr_nh (t_fib_dr *p_dr, t_fib_dr_nh *p_dr_nh);

int fib_delete_all_dr_nh (t_fib_dr *p_dr);

t_fib_dr_fh *fib_add_dr_fh (t_fib_dr *p_dr, t_fib_nh *p_fh);

int fib_del_dr_fh (t_fib_dr *p_dr, t_fib_dr_fh *p_dr_fh);

t_fib_dr_fh *fib_get_dr_fh (t_fib_dr *p_dr, t_fib_nh *p_fh);

int fib_del_fh (t_fib_dr *p_dr, t_fib_dr_fh *p_dr_fh);

int fib_delete_all_fh (t_fib_dr *p_dr);

t_fib_link_node *fib_add_dep_nh (t_fib_dr *p_dr, t_fib_nh *p_nh);

t_fib_link_node *fib_get_dep_nh (t_fib_dr *p_dr, t_fib_nh *p_nh);

int fib_del_dep_nh (t_fib_dr *p_dr, t_fib_link_node *p_link_node);

int fib_delete_all_dep_nh (t_fib_dr *p_dr);

int fib_add_degen_fh (t_fib_dr *p_dr, t_fib_nh *p_fh, t_fib_tunnel_fh *p_tunnel_fh);

t_fib_nh *fib_get_dr_degen_fh (t_fib_dr *p_dr);

int fib_del_dr_degen_fh (t_fib_dr *p_dr);

t_fib_dr *fib_get_best_fit_dr (uint32_t vrf_id, t_fib_ip_addr *p_ip_addr);

t_fib_dr *fib_get_next_best_fit_dr (uint32_t vrf_id, t_fib_ip_addr *p_ip_addr);

t_fib_cmp_result fib_dr_nh_cmp (t_fib_dr *p_dr, void *p_rtm_fib_cmd, int *p_nhInfo_size);

int fib_dr_walker_call_back (std_radical_head_t *p_rt_head, va_list ap);

int fib_resolve_dr (t_fib_dr *p_dr);

int fib_updt_best_fit_Of_affected_nh (t_fib_dr *p_dr);

int fib_proc_dr_degeneration (t_fib_dr *p_dr);

int fib_mark_dr_for_resolution (t_fib_dr *p_dr);

int fib_mark_dep_nh_for_resolution (t_fib_dr *p_dr);

int fib_resume_dr_walker_thread (uint8_t af_index);

int fib_update_route_summary (uint32_t vrf_id, uint8_t af_index, uint8_t prefix_len, bool action);

int fib_proc_rtm_vrf_add_del_msg (uint8_t *p_ipc_msg_buf);

int fib_proc_rtm_vrf_add (uint32_t vrf_id, uint8_t af_index, uint8_t *p_vrf_name);

int fib_proc_rtm_vrf_del (uint32_t vrf_id, uint8_t af_index);

int fib_send_rtm_vrf_del_ack_msg (t_fib_vrf_info *p_vrf_info);

int fib_add_fh_from_tunnel_nh_fh (t_fib_dr_fh *p_dr_fh, t_fib_nh *p_tunnel_nh);

int fib_del_tunnel_fh (t_fib_dr_fh *p_dr_fh, t_fib_nh *p_tunnel_nh);

int fib_proc_catch_all_config (uint8_t *p_ipc_msg_buf);

int fib_setup_catch_all_route (t_fib_dr *p_dr, bool is_disabled);

t_fib_link_node *fib_get_dr_dep_nh (t_fib_dr *p_dr, t_fib_nh *p_nh);

int fib_proc_dr_del_msg (uint8_t af_index, void *p_rtm_fib_cmd);

int fib_delete_all_dr_fh (t_fib_dr *p_dr);

int fib_updt_best_fit_dr_of_affected_nh (t_fib_dr *p_dr);

int fib_proc_dr_del (t_fib_dr *p_dr);

int fib_mark_dr_dep_nh_for_resolution (t_fib_dr *p_dr);

int fib_delete_all_dr_dep_nh (t_fib_dr *p_dr);

void fib_free_dr_node (t_fib_dr *p_dr);

int fib_dr_walker_init (void);

int fib_dr_walker_main (void );

t_fib_link_node *fib_add_dr_dep_nh (t_fib_dr *p_dr, t_fib_nh *p_nh);

int fib_del_dr_dep_nh (t_fib_dr *p_dr, t_fib_link_node *p_link_node);

/* Function signatures for dr.c - End */

/* Function signatures for nh.c - Start */

int fib_create_nh_tree (t_fib_vrf_info *p_vrf_info);

int fib_destroy_nh_tree (t_fib_vrf_info *p_vrf_info);

int fib_create_nh_dep_tree (t_fib_nh *p_nh);

int fib_destroy_nh_dep_tree (t_fib_nh *p_nh);

int fib_create_intf_tree (void);

int fib_destroy_intf_tree (void);

t_fib_nh *fib_proc_nh_add (uint32_t vrf_id, t_fib_ip_addr *p_ip_addr, uint32_t if_index,
                      t_fib_nh_owner_type owner_type, uint32_t owner_value);

int fib_proc_nh_delete (t_fib_nh *p_nh, t_fib_nh_owner_type owner_type, uint32_t owner_value);

int fib_proc_add_intf_fh (t_fib_nh *p_fh, bool add_phy_if_index);

int fib_proc_del_intf_fh (t_fib_nh *p_fh, bool del_phy_if_index);

int fib_proc_pending_fh_add (t_fib_nh *p_fh);

int fib_proc_pending_fh_del (t_fib_nh *p_fh);

t_fib_nh *fib_add_nh (uint32_t vrf_id, t_fib_ip_addr *p_ip_addr, uint32_t if_index);

t_fib_nh *fib_get_nh (uint32_t vrf_id, t_fib_ip_addr *p_ip_addr, uint32_t if_index);

t_fib_nh *fib_get_first_nh (uint32_t vrf_id, uint8_t af_index);

t_fib_nh *fib_get_next_nh(uint32_t vrf_id, t_fib_ip_addr *p_ip_addr, uint32_t if_index);

t_fib_nh *fib_get_nh_for_host (uint32_t vrf_id, t_fib_ip_addr *p_ip_addr);

t_fib_nh *fib_get_next_nh_for_snmp (uint32_t vrf_id, t_fib_ip_addr *p_ip_addr);

int fib_del_nh (t_fib_nh *p_nh);

t_fib_link_node *fib_add_nh_fh (t_fib_nh *p_nh, t_fib_nh *p_fh);

t_fib_link_node *fib_get_nh_fh (t_fib_nh *p_nh, t_fib_nh *p_fh);

int fib_del_nh_fh (t_fib_nh *p_nh, t_fib_link_node *p_link_node);

int fib_delete_all_nh_fh (t_fib_nh *p_nh);

t_fib_nh_dep_dr *fib_add_nh_dep_dr (t_fib_nh *p_nh, t_fib_dr *p_dr);

t_fib_nh_dep_dr *fib_get_nh_dep_dr (t_fib_nh *p_nh, t_fib_dr *p_dr);

t_fib_nh_dep_dr *fib_get_first_nh_dep_dr (t_fib_nh *p_nh);

t_fib_nh_dep_dr *fib_get_next_nh_dep_dr (t_fib_nh *p_nh,uint32_t vrf_id,t_fib_ip_addr *p_prefix,uint8_t prefix_len);

int fib_del_nh_dep_dr (t_fib_nh *p_nh, t_fib_nh_dep_dr *p_nh_dep_dr);

int fib_delete_all_nh_dep_dr (t_fib_nh *p_nh);

int fib_add_nh_best_fit_dr (t_fib_nh *p_nh, t_fib_dr *p_best_fit_dr);

t_fib_dr *fib_get_nh_best_fit_dr (t_fib_nh *p_nh);

int fib_del_nh_best_fit_ (t_fib_nh *p_nh);

t_fib_intf *fib_add_intf (uint32_t if_index, uint32_t vrf_id, uint8_t af_index);

t_fib_intf *fib_get_intf (uint32_t if_index, uint32_t vrf_id, uint8_t af_index);

int fib_del_intf (t_fib_intf *p_intf);

t_fib_link_node *fib_add_intf_fh (t_fib_intf *p_intf, t_fib_nh *p_fh);

t_fib_link_node *fib_get_intf_fh (t_fib_intf *p_intf, t_fib_nh *p_fh);

int fib_del_intf_fh (t_fib_intf *p_intf, t_fib_link_node *p_link_node);

t_fib_link_node *fib_add_intf_pending_fh (t_fib_intf *p_intf, t_fib_nh *p_fh);

t_fib_link_node *fib_get_intf_pending_fh (t_fib_intf *p_intf, t_fib_nh *p_fh);

int fib_del_intf_pending_fh (t_fib_intf *p_intf, t_fib_link_node *p_link_node);

int fib_check_and_delete_nh (t_fib_nh *p_nh);

int fib_check_and_delete_intf (t_fib_intf *p_intf);

int fib_nh_walker_init (void);

int fib_nh_walker_main (void);

int fib_nh_walker_call_back (std_radical_head_t *p_rt_head, va_list ap);

int fib_resolve_nh (t_fib_nh *p_nh);

int fib_add_nh_fh_from_best_fit_dr_nh (t_fib_nh *p_nh, t_fib_dr *p_best_fit_dr);

int fib_mark_nh_for_resolution (t_fib_nh *p_nh);

int fib_mark_nh_dep_dr_for_resolution (t_fib_nh *p_nh);

int fib_update_nh_dep_dr_resolution_status (t_fib_nh *p_nh);

int fib_resume_nh_walker_thread (uint8_t af_index);

t_fib_tunnel_fh *fib_add_nh_tunnel_fh (t_fib_nh *p_nh, t_fib_nh *p_fh);

t_fib_tunnel_fh *fib_get_nh_tunnel_fh (t_fib_nh *p_nh, t_fib_nh *p_fh);

int fib_del_nh_tunnel_fh (t_fib_nh *p_nh, t_fib_nh *p_fh);

int fib_check_and_delete_tunnel_fh (t_fib_tunnel_fh *p_tunnel_fh);

int fib_resolve_connected_tunnel_nh (uint32_t vrf_id, t_fib_nh *FH);

int fib_create_tnl_dest_tree (void);

/* Function signatures for nh.c - End */

/* Function signatures for arp.c - Start */

t_std_error fib_proc_nbr_download (t_fib_neighbour_entry *p_arp_info);

t_std_error fib_proc_arp_add (uint8_t af_index, void *p_arp_info);

t_std_error fib_proc_arp_del (uint8_t af_index, void *p_arp_info);

t_std_error fib_form_arp_msg_info (uint8_t af_index, void *p_arp_info, t_fib_arp_msg_info *p_fib_arp_msg_info,
                       bool is_clear_msg);

t_fib_cmp_result fib_arp_info_cmp (t_fib_nh *p_fh, t_fib_arp_msg_info *p_fib_arp_msg_info, uint32_t state);

/* Function signatures for arp.c - End */


int nas_rt_handle_dest_change(t_fib_dr *p_dr, t_fib_nh *p_nh, bool isAdd);
int nas_rt_handle_nht (t_fib_nht *p_nht_info, bool isAdd);
int fib_handle_intf_admin_status_change(int if_index, int vrf_id, int af_index, bool is_admin_up);
int nas_route_process_nbr_refresh(cps_api_object_t obj);
cps_api_object_t nas_route_nh_to_arp_cps_object(t_fib_nh *entry, cps_api_operation_types_t op);

#endif /* __HAL_RT_ROUTE_H__ */
