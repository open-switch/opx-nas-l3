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
 * \file   hal_rt_mem.h
 * \brief  Hal Routing Memory Management functionality
 * \date   05-2014
 * \author Prince Sunny and Satish Mynam
 */

#ifndef __HAL_RT_MEM_H__
#define __HAL_RT_MEM_H__

#include "hal_rt_route.h"
#include <stdlib.h>

#define FIB_MALLOC(_size_)             malloc(_size_)
#define FIB_FREE(_p_)                  free ((void *)(_p_))

#define FIB_VRF_MEM_MALLOC()           (t_fib_vrf *)FIB_MALLOC(sizeof (t_fib_vrf))
#define FIB_VRF_MEM_FREE(_p_)          FIB_FREE(_p_)

#define FIB_DR_MEM_MALLOC()            (t_fib_dr *)FIB_MALLOC(sizeof (t_fib_dr))
#define FIB_DR_MEM_FREE(_p_)           FIB_FREE(_p_)

#define FIB_NH_MEM_MALLOC()            (t_fib_nh *)FIB_MALLOC(sizeof (t_fib_nh))
#define FIB_NH_MEM_FREE(_p_)           FIB_FREE(_p_)

#define FIB_DR_NH_TLV_MEM_MALLOC()     (t_fib_dr_nh *)FIB_MALLOC(sizeof (t_fib_dr_nh) + RT_PER_TLV_MAX_LEN)
#define FIB_DR_NH_TLV_MEM_FREE(_p_)    FIB_FREE(_p_)

#define FIB_DR_NH_MEM_MALLOC()         (t_fib_dr_nh *)FIB_MALLOC(sizeof (t_fib_dr_nh))
#define FIB_DR_NH_MEM_FREE(_p_)        FIB_FREE(_p_)

#define FIB_DR_FH_MEM_MALLOC()         (t_fib_dr_fh *)FIB_MALLOC(sizeof (t_fib_dr_fh))
#define FIB_DR_FH_MEM_FREE(_p_)        FIB_FREE(_p_)

#define FIB_NH_DEP_DR_MEM_MALLOC()     (t_fib_nh_dep_dr *)FIB_MALLOC(sizeof (t_fib_nh_dep_dr))
#define FIB_NH_DEP_DR_MEM_FREE(_p_)    FIB_FREE(_p_)

#define FIB_ARP_INFO_MEM_MALLOC()      (t_fib_arp_info *)FIB_MALLOC(sizeof (t_fib_arp_info))
#define FIB_ARP_INFO_MEM_FREE(_p_)     FIB_FREE(_p_)

#define FIB_INTF_MEM_MALLOC()          (t_fib_intf *)FIB_MALLOC(sizeof (t_fib_intf))
#define FIB_INTF_MEM_FREE(_p_)         FIB_FREE(_p_)

#define FIB_TNL_DEST_MEM_MALLOC()      (t_fib_tnl_dest *)FIB_MALLOC(sizeof (t_fib_tnl_dest))
#define FIB_TNL_DEST_MEM_FREE(_p_)     FIB_FREE(_p_)

#define FIB_LINK_NODE_MEM_MALLOC()     (t_fib_link_node *)FIB_MALLOC(sizeof (t_fib_link_node))
#define FIB_LINK_NODE_MEM_FREE(_p_)    FIB_FREE(_p_)

#define FIB_TUNNEL_DR_FH_MEM_MALLOC()  (t_fib_tunnel_dr_fh *)FIB_MALLOC(sizeof (t_fib_tunnel_dr_fh))
#define FIB_TUNNEL_DR_FH_MEM_FREE(_p_) FIB_FREE(_p_)

#define FIB_TUNNEL_FH_MEM_MALLOC()     (t_fib_tunnel_fh *)FIB_MALLOC(sizeof (t_fib_tunnel_fh))
#define FIB_TUNNEL_FH_MEM_FREE(_p_)    FIB_FREE(_p_)

#define FIB_NHT_MEM_MALLOC()            (t_fib_nht *)FIB_MALLOC(sizeof (t_fib_nht))
#define FIB_NHT_MEM_FREE(_p_)           FIB_FREE(_p_)

t_fib_dr *fib_alloc_dr_node (void);

void fib_free_node (t_fib_dr *p_dr);

t_fib_nh *fib_alloc_nh_node (void);

void fib_free_nh_node (t_fib_nh *p_nh);

t_fib_tunnel_fh *fib_alloc_tunnel_fh_node (void);

void fib_free_tunnel_fh_node (t_fib_tunnel_fh *p_tunnel_fh);

t_fib_tunnel_dr_fh *fib_alloc_tunnel_dr_fh_node (void);

void fib_free_tunnel_dr_fh_node (t_fib_tunnel_dr_fh *p_tunnel_dr_fh);

int fib_num_tunnel_fh_nodes (void);

t_fib_nht *fib_alloc_nht_node (void);

void fib_free_nht_node (t_fib_nht *p_nht);


#endif /* __HAL_RT_MEM_H__ */
