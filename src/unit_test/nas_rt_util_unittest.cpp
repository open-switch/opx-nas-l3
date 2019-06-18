/*
 * Copyright (c) 2018 Dell Inc.
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

/*
 * nas_rt_util_unittest.cpp
 * Utility functions used by unit tests
 */


#include "nas_rt_util_unittest.h"

#include "dell-base-routing.h"
#include "nas_os_l3.h"
#include "nas_rt_api.h"
#include "vrf-mgmt.h"
#include "ietf-network-instance.h"

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

cps_api_return_code_t nas_ut_vrf_cfg (const char *vrf_name, bool is_add)
{
    cps_api_return_code_t rc = cps_api_ret_code_OK;
    cps_api_object_t obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    NI_NETWORK_INSTANCES_OBJ,cps_api_qualifier_TARGET);

    cps_api_object_attr_add(obj,NI_NETWORK_INSTANCES_NETWORK_INSTANCE_NAME, vrf_name,
                            strlen(vrf_name)+1);
    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    (void)cps_api_transaction_init(&tr);

    if (is_add)
        cps_api_create(&tr,obj);
    else
        cps_api_delete(&tr,obj);

    rc = cps_api_commit(&tr);
    cps_api_transaction_close(&tr);

    return rc;
}

cps_api_return_code_t nas_ut_intf_vrf_cfg (const char *vrf_name, const char *if_name, bool is_add)
{
    cps_api_return_code_t rc = cps_api_ret_code_OK;
    cps_api_object_t obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    VRF_MGMT_INTF_BIND_NI_OBJ,cps_api_qualifier_TARGET);

    cps_api_object_attr_add(obj,VRF_MGMT_INTF_BIND_NI_INPUT_NI_NAME, vrf_name,
                            strlen(vrf_name)+1);
    cps_api_object_attr_add(obj,VRF_MGMT_INTF_BIND_NI_INPUT_INTERFACE, if_name,
                            strlen(if_name)+1);
    cps_api_object_attr_add_u32(obj,VRF_MGMT_INTF_BIND_NI_INPUT_OPERATION,
                                (is_add ? BASE_CMN_OPERATION_TYPE_CREATE : BASE_CMN_OPERATION_TYPE_DELETE));
    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    (void)cps_api_transaction_init(&tr);

    rc = cps_api_action(&tr,obj);

    (void)cps_api_commit(&tr);

    if (is_add && (rc == cps_api_ret_code_OK)) {
        cps_api_object_attr_t if_index  = cps_api_object_attr_get(obj, VRF_MGMT_INTF_BIND_NI_OUTPUT_IFINDEX);
        const char *rt_if_name = (const char *)cps_api_object_get_data(obj,
                                                                    VRF_MGMT_INTF_BIND_NI_OUTPUT_IFNAME);
        const char *mac_addr = (const char *)cps_api_object_get_data(obj,
                                                                     VRF_MGMT_INTF_BIND_NI_OUTPUT_MAC_ADDR);
        if ((if_index == nullptr) || (rt_if_name == nullptr) || (mac_addr == nullptr)) {
            return cps_api_ret_code_ERR;
        }
        std::cout<<"VRF:"<<vrf_name<<" If-name:"<<if_name<<std::endl;
        std::cout<<"Router If-name:"<<rt_if_name<<" If-index:"<<cps_api_object_attr_data_u32(if_index)<<" mac-addr:"<<mac_addr<<std::endl;
    }
    cps_api_transaction_close(&tr);

    return rc;
}

cps_api_return_code_t nas_ut_intf_mgmt_vrf_cfg (const char *vrf_name, const char *if_name, bool is_add)
{
    cps_api_return_code_t rc = cps_api_ret_code_OK;
    cps_api_object_t obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    NI_IF_INTERFACES_INTERFACE_OBJ,cps_api_qualifier_TARGET);

    cps_api_object_attr_add(obj,NI_IF_INTERFACES_INTERFACE_BIND_NI_NAME, vrf_name,
                            strlen(vrf_name)+1);
    cps_api_object_attr_add(obj,IF_INTERFACES_INTERFACE_NAME, if_name,
                            strlen(if_name)+1);
    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    (void)cps_api_transaction_init(&tr);

    if (is_add)
        cps_api_create(&tr,obj);
    else
        cps_api_delete(&tr,obj);

    rc = cps_api_commit(&tr);
    cps_api_transaction_close(&tr);

    return rc;
}


cps_api_return_code_t nas_ut_rt_cfg (const char *rt_vrf_name, bool is_add, const char *ip_addr, uint32_t prefix_len,
                                     uint8_t af, const char *nh_vrf_name, const char *nh_addr, const char *if_name, bool is_onlink_nh,
                                     bool is_replace)
{
    cps_api_object_t obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
           BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);

    /*
     * Check mandatory route attributes
     */

    if (rt_vrf_name) {
        cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_VRF_NAME, rt_vrf_name,
                                strlen(rt_vrf_name)+1);
    }
    if (nh_vrf_name) {
        cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_ENTRY_NH_VRF_NAME, nh_vrf_name,
                                strlen(nh_vrf_name)+1);
    }

    if (af == AF_INET) {
        cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_AF,AF_INET);

        uint32_t ip;
        struct in_addr a;
        inet_aton(ip_addr, &a);
        ip=a.s_addr;

        cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,&ip,sizeof(ip));
    } else if (af == AF_INET6) {
        cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_AF,AF_INET6);

        struct in6_addr a6;
        inet_pton(AF_INET6, ip_addr, &a6);

        cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,&a6,sizeof(struct in6_addr));
    }

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN,prefix_len);

    cps_api_attr_id_t ids[3];
    const int ids_len = sizeof(ids)/sizeof(*ids);
    ids[0] = BASE_ROUTE_OBJ_ENTRY_NH_LIST;

    if (if_name) {
        ids[1] = 0;
        ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFNAME;
        cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,
                             if_name, strlen(if_name)+1);
    }
    if (nh_addr) {
        ids[1] = 0;
        ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR;

        if (af == AF_INET) {
            uint32_t ip;
            struct in_addr a;
            inet_aton(nh_addr, &a);
            ip=a.s_addr;

            cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,
                                 &ip, sizeof(ip));
        } else if (af == AF_INET6) {

            struct in6_addr a6;
            inet_pton(AF_INET6, nh_addr, &a6);

            cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,
                                 &a6, sizeof(struct in6_addr));
        }
        if (is_onlink_nh) {
            uint32_t onlink_nh = BASE_ROUTE_NH_FLAGS_ONLINK;
            ids[1] = 0;
            ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_FLAGS;
            cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,
                                 &onlink_nh, sizeof(uint32_t));
        }
    }
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_NH_COUNT,1);
    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    (void)cps_api_transaction_init(&tr);

    if (is_add) {
        if (is_replace) {
            cps_api_set(&tr,obj);
        } else {
            cps_api_create(&tr,obj);
        }
    } else {
        cps_api_delete(&tr,obj);
    }

    (void)cps_api_commit(&tr);
    cps_api_transaction_close(&tr);

    return cps_api_ret_code_OK;
}

cps_api_return_code_t nas_ut_rt_ipv6_nh_cfg (const char *rt_vrf_name, bool is_add, const char *ip_addr,
                                             uint32_t prefix_len, uint8_t af, const char *nh_vrf_name,
                                             const char *nh_addr1, const char *if_name1,
                                             const char *nh_addr2, const char *if_name2)
{
    if (af != AF_INET6)
    {
        return cps_api_ret_code_ERR;
    }
    cps_api_object_t obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
           BASE_ROUTE_ROUTE_NH_OPERATION_OBJ,cps_api_qualifier_TARGET);

    if (rt_vrf_name) {
        cps_api_object_attr_add(obj,BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_VRF_NAME, rt_vrf_name,
                                strlen(rt_vrf_name)+1);
    }
    if (nh_vrf_name) {
        cps_api_object_attr_add(obj,BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_VRF_NAME, nh_vrf_name,
                                strlen(nh_vrf_name)+1);
    }


    /*
     * Check mandatory route attributes
     */

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_AF,AF_INET6);

    struct in6_addr a6;
    inet_pton(AF_INET6, ip_addr, &a6);

    cps_api_object_attr_add(obj,BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_ROUTE_PREFIX,&a6,sizeof(struct in6_addr));

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_PREFIX_LEN,prefix_len);

    cps_api_attr_id_t ids[3];
    int nh_count = 0;
    const int ids_len = sizeof(ids)/sizeof(*ids);
    ids[0] = BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_LIST;

    if (if_name1) {
        if ((rt_vrf_name == NULL) ||
            ((strlen(rt_vrf_name) == strlen("default")) &&
             (strncmp(rt_vrf_name, "default", strlen("default")) == 0))) {
            uint32_t gw_idx = if_nametoindex(if_name1);
            ids[1] = 0;
            ids[2] = BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_LIST_IFINDEX;
            cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,
                                 (void *)&gw_idx, sizeof(uint32_t));
        }
        ids[1] = 0;
        ids[2] = BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_LIST_IFNAME;
        cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,
                             (void *)if_name1, sizeof(if_name1)+1);
        nh_count = 1;
    }
    if (nh_addr1) {
        ids[1] = 0;
        ids[2] = BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_LIST_NH_ADDR;

        struct in6_addr a6;
        inet_pton(AF_INET6, nh_addr1, &a6);

        cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,
                             &a6, sizeof(struct in6_addr));
        nh_count = 1;
    }

    if (if_name2) {
        if ((rt_vrf_name == NULL) ||
            ((strlen(rt_vrf_name) == strlen("default")) &&
             (strncmp(rt_vrf_name, "default", strlen("default")) == 0))) {
            uint32_t gw_idx = if_nametoindex(if_name2);
            ids[1] = 1;
            ids[2] = BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_LIST_IFINDEX;
            cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,
                                 (void *)&gw_idx, sizeof(uint32_t));
        }

        ids[1] = 1;
        ids[2] = BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_LIST_IFNAME;
        cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,
                             (void *)if_name2, sizeof(if_name2)+1);
        nh_count = 2;
    }
    if (nh_addr2) {
        ids[1] = 1;
        ids[2] = BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_LIST_NH_ADDR;

        struct in6_addr a6;
        inet_pton(AF_INET6, nh_addr2, &a6);

        cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,
                             &a6, sizeof(struct in6_addr));
        nh_count = 2;
    }

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_NH_COUNT,nh_count);
    if (is_add)
        cps_api_object_attr_add_u32(obj,BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_OPERATION,BASE_ROUTE_RT_OPERATION_TYPE_APPEND);
    else
        cps_api_object_attr_add_u32(obj,BASE_ROUTE_ROUTE_NH_OPERATION_INPUT_OPERATION,BASE_ROUTE_RT_OPERATION_TYPE_DELETE);
    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    (void)cps_api_transaction_init(&tr);

    (void)cps_api_action(&tr,obj);

    (void)cps_api_commit(&tr);
    cps_api_transaction_close(&tr);

    return cps_api_ret_code_OK;
}


cps_api_return_code_t nas_ut_neigh_cfg (bool is_add, const char *ip_addr, uint8_t af, const char *if_name, hal_mac_addr_t *hw_addr)
{

    cps_api_object_t obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
              BASE_ROUTE_OBJ_NBR,cps_api_qualifier_TARGET);

    if (af == AF_INET) {
        cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_AF,AF_INET);

        uint32_t ip;
        struct in_addr a;
        inet_aton(ip_addr, &a);
        ip=a.s_addr;

        cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_ADDRESS,&ip,sizeof(ip));
    } else if (af == AF_INET6) {
        cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_AF,AF_INET6);

        struct in6_addr a6;
        inet_pton(AF_INET6, ip_addr, &a6);

        cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_ADDRESS,&a6,sizeof(struct in6_addr));
    }

    //cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_TYPE,BASE_ROUTE_RT_TYPE_STATIC);
    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_IFNAME, if_name, strlen(if_name)+1);

    char mac_addr[256];
    memset(mac_addr, '\0', sizeof(mac_addr));
    std_mac_to_string (hw_addr, mac_addr, 256);
    cps_api_object_attr_add(obj, BASE_ROUTE_OBJ_NBR_MAC_ADDR, (const void *)mac_addr,
                            strlen(mac_addr)+1);

    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    (void)cps_api_transaction_init(&tr);

    if (is_add)
        cps_api_create(&tr,obj);
    else
        cps_api_delete(&tr,obj);

    (void)cps_api_commit(&tr);

    cps_api_transaction_close(&tr);

    return cps_api_ret_code_OK;
}

void nas_route_dump_arp_object_content(cps_api_object_t obj){
    void *p_ip_addr = NULL;
    uint32_t af = 0;
    char str[INET6_ADDRSTRLEN];

    cps_api_object_it_t it;
    cps_api_object_it_begin(obj,&it);

    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {

        switch (cps_api_object_attr_id(it.attr)) {

        case BASE_ROUTE_OBJ_NBR_ADDRESS:
            p_ip_addr = cps_api_object_attr_data_bin(it.attr);

            if (af == AF_INET || af == AF_INET6) {
                int addr_len = ((af == AF_INET6)?INET6_ADDRSTRLEN:INET_ADDRSTRLEN);
                std::cout<<"IP Address "<<inet_ntop(af,p_ip_addr,str, addr_len)<<std::endl;
            }
            break;

        case BASE_ROUTE_OBJ_NBR_AF:
            af = cps_api_object_attr_data_u32(it.attr);
            if (p_ip_addr) {
                int addr_len = ((af == AF_INET6)?INET6_ADDRSTRLEN:INET_ADDRSTRLEN);
                if (af == AF_INET || af == AF_INET6)
                    std::cout<<"IP Address "<<inet_ntop(af,p_ip_addr,str,addr_len)<<std::endl;
            }
            break;

        case BASE_ROUTE_OBJ_NBR_MAC_ADDR:
            {
                char mstring[50];
                memset(mstring,'\0',sizeof(mstring));
                memcpy(mstring,cps_api_object_attr_data_bin(it.attr),
                        cps_api_object_attr_len(it.attr));
                std::cout<<"MAC "<<mstring<<std::endl;
            }
            break;

        case BASE_ROUTE_OBJ_NBR_VRF_ID:
            std::cout<<"VRF Id "<<cps_api_object_attr_data_u32(it.attr)<<std::endl;
            break;

        case BASE_ROUTE_OBJ_NBR_IFINDEX:
            std::cout<<"Ifindex "<<cps_api_object_attr_data_u32(it.attr)<<std::endl;
            break;

        case BASE_ROUTE_OBJ_VRF_NAME:
            char vrf_name[256];
            memset(vrf_name,'\0',sizeof(vrf_name));
            memcpy(vrf_name, cps_api_object_attr_data_bin(it.attr), cps_api_object_attr_len(it.attr));
            std::cout<<"VRF-name: "<<vrf_name<<std::endl;
            break;

        case BASE_ROUTE_OBJ_NBR_IFNAME:
            char if_name[256];
            memset(if_name,'\0',sizeof(if_name));
            memcpy(if_name, cps_api_object_attr_data_bin(it.attr), cps_api_object_attr_len(it.attr));
            std::cout<<"If-name "<<if_name<<std::endl;
            break;

        case BASE_ROUTE_OBJ_NBR_FLAGS:
            std::cout<<"Flags "<<cps_api_object_attr_data_u32(it.attr)<<std::endl;
            break;

        case BASE_ROUTE_OBJ_NBR_STATE:
            std::cout<<"State "<<cps_api_object_attr_data_u32(it.attr)<<std::endl;
            break;

        case BASE_ROUTE_OBJ_NBR_TYPE:
            std::cout<<"Type "<<cps_api_object_attr_data_u32(it.attr)<<std::endl;
            break;

        default:
            break;
        }
    }
}

void nas_route_dump_route_object_content(cps_api_object_t obj) {

    char str[INET6_ADDRSTRLEN];
    char if_name[IFNAMSIZ];
    uint32_t addr_len = 0, af_data = 0;
    uint32_t nhc = 0, nh_itr = 0;

    cps_api_object_it_t it;
    cps_api_object_it_begin(obj,&it);

    cps_api_object_attr_t af       = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_AF);
    af_data = cps_api_object_attr_data_u32(af) ;

    addr_len = ((af_data == AF_INET) ? INET_ADDRSTRLEN: INET6_ADDRSTRLEN);

    const char *rt_vrf_name = (const char *)cps_api_object_get_data(obj,
                                                                    BASE_ROUTE_OBJ_VRF_NAME);
    const char *nh_vrf_name = (const char *)cps_api_object_get_data(obj,
                                                                    BASE_ROUTE_OBJ_ENTRY_NH_VRF_NAME);
    cps_api_object_attr_t prefix   = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX);
    cps_api_object_attr_t pref_len = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN);
    cps_api_object_attr_t nh_count = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_NH_COUNT);
    std::cout<<"Route VRF:"<<rt_vrf_name<<" NH VRF:"<<nh_vrf_name<<" AF "<<((af_data == AF_INET) ? "IPv4" : "IPv6")<<","<<
        (prefix ? inet_ntop(af_data, cps_api_object_attr_data_bin(prefix), str,addr_len) :"")<<"/"<<
        (pref_len ? cps_api_object_attr_data_u32(pref_len) : 0) <<std::endl;
    if (nh_count != CPS_API_ATTR_NULL) {
        nhc = cps_api_object_attr_data_u32(nh_count);
        std::cout<<"NHC "<<nhc<<std::endl;
    }

    for (nh_itr = 0; nh_itr < nhc; nh_itr++)
    {
        cps_api_attr_id_t ids[3] = { BASE_ROUTE_OBJ_ENTRY_NH_LIST,
            0, BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR};
        const int ids_len = sizeof(ids)/sizeof(*ids);
        ids[1] = nh_itr;

        cps_api_object_attr_t attr = cps_api_object_e_get(obj,ids,ids_len);
        if (attr != CPS_API_ATTR_NULL)
            std::cout<<"NextHop "<<inet_ntop(af_data,cps_api_object_attr_data_bin(attr),str,addr_len)<<std::endl;

        ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFINDEX;
        attr = cps_api_object_e_get(obj,ids,ids_len);
        if (attr != CPS_API_ATTR_NULL)
            if_indextoname((int)cps_api_object_attr_data_u32(attr), if_name);
        std::cout<<"IfIndex "<<if_name<<"("<<cps_api_object_attr_data_u32(attr)<<")"<<std::endl;

        ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_WEIGHT;
        attr = cps_api_object_e_get(obj,ids,ids_len);
        if (attr != CPS_API_ATTR_NULL)
            std::cout<<"Weight "<<cps_api_object_attr_data_u32(attr)<<std::endl;

        ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_RESOLVED;
        attr = cps_api_object_e_get(obj,ids,ids_len);
        if (attr != CPS_API_ATTR_NULL)
            std::cout<<"Is Next Hop Resolved "<<cps_api_object_attr_data_u32(attr)<<std::endl;

        ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_FLAGS;
        attr = cps_api_object_e_get(obj,ids,ids_len);
        if (attr != CPS_API_ATTR_NULL)
            std::cout<<"Is Next Hop onlink "<<cps_api_object_attr_data_u32(attr)<<std::endl;
    }
}


cps_api_return_code_t nas_ut_validate_neigh_cfg (const char *vrf_name, uint32_t af, const char *ip_addr,
                                                 uint32_t state, bool should_exist_in_npu, const char *nh_vrf_name)
{
    cps_api_return_code_t rc = cps_api_ret_code_ERR;
    cps_api_get_params_t gp;
    cps_api_get_request_init(&gp);

    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
              BASE_ROUTE_OBJ_NBR,cps_api_qualifier_TARGET);

    cps_api_set_key_data(obj,BASE_ROUTE_OBJ_VRF_NAME, cps_api_object_ATTR_T_BIN, vrf_name,
                            strlen(vrf_name)+1);
    if (af == AF_INET) {
        cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_AF,AF_INET);

        uint32_t ip;
        struct in_addr a;
        inet_aton(ip_addr, &a);
        ip=a.s_addr;

        cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_ADDRESS,&ip,sizeof(ip));
    } else if (af == AF_INET6) {
        cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_AF,AF_INET6);

        struct in6_addr a6;
        inet_pton(AF_INET6, ip_addr, &a6);

        cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_ADDRESS,&a6,sizeof(struct in6_addr));
    }

   if (cps_api_get(&gp)==cps_api_ret_code_OK) {
       size_t mx = cps_api_object_list_size(gp.list);
        if (mx)
        {
            rc = cps_api_ret_code_OK;
            std::cout<<"ARP ENTRY "<<std::endl;
            std::cout<<"================================="<<std::endl;

            for ( size_t ix = 0 ; ix < mx ; ++ix ) {
                obj = cps_api_object_list_get(gp.list,ix);

                nas_route_dump_arp_object_content(obj);
                std::cout<<std::endl;
                std::cout<<"================================="<<std::endl;
                cps_api_object_attr_t prg_done_attr = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_NBR_NPU_PRG_DONE);
                cps_api_object_attr_t state_attr = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_NBR_STATE);
                if ((prg_done_attr == nullptr) || (state_attr == nullptr)) {
                    rc = cps_api_ret_code_ERR;
                    break;
                }

                const char *nh_obj_vrf_name = (const char *)cps_api_object_get_data(obj, BASE_ROUTE_OBJ_NBR_VRF_NAME);
                if (nh_vrf_name) {
                    if (nh_obj_vrf_name == NULL) {
                        rc = cps_api_ret_code_ERR;
                        break;
                    }
                    if (strncmp(nh_vrf_name, nh_obj_vrf_name, strlen(nh_vrf_name))) {
                        std::cout<<"Nbr NH Expected: "<<nh_vrf_name<<" Actual: "<<nh_obj_vrf_name<<std::endl;
                        rc = cps_api_ret_code_ERR;
                        break;
                    }
                }
                if (should_exist_in_npu && (cps_api_object_attr_data_u32(prg_done_attr) == false)) {
                    std::cout<<"IP nbr not exist in NPU:"<<std::endl;
                    rc = cps_api_ret_code_ERR;
                    break;
                }
                uint32_t state_val = cps_api_object_attr_data_u32(state_attr);
                if (state_val != state) {
                    if ((state == 2) && (state_val == 4)) {
                        /* Sometimes state is 4 (stale) instead of 2 (reachable), this is expected during refresh in progress. */
                    } else {
                        std::cout<<"Nbr state Expected: "<<state<<" Actual: "<<state_val<<std::endl;
                        rc = cps_api_ret_code_ERR;
                        break;
                    }
                }
            }
        }

    }

    cps_api_get_request_close(&gp);
    return rc;
}

cps_api_return_code_t nas_ut_validate_rt_cfg (const char *rt_vrf_name, uint32_t af, const char *ip_addr, uint32_t prefix_len,
                                              const char *nh_vrf_name, const char *nh_addr, const char *if_name, bool should_exist_in_npu,
                                              bool is_onlink_nh)
{
    cps_api_return_code_t rc = cps_api_ret_code_ERR;
    cps_api_get_params_t gp;
    cps_api_get_request_init(&gp);

    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),BASE_ROUTE_OBJ_ENTRY,
                                    cps_api_qualifier_TARGET);

    cps_api_set_key_data(obj,BASE_ROUTE_OBJ_VRF_NAME, cps_api_object_ATTR_T_BIN, rt_vrf_name,
                         strlen(rt_vrf_name)+1);
    cps_api_set_key_data(obj,BASE_ROUTE_OBJ_ENTRY_AF,cps_api_object_ATTR_T_U32,
                         &af,sizeof(af));

    if (af == AF_INET) {
        uint32_t ip;
        struct in_addr a;
        inet_aton(ip_addr, &a);
        ip=a.s_addr;

        cps_api_set_key_data(obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,cps_api_object_ATTR_T_BIN, &ip,sizeof(ip));
    } else if (af == AF_INET6) {
        struct in6_addr a6;
        inet_pton(AF_INET6, ip_addr, &a6);

        cps_api_set_key_data (obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,cps_api_object_ATTR_T_BIN, &a6,sizeof(struct in6_addr));
    }
    cps_api_set_key_data (obj,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN, cps_api_object_ATTR_T_U32, &prefix_len, sizeof (prefix_len));

    if (cps_api_get(&gp)==cps_api_ret_code_OK) {
        size_t mx = cps_api_object_list_size(gp.list);
        if (mx)
        {
            rc = cps_api_ret_code_OK;

            std::cout<<"IP FIB Entries, Family:"<<af<<std::endl;
            std::cout<<"================================="<<std::endl;
            for ( size_t ix = 0 ; ix < mx ; ++ix ) {
                obj = cps_api_object_list_get(gp.list,ix);

                const char *nh_obj_vrf_name = (const char *)cps_api_object_get_data(obj, BASE_ROUTE_OBJ_ENTRY_NH_VRF_NAME);
                if (nh_vrf_name) {
                    if (nh_obj_vrf_name == NULL) {
                        rc = cps_api_ret_code_ERR;
                        break;
                    }
                    if (strncmp(nh_vrf_name, nh_obj_vrf_name, strlen(nh_vrf_name))) {
                        std::cout<<"Route NH Expected: "<<nh_vrf_name<<" Actual: "<<nh_obj_vrf_name<<std::endl;
                        rc = cps_api_ret_code_ERR;
                        break;
                    }
                }

                cps_api_object_attr_t prg_done = cps_api_object_attr_get(obj,
                                                                         BASE_ROUTE_OBJ_ENTRY_NPU_PRG_DONE);
                if (prg_done && (cps_api_object_attr_data_u32(prg_done))) {
                    if (should_exist_in_npu == false) {
                        std::cout<<"IP route not exist in NPU:"<<std::endl;
                        rc = cps_api_ret_code_ERR;
                    }
                } else {
                    if (should_exist_in_npu) {
                        std::cout<<"IP route exists in NPU:"<<std::endl;
                        rc = cps_api_ret_code_ERR;
                    }
                }
                if (is_onlink_nh) {
                    uint32_t nhc = 0, nh_itr = 0;
                    cps_api_object_attr_t nh_count = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_NH_COUNT);
                    if (nh_count != CPS_API_ATTR_NULL) {
                        nhc = cps_api_object_attr_data_u32(nh_count);
                    }

                    for (nh_itr = 0; nh_itr < nhc; nh_itr++)
                    {
                        cps_api_attr_id_t ids[3] = { BASE_ROUTE_OBJ_ENTRY_NH_LIST,
                            0, BASE_ROUTE_OBJ_ENTRY_NH_LIST_FLAGS};
                        const int ids_len = sizeof(ids)/sizeof(*ids);
                        ids[1] = nh_itr;

                        cps_api_object_attr_t attr = cps_api_object_e_get(obj,ids,ids_len);
                        if ((attr == CPS_API_ATTR_NULL) || (cps_api_object_attr_data_u32(attr) != BASE_ROUTE_NH_FLAGS_ONLINK)) {
                            std::cout<<"NH is not onlink"<<std::endl;
                            rc = cps_api_ret_code_ERR;
                        }
                    }
                }
                nas_route_dump_route_object_content(obj);
                std::cout<<std::endl;
            }
        }
    }

    cps_api_get_request_close(&gp);
    return rc;
}

cps_api_return_code_t nas_ut_validate_rt_ecmp_cfg (const char *rt_vrf_name, uint32_t af, const char *ip_addr, uint32_t prefix_len,
                                              const char *nh_vrf_name, const char *nh_addr, const char *if_name, bool should_exist_in_npu, uint32_t rt_nh_cnt)
{
    cps_api_return_code_t rc = cps_api_ret_code_ERR;
    cps_api_get_params_t gp;
    cps_api_get_request_init(&gp);

    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),BASE_ROUTE_OBJ_ENTRY,
                                    cps_api_qualifier_TARGET);

    cps_api_set_key_data(obj,BASE_ROUTE_OBJ_VRF_NAME, cps_api_object_ATTR_T_BIN, rt_vrf_name,
                         strlen(rt_vrf_name)+1);
    cps_api_set_key_data(obj,BASE_ROUTE_OBJ_ENTRY_AF,cps_api_object_ATTR_T_U32,
                         &af,sizeof(af));

    if (af == AF_INET) {
        uint32_t ip;
        struct in_addr a;
        inet_aton(ip_addr, &a);
        ip=a.s_addr;

        cps_api_set_key_data(obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,cps_api_object_ATTR_T_BIN, &ip,sizeof(ip));
    } else if (af == AF_INET6) {
        struct in6_addr a6;
        inet_pton(AF_INET6, ip_addr, &a6);

        cps_api_set_key_data (obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,cps_api_object_ATTR_T_BIN, &a6,sizeof(struct in6_addr));
    }
    cps_api_set_key_data (obj,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN, cps_api_object_ATTR_T_U32, &prefix_len, sizeof (prefix_len));

    if (cps_api_get(&gp)==cps_api_ret_code_OK) {
        size_t mx = cps_api_object_list_size(gp.list);
        if (mx)
        {
            rc = cps_api_ret_code_OK;
            std::cout<<"Route get successful"<<std::endl;
            cps_api_object_attr_t nh_count = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_NH_COUNT);
            if (nh_count) {
                uint32_t nhc = cps_api_object_attr_data_u32(nh_count);
            std::cout<<"Route get successful"<<nhc<<std::endl;
                if (nhc != rt_nh_cnt) {
                    cps_api_get_request_close(&gp);
                    return (cps_api_ret_code_ERR);
                }
            }
            std::cout<<"IP FIB Entries, Family:"<<af<<std::endl;
            std::cout<<"================================="<<std::endl;
            for ( size_t ix = 0 ; ix < mx ; ++ix ) {
                obj = cps_api_object_list_get(gp.list,ix);
                cps_api_object_attr_t prg_done = cps_api_object_attr_get(obj,
                                                                         BASE_ROUTE_OBJ_ENTRY_NPU_PRG_DONE);
                if (prg_done && (cps_api_object_attr_data_u32(prg_done))) {
                    std::cout<<"IP route exists in NPU:"<<std::endl;
                    if (should_exist_in_npu == false) {
                        rc = cps_api_ret_code_ERR;
                    }
                } else {
                    if (should_exist_in_npu) {
                        rc = cps_api_ret_code_ERR;
                    }
                    std::cout<<"IP route not exist in NPU:"<<std::endl;
                }
                nas_route_dump_route_object_content(obj);
                std::cout<<std::endl;
            }
        }
    }

    cps_api_get_request_close(&gp);
    return rc;
}


cps_api_return_code_t nas_ut_route_op_spl_nh (bool is_add, const char *vrf_name, const char *ip_addr, uint32_t prefix_len,
                             uint32_t spl_nh_option, uint8_t af)
{
    cps_api_return_code_t rc = cps_api_ret_code_ERR;
    cps_api_object_t obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
           BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);

    /*
     * Check mandatory route attributes
     *  BASE_ROUTE_OBJ_ENTRY_AF,     BASE_ROUTE_OBJ_VRF_NAME);
     * BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,   BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN;
     */

    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_VRF_NAME, vrf_name,
                            strlen(vrf_name)+1);
    if (af == AF_INET) {
        cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_AF,AF_INET);

        uint32_t ip;
        struct in_addr a;
        inet_aton(ip_addr, &a);
        ip=a.s_addr;

        cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,&ip,sizeof(ip));
    } else if (af == AF_INET6) {
        cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_AF,AF_INET6);

        struct in6_addr a6;
        inet_pton(AF_INET6, ip_addr, &a6);

        cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,&a6,sizeof(struct in6_addr));
    }

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN,prefix_len);

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_SPECIAL_NEXT_HOP,spl_nh_option);


    if (spl_nh_option == BASE_ROUTE_SPECIAL_NEXT_HOP_RECEIVE) {
        cps_api_attr_id_t ids[3];
        const int ids_len = sizeof(ids)/sizeof(*ids);
        ids[0] = BASE_ROUTE_OBJ_ENTRY_NH_LIST;

        uint32_t gw_idx = if_nametoindex("br100");
        ids[1] = 0;
        ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFINDEX;
        cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,
                             (void *)&gw_idx, sizeof(uint32_t));

        cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_NH_COUNT,1);
    }

    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    rc = cps_api_transaction_init(&tr);
    if (rc != cps_api_ret_code_OK) {
        return cps_api_ret_code_ERR;
    }
    if (is_add)
        cps_api_create(&tr,obj);
    else
        cps_api_delete(&tr,obj);

    rc = cps_api_commit(&tr);
    cps_api_transaction_close(&tr);
    return rc;
}


