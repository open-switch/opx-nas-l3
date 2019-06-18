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
 * nas_rt_offload_cps_unittest.cpp
 * UT to validate the offload message processing functionality in nas-l3
 */


#include "cps_api_events.h"

#include "std_mac_utils.h"
#include "std_ip_utils.h"

#include "dell-base-routing.h"
#include "nas_rt_api.h"
#include "ds_common_types.h"
#include "cps_class_map.h"
#include "cps_api_object.h"
#include "cps_api_operation.h"
#include "cps_class_map.h"
#include "cps_api_object_key.h"

#include "nas_os_l3.h"

#include <sys/time.h>
#include <time.h>
#include <math.h>

#include <gtest/gtest.h>
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

static cps_api_return_code_t nas_ut_rt_cfg (bool is_add, const char *ip_addr, uint32_t prefix_len, uint8_t af)
{
    cps_api_object_t obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
           BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);

    /*
     * Check mandatory route attributes
     *  BASE_ROUTE_OBJ_ENTRY_AF,     BASE_ROUTE_OBJ_VRF_NAME);
     * BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,   BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN;
     */

    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_VRF_NAME, FIB_DEFAULT_VRF_NAME,
                            sizeof(FIB_DEFAULT_VRF_NAME));
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

    uint32_t gw_idx = if_nametoindex("br100");
    ids[1] = 0;
    ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFINDEX;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,
                         (void *)&gw_idx, sizeof(uint32_t));

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_NH_COUNT,1);

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


static cps_api_return_code_t nas_ut_neigh_cfg (bool is_add, const char *ip_addr, uint8_t af)
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
    const char *if_name = "br100";
    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_IFNAME, if_name, strlen(if_name)+1);

    hal_mac_addr_t hw_addr = {0x00, 0x02, 0x03, 0x04, 0x05, 0x06};

    char mac_addr[256];
    memset(mac_addr, '\0', sizeof(mac_addr));
    std_mac_to_string (&hw_addr, mac_addr, 256);
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

static void nas_route_dump_arp_object_content(cps_api_object_t obj){
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
            std::cout<<"VRF-name "<<vrf_name<<std::endl;
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

static cps_api_return_code_t nas_ut_validate_neigh_cfg (const char *ip_addr, uint8_t af)
{
    cps_api_return_code_t rc = cps_api_ret_code_ERR;
    cps_api_get_params_t gp;
    cps_api_get_request_init(&gp);

    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);


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
            }
        }

    }

    cps_api_get_request_close(&gp);
    return rc;
}


static cps_api_return_code_t nas_rt_offload_ut_v4_cfg_add ()
{
    nas_ut_rt_cfg (1, "101.101.101.0", 24, AF_INET);
    nas_ut_neigh_cfg (1, "101.101.101.10", AF_INET);

    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_rt_offload_ut_v6_cfg_add ()
{
    nas_ut_rt_cfg (1, "101:101::0", 64, AF_INET6);
    nas_ut_neigh_cfg (1, "101:101::10", AF_INET6);

    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_rt_offload_validate_v4_cfg(bool is_add)
{
    cps_api_return_code_t rc = nas_ut_validate_neigh_cfg ("101.101.101.10", AF_INET);

    return rc;
}

static cps_api_return_code_t nas_rt_offload_validate_v6_cfg(bool is_add)
{
    cps_api_return_code_t rc = nas_ut_validate_neigh_cfg ("101:101::10", AF_INET6);

    return rc;

}

static cps_api_return_code_t nas_rt_offload_ut_v4_cfg_del ()
{
    nas_ut_rt_cfg (0, "101.101.101.0", 24, AF_INET);
    nas_ut_neigh_cfg (0, "101.101.101.10", AF_INET);

    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_rt_offload_ut_v6_cfg_del ()
{
    nas_ut_rt_cfg (0, "101:101::0", 64, AF_INET6);
    nas_ut_neigh_cfg (0, "101:101::10", AF_INET6);

    return cps_api_ret_code_OK;
}


TEST(std_nas_route_test, nas_rt_offload_ut) {
    cps_api_return_code_t rc;
    nas_rt_offload_ut_v4_cfg_add();
    nas_rt_offload_ut_v6_cfg_add();

    /* wait for few secs after configuration, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_rt_offload_validate_v4_cfg(1);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    rc = nas_rt_offload_validate_v6_cfg(1);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    nas_rt_offload_ut_v4_cfg_del();
    nas_rt_offload_ut_v6_cfg_del();

    /* wait for few secs after config delete, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_rt_offload_validate_v4_cfg(0);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);

    rc = nas_rt_offload_validate_v6_cfg(0);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);


  /* configure the test pre-requisite */
  printf("___________________________________________\n");
  system("ip address add 6.6.6.1/24  dev e101-005-0");
  system("ifconfig e101-005-0");
  /* Incase of premium package, all the ports are part of default bridge,
   * remove it from the bridge to operate as the router intf. */
  system("brctl addbr br100 up");
  system("ifconfig br100 down");
  system("ip link add link e101-003-0 name e101-003-0.100 type vlan id 100");
  system("ifconfig e101-003-0 up");
  system("ip link set dev e101-003-0.100 up");
  system("brctl addif br100 e101-003-0.100");
  system("ip addr add 100.1.1.2/24 dev br100");
  system("ip neigh add 100.1.1.10 lladdr 00:00:00:00:11:22");
  system("ifconfig br100 up");
  system("brctl stp br100 on");

  system("brctl addbr br200 up");
  system("ip link add link e101-003-0 name e101-003-0.200 type vlan id 200");
  system("ifconfig e101-003-0 up");
  system("ip link set dev e101-003-0.200 up");
  system("brctl addif br200 e101-003-0.200");
  system("ip addr add 200.1.1.2/24 dev br200");
  system("ifconfig br200 up");
  system("brctl stp br200 on");

  printf("___________________________________________\n");

  return RUN_ALL_TESTS();
}
