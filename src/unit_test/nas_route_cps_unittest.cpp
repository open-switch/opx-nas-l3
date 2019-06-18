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
 * nas_rt_cps_api_unittest.cpp
 *
 *  Created on: May 20, 2015
 *      Author: Satish Mynam
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
#include "nas_rt_util_unittest.h"

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

cps_api_object_list_t list_of_objects;

TEST(std_nas_route_test, nas_route_add_blackhole) {
    nas_ut_route_op_spl_nh (1, "default", "44.1.0.0", 16, BASE_ROUTE_SPECIAL_NEXT_HOP_BLACKHOLE, AF_INET);
    sleep(3);
    cps_api_return_code_t rc = nas_ut_validate_rt_cfg ("default", AF_INET, "44.1.0.0", 16, "default",
                                                       NULL, NULL, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
}

TEST(std_nas_route_test, nas_route_add_unreachable) {
    nas_ut_route_op_spl_nh (1, "default", "44.2.0.0", 16, BASE_ROUTE_SPECIAL_NEXT_HOP_UNREACHABLE, AF_INET);
    sleep(3);
    cps_api_return_code_t rc =  nas_ut_validate_rt_cfg ("default", AF_INET,"44.2.0.0", 16, "default",
                                                       NULL, NULL, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
}

TEST(std_nas_route_test, nas_route_add_prohibit) {
    nas_ut_route_op_spl_nh (1, "default", "44.3.0.0", 16, BASE_ROUTE_SPECIAL_NEXT_HOP_PROHIBIT, AF_INET);
    sleep(3);
    cps_api_return_code_t rc =  nas_ut_validate_rt_cfg ("default", AF_INET,"44.3.0.0", 16, "default",
                                                       NULL, NULL, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
}

TEST(std_nas_route_test, nas_route_add_receive) {
    nas_ut_route_op_spl_nh (1, "default", "44.4.0.0", 16, BASE_ROUTE_SPECIAL_NEXT_HOP_RECEIVE, AF_INET);
    sleep(3);
    cps_api_return_code_t rc =  nas_ut_validate_rt_cfg ("default", AF_INET,"44.4.0.0", 16, "default",
                                                       NULL, NULL, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
}

TEST(std_nas_route_test, nas_route_del_blackhole) {
    nas_ut_route_op_spl_nh (0, "default", "44.1.0.0", 16, BASE_ROUTE_SPECIAL_NEXT_HOP_BLACKHOLE, AF_INET);
    sleep(3);
    cps_api_return_code_t rc =  nas_ut_validate_rt_cfg ("default", AF_INET,"44.1.0.0", 16, "default",
                                                       NULL, NULL, true);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);

}

TEST(std_nas_route_test, nas_route_del_unreachable) {
    nas_ut_route_op_spl_nh (0, "default", "44.2.0.0", 16, BASE_ROUTE_SPECIAL_NEXT_HOP_UNREACHABLE, AF_INET);
    sleep(3);
    cps_api_return_code_t rc =  nas_ut_validate_rt_cfg ("default", AF_INET,"44.2.0.0", 16, "default",
                                                       NULL, NULL, true);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);

}

TEST(std_nas_route_test, nas_route_del_prohibit) {
    nas_ut_route_op_spl_nh (0, "default", "44.3.0.0", 16, BASE_ROUTE_SPECIAL_NEXT_HOP_PROHIBIT, AF_INET);
    sleep(3);
    cps_api_return_code_t rc =  nas_ut_validate_rt_cfg ("default", AF_INET,"44.3.0.0", 16, "default",
                                                       NULL, NULL, true);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);
}

TEST(std_nas_route_test, nas_route_del_receive) {
    nas_ut_route_op_spl_nh (0, "default", "44.4.0.0", 16, BASE_ROUTE_SPECIAL_NEXT_HOP_RECEIVE, AF_INET);
    sleep(3);
    cps_api_return_code_t rc =  nas_ut_validate_rt_cfg ("default", AF_INET,"44.4.0.0", 16, "default",
                                                       NULL, NULL, true);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);

}

TEST(std_nas_route_test, nas_default_route_add_blackhole) {
    nas_ut_route_op_spl_nh (1, "default", "0.0.0.0", 0, BASE_ROUTE_SPECIAL_NEXT_HOP_BLACKHOLE, AF_INET);
    sleep(5);
    cps_api_return_code_t rc =  nas_ut_validate_rt_cfg ("default", AF_INET,"0.0.0.0", 0, "default",
                                                       NULL, NULL, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
}

TEST(std_nas_route_test, nas_default_route_add_blackhole_when_mgmt_route_exist) {
    system("ip route add default dev eth0");
    nas_ut_route_op_spl_nh (1, "default", "0.0.0.0", 0, BASE_ROUTE_SPECIAL_NEXT_HOP_BLACKHOLE, AF_INET);
    sleep(5);
    cps_api_return_code_t rc =  nas_ut_validate_rt_cfg ("default", AF_INET,"0.0.0.0", 0, "default",
                                                       NULL, NULL, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    system("ip route replace default dev eth0");
    sleep(3);
    rc =  nas_ut_validate_rt_cfg ("default", AF_INET,"0.0.0.0", 0, "default", NULL, NULL, false);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    system("ip route del default dev eth0");
    sleep(3);
    rc =  nas_ut_validate_rt_cfg ("default", AF_INET,"0.0.0.0", 0, "default", NULL, NULL, false);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);
}

TEST(std_nas_route_test, nas_default_route_add_mgmt_route_when_blackhole_route_exist) {
    nas_ut_route_op_spl_nh (1, "default", "0.0.0.0", 0, BASE_ROUTE_SPECIAL_NEXT_HOP_BLACKHOLE, AF_INET);
    sleep(5);
    cps_api_return_code_t rc =  nas_ut_validate_rt_cfg ("default", AF_INET,"0.0.0.0", 0, "default",
                                                       NULL, NULL, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    system("ip route replace default dev eth0");
    sleep(3);
    rc =  nas_ut_validate_rt_cfg ("default", AF_INET,"0.0.0.0", 0, "default", NULL, NULL, false);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    system("ip route del default dev eth0");
    sleep(3);
    rc =  nas_ut_validate_rt_cfg ("default", AF_INET,"0.0.0.0", 0, "default", NULL, NULL, false);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);
}

TEST(std_nas_route_test, nas_default_route_add_unreachable) {
    nas_ut_route_op_spl_nh (1, "default", "0.0.0.0", 0, BASE_ROUTE_SPECIAL_NEXT_HOP_UNREACHABLE, AF_INET);
    sleep(3);
    cps_api_return_code_t rc =  nas_ut_validate_rt_cfg ("default", AF_INET,"0.0.0.0", 0, "default",
                                                       NULL, NULL, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

}

TEST(std_nas_route_test, nas_default_route_add_prohibit) {
    nas_ut_route_op_spl_nh (1, "default", "0.0.0.0", 0, BASE_ROUTE_SPECIAL_NEXT_HOP_PROHIBIT, AF_INET);
    sleep(3);
    cps_api_return_code_t rc =  nas_ut_validate_rt_cfg ("default", AF_INET,"0.0.0.0", 0, "default",
                                                       NULL, NULL, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

}

TEST(std_nas_route_test, nas_default_route_del_blackhole) {
    nas_ut_route_op_spl_nh (0, "default", "0.0.0.0", 0, BASE_ROUTE_SPECIAL_NEXT_HOP_BLACKHOLE, AF_INET);
    sleep(3);
    cps_api_return_code_t rc =  nas_ut_validate_rt_cfg ("default", AF_INET,"0.0.0.0", 0, "default",
                                                       NULL, NULL, true);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);

}

TEST(std_nas_route_test, nas_default_route_del_unreachable) {
    nas_ut_route_op_spl_nh (0, "default", "0.0.0.0", 0, BASE_ROUTE_SPECIAL_NEXT_HOP_UNREACHABLE, AF_INET);
    sleep(3);
    cps_api_return_code_t rc =  nas_ut_validate_rt_cfg ("default", AF_INET,"0.0.0.0", 0, "default",
                                                       NULL, NULL, true);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);

}

TEST(std_nas_route_test, nas_default_route_del_prohibit) {
    nas_ut_route_op_spl_nh (0, "default", "0.0.0.0", 0, BASE_ROUTE_SPECIAL_NEXT_HOP_PROHIBIT, AF_INET);
    sleep(3);
    cps_api_return_code_t rc =  nas_ut_validate_rt_cfg ("default", AF_INET,"0.0.0.0", 0, "default",
                                                       NULL, NULL, true);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);

}


TEST(std_nas_route_test, nas_v6_route_add_blackhole) {
    nas_ut_route_op_spl_nh (1, "default", "1111:1111::", 64, BASE_ROUTE_SPECIAL_NEXT_HOP_BLACKHOLE, AF_INET6);
    sleep(3);
    cps_api_return_code_t rc =  nas_ut_validate_rt_cfg ("default", AF_INET6,"1111:1111::", 64, "default",
                                                       NULL, NULL, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

}

TEST(std_nas_route_test, nas_v6_route_add_unreachable) {
    nas_ut_route_op_spl_nh (1, "default", "1111:2222::", 64, BASE_ROUTE_SPECIAL_NEXT_HOP_UNREACHABLE, AF_INET6);
    sleep(3);
    cps_api_return_code_t rc =  nas_ut_validate_rt_cfg ("default", AF_INET6,"1111:2222::", 64, "default",
                                                       NULL, NULL, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

}

TEST(std_nas_route_test, nas_v6_route_add_prohibit) {
    nas_ut_route_op_spl_nh (1, "default", "1111:3333::", 64, BASE_ROUTE_SPECIAL_NEXT_HOP_PROHIBIT, AF_INET6);
    sleep(3);
    cps_api_return_code_t rc =  nas_ut_validate_rt_cfg ("default", AF_INET6,"1111:3333::", 64,"default",
                                                       NULL, NULL, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

}

TEST(std_nas_route_test, nas_v6_route_add_receive) {
    nas_ut_route_op_spl_nh (1, "default", "1111:4444::", 64, BASE_ROUTE_SPECIAL_NEXT_HOP_RECEIVE, AF_INET6);
    sleep(3);
    cps_api_return_code_t rc =  nas_ut_validate_rt_cfg ("default", AF_INET6,"1111:4444::", 64, "default",
                                                       NULL, NULL, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

}

TEST(std_nas_route_test, nas_v6_route_del_blackhole) {
    nas_ut_route_op_spl_nh (0, "default", "1111:1111::", 64, BASE_ROUTE_SPECIAL_NEXT_HOP_BLACKHOLE, AF_INET6);
    sleep(3);
    cps_api_return_code_t rc =  nas_ut_validate_rt_cfg ("default", AF_INET6,"1111:1111::", 64, "default",
                                                       NULL, NULL, true);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);

}

TEST(std_nas_route_test, nas_v6_route_del_unreachable) {
    nas_ut_route_op_spl_nh (0, "default", "1111:2222::", 64, BASE_ROUTE_SPECIAL_NEXT_HOP_UNREACHABLE, AF_INET6);
    sleep(3);
    cps_api_return_code_t rc =  nas_ut_validate_rt_cfg ("default", AF_INET6,"1111:2222::", 64, "default",
                                                       NULL, NULL, true);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);

}

TEST(std_nas_route_test, nas_v6_route_del_prohibit) {
    nas_ut_route_op_spl_nh (0, "default", "1111:3333::", 64, BASE_ROUTE_SPECIAL_NEXT_HOP_PROHIBIT, AF_INET6);
    sleep(3);
    cps_api_return_code_t rc =  nas_ut_validate_rt_cfg ("default", AF_INET6,"1111:3333::", 64, "default",
                                                       NULL, NULL, true);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);
}

TEST(std_nas_route_test, nas_v6_route_del_receive) {
    nas_ut_route_op_spl_nh (0, "default", "1111:4444::", 64, BASE_ROUTE_SPECIAL_NEXT_HOP_RECEIVE, AF_INET6);
    sleep(3);
    cps_api_return_code_t rc =  nas_ut_validate_rt_cfg ("default", AF_INET6,"1111:4444::", 64, "default",
                                                       NULL, NULL, true);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);
}

void nas_ut_route_test (bool is_add, bool is_set, uint32_t af, const char *prefix, uint32_t prefix_len,
                        const char *gw, uint32_t gw_index, const char *gw_if_name, const char *vrf_name) {
    cps_api_object_t obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_AF, af);
    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_VRF_NAME, vrf_name, strlen(vrf_name)+1);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN,prefix_len);

    if (af == AF_INET) {
        uint32_t ip;
        struct in_addr a;
        inet_aton(prefix,&a);
        ip=a.s_addr;
        cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,&ip,sizeof(ip));
    } else {
        struct in6_addr a6;
        inet_pton(AF_INET6, prefix, &a6);
        cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,&a6,sizeof(struct in6_addr));
    }
    cps_api_attr_id_t ids[3];
    const int ids_len = sizeof(ids)/sizeof(*ids);
    ids[0] = BASE_ROUTE_OBJ_ENTRY_NH_LIST;
    ids[1] = 0;
    ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR;

    if (gw) {
        if (af == AF_INET) {
            uint32_t ip;
            struct in_addr a;
            inet_aton(gw,&a);
            ip=a.s_addr;
            cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,
                                 &ip,sizeof(ip));
        } else {
            struct in6_addr a6;
            inet_pton(AF_INET6, gw, &a6);
            cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,
                                 &a6,sizeof(struct in6_addr));
        }
    }
    //enable below code for route with nexthop interface
    if (gw_index) {
        ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFINDEX;
        cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,
                             (void *)&gw_index, sizeof(uint32_t));
    }
    if (gw_if_name) {
        ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFNAME;
        cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,
                             gw_if_name, strlen(gw_if_name)+1);
    }
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_NH_COUNT,1);

    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    if (is_set)
        cps_api_set(&tr,obj);
    else if (is_add)
        cps_api_create(&tr,obj);
    else
        cps_api_delete(&tr,obj);

    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
}

TEST(std_nas_route_test, nas_mgmt_route_add) {
    nas_ut_route_test(1, 0, AF_INET, "60.0.0.0", 16, "10.11.70.254", 0, "eth0", "default");
    nas_ut_route_test(1, 0, AF_INET, "65.0.0.0", 16, NULL, 0, "eth0", "default");
    nas_ut_route_test(1, 0, AF_INET6, "6::", 64, NULL, 0, "eth0", "default");
}
TEST(std_nas_route_test, nas_mgmt_route_set) {
    nas_ut_route_test(1, 1, AF_INET, "60.0.0.0", 16, NULL, 0, "eth0", "default");
    nas_ut_route_test(1, 1, AF_INET, "65.0.0.0", 16, "10.11.70.254", 0, NULL, "default");
}
TEST(std_nas_route_test, nas_mgmt_route_del) {
    nas_ut_route_test(0, 0, AF_INET, "60.0.0.0", 16, NULL, 0, "eth0", "default");
    nas_ut_route_test(0, 0, AF_INET, "65.0.0.0", 16, "10.11.70.254", 0, NULL, "default");
    nas_ut_route_test(0, 0, AF_INET6, "6::", 64, NULL, 0, "eth0", "default");
}

/*
TEST(std_nas_route_test, nas_mgmt_route_add_mgmt_vrf) {
    nas_ut_route_test(1, 0, AF_INET, "60.0.0.0", 16, "10.11.70.254", 0, "eth0", "management");
    nas_ut_route_test(1, 0, AF_INET, "65.0.0.0", 16, NULL, 0, "eth0", "management");
    nas_ut_route_test(1, 0, AF_INET6, "6::", 64, NULL, 0, "eth0", "management");
}
TEST(std_nas_route_test, nas_mgmt_route_set_mgmt_vrf) {
    nas_ut_route_test(1, 1, AF_INET, "60.0.0.0", 16, NULL, 0, "eth0", "management");
    nas_ut_route_test(1, 1, AF_INET, "65.0.0.0", 16, "10.11.70.254", 0, NULL, "management");
}
TEST(std_nas_route_test, nas_mgmt_route_del_mgmt_vrf) {
    nas_ut_route_test(0, 0, AF_INET, "60.0.0.0", 16, NULL, 0, "eth0", "management");
    nas_ut_route_test(0, 0, AF_INET, "65.0.0.0", 16, "10.11.70.254", 0, NULL, "management");
    nas_ut_route_test(0, 0, AF_INET6, "6::", 64, NULL, 0, "eth0", "management");
}
*/

TEST(std_nas_route_test, nas_default_v6_route_add_blackhole) {
    nas_ut_route_op_spl_nh (1, "default", "0::0", 0, BASE_ROUTE_SPECIAL_NEXT_HOP_BLACKHOLE, AF_INET6);
}

TEST(std_nas_route_test, nas_default_v6_route_add_unreachable) {
    nas_ut_route_op_spl_nh (1, "default", "0::0", 0, BASE_ROUTE_SPECIAL_NEXT_HOP_UNREACHABLE, AF_INET6);
}

TEST(std_nas_route_test, nas_default_v6_route_add_prohibit) {
    nas_ut_route_op_spl_nh (1, "default", "0::0", 0, BASE_ROUTE_SPECIAL_NEXT_HOP_PROHIBIT, AF_INET6);
}

/*
TEST(std_nas_route_test, nas_default_v6_route_del_blackhole) {
    nas_ut_route_op_spl_nh (0, "default", "0::0", 0, BASE_ROUTE_SPECIAL_NEXT_HOP_BLACKHOLE, AF_INET6);
}

TEST(std_nas_route_test, nas_default_v6_route_del_unreachable) {
    nas_ut_route_op_spl_nh (0, "default", "0::0", 0, BASE_ROUTE_SPECIAL_NEXT_HOP_UNREACHABLE, AF_INET6);
}

TEST(std_nas_route_test, nas_default_v6_route_del_prohibit) {
    nas_ut_route_op_spl_nh (0, "default", "0::0", 0, BASE_ROUTE_SPECIAL_NEXT_HOP_PROHIBIT, AF_INET6);
}

*/


TEST(std_nas_route_test, nas_route_add) {

    cps_api_object_t obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
           BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);

    //cps_api_key_init(cps_api_object_key(obj),cps_api_qualifier_TARGET,
       //     cps_api_obj_CAT_BASE_ROUTE, BASE_ROUTE_OBJ_OBJ,0 );

    /*
     * Check mandatory route attributes
     *  BASE_ROUTE_OBJ_ENTRY_AF,     BASE_ROUTE_OBJ_VRF_NAME);
     * BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,   BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN;
     */

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_AF,AF_INET);
    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_VRF_NAME, FIB_DEFAULT_VRF_NAME,
                            sizeof(FIB_DEFAULT_VRF_NAME));
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN,32);

    uint32_t ip;
    struct in_addr a;
    inet_aton("6.6.6.6",&a);
    ip=a.s_addr;

    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,&ip,sizeof(ip));
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN,32);
    cps_api_attr_id_t ids[3];
    const int ids_len = sizeof(ids)/sizeof(*ids);
    ids[0] = BASE_ROUTE_OBJ_ENTRY_NH_LIST;
    ids[1] = 0;
    ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR;

    /*
     * Set Loopback0 NH
     */
    inet_aton("127.0.0.1",&a);
    ip=a.s_addr;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,
                    &ip,sizeof(ip));

    //enable below code for route with nexthop interface
    //uint32_t gw_idx = if_nametoindex("e101-005-0");
    //ids[0] = BASE_ROUTE_OBJ_ENTRY_NH_LIST;
    //ids[1] = 0;
    //ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFINDEX;
    //cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,
    //                     (void *)&gw_idx, sizeof(uint32_t));

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_NH_COUNT,1);

    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_create(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);

}

TEST(std_nas_route_test, nas_route_set) {

    cps_api_object_t obj = cps_api_object_create();
    //cps_api_key_init(cps_api_object_key(obj),cps_api_qualifier_TARGET,
      //      cps_api_obj_CAT_BASE_ROUTE, BASE_ROUTE_OBJ_OBJ,0 );

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
              BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);

    /*
     * Check mandatory route attributes
     *  BASE_ROUTE_OBJ_ENTRY_AF,     BASE_ROUTE_OBJ_VRF_NAME);
     * BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,   BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN;
     * For NH: BASE_ROUTE_OBJ_ENTRY_NH_COUNT, BASE_ROUTE_OBJ_ENTRY_NH_LIST,
     * BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR
     */

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_AF,AF_INET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN,32);
    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_VRF_NAME, FIB_DEFAULT_VRF_NAME,
                            sizeof(FIB_DEFAULT_VRF_NAME));

    uint32_t ip;
    struct in_addr a;
    inet_aton("6.6.6.6",&a);
    ip=a.s_addr;

    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,&ip,sizeof(ip));
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN,32);
    cps_api_attr_id_t ids[3];
    const int ids_len = sizeof(ids)/sizeof(*ids);
    ids[0] = BASE_ROUTE_OBJ_ENTRY_NH_LIST;
    ids[1] = 0;
    ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR;

    inet_aton("127.0.0.2",&a);
    ip=a.s_addr;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,
                    &ip,sizeof(ip));
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_NH_COUNT,1);

    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_set(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);

}


TEST(std_nas_route_test, nas_neighbor_add) {

    cps_api_object_t obj = cps_api_object_create();
    //cps_api_key_init(cps_api_object_key(obj),cps_api_qualifier_TARGET,
    //        cps_api_obj_CAT_BASE_ROUTE, BASE_ROUTE_OBJ_OBJ,0 );

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
              BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_AF,AF_INET);

    uint32_t ip;
    struct in_addr a;
    inet_aton("6.6.6.6",&a);
    ip=a.s_addr;

    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_ADDRESS,&ip,sizeof(ip));
    //int port_index = if_nametoindex("e101-001-0");
    //cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_IFINDEX, port_index);

    const char *if_name = "e101-001-0";
    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_IFNAME, if_name, strlen(if_name)+1);

    hal_mac_addr_t hw_addr = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

    char mac_addr[256];
    memset(mac_addr, '\0', sizeof(mac_addr));
    std_mac_to_string (&hw_addr, mac_addr, 256);
    cps_api_object_attr_add(obj, BASE_ROUTE_OBJ_NBR_MAC_ADDR, (const void *)mac_addr,
                            strlen(mac_addr)+1);
    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_create(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);

}

TEST(std_nas_route_test, nas_neighbor_set) {

    cps_api_object_t obj = cps_api_object_create();
    //cps_api_key_init(cps_api_object_key(obj),cps_api_qualifier_TARGET,
     //       cps_api_obj_CAT_BASE_ROUTE, BASE_ROUTE_OBJ_OBJ,0 );
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
              BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_AF,AF_INET);

    uint32_t ip;
    struct in_addr a;
    inet_aton("6.6.6.6",&a);
    ip=a.s_addr;

    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_ADDRESS,&ip,sizeof(ip));
    //int port_index = if_nametoindex("e101-001-0");
    //cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_IFINDEX, port_index);
    const char *if_name = "e101-001-0";
    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_IFNAME, if_name, strlen(if_name)+1);

    hal_mac_addr_t hw_addr = {0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc};

    char mac_addr[256];
    memset(mac_addr, '\0', sizeof(mac_addr));
    std_mac_to_string (&hw_addr, mac_addr, 256);
    cps_api_object_attr_add(obj, BASE_ROUTE_OBJ_NBR_MAC_ADDR, (const void *)mac_addr,
                            strlen(mac_addr)+1);
    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_set(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
}

TEST(std_nas_route_test, nas_neighbor_delete) {

    cps_api_object_t obj = cps_api_object_create();
    //cps_api_key_init(cps_api_object_key(obj),cps_api_qualifier_TARGET,
     //       cps_api_obj_CAT_BASE_ROUTE, BASE_ROUTE_OBJ_OBJ,0 );
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
              BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_AF,AF_INET);

    uint32_t ip;
    struct in_addr a;
    inet_aton("6.6.6.6",&a);
    ip=a.s_addr;

    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_ADDRESS,&ip,sizeof(ip));
    //int port_index = if_nametoindex("e101-001-0");
    //cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_IFINDEX, port_index);

    const char *if_name = "e101-001-0";
    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_IFNAME, if_name, strlen(if_name)+1);
    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_delete(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
}

TEST(std_nas_route_test, nas_neighbor_add_scale) {
    for (int i1 = 1; i1 < 2; i1++) {
        for (int i2 = 5; i2 <= 245; i2++) {
            cps_api_object_t obj = cps_api_object_create();
            cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                            BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);
            cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_AF,AF_INET);

            cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_TYPE,BASE_ROUTE_RT_TYPE_DYNAMIC);
            uint32_t ip;
            struct in_addr a;
            char ip_addr[256];

            snprintf(ip_addr,256, "100.1.%d.%d",i1,i2);
            inet_aton(ip_addr,&a);
            ip=a.s_addr;

            cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_ADDRESS,&ip,sizeof(ip));
            //int port_index = if_nametoindex("e101-001-0");
            //cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_IFINDEX, port_index);

            const char *if_name = "br100";
            cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_IFNAME, if_name, strlen(if_name)+1);
            hal_mac_addr_t hw_addr = {0x00, 0x00, 0x11, 0xaa, 0, 0};
            hw_addr[4] = i1;
            hw_addr[5] = i2;

            char mac_addr[256];
            memset(mac_addr, '\0', sizeof(mac_addr));
            std_mac_to_string (&hw_addr, mac_addr, 256);
            cps_api_object_attr_add(obj, BASE_ROUTE_OBJ_NBR_MAC_ADDR, (const void *)mac_addr,
                                    strlen(mac_addr)+1);

            /*
             * CPS transaction
             */
            cps_api_transaction_params_t tr;
            ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
            cps_api_create(&tr,obj);
            ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
            cps_api_transaction_close(&tr);
        }
    }
}

TEST(std_nas_route_test, nas_neighbor_refresh_scale) {
    for (int i1 = 1; i1 < 2; i1++) {
        for (int i2 = 5; i2 <= 245; i2++) {
            cps_api_object_t obj = cps_api_object_create();
            cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                            BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);
            cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_AF,AF_INET);

            cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_TYPE,BASE_ROUTE_RT_TYPE_DYNAMIC);
            cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_STATE,BASE_ROUTE_NEIGHBOR_STATE_PROBE);
            uint32_t ip;
            struct in_addr a;
            char ip_addr[256];

            snprintf(ip_addr,256, "100.1.%d.%d",i1,i2);
            inet_aton(ip_addr,&a);
            ip=a.s_addr;

            cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_ADDRESS,&ip,sizeof(ip));
            //int port_index = if_nametoindex("e101-001-0");
            //cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_IFINDEX, port_index);

            const char *if_name = "br100";
            cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_IFNAME, if_name, strlen(if_name)+1);
            hal_mac_addr_t hw_addr = {0x00, 0x00, 0x11, 0xaa, 0, 0};
            hw_addr[4] = i1;
            hw_addr[5] = i2;

            char mac_addr[256];
            memset(mac_addr, '\0', sizeof(mac_addr));
            std_mac_to_string (&hw_addr, mac_addr, 256);
            cps_api_object_attr_add(obj, BASE_ROUTE_OBJ_NBR_MAC_ADDR, (const void *)mac_addr,
                                    strlen(mac_addr)+1);

            /*
             * CPS transaction
             */
            cps_api_transaction_params_t tr;
            ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
            cps_api_set(&tr,obj);
            ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
            cps_api_transaction_close(&tr);
        }
    }
}


TEST(std_nas_route_test, nas_neighbor_set_scale) {
    for (int i1 = 1; i1 < 2; i1++) {
        for (int i2 = 5; i2 <= 245; i2++) {
            cps_api_object_t obj = cps_api_object_create();
            cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                            BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);
            cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_AF,AF_INET);

            cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_TYPE,BASE_ROUTE_RT_TYPE_DYNAMIC);
            uint32_t ip;
            struct in_addr a;
            char ip_addr[256];

            snprintf(ip_addr,256, "100.1.%d.%d",i1,i2);
            inet_aton(ip_addr,&a);
            ip=a.s_addr;

            cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_ADDRESS,&ip,sizeof(ip));
            //int port_index = if_nametoindex("e101-001-0");
            //cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_IFINDEX, port_index);

            const char *if_name = "br100";
            cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_IFNAME, if_name, strlen(if_name)+1);
            hal_mac_addr_t hw_addr = {0x00, 0x00, 0, 0, 0x1, 0x2};
            hw_addr[2] = i1;
            hw_addr[3] = i2;

            char mac_addr[256];
            memset(mac_addr, '\0', sizeof(mac_addr));
            std_mac_to_string (&hw_addr, mac_addr, 256);
            cps_api_object_attr_add(obj, BASE_ROUTE_OBJ_NBR_MAC_ADDR, (const void *)mac_addr,
                                    strlen(mac_addr)+1);

            /*
             * CPS transaction
             */
            cps_api_transaction_params_t tr;
            ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
            cps_api_set(&tr,obj);
            ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
            cps_api_transaction_close(&tr);
        }
    }
}

TEST(std_nas_route_test, nas_neighbor_delete_scale) {
    for (int i1 = 1; i1 <= 2; i1++) {
        for (int i2 = 5; i2 <= 245; i2++) {
            cps_api_object_t obj = cps_api_object_create();
            cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                            BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);
            cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_AF,AF_INET);

            cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_TYPE,BASE_ROUTE_RT_TYPE_DYNAMIC);
            uint32_t ip;
            struct in_addr a;
            char ip_addr[256];

            snprintf(ip_addr,256, "100.1.%d.%d",i1,i2);
            inet_aton(ip_addr,&a);
            ip=a.s_addr;

            cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_ADDRESS,&ip,sizeof(ip));
            //int port_index = if_nametoindex("e101-001-0");
            //cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_IFINDEX, port_index);

            const char *if_name = "br100";
            cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_IFNAME, if_name, strlen(if_name)+1);

            /*
             * CPS transaction
             */
            cps_api_transaction_params_t tr;
            ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
            cps_api_delete(&tr,obj);
            ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
            cps_api_transaction_close(&tr);
        }
    }
}

TEST(std_nas_route_test, nas_neighbor_add_static) {

    cps_api_object_t obj = cps_api_object_create();
    //cps_api_key_init(cps_api_object_key(obj),cps_api_qualifier_TARGET,
    //        cps_api_obj_CAT_BASE_ROUTE, BASE_ROUTE_OBJ_OBJ,0 );

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
              BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_AF,AF_INET);

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_TYPE,BASE_ROUTE_RT_TYPE_STATIC);
    uint32_t ip;
    struct in_addr a;
    inet_aton("6.6.6.7",&a);
    ip=a.s_addr;

    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_ADDRESS,&ip,sizeof(ip));
    int port_index = if_nametoindex("e101-001-0");
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_IFINDEX, port_index);

    //const char *if_name = "e101-001-0";
    //cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_IFNAME, if_name, strlen(if_name)+1);
    hal_mac_addr_t hw_addr = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16};

    char mac_addr[256];
    memset(mac_addr, '\0', sizeof(mac_addr));
    std_mac_to_string (&hw_addr, mac_addr, 256);
    cps_api_object_attr_add(obj, BASE_ROUTE_OBJ_NBR_MAC_ADDR, (const void *)mac_addr,
                            strlen(mac_addr)+1);

    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_create(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);

}

TEST(std_nas_route_test, nas_neighbor_set_static) {

    cps_api_object_t obj = cps_api_object_create();
    //cps_api_key_init(cps_api_object_key(obj),cps_api_qualifier_TARGET,
     //       cps_api_obj_CAT_BASE_ROUTE, BASE_ROUTE_OBJ_OBJ,0 );
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
              BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_AF,AF_INET);

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_TYPE,BASE_ROUTE_RT_TYPE_STATIC);
    uint32_t ip;
    struct in_addr a;
    inet_aton("6.6.6.7",&a);
    ip=a.s_addr;

    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_ADDRESS,&ip,sizeof(ip));
    //int port_index = if_nametoindex("e101-001-0");
    //cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_IFINDEX, port_index);

    const char *if_name = "e101-001-0";
    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_IFNAME, if_name, strlen(if_name)+1);
    hal_mac_addr_t hw_addr = {0x00, 0x00, 0x11, 0xaa, 0xbb, 0xcc};

    char mac_addr[256];
    memset(mac_addr, '\0', sizeof(mac_addr));
    std_mac_to_string (&hw_addr, mac_addr, 256);
    cps_api_object_attr_add(obj, BASE_ROUTE_OBJ_NBR_MAC_ADDR, (const void *)mac_addr,
                            strlen(mac_addr)+1);

    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_set(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
}

TEST(std_nas_route_test, nas_neighbor_delete_static) {

    cps_api_object_t obj = cps_api_object_create();
    //cps_api_key_init(cps_api_object_key(obj),cps_api_qualifier_TARGET,
     //       cps_api_obj_CAT_BASE_ROUTE, BASE_ROUTE_OBJ_OBJ,0 );
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
              BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_AF,AF_INET);

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_TYPE,BASE_ROUTE_RT_TYPE_STATIC);
    uint32_t ip;
    struct in_addr a;
    inet_aton("6.6.6.7",&a);
    ip=a.s_addr;

    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_ADDRESS,&ip,sizeof(ip));
    //int port_index = if_nametoindex("e101-001-0");
    //cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_IFINDEX, port_index);

    const char *if_name = "e101-001-0";
    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_IFNAME, if_name, strlen(if_name)+1);
    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_delete(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
}

TEST(std_nas_route_test, nas_neighbor_add_static_ipv6) {

    cps_api_object_t obj = cps_api_object_create();
    //cps_api_key_init(cps_api_object_key(obj),cps_api_qualifier_TARGET,
    //        cps_api_obj_CAT_BASE_ROUTE, BASE_ROUTE_OBJ_OBJ,0 );

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
              BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_AF,AF_INET6);

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_TYPE,BASE_ROUTE_RT_TYPE_STATIC);

    struct in6_addr a6;
    inet_pton(AF_INET6, "2::3", &a6);
    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_ADDRESS,&a6,sizeof(struct in6_addr));

    int port_index = if_nametoindex("e101-001-0");
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_IFINDEX, port_index);

    //const char *if_name = "e101-001-0";
    //cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_IFNAME, if_name, strlen(if_name)+1);
    hal_mac_addr_t hw_addr = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16};

    char mac_addr[256];
    memset(mac_addr, '\0', sizeof(mac_addr));
    std_mac_to_string (&hw_addr, mac_addr, 256);
    cps_api_object_attr_add(obj, BASE_ROUTE_OBJ_NBR_MAC_ADDR, (const void *)mac_addr,
                            strlen(mac_addr)+1);

    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_create(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);

}

TEST(std_nas_route_test, nas_neighbor_delete_static_ipv6) {

    cps_api_object_t obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
              BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_AF,AF_INET6);

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_TYPE,BASE_ROUTE_RT_TYPE_STATIC);

    struct in6_addr a6;
    inet_pton(AF_INET6, "2::3", &a6);
    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_ADDRESS,&a6,sizeof(struct in6_addr));
    //int port_index = if_nametoindex("e101-001-0");
    //cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_NBR_IFINDEX, port_index);

    const char *if_name = "e101-001-0";
    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_NBR_IFNAME, if_name, strlen(if_name)+1);
    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_delete(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
}

TEST(std_nas_route_test, nas_route_delete) {

    cps_api_object_t obj = cps_api_object_create();
    //cps_api_key_init(cps_api_object_key(obj),cps_api_qualifier_TARGET,
    //        cps_api_obj_CAT_BASE_ROUTE, BASE_ROUTE_OBJ_OBJ,0 );

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
              BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_AF,AF_INET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN,32);
    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_VRF_NAME, FIB_DEFAULT_VRF_NAME,
                            sizeof(FIB_DEFAULT_VRF_NAME));

    uint32_t ip;
    struct in_addr a;
    inet_aton("6.6.6.6",&a);
    ip=a.s_addr;

    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,&ip,sizeof(ip));

    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_delete(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);

}

#if 0
TEST(std_nas_route_test, nas_route_mp_add) {

    cps_api_object_t obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
           BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);

    //cps_api_key_init(cps_api_object_key(obj),cps_api_qualifier_TARGET,
       //     cps_api_obj_CAT_BASE_ROUTE, BASE_ROUTE_OBJ_OBJ,0 );

    /*
     * Check mandatory route attributes
     *  BASE_ROUTE_OBJ_ENTRY_AF,     BASE_ROUTE_OBJ_VRF_NAME);
     * BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,   BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN;
     */

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_AF,AF_INET);
    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_VRF_NAME, FIB_DEFAULT_VRF_NAME,
                            sizeof(FIB_DEFAULT_VRF_NAME));
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN,32);

    uint32_t ip;
    struct in_addr a;
    inet_aton("6.6.6.6",&a);
    ip=a.s_addr;

    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,&ip,sizeof(ip));
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN,32);
    cps_api_attr_id_t ids[3];
    const int ids_len = sizeof(ids)/sizeof(*ids);
    ids[0] = BASE_ROUTE_OBJ_ENTRY_NH_LIST;
    ids[1] = 0;
    ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR;

    /*
     * Set Loopback0 NH
     */
    inet_aton("4.4.4.2",&a);
    ip=a.s_addr;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,
                    &ip,sizeof(ip));

    ids[1] = 1;
    inet_aton("1.1.1.2",&a);
    ip=a.s_addr;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,
            &ip,sizeof(ip));

    ids[1] = 2;
    inet_aton("2.2.2.2",&a);
    ip=a.s_addr;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,
            &ip,sizeof(ip));
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_NH_COUNT,3);

    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_create(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
    printf("___________________________________________\n");
    if(system("ip route show 6.6.6.6"));
    printf("___________________________________________\n");
}

TEST(std_nas_route_test, nas_route_mp_set) {

    cps_api_object_t obj = cps_api_object_create();
    //cps_api_key_init(cps_api_object_key(obj),cps_api_qualifier_TARGET,
      //      cps_api_obj_CAT_BASE_ROUTE, BASE_ROUTE_OBJ_OBJ,0 );

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
              BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);

    /*
     * Check mandatory route attributes
     *  BASE_ROUTE_OBJ_ENTRY_AF,     BASE_ROUTE_OBJ_VRF_NAME);
     * BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,   BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN;
     * For NH: BASE_ROUTE_OBJ_ENTRY_NH_COUNT, BASE_ROUTE_OBJ_ENTRY_NH_LIST,
     * BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR
     */

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_AF,AF_INET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN,32);
    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_VRF_NAME, FIB_DEFAULT_VRF_NAME,
                            sizeof(FIB_DEFAULT_VRF_NAME));

    uint32_t ip;
    struct in_addr a;
    inet_aton("6.6.6.6",&a);
    ip=a.s_addr;

    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,&ip,sizeof(ip));
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN,32);
    cps_api_attr_id_t ids[3];
    const int ids_len = sizeof(ids)/sizeof(*ids);
    ids[0] = BASE_ROUTE_OBJ_ENTRY_NH_LIST;
    ids[1] = 0;
    ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR;

    inet_aton("4.4.4.3",&a);
    ip=a.s_addr;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,
                    &ip,sizeof(ip));
    ids[1] = 1;
    inet_aton("1.1.1.3",&a);
    ip=a.s_addr;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,
            &ip,sizeof(ip));

    ids[1] = 2;
    inet_aton("2.2.2.3",&a);
    ip=a.s_addr;
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,
            &ip,sizeof(ip));
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_NH_COUNT,3);

    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_set(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);

    printf("___________________________________________\n");
    if(system("ip route show 6.6.6.6"));
    printf("___________________________________________\n");

}


TEST(std_nas_route_test, nas_route_mp_delete) {

    cps_api_object_t obj = cps_api_object_create();
    //cps_api_key_init(cps_api_object_key(obj),cps_api_qualifier_TARGET,
    //        cps_api_obj_CAT_BASE_ROUTE, BASE_ROUTE_OBJ_OBJ,0 );

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
              BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_AF,AF_INET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN,32);
    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_VRF_NAME, FIB_DEFAULT_VRF_NAME,
                            sizeof(FIB_DEFAULT_VRF_NAME));

    uint32_t ip;
    struct in_addr a;
    inet_aton("6.6.6.6",&a);
    ip=a.s_addr;

    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,&ip,sizeof(ip));

    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_delete(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
    printf("___________________________________________\n");
    if(system("ip route show 6.6.6.6"));
    printf("___________________________________________\n");
}


TEST(std_nas_route_test, nas_route_mp_add_ipv6) {

    cps_api_object_t obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
           BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_AF,AF_INET6);
    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_VRF_NAME, FIB_DEFAULT_VRF_NAME,
                            sizeof(FIB_DEFAULT_VRF_NAME));
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN,64);

    struct in6_addr a6;
    inet_pton(AF_INET6, "6::", &a6);

    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,&a6,sizeof(struct in6_addr));
    cps_api_attr_id_t ids[3];
    const int ids_len = sizeof(ids)/sizeof(*ids);
    ids[0] = BASE_ROUTE_OBJ_ENTRY_NH_LIST;

    uint32_t gw_idx = if_nametoindex("e101-001-0");
    int itr = 0;
    char ip_addr[256];
    for (;itr < 64; itr++) {
        ids[1] = itr;
        ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR;
        memset(ip_addr, '\0', sizeof(ip_addr));
        snprintf(ip_addr,64, "2::%d",(itr+2));
        inet_pton(AF_INET6, ip_addr, &a6);
        cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,
                             &a6,sizeof(struct in6_addr));
        ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFINDEX;
        cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,
                             (void *)&gw_idx, sizeof(uint32_t));

        uint32_t weight = 1;
        ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_WEIGHT;
        cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_U32,
                             (void *)&weight, sizeof(uint32_t));
    }
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_NH_COUNT,itr);

    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_create(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
}

TEST(std_nas_route_test, nas_route_mp_set_ipv6) {

    cps_api_object_t obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
           BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_AF,AF_INET6);
    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_VRF_NAME, FIB_DEFAULT_VRF_NAME,
                            sizeof(FIB_DEFAULT_VRF_NAME));
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN,64);

    struct in6_addr a6;
    inet_pton(AF_INET6, "6::", &a6);

    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,&a6,sizeof(struct in6_addr));
    cps_api_attr_id_t ids[3];
    const int ids_len = sizeof(ids)/sizeof(*ids);
    ids[0] = BASE_ROUTE_OBJ_ENTRY_NH_LIST;
    ids[1] = 0;
    ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR;

    inet_pton(AF_INET6, "3::2", &a6);
    cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,
                    &a6,sizeof(struct in6_addr));

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_NH_COUNT,1);

    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_set(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
}

TEST(std_nas_route_test, nas_route_mp_del_ipv6) {

    cps_api_object_t obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
           BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_AF,AF_INET6);
    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_VRF_NAME, FIB_DEFAULT_VRF_NAME,
                            sizeof(FIB_DEFAULT_VRF_NAME));
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN,64);

    struct in6_addr a6;
    inet_pton(AF_INET6, "6::", &a6);

    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,&a6,sizeof(struct in6_addr));

    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_delete(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
}
#endif

void print_time(char *buffer, int *p_sec, int *p_milli_sec)
{
    char buf[50];
    int millisec;
    struct tm* tm_info;
    struct timeval tv;

    gettimeofday(&tv, NULL);

    /* Get the milli-sec */
    millisec = lrint(tv.tv_usec/1000.0);
    if (millisec >= 1000) {
        /* Get the sec from milli-sec and update the milli-sec */
        tv.tv_sec += millisec/1000;
        millisec = millisec % 1000;
    }
    *p_sec = tv.tv_sec;
    *p_milli_sec = millisec;

    tm_info = localtime(&tv.tv_sec);

    strftime(buf, 40, "%Y:%m:%d %H:%M:%S", tm_info);
    snprintf(buffer, 50, "%s.%03d\n", buf, millisec);

    return;
}

TEST(std_nas_route_test, nas_route_arp_get) {
    cps_api_get_params_t gp;
    cps_api_get_request_init(&gp);

    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),BASE_ROUTE_OBJ_NBR,
                                        cps_api_qualifier_TARGET);
    unsigned short af = 2;
    cps_api_set_key_data(obj,BASE_ROUTE_OBJ_NBR_AF,cps_api_object_ATTR_T_U16,
                                 &af,sizeof(af));

    if (cps_api_get(&gp)==cps_api_ret_code_OK) {
        size_t mx = cps_api_object_list_size(gp.list);

        for ( size_t ix = 0 ; ix < mx ; ++ix ) {
            obj = cps_api_object_list_get(gp.list,ix);
            std::cout<<"ARP ENTRY "<<std::endl;
            std::cout<<"================================="<<std::endl;
            nas_route_dump_arp_object_content(obj);
            std::cout<<std::endl;
        }
    }

    cps_api_get_request_close(&gp);

}

TEST(std_nas_route_test, nas_peer_routing_config_enable) {
    cps_api_object_t obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,cps_api_qualifier_TARGET);

    cps_api_object_attr_add(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_NAME, FIB_DEFAULT_VRF_NAME,
                            sizeof(FIB_DEFAULT_VRF_NAME));

    hal_mac_addr_t mac_addr = {0x01, 0x12, 0x13, 0x14, 0x15, 0x16};

    cps_api_object_attr_add(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR, &mac_addr, HAL_MAC_ADDR_LEN);

    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_create(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
}

TEST(std_nas_route_test, nas_peer_routing_config_set) {
    cps_api_object_t obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,cps_api_qualifier_TARGET);

    cps_api_object_attr_add(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_NAME, FIB_DEFAULT_VRF_NAME,
                            sizeof(FIB_DEFAULT_VRF_NAME));

    hal_mac_addr_t mac_addr = {0x01, 0x22, 0x23, 0x24, 0x25, 0x26};

    cps_api_object_attr_add(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR, &mac_addr, HAL_MAC_ADDR_LEN);

    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_set(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
}


TEST(std_nas_route_test, nas_peer_routing_config_disable) {
    cps_api_object_t obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,cps_api_qualifier_TARGET);

    cps_api_object_attr_add(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_NAME, FIB_DEFAULT_VRF_NAME,
                            sizeof(FIB_DEFAULT_VRF_NAME));

    hal_mac_addr_t mac_addr = {0x01, 0x12, 0x13, 0x14, 0x15, 0x16};

    cps_api_object_attr_add(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR, &mac_addr, HAL_MAC_ADDR_LEN);

    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_delete(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);

}

void nas_route_dump_peer_routing_object_content(cps_api_object_t obj){
    cps_api_object_it_t it;
    cps_api_object_it_begin(obj,&it);

    for ( ; cps_api_object_it_valid(&it) ; cps_api_object_it_next(&it) ) {

        switch (cps_api_object_attr_id(it.attr)) {

        case BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_ID:
            std::cout<<"VRF Id: "<<cps_api_object_attr_data_u32(it.attr)<<std::endl;
            break;

        case BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_NAME:
            char vrf_name[256];
            memset(vrf_name,'\0',sizeof(vrf_name));
            memcpy(vrf_name, cps_api_object_attr_data_bin(it.attr), cps_api_object_attr_len(it.attr));
            std::cout<<"VRF-name: "<<vrf_name<<std::endl;
            break;

        case BASE_ROUTE_PEER_ROUTING_CONFIG_IFNAME:
            char if_name[256];
            memset(if_name,'\0',sizeof(if_name));
            memcpy(if_name, cps_api_object_attr_data_bin(it.attr), cps_api_object_attr_len(it.attr));
            std::cout<<"If-name: "<<if_name<<std::endl;
            break;

        case BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR:
            {
                char mac[256];
                memset(mac,'\0',sizeof(mac));
                memcpy(mac, cps_api_object_attr_data_bin(it.attr), cps_api_object_attr_len(it.attr));
                std::cout<<"MAC: "<<mac<<std::endl;
            }
            break;

        case BASE_ROUTE_PEER_ROUTING_CONFIG_INGRESS_ONLY:
            std::cout<<"Ingress-Only: "<<cps_api_object_attr_data_u32(it.attr)<<std::endl;
            break;

        default:
            break;
        }
    }
}

cps_api_return_code_t nas_ut_peer_routing_config (bool is_add, const char *vrf_name,
                                                  const char *mac, const char *ifname, bool *ingress_only)
{
    cps_api_return_code_t rc = cps_api_ret_code_OK;
    cps_api_object_t obj;
    cps_api_transaction_params_t tr;

    obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,cps_api_qualifier_TARGET);

    if (vrf_name != NULL)
        cps_api_object_attr_add(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_NAME, vrf_name, strlen(vrf_name)+1);
    if (ifname != NULL)
        cps_api_object_attr_add(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_IFNAME, ifname, strlen(ifname)+1);
    cps_api_object_attr_add(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR, mac, strlen(mac)+1);

    if (ingress_only != NULL)
        cps_api_object_attr_add_u32(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_INGRESS_ONLY, *ingress_only);

    rc = cps_api_transaction_init(&tr);
    if (rc != cps_api_ret_code_OK)
        return rc;
    if (is_add)
        cps_api_create(&tr,obj);
    else
        cps_api_delete(&tr,obj);
    rc = cps_api_commit(&tr);
    cps_api_transaction_close(&tr);

    return rc;
}

bool nas_ut_peer_routing_config_validate (const char *vrf_name,const char *mac, const char *ifname, bool *ingress_only)
{
    cps_api_object_t obj;
    cps_api_get_params_t gp;
    cps_api_get_request_init(&gp);

    obj = cps_api_object_list_create_obj_and_append(gp.filters);
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,
            cps_api_qualifier_TARGET);

    if (vrf_name != NULL)
        cps_api_object_attr_add(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_NAME, vrf_name, strlen(vrf_name)+1);

    if (ifname != NULL)
        cps_api_object_attr_add(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_IFNAME, ifname, strlen(ifname)+1);

    if (mac != NULL)
        cps_api_object_attr_add(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR, mac, strlen(mac)+1);

    bool entry_found = false;
    if (cps_api_get(&gp)==cps_api_ret_code_OK) {
        size_t mx = cps_api_object_list_size(gp.list);

        for ( size_t ix = 0 ; ix < mx ; ++ix ) {
            obj = cps_api_object_list_get(gp.list,ix);
            std::cout<<"Peer Routing Status"<<std::endl;
            std::cout<<"==================="<<std::endl;
            nas_route_dump_peer_routing_object_content(obj);
            std::cout<<std::endl;

            cps_api_object_attr_t ingress_only_attr = cps_api_object_attr_get(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_INGRESS_ONLY);

            if (ingress_only) {
                if (ingress_only_attr) {
                    bool val = (bool) cps_api_object_attr_data_u32(ingress_only_attr);
                    if (val == *ingress_only)
                        entry_found = true;
                }
            } else {
                entry_found = true;
            }
        }
        if (vrf_name && ifname && mac && (mx > 1))
            entry_found = false;
    }

    cps_api_get_request_close(&gp);
    return entry_found;
}

TEST(std_nas_route_test, nas_peer_routing_validate_virtual_rif_ut)
{
    cps_api_return_code_t ret_code;

    //PHY RIF
    const char *ifname = "e101-001-0";
    const char *mac= "00:00:01:11:22:33";
    ret_code = nas_ut_peer_routing_config (1, NAS_DEFAULT_VRF_NAME, mac, ifname, NULL);
    ASSERT_TRUE(ret_code == cps_api_ret_code_OK);
    bool entry_found = nas_ut_peer_routing_config_validate (NAS_DEFAULT_VRF_NAME, mac, ifname, NULL);
    ASSERT_TRUE(entry_found);

    //VLAN RIF
    const char *vlan_ifname = "br100";
    const char *vlan_mac= "00:00:02:11:22:33";
    ret_code = nas_ut_peer_routing_config (1, NAS_DEFAULT_VRF_NAME, vlan_mac, vlan_ifname, NULL);
    ASSERT_TRUE(ret_code == cps_api_ret_code_OK);
    entry_found = nas_ut_peer_routing_config_validate (NAS_DEFAULT_VRF_NAME, vlan_mac, vlan_ifname, NULL);
    ASSERT_TRUE(entry_found);

    const char *mac1= "00:00:5E:00:01:01";
    ret_code = nas_ut_peer_routing_config (1, NAS_DEFAULT_VRF_NAME, mac1, ifname, NULL);
    ASSERT_TRUE(ret_code == cps_api_ret_code_OK);
    entry_found = nas_ut_peer_routing_config_validate (NAS_DEFAULT_VRF_NAME, mac1, ifname, NULL);
    ASSERT_TRUE(entry_found);

    const char *mac2= "00:00:5E:00:02:01";
    ret_code = nas_ut_peer_routing_config (1, NAS_DEFAULT_VRF_NAME, mac2, ifname, NULL);
    ASSERT_TRUE(ret_code == cps_api_ret_code_OK);
    entry_found = nas_ut_peer_routing_config_validate (NAS_DEFAULT_VRF_NAME, mac2, ifname, NULL);
    ASSERT_TRUE(entry_found);

    ret_code = nas_ut_peer_routing_config (1, NAS_DEFAULT_VRF_NAME, mac1, vlan_ifname, NULL);
    ASSERT_TRUE(ret_code == cps_api_ret_code_OK);
    entry_found = nas_ut_peer_routing_config_validate (NAS_DEFAULT_VRF_NAME, mac1, vlan_ifname, NULL);
    ASSERT_TRUE(entry_found);

    ret_code = nas_ut_peer_routing_config (1, NAS_DEFAULT_VRF_NAME, mac2, vlan_ifname, NULL);
    ASSERT_TRUE(ret_code == cps_api_ret_code_OK);
    entry_found = nas_ut_peer_routing_config_validate (NAS_DEFAULT_VRF_NAME, mac2, vlan_ifname, NULL);
    ASSERT_TRUE(entry_found);

    //PHY RIF
    bool ingress_only = 1;
    const char *virt_mac1= "00:00:01:11:22:34";
    ret_code = nas_ut_peer_routing_config (1, NAS_DEFAULT_VRF_NAME, virt_mac1, ifname, &ingress_only);
    ASSERT_TRUE(ret_code == cps_api_ret_code_OK);
    entry_found = nas_ut_peer_routing_config_validate (NAS_DEFAULT_VRF_NAME, virt_mac1, ifname, &ingress_only);
    ASSERT_TRUE(entry_found);

    const char *virt_mac2= "00:00:5E:00:01:02";
    ret_code = nas_ut_peer_routing_config (1, NAS_DEFAULT_VRF_NAME, virt_mac2, ifname, &ingress_only);
    ASSERT_TRUE(ret_code == cps_api_ret_code_OK);
    entry_found = nas_ut_peer_routing_config_validate (NAS_DEFAULT_VRF_NAME, virt_mac2, ifname, &ingress_only);
    ASSERT_TRUE(entry_found);


    //VLAN RIF
    const char *virt_vlan_mac1= "00:00:02:11:22:34";
    ret_code = nas_ut_peer_routing_config (1, NAS_DEFAULT_VRF_NAME, virt_vlan_mac1, vlan_ifname, &ingress_only);
    ASSERT_TRUE(ret_code == cps_api_ret_code_OK);
    entry_found = nas_ut_peer_routing_config_validate (NAS_DEFAULT_VRF_NAME, virt_vlan_mac1, vlan_ifname, &ingress_only);
    ASSERT_TRUE(entry_found);

    const char *virt_vlan_mac2= "00:00:5E:00:02:02";
    ret_code = nas_ut_peer_routing_config (1, NAS_DEFAULT_VRF_NAME, virt_vlan_mac2, vlan_ifname, &ingress_only);
    ASSERT_TRUE(ret_code == cps_api_ret_code_OK);
    entry_found = nas_ut_peer_routing_config_validate (NAS_DEFAULT_VRF_NAME, virt_vlan_mac2, vlan_ifname, &ingress_only);
    ASSERT_TRUE(entry_found);

    //clean-up
    ret_code = nas_ut_peer_routing_config (0, NAS_DEFAULT_VRF_NAME, mac, ifname, NULL);
    ASSERT_TRUE(ret_code == cps_api_ret_code_OK);

    ret_code = nas_ut_peer_routing_config (0, NAS_DEFAULT_VRF_NAME, vlan_mac, vlan_ifname, NULL);
    ASSERT_TRUE(ret_code == cps_api_ret_code_OK);

    ret_code = nas_ut_peer_routing_config (0, NAS_DEFAULT_VRF_NAME, mac1, ifname, NULL);
    ASSERT_TRUE(ret_code == cps_api_ret_code_OK);
    ret_code = nas_ut_peer_routing_config (0, NAS_DEFAULT_VRF_NAME, mac2, ifname, NULL);
    ASSERT_TRUE(ret_code == cps_api_ret_code_OK);

    ret_code = nas_ut_peer_routing_config (0, NAS_DEFAULT_VRF_NAME, mac1, vlan_ifname, NULL);
    ASSERT_TRUE(ret_code == cps_api_ret_code_OK);
    ret_code = nas_ut_peer_routing_config (0, NAS_DEFAULT_VRF_NAME, mac2, vlan_ifname, NULL);
    ASSERT_TRUE(ret_code == cps_api_ret_code_OK);

    ret_code = nas_ut_peer_routing_config (0, NAS_DEFAULT_VRF_NAME, virt_mac1, ifname, &ingress_only);
    ASSERT_TRUE(ret_code == cps_api_ret_code_OK);
    ret_code = nas_ut_peer_routing_config (0, NAS_DEFAULT_VRF_NAME, virt_mac2, ifname, &ingress_only);
    ASSERT_TRUE(ret_code == cps_api_ret_code_OK);

    ret_code = nas_ut_peer_routing_config (0, NAS_DEFAULT_VRF_NAME, virt_vlan_mac1, vlan_ifname, &ingress_only);
    ASSERT_TRUE(ret_code == cps_api_ret_code_OK);
    ret_code = nas_ut_peer_routing_config (0, NAS_DEFAULT_VRF_NAME, virt_vlan_mac2, vlan_ifname, &ingress_only);
    ASSERT_TRUE(ret_code == cps_api_ret_code_OK);


    entry_found = nas_ut_peer_routing_config_validate (NAS_DEFAULT_VRF_NAME, mac, ifname, NULL);
    ASSERT_TRUE(!entry_found);
    entry_found = nas_ut_peer_routing_config_validate (NAS_DEFAULT_VRF_NAME, vlan_mac, vlan_ifname, NULL);
    ASSERT_TRUE(!entry_found);
    entry_found = nas_ut_peer_routing_config_validate (NAS_DEFAULT_VRF_NAME, mac1, ifname, NULL);
    ASSERT_TRUE(!entry_found);
    entry_found = nas_ut_peer_routing_config_validate (NAS_DEFAULT_VRF_NAME, mac2, ifname, NULL);
    ASSERT_TRUE(!entry_found);
    entry_found = nas_ut_peer_routing_config_validate (NAS_DEFAULT_VRF_NAME, mac1, vlan_ifname, NULL);
    ASSERT_TRUE(!entry_found);
    entry_found = nas_ut_peer_routing_config_validate (NAS_DEFAULT_VRF_NAME, mac2, vlan_ifname, NULL);
    ASSERT_TRUE(!entry_found);
    entry_found = nas_ut_peer_routing_config_validate (NAS_DEFAULT_VRF_NAME, virt_mac1, ifname, NULL);
    ASSERT_TRUE(!entry_found);
    entry_found = nas_ut_peer_routing_config_validate (NAS_DEFAULT_VRF_NAME, virt_mac2, ifname, NULL);
    ASSERT_TRUE(!entry_found);
    entry_found = nas_ut_peer_routing_config_validate (NAS_DEFAULT_VRF_NAME, virt_vlan_mac1, vlan_ifname, NULL);
    ASSERT_TRUE(!entry_found);
    entry_found = nas_ut_peer_routing_config_validate (NAS_DEFAULT_VRF_NAME, virt_vlan_mac2, vlan_ifname, NULL);
    ASSERT_TRUE(!entry_found);
}

void nas_peer_routing_get() {
    cps_api_get_params_t gp;
    cps_api_get_request_init(&gp);

    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,
                                    cps_api_qualifier_TARGET);

    if (cps_api_get(&gp)==cps_api_ret_code_OK) {
        size_t mx = cps_api_object_list_size(gp.list);

        for ( size_t ix = 0 ; ix < mx ; ++ix ) {
            obj = cps_api_object_list_get(gp.list,ix);
            std::cout<<"Peer Routing Status "<<std::endl;
            std::cout<<"================================="<<std::endl;
            nas_route_dump_peer_routing_object_content(obj);
            std::cout<<std::endl;
        }
    }

    cps_api_get_request_close(&gp);
}

TEST(std_nas_route_test, nas_peer_routing_config_get) {
    nas_peer_routing_get();
}

void nas_peer_routing_config_vrf() {
    cps_api_object_t obj;
    cps_api_transaction_params_t tr;
    int ret;

    /* MAC UT cases */
    obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,cps_api_qualifier_TARGET);

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_ID,0);
    const char *mac_addr1 = "01:12:13:14:15:16";
    cps_api_object_attr_add(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR, mac_addr1, strlen(mac_addr1)+1);

    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_create(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);

    ret = system("hshell -c 'd my_station_tcam' | grep MAC_ADDR=0x011213141516");
    if (ret != 0) {
        std::cout << "-----------Test case 1 failed--------------" << std::endl;
        return;
    }
    nas_peer_routing_get();

    obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,cps_api_qualifier_TARGET);

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_ID,0);
    const char *mac_addr2 = "01:12:13:14:15:17";
    cps_api_object_attr_add(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR, mac_addr2, strlen(mac_addr1)+1);


    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_set(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
    ret = system("hshell -c 'd my_station_tcam' | grep MAC_ADDR=0x011213141517");
    if (ret != 0) {
        std::cout << "----------Test case 2 failed-----------" << std::endl;
        return;
    }
    nas_peer_routing_get();

    obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,cps_api_qualifier_TARGET);

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_ID,0);
    const char *mac_addr3 = "01:12:13:14:15:17";
    cps_api_object_attr_add(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR, mac_addr3, strlen(mac_addr3)+1);


    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_delete(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
    ret = system("hshell -c 'd my_station_tcam' | grep MAC_ADDR=0x011213141517");
    if (ret == 0) {
        std::cout << "------------Test case 3 failed---------" << std::endl;
        return;
    }
    nas_peer_routing_get();

    obj = cps_api_object_create();
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_ID,0);
    const char *mac_addr4 = "01:12:13:14:15:16";
    cps_api_object_attr_add(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR, mac_addr4, strlen(mac_addr4)+1);

    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_delete(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
    ret = system("hshell -c 'd my_station_tcam' | grep MAC_ADDR=0x011213141516");
    if (ret == 0) {
        std::cout << "---------Test case 4 failed-----------" << std::endl;
    }
    nas_peer_routing_get();
    std::cout << "------------Peer routing VRF testcases passed successfully---------" << std::endl;
}

void nas_peer_routing_config_rif_phy() {
    cps_api_object_t obj;
    cps_api_transaction_params_t tr;
    int ret;

    /* IF_NAME PHY and MAC UT cases */
    obj = cps_api_object_create();
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_ID,0);
    const char *if_name1 = "e101-001-0";
    cps_api_object_attr_add(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_IFNAME, if_name1, strlen(if_name1)+1);
    const char *mac_addr1 = "01:12:13:14:15:16";
    cps_api_object_attr_add(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR, mac_addr1, strlen(mac_addr1)+1);

    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_create(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
    ret = system("hshell -c 'd my_station_tcam' | grep ING_PORT_NUM=1 | grep MAC_ADDR=0x011213141516");
    if (ret != 0) {
        std::cout << "-------Test case 5 failed-----------" << std::endl;
        return;
    }
    nas_peer_routing_get();

    obj = cps_api_object_create();
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_ID,0);
    const char *if_name2 = "e101-001-0";
    cps_api_object_attr_add(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_IFNAME, if_name2, strlen(if_name2)+1);
    const char *mac_addr2 = "01:12:13:14:15:17";
    cps_api_object_attr_add(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR, mac_addr2, strlen(mac_addr2)+1);

    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_set(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
    ret = system("hshell -c 'd my_station_tcam' | grep ING_PORT_NUM=1 | grep MAC_ADDR=0x011213141517");
    if (ret != 0) {
        std::cout << "-------Test case 6 failed-----------" << std::endl;
        return;
    }
    nas_peer_routing_get();

    obj = cps_api_object_create();
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_ID,0);
    const char *if_name21 = "e101-001-0";
    cps_api_object_attr_add(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_IFNAME, if_name21, strlen(if_name21)+1);
    const char *mac_addr21 = "01:12:13:14:15:17";
    cps_api_object_attr_add(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR, mac_addr21, strlen(mac_addr21)+1);

    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_set(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
    ret = system("hshell -c 'd my_station_tcam' | grep ING_PORT_NUM=1 | grep MAC_ADDR=0x011213141517");
    if (ret != 0) {
        std::cout << "------Already exists-Test case 6 failed-----------" << std::endl;
        return;
    }
    nas_peer_routing_get();

    obj = cps_api_object_create();
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_ID,0);
    const char *if_name3 = "e101-010-0";
    cps_api_object_attr_add(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_IFNAME, if_name3, strlen(if_name3)+1);
    const char *mac_addr3 = "01:12:13:14:15:17";
    cps_api_object_attr_add(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR, mac_addr3, strlen(mac_addr3)+1);

    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_create(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
    ret = system("hshell -c 'd my_station_tcam' | grep ING_PORT_NUM=0x25 | grep MAC_ADDR=0x011213141517");
    if (ret != 0) {
        std::cout << "-------Test case 7 failed-----------" << std::endl;
        return;
    }
    nas_peer_routing_get();

    obj = cps_api_object_create();
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_ID,0);
    const char *if_name4 = "e101-001-0";
    cps_api_object_attr_add(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_IFNAME, if_name4, strlen(if_name4)+1);
    const char *mac_addr4 = "01:12:13:14:15:16";
    cps_api_object_attr_add(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR, mac_addr4, strlen(mac_addr4)+1);

    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_delete(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
    ret = system("hshell -c 'd my_station_tcam' | grep ING_PORT_NUM=1 | grep MAC_ADDR=0x011213141516");
    if (ret == 0) {
        std::cout << "-------Test case 8 failed-----------" << std::endl;
        return;
    }
    nas_peer_routing_get();

    obj = cps_api_object_create();
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_ID,0);
    const char *if_name5 = "e101-001-0";
    cps_api_object_attr_add(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_IFNAME, if_name5, strlen(if_name5)+1);
    const char *mac_addr5 = "01:12:13:14:15:17";
    cps_api_object_attr_add(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR, mac_addr5, strlen(mac_addr5)+1);

    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_delete(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
    ret = system("hshell -c 'd my_station_tcam' | grep ING_PORT_NUM=1 | grep MAC_ADDR=0x011213141517");
    if (ret == 0) {
        std::cout << "-------Test case 9 failed-----------" << std::endl;
        return;
    }
    nas_peer_routing_get();

    obj = cps_api_object_create();
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_ID,0);
    const char *if_name6 = "e101-010-0";
    cps_api_object_attr_add(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_IFNAME, if_name6, strlen(if_name6)+1);
    const char *mac_addr6 = "01:12:13:14:15:17";
    cps_api_object_attr_add(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR, mac_addr6, strlen(mac_addr6)+1);

    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_delete(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
    ret = system("hshell -c 'd my_station_tcam' | grep ING_PORT_NUM=0x25 | grep MAC_ADDR=0x011213141517");
    if (ret == 0) {
        std::cout << "-------Test case 10 failed-----------" << std::endl;
        return;
    }
    nas_peer_routing_get();
    std::cout << "------------Peer routing RIF PHY testcases passed successfully---------" << std::endl;
}

void nas_peer_routing_config_rif_vlan() {
    cps_api_object_t obj;
    cps_api_transaction_params_t tr;
    int ret;

    /* IF_NAME VLAN and MAC UT cases */
    obj = cps_api_object_create();
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_ID,0);
    const char *if_name7 = "br100";
    cps_api_object_attr_add(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_IFNAME, if_name7, strlen(if_name7)+1);
    const char *mac_addr7 = "01:12:13:14:15:16";
    cps_api_object_attr_add(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR, mac_addr7, strlen(mac_addr7)+1);

    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_create(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
    ret = system("hshell -c 'd my_station_tcam' | grep VLAN_ID=0x64 | grep MAC_ADDR=0x011213141516");
    if (ret != 0) {
        std::cout << "-------Test case 11 failed-----------" << std::endl;
        return;
    }
    nas_peer_routing_get();

    obj = cps_api_object_create();
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_ID,0);
    const char *if_name8 = "br100";
    cps_api_object_attr_add(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_IFNAME, if_name8, strlen(if_name8)+1);
    const char *mac_addr8 = "01:12:13:14:15:17";
    cps_api_object_attr_add(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR, mac_addr8, strlen(mac_addr8)+1);

    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_set(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
    ret = system("hshell -c 'd my_station_tcam' | grep VLAN_ID=0x64 | grep MAC_ADDR=0x011213141517");
    if (ret != 0) {
        std::cout << "-------Test case 12 failed-----------" << std::endl;
        return;
    }
    nas_peer_routing_get();

    obj = cps_api_object_create();
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_ID,0);
    const char *if_name81 = "br100";
    cps_api_object_attr_add(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_IFNAME, if_name81, strlen(if_name81)+1);
    const char *mac_addr81 = "01:12:13:14:15:17";
    cps_api_object_attr_add(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR, mac_addr81, strlen(mac_addr81)+1);

    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_set(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
    ret = system("hshell -c 'd my_station_tcam' | grep VLAN_ID=0x64 | grep MAC_ADDR=0x011213141517");
    if (ret != 0) {
        std::cout << "-------Already exists case, Test case 12 failed-----------" << std::endl;
        return;
    }
    nas_peer_routing_get();

    obj = cps_api_object_create();
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_ID,0);
    const char *if_name9 = "br200";
    cps_api_object_attr_add(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_IFNAME, if_name9, strlen(if_name9)+1);
    const char *mac_addr9 = "01:12:13:14:15:17";
    cps_api_object_attr_add(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR, mac_addr9, strlen(mac_addr9)+1);

    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_create(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
    ret = system("hshell -c 'd my_station_tcam' | grep VLAN_ID=0xc8 | grep MAC_ADDR=0x011213141517");
    if (ret != 0) {
        std::cout << "-------Test case 13 failed-----------" << std::endl;
        return;
    }
    nas_peer_routing_get();

    obj = cps_api_object_create();
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_ID,0);
    const char *if_name10 = "br100";
    cps_api_object_attr_add(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_IFNAME, if_name10, strlen(if_name10)+1);
    const char *mac_addr10 = "01:12:13:14:15:16";
    cps_api_object_attr_add(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR, mac_addr10, strlen(mac_addr10)+1);

    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_delete(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
    ret = system("hshell -c 'd my_station_tcam' | grep VLAN_ID=0x64 | grep MAC_ADDR=0x011213141516");
    if (ret == 0) {
        std::cout << "-------Test case 14 failed-----------" << std::endl;
        return;
    }
    nas_peer_routing_get();

    obj = cps_api_object_create();
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_ID,0);
    const char *if_name11 = "br100";
    cps_api_object_attr_add(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_IFNAME, if_name11, strlen(if_name11)+1);
    const char *mac_addr11 = "01:12:13:14:15:17";
    cps_api_object_attr_add(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR, mac_addr11, strlen(mac_addr11)+1);

    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_delete(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
    ret = system("hshell -c 'd my_station_tcam' | grep VLAN_ID=0x64 | grep MAC_ADDR=0x011213141517");
    if (ret == 0) {
        std::cout << "-------Test case 15 failed-----------" << std::endl;
        return;
    }
    nas_peer_routing_get();

    obj = cps_api_object_create();
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_ID,0);
    const char *if_name12 = "br100";
    cps_api_object_attr_add(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_IFNAME, if_name12, strlen(if_name12)+1);
    const char *mac_addr12 = "01:12:13:14:15:17";
    cps_api_object_attr_add(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR, mac_addr12, strlen(mac_addr12)+1);

    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_delete(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
    ret = system("hshell -c 'd my_station_tcam' | grep VLAN_ID=0x64 | grep MAC_ADDR=0x011213141517");
    if (ret == 0) {
        std::cout << "-------Test case 16 failed-----------" << std::endl;
        return;
    }
    nas_peer_routing_get();
    std::cout << "------------Peer routing RIF VLAN testcases passed successfully---------" << std::endl;
}

void nas_peer_routing_config_neg() {
    /* Negative cases - Delete the invalid entry */
    cps_api_object_t obj;
    cps_api_transaction_params_t tr;
    int ret;

    obj = cps_api_object_create();
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_ID,0);
    const char *if_name13 = "e101-001-0";
    cps_api_object_attr_add(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_IFNAME, if_name13, strlen(if_name13)+1);
    const char *mac_addr13 = "01:12:13:14:15:16";
    cps_api_object_attr_add(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR, mac_addr13, strlen(mac_addr13)+1);

    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_delete(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
    ret = system("hshell -c 'd my_station_tcam' | grep ING_PORT_NUM=1 | grep MAC_ADDR=0x011213141516");
    if (ret == 0) {
        std::cout << "-------Test case 17 failed-----------" << std::endl;
        return;
    }
    nas_peer_routing_get();

    obj = cps_api_object_create();
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_ID,0);
    const char *if_name14 = "br100";
    cps_api_object_attr_add(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_IFNAME, if_name14, strlen(if_name14)+1);
    const char *mac_addr14 = "01:12:13:14:15:17";
    cps_api_object_attr_add(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR, mac_addr14, strlen(mac_addr14)+1);

    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_delete(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
    ret = system("hshell -c 'd my_station_tcam' | grep VLAN_ID=0x64 | grep MAC_ADDR=0x011213141517");
    if (ret == 0) {
        std::cout << "-------Test case 18 failed-----------" << std::endl;
        return;
    }
    nas_peer_routing_get();

    obj = cps_api_object_create();
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_PEER_ROUTING_CONFIG_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_PEER_ROUTING_CONFIG_VRF_ID,0);
    const char *mac_addr15 = "01:12:13:14:15:16";
    cps_api_object_attr_add(obj, BASE_ROUTE_PEER_ROUTING_CONFIG_PEER_MAC_ADDR, mac_addr15, strlen(mac_addr15)+1);

    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_delete(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
    ret = system("hshell -c 'd my_station_tcam' | grep MAC_ADDR=0x011213141516");
    if (ret == 0) {
        std::cout << "---------Test case 19 failed-----------" << std::endl;
        return;
    }
    nas_peer_routing_get();
    std::cout << "------------Peer routing Negative testcases passed successfully---------" << std::endl;
}

TEST(std_nas_route_test, nas_peer_routing_config_ut) {
    nas_peer_routing_config_vrf();
    nas_peer_routing_config_rif_phy();
    nas_peer_routing_config_rif_vlan();
    nas_peer_routing_config_neg();
}

TEST(std_nas_route_test, nas_route_ipv4_get) {
    cps_api_get_params_t gp;
    cps_api_get_request_init(&gp);

    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),BASE_ROUTE_OBJ_ENTRY,
                                        cps_api_qualifier_TARGET);
    unsigned int af = AF_INET;
    cps_api_set_key_data(obj,BASE_ROUTE_OBJ_ENTRY_AF,cps_api_object_ATTR_T_U32,
                                 &af,sizeof(af));

    if (cps_api_get(&gp)==cps_api_ret_code_OK) {
        size_t mx = cps_api_object_list_size(gp.list);

        std::cout<<"IPv4 FIB Entries"<<std::endl;
        std::cout<<"================================="<<std::endl;
        for ( size_t ix = 0 ; ix < mx ; ++ix ) {
            obj = cps_api_object_list_get(gp.list,ix);
            nas_route_dump_route_object_content(obj);
            std::cout<<std::endl;
        }
    }
    cps_api_get_request_close(&gp);
}

TEST(std_nas_route_test, nas_route_ipv6_get) {
    cps_api_get_params_t gp;
    cps_api_get_request_init(&gp);

    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),BASE_ROUTE_OBJ_ENTRY,
                                        cps_api_qualifier_TARGET);
    unsigned int af = AF_INET6;
    cps_api_set_key_data(obj,BASE_ROUTE_OBJ_ENTRY_AF,cps_api_object_ATTR_T_U32,
                                 &af,sizeof(af));

    if (cps_api_get(&gp)==cps_api_ret_code_OK) {
        size_t mx = cps_api_object_list_size(gp.list);

        std::cout<<"IPv6 FIB Entries"<<std::endl;
        std::cout<<"================================="<<std::endl;
        for ( size_t ix = 0 ; ix < mx ; ++ix ) {
            obj = cps_api_object_list_get(gp.list,ix);
            nas_route_dump_route_object_content(obj);
            std::cout<<std::endl;
        }
    }
    cps_api_get_request_close(&gp);
}

//Scale tests for route add/delete
TEST(std_nas_route_test, nas_route_add_scale) {
    char ip_addr[256];
    int i=1, j=1 ,count=0, start_sec = 0, start_milli_sec = 0, end_sec = 0, end_milli_sec = 0;
    uint32_t ip;
    struct in_addr a;
    char start_time[50], end_time[50];
    int no_of_msgs_per_transaction = 1; /* Change this if more msgs needs
                                             to be sent per transaction */

    cps_api_transaction_params_t tr;
    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);

    print_time(start_time, &start_sec, &start_milli_sec);
    /* 16K routes are being sent from this gtest test case */
    for(i=1; i<101; i++) {
        for (j=1; j<161; j++) {

            cps_api_object_t obj = cps_api_object_create();
            cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                            BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);
            cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_AF,AF_INET);
            cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_VRF_NAME, FIB_DEFAULT_VRF_NAME,
                            sizeof(FIB_DEFAULT_VRF_NAME));

            /* 75.x.x.0 network */
            snprintf(ip_addr,256, "75.%d.%d.0",i,j);

            inet_aton(ip_addr,&a);
            ip=a.s_addr;
            cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,&ip,sizeof(ip));
            cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN,24);
            cps_api_attr_id_t ids[3];
            const int ids_len = sizeof(ids)/sizeof(*ids);
            ids[0] = BASE_ROUTE_OBJ_ENTRY_NH_LIST;
            ids[1] = 0;
            ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR;

            /*
             * Set  NH
             */
            inet_aton("100.1.1.10",&a);
            ip=a.s_addr;
            cps_api_object_e_add(obj,ids,ids_len,cps_api_object_ATTR_T_BIN,
                                 &ip,sizeof(ip));
            cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_NH_COUNT,1);

            count++;
            /*
             * CPS transaction
             */
            cps_api_create(&tr,obj);
            if ((j % no_of_msgs_per_transaction) == 0)
            {
                ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
                cps_api_transaction_close(&tr);
            //    print_time(time);
            //    printf("Sent %d Routes, time:%s\n", count,time);
                ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
            }
        }
    }
    print_time(end_time, &end_sec, &end_milli_sec);
    printf("Sent %d Routes, time start:%s end:%s\n", count,start_time, end_time);
    start_milli_sec += (start_sec * 1000);
    end_milli_sec += (end_sec * 1000);
    printf("Diff sec:%d, milli-sec:%d \n",
           ((end_milli_sec - start_milli_sec)/1000), ((end_milli_sec - start_milli_sec) % 1000));
}

TEST(std_nas_route_test, nas_route_delete_scale) {

    char ip_addr[256];
    int i=1, j=1;
    uint32_t ip;
    struct in_addr a;



    for(i=1; i<101; i++) {
        for (j=1; j<161; j++) {

    cps_api_object_t obj = cps_api_object_create();
    //cps_api_key_init(cps_api_object_key(obj),cps_api_qualifier_TARGET,
    //        cps_api_obj_CAT_BASE_ROUTE, BASE_ROUTE_OBJ_OBJ,0 );

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
              BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_AF,AF_INET);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN,24);
    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_VRF_NAME, FIB_DEFAULT_VRF_NAME,
                            sizeof(FIB_DEFAULT_VRF_NAME));


    snprintf(ip_addr,256, "75.%d.%d.0",i,j);
    //printf ("Delete Route:%s \n", ip_addr);

    inet_aton(ip_addr,&a);
    //inet_aton("6.6.6.6",&a);
    ip=a.s_addr;

    cps_api_object_attr_add(obj,BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX,&ip,sizeof(ip));

    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_delete(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
        }
    }

}



int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);


  printf("___________________________________________\n");
  (void)system("ip address add 6.6.6.1/24  dev e101-005-0");
  (void)system("ifconfig e101-005-0");
  /* Incase of premium package, all the ports are part of default bridge,
   * remove it from the bridge to operate as the router intf. */

  (void)system("brctl addbr br100 up");
  (void)system("ip link add link e101-003-0 name e101-003-0.100 type vlan id 100");
  (void)system("ifconfig e101-003-0 up");
  (void)system("ip link set dev e101-003-0.100 up");
  (void)system("brctl addif br100 e101-003-0.100");
  (void)system("ip addr add 100.1.1.2/24 dev br100");
  (void)system("ip neigh add 100.1.1.10 lladdr 00:00:00:00:11:22");
  (void)system("ifconfig br100 up");
  (void)system("brctl stp br100 on");

  (void)system("brctl addbr br200 up");
  (void)system("ip link add link e101-003-0 name e101-003-0.200 type vlan id 200");
  (void)system("ifconfig e101-003-0 up");
  (void)system("ip link set dev e101-003-0.200 up");
  (void)system("brctl addif br200 e101-003-0.200");
  (void)system("ip addr add 200.1.1.2/24 dev br200");
  (void)system("ifconfig br200 up");
  (void)system("brctl stp br200 on");

  printf("___________________________________________\n");
  printf("Run the NAS CPS routing test cases the below order: "
          "route add, route set, nbr add, nbr set, nbr deleet, route delete\n");

  return RUN_ALL_TESTS();
}
