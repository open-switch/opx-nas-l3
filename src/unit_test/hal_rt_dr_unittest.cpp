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
 * hal_rt_dr_unittest.cpp
 * UT for hal_rt_dr.c
 */
#include "nas_rt_util_unittest.h"

#include <gtest/gtest.h>
#include <iostream>

static cps_api_return_code_t nas_rt_ut_v4_cfg_add()
{
    hal_mac_addr_t hw_addr = {0x00, 0x02, 0x03, 0x04, 0x05, 0x06};

    nas_ut_neigh_cfg (1, "100.1.1.11", AF_INET, "br100", &hw_addr);
    nas_ut_rt_cfg ("default",1, "101.101.101.0", 24, AF_INET, "default", "100.1.1.11", "br100");

    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_rt_ut_v6_cfg_add()
{
    hal_mac_addr_t hw_addr = {0x00, 0x02, 0x03, 0x04, 0x05, 0x06};

    nas_ut_neigh_cfg (1, "100:1::11", AF_INET6, "br100", &hw_addr);
    nas_ut_rt_cfg ("default", 1, "101:101::0", 64, AF_INET6,  "default", "100:1::11", "br100");

    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_rt_ut_v4_rt_cfg(bool is_add)
{
    nas_ut_rt_cfg ("default", is_add, "101.101.101.0", 24, AF_INET, "default", "100.1.1.11", "br100");

    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_rt_ut_v6_rt_cfg(bool is_add)
{
    nas_ut_rt_cfg ("default", is_add, "101:101::0", 64, AF_INET6, "default", "100:1::11", "br100");

    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_rt_ut_v6_rt_nh_cfg (bool is_add)
{
    if (is_add)
    {
        hal_mac_addr_t hw_addr = {0x00, 0x02, 0x03, 0x04, 0x05, 0x16};

        nas_ut_neigh_cfg (1, "200:1::11", AF_INET6, "br200", &hw_addr);
        nas_ut_neigh_cfg (1, "201:1::11", AF_INET6, "br201", &hw_addr);
    }
    nas_ut_rt_ipv6_nh_cfg (is_add, "101:101::0", 64, AF_INET6, "200:1::11", "br200", "201:1::11", "br201");

    return cps_api_ret_code_OK;
}


static cps_api_return_code_t nas_rt_ut_v4_cfg_del ()
{
    hal_mac_addr_t hw_addr = {0x00, 0x02, 0x03, 0x04, 0x05, 0x06};

    nas_ut_rt_cfg ("default", 0, "101.101.101.0", 24, AF_INET, "default", "100.1.1.11", "br100");
    nas_ut_neigh_cfg (0, "100.1.1.11", AF_INET, "br100", &hw_addr);
    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_rt_ut_v6_cfg_del ()
{
    hal_mac_addr_t hw_addr = {0x00, 0x02, 0x03, 0x04, 0x05, 0x06};

    nas_ut_rt_cfg ("default", 0, "101:101::0", 64, AF_INET6, "default", "100:1::11", "br100");
    nas_ut_neigh_cfg (0, "100:1::11", AF_INET6, "br100", &hw_addr);

    return cps_api_ret_code_OK;
}


static cps_api_return_code_t nas_rt_ut_validate_v4_rt_cfg(bool is_add)
{
    cps_api_return_code_t rc = nas_ut_validate_rt_cfg ("default", AF_INET, "101.101.101.0", 24, "default", "100.1.1.11", "br100", true);

    return rc;
}

static cps_api_return_code_t nas_rt_ut_validate_v6_rt_cfg(bool is_add)
{
    cps_api_return_code_t rc = nas_ut_validate_rt_cfg ("default", AF_INET6, "101:101::0", 64, "default", "100:1::11", "br100", true);

    return rc;

}


TEST(hal_rt_dr_test, hal_rt_dr_ut_dup_rt_1nh_del) {
    cps_api_return_code_t rc;
    nas_rt_ut_v4_cfg_add();
    nas_rt_ut_v6_cfg_add();

    /* wait for few secs after configuration, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    //nas_rt_ut_validate_v4_rt_cfg(1);
    rc = nas_rt_ut_validate_v4_rt_cfg(1);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    //nas_rt_ut_validate_v6_rt_cfg(1);
    rc = nas_rt_ut_validate_v6_rt_cfg(1);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    /* bring admin down */
    system("ifconfig br100 down");
    /* delete the route */
    nas_rt_ut_v4_rt_cfg(0);
    nas_rt_ut_v6_rt_cfg(0);

    /* wait for few secs after config delete, to make sure NAS-L3 processed those netlink events */
    sleep (5);

    /* verify the route is deleted */
    rc = nas_rt_ut_validate_v4_rt_cfg(0);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);

    rc = nas_rt_ut_validate_v6_rt_cfg(0);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);


    /* clean up */
    nas_rt_ut_v4_cfg_del();
    nas_rt_ut_v6_cfg_del();
    system("ifconfig br100 down");
}

TEST(hal_rt_dr_test, hal_rt_dr_ut_dup_rt_2nh_del) {
    cps_api_return_code_t rc;
    system("ifconfig br100 up");
    system("ip addr add 100.1.1.2/24 dev br100");
    system("ip addr add  100:1::1/64 dev br100");
    nas_rt_ut_v4_cfg_add();
    nas_rt_ut_v6_cfg_add();

    /* add route nh */
    //@@TODO - to call route replace with all nh's including new nh for IPv4
    nas_rt_ut_v6_rt_nh_cfg(1);

    /* wait for few secs after configuration, to make sure NAS-L3 processed those netlink events */
    sleep (5);
    rc = nas_rt_ut_validate_v4_rt_cfg(1);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    rc = nas_rt_ut_validate_v6_rt_cfg(1);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    /* bring admin down */
    system("ifconfig br200 down");
    system("ifconfig br201 down");
    /* delete the route nh */
    //@@TODO - to call route replace with remaining nh's excluding deleted nh for IPv4
    nas_rt_ut_v6_rt_nh_cfg(0);

    /* wait for few secs after config delete, to make sure NAS-L3 processed those netlink events */
    sleep (5);

    /* verify the route is still present */
    rc = nas_rt_ut_validate_v4_rt_cfg(1);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    rc = nas_rt_ut_validate_v6_rt_cfg(1);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    ///* clean up */
    nas_rt_ut_v4_cfg_del();
    nas_rt_ut_v6_cfg_del();
}

TEST(hal_rt_dr_test, hal_rt_dr_check_full_addr) {
    cps_api_return_code_t rc = nas_ut_validate_rt_cfg ("default", AF_INET, "100.1.1.2", 32, "default",
                                                       NULL, NULL, false);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
}

TEST(hal_rt_dr_test, hal_rt_dr_check_loopback_addr_in_hw) {
    system("ip link add lo1 type dummy");
    system("ip addr add 50.1.1.1/32 dev lo1");
    system("ip -6 addr add 5111::1/128 dev lo1");
    sleep(5);
    cps_api_return_code_t rc = nas_ut_validate_rt_cfg ("default", AF_INET, "50.1.1.1", 32, "default",
                                                       NULL, NULL, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    rc = nas_ut_validate_rt_cfg ("default", AF_INET6, "5111::1", 128, "default", NULL, NULL, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    system("ip link del lo1");
    sleep(5);
    /* Verify that the route entries are not present in the NPU */
    rc = nas_ut_validate_rt_cfg ("default", AF_INET, "50.1.1.1", 32, "default",
                                 NULL, NULL, true);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);
    rc = nas_ut_validate_rt_cfg ("default", AF_INET6, "5111::1", 128, "default", NULL, NULL, true);
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
  system("ip addr add  100:1::1/64 dev br100");
  system("ifconfig br100 up");
  system("brctl stp br100 on");
  system("ip neigh add 100.1.1.10 lladdr 00:00:00:00:11:22");

  system("brctl addbr br200 up");
  system("ifconfig br200 down");
  system("ip link add link e101-003-0 name e101-003-0.200 type vlan id 200");
  system("ifconfig e101-003-0 up");
  system("ip link set dev e101-003-0.200 up");
  system("brctl addif br200 e101-003-0.200");
  system("ip addr add 200.1.1.2/24 dev br200");
  system("ip addr add  200:1::1/64 dev br200");
  system("ifconfig br200 up");
  system("brctl stp br200 on");

  system("brctl addbr br201 up");
  system("ifconfig br201 down");
  system("ip link add link e101-003-0 name e101-003-0.201 type vlan id 201");
  system("ifconfig e101-003-0 up");
  system("ip link set dev e101-003-0.201 up");
  system("brctl addif br201 e101-003-0.201");
  system("ip addr add 201.1.1.2/24 dev br201");
  system("ip addr add  201:1::1/64 dev br201");
  system("ifconfig br201 up");
  system("brctl stp br201 on");


  printf("___________________________________________\n");

  return RUN_ALL_TESTS();
}
