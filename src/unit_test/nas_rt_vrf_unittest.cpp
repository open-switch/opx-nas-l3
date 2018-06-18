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
 * nas_rt_vrf_unittest.cpp
 */
#include "nas_rt_util_unittest.h"
#include "dell-base-routing.h"

#include <gtest/gtest.h>
#include <iostream>
#include "sys/time.h"
#include "math.h"

/* NOTE: Change the back to back connected ports here based on availability in the node, also,
 * if we are running this test in Enterprise package, make sure "no switchport" command is executed in CLI
 * on these two ports before running the script. */
const char *b2b_intf1 = "e101-019-0";
const char *b2b_intf2 = "e101-020-0";
const char *DoD_b2b_intf1 = "1/1/19";
const char *DoD_b2b_intf2 = "1/1/20";

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
    snprintf(buffer, 50, "%s.%03d ", buf, millisec);

    return;
}


static void nas_vrf_change_mode(bool is_l3) {
    int ret = system("opx-show-version | grep \"OS_NAME.*Enterprise\"");
    if (ret == 0) {
        FILE *fp;

        fp = fopen("/tmp/test_pre_req","w");
        fprintf(fp, "configure terminal\n");
        fprintf(fp, "interface ethernet %s\n", DoD_b2b_intf1);
        if (is_l3) {
            fprintf(fp, "no switchport\n");
        } else {
            fprintf(fp, "switchport mode access\n");
        }

        fprintf(fp, "exit\n");
        fprintf(fp, "interface ethernet %s\n", DoD_b2b_intf2);
        if (is_l3) {
            fprintf(fp, "no switchport\n");
        } else {
            fprintf(fp, "switchport mode access\n");
        }
        fprintf(fp, "exit\n");
        fflush(fp);
        system("sudo -u admin clish --b /tmp/test_pre_req");
    }
}


static void nas_rt_special_next_hop_config(bool is_add, const char *vrf_name) {
    cps_api_return_code_t rc;
    rc = nas_ut_route_op_spl_nh (is_add, vrf_name, "44.1.0.0", 16, BASE_ROUTE_SPECIAL_NEXT_HOP_BLACKHOLE, AF_INET);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    rc = nas_ut_route_op_spl_nh (is_add, vrf_name, "44.2.0.0", 16, BASE_ROUTE_SPECIAL_NEXT_HOP_UNREACHABLE, AF_INET);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    rc = nas_ut_route_op_spl_nh (is_add, vrf_name, "44.3.0.0", 16, BASE_ROUTE_SPECIAL_NEXT_HOP_PROHIBIT, AF_INET);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    rc = nas_ut_route_op_spl_nh (is_add, vrf_name, "0.0.0.0", 0, BASE_ROUTE_SPECIAL_NEXT_HOP_BLACKHOLE, AF_INET);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    rc = nas_ut_route_op_spl_nh (is_add, vrf_name, "1111:1111::", 64, BASE_ROUTE_SPECIAL_NEXT_HOP_BLACKHOLE, AF_INET6);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    rc = nas_ut_route_op_spl_nh (is_add, vrf_name, "1111:2222::", 64, BASE_ROUTE_SPECIAL_NEXT_HOP_UNREACHABLE, AF_INET6);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    rc = nas_ut_route_op_spl_nh (is_add, vrf_name, "1111:3333::", 64, BASE_ROUTE_SPECIAL_NEXT_HOP_PROHIBIT, AF_INET6);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    rc = nas_ut_route_op_spl_nh (is_add, vrf_name, "0::0", 0, BASE_ROUTE_SPECIAL_NEXT_HOP_BLACKHOLE, AF_INET6);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
}

static void nas_rt_special_next_hop_validate(const char *vrf_name, cps_api_return_code_t rc_check) {
    cps_api_return_code_t rc;
    sleep(5);
    rc = nas_ut_validate_rt_cfg (vrf_name, AF_INET, "44.1.0.0", 16, vrf_name, NULL, NULL, true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg (vrf_name, AF_INET, "44.2.0.0", 16, vrf_name, NULL, NULL, true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg (vrf_name, AF_INET, "44.3.0.0", 16, vrf_name, NULL, NULL, true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg (vrf_name, AF_INET, "0.0.0.0", 0, vrf_name, NULL, NULL, true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg (vrf_name, AF_INET6,"1111:1111::", 64, vrf_name, NULL, NULL, true);
    ASSERT_TRUE(rc == rc_check);
    rc =  nas_ut_validate_rt_cfg (vrf_name, AF_INET6,"1111:2222::", 64, vrf_name, NULL, NULL, true);
    ASSERT_TRUE(rc == rc_check);
    rc =  nas_ut_validate_rt_cfg (vrf_name, AF_INET6,"1111:3333::", 64, vrf_name, NULL, NULL, true);
    ASSERT_TRUE(rc == rc_check);
    rc =  nas_ut_validate_rt_cfg (vrf_name, AF_INET6,"0::0", 0, vrf_name, NULL, NULL, true);
    ASSERT_TRUE(rc == rc_check);
}

static void nas_rt_scal_test(int start_vrf_id, int no_of_vrfs, bool is_add, cps_api_return_code_t rc_check) {
    char cmd [512];
    char vrf[10];
    char vlan[10];
    int id;
    cps_api_return_code_t rc;

    for (id = start_vrf_id ;id < (start_vrf_id+no_of_vrfs); id++) {
        memset(vrf, '\0', sizeof(vrf));
        memset(vlan, '\0', sizeof(vlan));
        snprintf(vrf, sizeof(vrf), "vrf%d", id);
        snprintf(vlan, sizeof(vlan), "br%d", id);

        if (is_add == false) {
            rc = nas_ut_intf_vrf_cfg(vrf,vlan,false);
            ASSERT_TRUE(rc == cps_api_ret_code_OK);
            rc = nas_ut_vrf_cfg(vrf,false);
            ASSERT_TRUE(rc == cps_api_ret_code_OK);

            memset(cmd, '\0', sizeof(cmd));
            snprintf(cmd, 511, "ip link delete %s.%d", b2b_intf1, id);
            system(cmd);

            memset(cmd, '\0', sizeof(cmd));
            snprintf(cmd, 511, "ip link set dev %s down", vlan);
            system(cmd);

            memset(cmd, '\0', sizeof(cmd));
            snprintf(cmd, 511, "ip link delete %s", vlan);
            system(cmd);
            continue;
        }

        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "brctl addbr %s", vlan);
        system(cmd);

        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip link set dev %s up", vlan);
        system(cmd);

        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip link add link %s name %s.%d type vlan id %d",
                 b2b_intf1, b2b_intf1, id, id);
        system(cmd);
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "brctl addif %s %s.%d", vlan, b2b_intf1, id);
        system(cmd);
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip link set dev %s.%d up", b2b_intf1, id);
        system(cmd);
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip link set dev %s up", vlan);
        system(cmd);

        rc = nas_ut_vrf_cfg(vrf,true);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);
        rc = nas_ut_intf_vrf_cfg(vrf,vlan,true);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);

        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip -n %s addr add 100.0.0.1/24 dev v-%s", vrf, vlan);
        system(cmd);
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip -n %s neigh add 100.0.0.2 lladdr 00:11:22:33:44:55 dev v-%s", vrf, vlan);
        system(cmd);
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip -n %s route add 60.0.0.0/8 via 100.0.0.2", vrf);
        system(cmd);
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip -n %s addr add 100::1/64 dev v-%s", vrf, vlan);
        system(cmd);
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip -n %s neigh add 100::2 lladdr 00:11:22:33:44:55 dev v-%s", vrf, vlan);
        system(cmd);
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip -n %s -6 route add 60::/64 via 100::2", vrf);
        system(cmd);
    }
    if (is_add) {
        sleep(10);
    }
    for (id = start_vrf_id ;id < (start_vrf_id+no_of_vrfs); id++) {
        memset(vrf, '\0', sizeof(vrf));
        snprintf(vrf, sizeof(vrf), "vrf%d", id);
        printf("\r\n VRF:%s is_add:%d", vrf, is_add);
        rc = nas_ut_validate_rt_cfg (vrf, AF_INET, "100.0.0.1", 32, vrf, "", "", false);
        ASSERT_TRUE(rc == rc_check);
        rc = nas_ut_validate_rt_cfg (vrf, AF_INET, "100.0.0.0", 24, vrf, "", "", true);
        ASSERT_TRUE(rc == rc_check);
        rc = nas_ut_validate_neigh_cfg(vrf, AF_INET, "100.0.0.2", 128, true);
        ASSERT_TRUE(rc == rc_check);
        rc = nas_ut_validate_rt_cfg (vrf, AF_INET, "60.0.0.0", 8, vrf, "", "", true);
        ASSERT_TRUE(rc == rc_check);
        rc = nas_ut_validate_rt_cfg (vrf, AF_INET6, "100::1", 128, vrf, "", "", false);
        ASSERT_TRUE(rc == rc_check);
        rc = nas_ut_validate_rt_cfg (vrf, AF_INET6, "100::0", 64, vrf, "", "", true);
        ASSERT_TRUE(rc == rc_check);
        rc = nas_ut_validate_neigh_cfg(vrf, AF_INET6, "100::2", 128, true);
        ASSERT_TRUE(rc == rc_check);
        rc = nas_ut_validate_rt_cfg (vrf, AF_INET6, "60::0", 64, vrf, "", "", true);
        ASSERT_TRUE(rc == rc_check);
        rc = nas_ut_validate_rt_cfg (vrf, AF_INET6, "fe80::", 10, vrf, "", "", true);
        ASSERT_TRUE(rc == rc_check);
    }
}

static void nas_rt_scal_neigh_test(int start_vrf_id, int no_of_vrfs, int scal_arp_limit, int scal_neigh_limit,
                                   bool is_add, cps_api_return_code_t rc_check, bool is_neg_test, bool fail_ok) {
    char cmd [512];
    char vrf[10];
    char vlan[10];
    int id, itr = 0;
    cps_api_return_code_t rc;

    /* Add/Del neighbors on the br1 in the default VRF */
    for (itr = 2; itr <= (scal_arp_limit +1); itr++) {
        if (is_neg_test == false) {
            memset(cmd, '\0', sizeof(cmd));
            if (is_add) {
                snprintf(cmd, 511, "/usr/bin/cps_config_mac.py create mac 00:11:22:33:44:%02x port %s vlan 1 static", itr, b2b_intf1);
            } else {
                snprintf(cmd, 511, "/usr/bin/cps_config_mac.py delete vlan 1 port %s 00:11:22:33:44:%02x static", b2b_intf1, itr);
            }
            system(cmd);
        }
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip neigh %s 100.0.0.%d lladdr 00:11:22:33:44:%02x dev br1",
                 (is_add ? "add" : "del"), itr, itr);
        system(cmd);
        if (itr <= (scal_neigh_limit+1)) {
            memset(cmd, '\0', sizeof(cmd));
            snprintf(cmd, 511, "ip neigh %s 100::%x lladdr 00:11:22:33:44:%02x dev br1",
                     (is_add ? "add" : "del"), itr, itr);
            system(cmd);
        }
    }
    for (id = start_vrf_id ;id < (start_vrf_id+no_of_vrfs); id++) {
        memset(vrf, '\0', sizeof(vrf));
        memset(vlan, '\0', sizeof(vlan));
        snprintf(vrf, sizeof(vrf), "vrf%d", id);
        snprintf(vlan, sizeof(vlan), "br%d", id);

        if (is_add == false) {
            if (is_neg_test == false) {
                for (itr = 2; itr <= (scal_arp_limit +1); itr++) {
                    memset(cmd, '\0', sizeof(cmd));
                    snprintf(cmd, 511, "/opt/opx/bin/cps_config_mac.py delete vlan %d port %s 00:11:22:33:44:%02x static", id, b2b_intf1, itr);
                    system(cmd);
                }
            }
            rc = nas_ut_intf_vrf_cfg(vrf,vlan,false);
            if (!fail_ok)
                ASSERT_TRUE(rc == cps_api_ret_code_OK);
            rc = nas_ut_vrf_cfg(vrf,false);
            if (!fail_ok)
                ASSERT_TRUE(rc == cps_api_ret_code_OK);

            memset(cmd, '\0', sizeof(cmd));
            snprintf(cmd, 511, "ip link delete %s.%d", b2b_intf1, id);
            system(cmd);

            memset(cmd, '\0', sizeof(cmd));
            snprintf(cmd, 511, "ip link set dev %s down", vlan);
            system(cmd);

            memset(cmd, '\0', sizeof(cmd));
            snprintf(cmd, 511, "ip link delete %s", vlan);
            system(cmd);
            continue;
        }

        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "brctl addbr %s", vlan);
        system(cmd);

        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip link set dev %s up", vlan);
        system(cmd);

        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip link add link %s name %s.%d type vlan id %d",
                 b2b_intf1, b2b_intf1, id, id);
        system(cmd);
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "brctl addif %s %s.%d", vlan, b2b_intf1, id);
        system(cmd);
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip link set dev %s.%d up", b2b_intf1, id);
        system(cmd);
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip link set dev %s up", vlan);
        system(cmd);

        rc = nas_ut_vrf_cfg(vrf,true);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);
        rc = nas_ut_intf_vrf_cfg(vrf,vlan,true);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);

        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip -n %s addr add 100.0.0.1/24 dev v-%s", vrf, vlan);
        system(cmd);
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip -n %s addr add 100::1/64 dev v-%s", vrf, vlan);
        system(cmd);
        for (itr = 2; itr <= (scal_arp_limit +1); itr++) {
            if (is_neg_test == false) {
                memset(cmd, '\0', sizeof(cmd));
                snprintf(cmd, 511, "/usr/bin/cps_config_mac.py create mac 00:11:22:33:44:%02x port %s vlan %d static", itr, b2b_intf1, id);
                system(cmd);
            }
            memset(cmd, '\0', sizeof(cmd));
            snprintf(cmd, 511, "ip -n %s neigh add 100.0.0.%d lladdr 00:11:22:33:44:%02x dev v-%s",
                     vrf, itr, itr, vlan);
            system(cmd);
            if (itr <= (scal_neigh_limit+1)) {
                memset(cmd, '\0', sizeof(cmd));
                snprintf(cmd, 511, "ip -n %s neigh add 100::%x lladdr 00:11:22:33:44:%02x dev v-%s",
                         vrf, itr, itr, vlan);
                system(cmd);
            }
        }
    }
    sleep(10);
    char ip[64];
    for (id = 1 ;id < (start_vrf_id+no_of_vrfs); id++) {
        memset(vrf, '\0', sizeof(vrf));
        if (id == 1) {
            snprintf(vrf, sizeof(vrf), "default");
            printf("\r\n VRF:%s is_add:%d", vrf, is_add);
        } else {
            snprintf(vrf, sizeof(vrf), "vrf%d", id);
            printf("\r\n VRF:%s is_add:%d", vrf, is_add);
        }
        for (itr = 2; itr <= (scal_arp_limit +1); itr++) {
            memset(ip, '\0', sizeof(ip));
            snprintf(ip, sizeof(ip), "100.0.0.%d", itr);
            rc = nas_ut_validate_neigh_cfg(vrf, AF_INET, ip, 128, true);
            ASSERT_TRUE(rc == rc_check);
            if (itr <= (scal_neigh_limit+1)) {
                memset(ip, '\0', sizeof(ip));
                snprintf(ip, sizeof(ip), "100::%x", itr);
                rc = nas_ut_validate_neigh_cfg(vrf, AF_INET6, ip, 128, true);
                ASSERT_TRUE(rc == rc_check);
            }
        }
    }
}

static void nas_rt_cleanup() {
    char cmd [512];
    memset(cmd, '\0', sizeof(cmd));
    snprintf(cmd, 511, "ip link set dev %s down", b2b_intf1);
    system(cmd);
    memset(cmd, '\0', sizeof(cmd));
    snprintf(cmd, 511, "ip link set dev %s up", b2b_intf1);
    system(cmd);

    memset(cmd, '\0', sizeof(cmd));
    snprintf(cmd, 511, "ip link set dev %s down", b2b_intf2);
    system(cmd);
    memset(cmd, '\0', sizeof(cmd));
    snprintf(cmd, 511, "ip link set dev %s up", b2b_intf2);
    system(cmd);
}

static void nas_rt_validate_blue_vrf_config(cps_api_return_code_t rc_check) {
    cps_api_return_code_t rc;
    sleep(5);
    rc = nas_ut_validate_rt_cfg ("default", AF_INET, "30.0.0.0", 24, "default", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("default", AF_INET6, "3333::0", 64, "default", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("default", AF_INET, "40.0.0.1", 32, "default", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("default", AF_INET6, "4444::1", 128, "default", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("default", AF_INET, "50.0.0.0", 24, "default", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("default", AF_INET6, "5555::0", 64, "default", "", "", true);
    ASSERT_TRUE(rc == rc_check);

    rc = nas_ut_validate_rt_cfg ("blue", AF_INET, "30.0.0.0", 24, "blue", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("blue", AF_INET6, "3333::0", 64, "blue", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("blue", AF_INET, "50.0.0.1", 32, "blue", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("blue", AF_INET6, "5555::1", 128, "blue", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("blue", AF_INET, "40.0.0.0", 24, "blue", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("blue", AF_INET6, "4444::0", 64, "blue", "", "", true);
    ASSERT_TRUE(rc == rc_check);

    rc = nas_ut_validate_neigh_cfg("default", 2, "30.0.0.2", 2, true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_neigh_cfg("default", 10, "3333::2", 2, true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_neigh_cfg("blue", 2, "30.0.0.1", 2, true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_neigh_cfg("blue", 10, "3333::1", 2, true);
    ASSERT_TRUE(rc == rc_check);
}

static void nas_rt_validate_red_vrf_config(cps_api_return_code_t rc_check) {
    cps_api_return_code_t rc;
    sleep(5);
    rc = nas_ut_validate_rt_cfg ("red", AF_INET, "30.0.0.0", 24, "red", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("red", AF_INET6, "3333::0", 64, "red", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("red", AF_INET, "40.0.0.1", 32, "red", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("red", AF_INET6, "4444::1", 128, "red", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("red", AF_INET, "50.0.0.0", 24, "red", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("red", AF_INET6, "5555::0", 64, "red", "", "", true);
    ASSERT_TRUE(rc == rc_check);


    rc = nas_ut_validate_rt_cfg ("default", AF_INET, "30.0.0.0", 24, "default", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("default", AF_INET6, "3333::0", 64, "default", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("default", AF_INET, "50.0.0.1", 32, "default", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("default", AF_INET6, "5555::1", 128, "default", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("default", AF_INET, "40.0.0.0", 24, "default", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("default", AF_INET6, "4444::0", 64, "default", "", "", true);
    ASSERT_TRUE(rc == rc_check);

    rc = nas_ut_validate_neigh_cfg("red", 2, "30.0.0.2", 2, true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_neigh_cfg("red", 10, "3333::2", 2, true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_neigh_cfg("default", 2, "30.0.0.1", 2, true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_neigh_cfg("default", 10, "3333::1", 2, true);
    ASSERT_TRUE(rc == rc_check);
}

static void nas_rt_basic_red_vrf_vlan_cfg(bool is_add) {
    cps_api_return_code_t rc;
    char cmd [512];

    if (is_add == false) {
        std::cout <<"********* Removing VRF with VLAN configurations *********"<<std::endl;
        system("ip -n red addr del 30.0.0.1/24 dev v-br100");
        system("ip -n red addr del 3333::1/64 dev v-br100");
        system("ip -n red link del dev lo1");
        rc = nas_ut_intf_vrf_cfg("red","br100",false);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);
        rc = nas_ut_vrf_cfg("red",false);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "brctl delif br100 %s", b2b_intf1);
        system(cmd);
        system("ifconfig br100 down");
        system("brctl delbr br100");

        system("ip route del 40.0.0.0/24 via 30.0.0.1");
        system("ip -6 route del 4444::/64 via 3333::1");
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip addr del 30.0.0.2/24 dev %s", b2b_intf2);
        system(cmd);
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip addr del 3333::2/64 dev %s", b2b_intf2);
        system(cmd);

        system("ip link del dev lo2");
        return;
    }
    std::cout <<"********* Adding VRF with VLAN configurations *********"<<std::endl;

    system("brctl addbr br100");
    memset(cmd, '\0', sizeof(cmd));
    snprintf(cmd, 511, "brctl addif br100 %s", b2b_intf1);
    system(cmd);
    system("ip link set dev br100 up");
    system("ip link add link e101-002-0 name e101-002-0.100 type vlan id 100");
    system("brctl addif br100 e101-002-0.100");

    rc = nas_ut_vrf_cfg("red",true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    rc = nas_ut_intf_vrf_cfg("red","br100",true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    system("ip -n red addr add 30.0.0.1/24 dev v-br100");
    system("ip -n red addr add  3333::1/64 dev v-br100");

    system("ip -n red link add lo1 type dummy");
    system("ip -n red link set dev lo1 up");
    system("ip -n red addr add 40.0.0.1/32 dev lo1");
    system("ip -n red addr add  4444::1/128 dev lo1");
    system("ip -n red route add 50.0.0.0/24 via 30.0.0.2");
    system("ip -n red -6 route add 5555::/64 via 3333::2");

    memset(cmd, '\0', sizeof(cmd));
    snprintf(cmd, 511, "ip addr add 30.0.0.2/24 dev %s", b2b_intf2);
    system(cmd);
    memset(cmd, '\0', sizeof(cmd));
    snprintf(cmd, 511, "ip addr add 3333::2/64 dev %s", b2b_intf2);
    system(cmd);

    system("ip link add lo2 type dummy");
    system("ip link set dev lo2 up");
    system("ip addr add 50.0.0.1/32 dev lo2");
    system("ip addr add  5555::1/128 dev lo2");
    system("ip route add 40.0.0.0/24 via 30.0.0.1");
    system("ip -6 route add 4444::/64 via 3333::1");
}

static void nas_rt_basic_blue_vrf_lag_cfg(bool is_add) {
    cps_api_return_code_t rc;
    char cmd [512];

    if (is_add == false) {
        std::cout <<"********* Removing VRF with LAG configurations *********"<<std::endl;
        system("ip route del 50.0.0.0/24 via 30.0.0.2");
        system("ip -6 route del 5555::/64 via 3333::2");
        system("ip addr del 40.0.0.1/32 dev lo1");
        system("ip addr del  4444::1/128 dev lo1");
        system("ip link del lo1");
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip addr del 30.0.0.1/24 dev %s", b2b_intf1);
        system(cmd);
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip addr del 3333::1/64 dev %s", b2b_intf1);
        system(cmd);

        rc = nas_ut_intf_vrf_cfg("blue","bo50",false);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);
        rc = nas_ut_intf_vrf_cfg("blue","lo2",false);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);
        rc = nas_ut_vrf_cfg("blue",false);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);

        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip link set %s nomaster", b2b_intf2);
        system(cmd);
        system("ip link del dev bo50");
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip link set dev %s up", b2b_intf2);
        system(cmd);
        system("ip link del lo2");
        return;
    }

    std::cout <<"********* Adding VRF with LAG configurations *********"<<std::endl;
    memset(cmd, '\0', sizeof(cmd));
    snprintf(cmd, 511, "ip addr add 30.0.0.1/24 dev %s", b2b_intf1);
    system(cmd);
    memset(cmd, '\0', sizeof(cmd));
    snprintf(cmd, 511, "ip addr add 3333::1/64 dev %s", b2b_intf1);
    system(cmd);
    system("ip link add lo1 type dummy");
    system("ip link set dev lo1 up");
    system("ip addr add 40.0.0.1/32 dev lo1");
    system("ip addr add  4444::1/128 dev lo1");
    system("ip route add 50.0.0.0/24 via 30.0.0.2");
    system("ip -6 route add 5555::/64 via 3333::2");

    system("ip link add bo50 type bond mode 1 miimon 100");
    system("ip link set dev bo50 up");
    memset(cmd, '\0', sizeof(cmd));
    snprintf(cmd, 511, "ip link set dev %s down", b2b_intf2);
    system(cmd);
    memset(cmd, '\0', sizeof(cmd));
    snprintf(cmd, 511, "ip link set %s master bo50", b2b_intf2);
    system(cmd);
    system("ifconfig bo50 up");

    rc = nas_ut_vrf_cfg("blue",true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    system("ip link add lo2 type dummy");
    system("ip link set dev lo2 up");
    rc = nas_ut_intf_vrf_cfg("blue","lo2",true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    rc = nas_ut_intf_vrf_cfg("blue","bo50",true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    /* @@TODO This sleep is required today, since NAS-interface updates the intf-DB
     * after getting the route update in NAS-L3 */
    sleep(2);
    system("ip -n blue addr add 30.0.0.2/24 dev v-bo50");
    system("ip -n blue addr add  3333::2/64 dev v-bo50");
    system("ip -n blue addr add 50.0.0.1/32 dev v-lo2");
    system("ip -n blue addr add  5555::1/128 dev v-lo2");
    system("ip -n blue route add 40.0.0.0/24 via 30.0.0.1");
    system("ip -n blue -6 route add 4444::/64 via 3333::1");
}

static void nas_rt_basic_blue_vrf_phy_cfg(bool is_add) {
    cps_api_return_code_t rc;
    char cmd [512];

    if (is_add == false) {
        std::cout <<"********* Removing VRF with PHY configurations *********"<<std::endl;
        nas_rt_special_next_hop_config(false, "blue");
        rc = nas_ut_intf_vrf_cfg("blue",b2b_intf2,false);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);
        rc = nas_ut_intf_vrf_cfg("blue","lo2",false);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);
        rc = nas_ut_vrf_cfg("blue",false);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);
        system("ip link del lo2");

        nas_ut_rt_cfg (NULL,0, "50.0.0.0", 24, AF_INET, NULL, "30.0.0.2", b2b_intf1);
        nas_ut_rt_cfg ("default",0, "5555::", 64, AF_INET6, NULL, "3333::2", b2b_intf1);
        system("ip addr del 40.0.0.1/32 dev lo1");
        system("ip addr del  4444::1/128 dev lo1");
        system("ip link del lo1");
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip addr del 30.0.0.1/24 dev %s", b2b_intf1);
        system(cmd);
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip addr del 3333::1/64 dev %s", b2b_intf1);
        system(cmd);

        return;
    }
    std::cout <<"********* Adding VRF with PHY configurations *********"<<std::endl;
    memset(cmd, '\0', sizeof(cmd));
    snprintf(cmd, 511, "ip addr add 30.0.0.1/24 dev %s", b2b_intf1);
    system(cmd);
    memset(cmd, '\0', sizeof(cmd));
    snprintf(cmd, 511, "ip addr add 3333::1/64 dev %s", b2b_intf1);
    system(cmd);
    system("ip link add lo1 type dummy");
    system("ip link set dev lo1 up");
    system("ip addr add 40.0.0.1/32 dev lo1");
    system("ip addr add  4444::1/128 dev lo1");

    nas_ut_rt_cfg (NULL,1, "50.0.0.0", 24, AF_INET, NULL, "30.0.0.2", b2b_intf1);
    nas_ut_rt_cfg ("default",1, "5555::", 64, AF_INET6, NULL, "3333::2", b2b_intf1);

    rc = nas_ut_vrf_cfg("blue",true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    rc = nas_ut_intf_vrf_cfg("blue",b2b_intf2,true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    system("ip link add lo2 type dummy");
    system("ip link set dev lo2 up");
    rc = nas_ut_intf_vrf_cfg("blue","lo2",true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    /* @@TODO This sleep is required today, since NAS-interface updates the intf-DB
     * after getting the route update in NAS-L3 */
    sleep(2);
    memset(cmd, '\0', sizeof(cmd));
    snprintf(cmd, 511, "ip -n blue addr add 30.0.0.2/24 dev v-%s", b2b_intf2);
    system(cmd);
    memset(cmd, '\0', sizeof(cmd));
    snprintf(cmd, 511, "ip -n blue addr add 3333::2/64 dev v-%s", b2b_intf2);
    system(cmd);
    system("ip -n blue addr add 50.0.0.1/32 dev v-lo2");
    system("ip -n blue addr add  5555::1/128 dev v-lo2");
    char rt_intf[15];
    memset(rt_intf, '\0', sizeof(rt_intf));
    snprintf(rt_intf, sizeof(rt_intf), "v-%s", b2b_intf2);

    nas_ut_rt_cfg ("blue",1, "40.0.0.0", 24, AF_INET, NULL, "30.0.0.1", rt_intf);
    nas_ut_rt_cfg ("blue",1, "4444::", 64, AF_INET6, "blue", "3333::1", rt_intf);

    nas_rt_special_next_hop_config(true, "blue");
}

static void nas_rt_perf_test(int no_of_intfs, bool is_add) {
    char cmd [512];
    char vlan[10];
    int id, start_intf_id = 2;
    cps_api_return_code_t rc;

    rc = nas_ut_vrf_cfg("blue", is_add);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    for (id = start_intf_id; id < (start_intf_id + no_of_intfs); id++) {
        memset(vlan, '\0', sizeof(vlan));
        snprintf(vlan, sizeof(vlan), "br%d", id);

        if (is_add == false) {
            memset(cmd, '\0', sizeof(cmd));
            snprintf(cmd, 511, "ip link delete %s.%d", b2b_intf1, id);
            system(cmd);

            memset(cmd, '\0', sizeof(cmd));
            snprintf(cmd, 511, "ip link set dev %s down", vlan);
            system(cmd);

            memset(cmd, '\0', sizeof(cmd));
            snprintf(cmd, 511, "ip link delete %s", vlan);
            system(cmd);
            continue;
        }

        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "brctl addbr %s", vlan);
        system(cmd);

        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip link set dev %s up", vlan);
        system(cmd);

        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip link add link %s name %s.%d type vlan id %d",
                 b2b_intf1, b2b_intf1, id, id);
        system(cmd);
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "brctl addif %s %s.%d", vlan, b2b_intf1, id);
        system(cmd);
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip link set dev %s.%d up", b2b_intf1, id);
        system(cmd);
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip link set dev %s up", vlan);
        system(cmd);
    }
}


TEST(nas_rt_vrf_test, nas_rt_basic_vlan_vrf) {
    /* @@TODO Fix VLAN test case/ */
    return;
    nas_rt_basic_red_vrf_vlan_cfg(true);
    nas_rt_validate_red_vrf_config(cps_api_ret_code_OK);
    system("ip netns exec red ping -c 3 30.0.0.2");
    system("ip netns exec red ping6 -c 3 3333::2");
    system("ip netns exec red ping -c 3 50.0.0.1");
    system("ip netns exec red ping6 -c 3 5555::1");
    nas_rt_basic_red_vrf_vlan_cfg(false);
    nas_rt_validate_red_vrf_config(cps_api_ret_code_ERR);
    nas_rt_cleanup();
}

TEST(nas_rt_vrf_test, nas_rt_basic_lag_vrf) {
    nas_rt_basic_blue_vrf_lag_cfg(true);
    nas_rt_validate_blue_vrf_config(cps_api_ret_code_OK);
    system("ping -c 3 30.0.0.2");
    system("ping6 -c 3 3333::2");
    system("ping -c 3 50.0.0.1");
    system("ping6 -c 3 5555::1");
    nas_rt_basic_blue_vrf_lag_cfg(false);
    nas_rt_validate_blue_vrf_config(cps_api_ret_code_ERR);
    nas_rt_cleanup();
}

TEST(nas_rt_vrf_test, nas_rt_basic_phy_vrf) {
    char cmd [512];
    uint32_t loop_cnt = 3;
    while (loop_cnt--) {
        printf("\r\n PHY config. loop:%d\r\n", loop_cnt);
        nas_rt_basic_blue_vrf_phy_cfg(true);
        nas_rt_special_next_hop_validate("blue", cps_api_ret_code_OK);

        nas_rt_validate_blue_vrf_config(cps_api_ret_code_OK);
        system("ping -c 3 30.0.0.2");
        system("ping6 -c 3 3333::2");
        system("ping -c 3 50.0.0.1");
        system("ping6 -c 3 5555::1");

        system("ip addr del 40.0.0.1/32 dev lo1");
        system("ip addr del  4444::1/128 dev lo1");
        system("ip -n blue addr del 50.0.0.1/32 dev v-lo2");
        system("ip -n blue addr del  5555::1/128 dev v-lo2");
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip link set dev %s down", b2b_intf1);
        system(cmd);
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip -n blue link set dev v-%s down", b2b_intf2);
        system(cmd);
        if (loop_cnt == 2) {
            nas_rt_basic_blue_vrf_phy_cfg(false);
            nas_rt_special_next_hop_validate("blue", cps_api_ret_code_ERR);
            nas_rt_validate_blue_vrf_config(cps_api_ret_code_ERR);
            memset(cmd, '\0', sizeof(cmd));
            snprintf(cmd, 511, "ip link set dev %s up", b2b_intf1);
            system(cmd);
            continue;
        }
        nas_rt_basic_blue_vrf_phy_cfg(false);
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip link set dev %s up", b2b_intf1);
        system(cmd);
        sleep(1);
    }
    nas_rt_special_next_hop_validate("blue", cps_api_ret_code_ERR);
    nas_rt_validate_blue_vrf_config(cps_api_ret_code_ERR);
    nas_rt_cleanup();
}

TEST(nas_rt_vrf_test, nas_rt_leak_route) {
    cps_api_return_code_t rc;
    char cmd [512];
    uint32_t loop_cnt = 3;
    while (loop_cnt--) {
        printf("\r\n PHY config. loop:%d\r\n", loop_cnt);
        nas_rt_basic_blue_vrf_phy_cfg(true);
        nas_rt_special_next_hop_validate("blue", cps_api_ret_code_OK);
        nas_rt_validate_blue_vrf_config(cps_api_ret_code_OK);

        /* Leak 40.0.0.0/24 route from blue VRF to red VRF */
        rc = nas_ut_vrf_cfg("red",true);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);
        char rt_intf[15];
        memset(rt_intf, '\0', sizeof(rt_intf));
        snprintf(rt_intf, sizeof(rt_intf), "v-%s", b2b_intf2);
        nas_ut_rt_cfg ("red",1, "40.0.0.0", 24, AF_INET, "blue", "30.0.0.1", rt_intf);
        nas_ut_rt_cfg ("red",1, "4444::", 64, AF_INET6, "blue", "3333::1", rt_intf);
        nas_ut_rt_cfg (NULL,1, "60.0.0.0", 24, AF_INET, "blue", "30.0.0.1", rt_intf);
        nas_ut_rt_cfg ("default",1, "6666::", 64, AF_INET6, "blue", "3333::1", rt_intf);

        /* Leak 50.0.0.0/24 route from default VRF to green VRF */
        rc = nas_ut_vrf_cfg("green",true);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);
        nas_ut_rt_cfg ("green",1, "50.0.0.0", 24, AF_INET, "default", "30.0.0.2", b2b_intf1);
        nas_ut_rt_cfg ("green",1, "5555::", 64, AF_INET6, "default", "3333::2", b2b_intf1);
        sleep(3);

        rc = nas_ut_validate_rt_cfg ("red", AF_INET, "40.0.0.0", 24, "blue", "", "", true);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);
        rc = nas_ut_validate_rt_cfg ("red", AF_INET6, "4444::", 64, "blue", "", "", true);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);
        rc = nas_ut_validate_rt_cfg ("default", AF_INET, "60.0.0.0", 24, "blue", "", "", true);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);
        rc = nas_ut_validate_rt_cfg ("default", AF_INET6, "6666::", 64, "blue", "", "", true);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);
        rc = nas_ut_validate_rt_cfg ("green", AF_INET, "50.0.0.0", 24, "default", "", "", true);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);
        rc = nas_ut_validate_rt_cfg ("green", AF_INET6, "5555::", 64, "default", "", "", true);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);

        system("ping -c 3 30.0.0.2");
        system("ping6 -c 3 3333::2");
        system("ping -c 3 50.0.0.1");
        system("ping6 -c 3 5555::1");
        system("ip addr del 40.0.0.1/32 dev lo1");
        system("ip addr del  4444::1/128 dev lo1");
        system("ip -n blue addr del 50.0.0.1/32 dev v-lo2");
        system("ip -n blue addr del  5555::1/128 dev v-lo2");
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip link set dev %s down", b2b_intf1);
        system(cmd);
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip -n blue link set dev v-%s down", b2b_intf2);
        system(cmd);
        nas_rt_special_next_hop_validate("blue", cps_api_ret_code_OK);
        nas_rt_validate_blue_vrf_config(cps_api_ret_code_ERR);
        sleep(3);
        rc = nas_ut_validate_rt_cfg ("red", AF_INET, "40.0.0.0", 24, "blue", "", "", true);
        ASSERT_TRUE(rc == cps_api_ret_code_ERR);
        rc = nas_ut_validate_rt_cfg ("red", AF_INET6, "4444::", 64, "blue", "", "", true);
        ASSERT_TRUE(rc == cps_api_ret_code_ERR);
        rc = nas_ut_validate_rt_cfg ("default", AF_INET, "60.0.0.0", 24, "blue", "", "", true);
        ASSERT_TRUE(rc == cps_api_ret_code_ERR);
        rc = nas_ut_validate_rt_cfg ("default", AF_INET6, "6666::", 64, "blue", "", "", true);
        ASSERT_TRUE(rc == cps_api_ret_code_ERR);
        rc = nas_ut_validate_rt_cfg ("green", AF_INET, "50.0.0.0", 24, "default", "", "", true);
        ASSERT_TRUE(rc == cps_api_ret_code_ERR);
        rc = nas_ut_validate_rt_cfg ("green", AF_INET6, "5555::", 64, "default", "", "", true);
        ASSERT_TRUE(rc == cps_api_ret_code_ERR);

        nas_rt_basic_blue_vrf_phy_cfg(false);
        rc = nas_ut_vrf_cfg("green",false);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);
        rc = nas_ut_vrf_cfg("red",false);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);
        memset(cmd, '\0', sizeof(cmd));
        snprintf(cmd, 511, "ip link set dev %s up", b2b_intf1);
        system(cmd);
    }
    nas_rt_special_next_hop_validate("blue", cps_api_ret_code_ERR);
    nas_rt_validate_blue_vrf_config(cps_api_ret_code_ERR);
    nas_rt_cleanup();
}

TEST(nas_rt_vrf_test, nas_rt_scal_vrf) {
    cps_api_return_code_t rc;
    char vrf[10];
    uint32_t id = 0, start_vrf_id = 2, scal_limit = 128, loop_cnt = 3;

    nas_vrf_change_mode(false);
    while (loop_cnt--) {
        nas_rt_scal_test(start_vrf_id, scal_limit, true, cps_api_ret_code_OK);
        /* Check that we cant go beyond allowed 1024 data VRFs */
        //rc = nas_ut_vrf_cfg("blue",true);
        //ASSERT_TRUE(rc == cps_api_ret_code_ERR);
        char vlan[10];

        for (id = start_vrf_id ;id < (start_vrf_id+scal_limit); id++) {
            memset(vrf, '\0', sizeof(vrf));
            snprintf(vrf, sizeof(vrf), "vrf%d", id);
            memset(vlan, '\0', sizeof(vlan));
            snprintf(vlan, sizeof(vlan), "br%d", id);
            char cmd [512];
            memset(cmd, '\0', sizeof(cmd));
            snprintf(cmd, 511, "ip -n %s link set dev v-%s down", vrf, vlan);
            system(cmd);
        }
        if (loop_cnt == 1) {
            nas_rt_scal_test(start_vrf_id, scal_limit, false, cps_api_ret_code_ERR);
            continue;
        }
        sleep(10);
        for (id = start_vrf_id ;id < (start_vrf_id+scal_limit); id++) {
            memset(vrf, '\0', sizeof(vrf));
            snprintf(vrf, sizeof(vrf), "vrf%d", id);
            printf("\r\n VRF:%s route/nbr verification after admin down\r\n", vrf);
            rc = nas_ut_validate_rt_cfg (vrf, AF_INET, "100.0.0.1", 32, vrf, "", "", false);
            ASSERT_TRUE(rc == cps_api_ret_code_ERR);
            rc = nas_ut_validate_rt_cfg (vrf, AF_INET, "100.0.0.0", 24, vrf, "", "", true);
            ASSERT_TRUE(rc == cps_api_ret_code_ERR);
            rc = nas_ut_validate_neigh_cfg(vrf, AF_INET, "100.0.0.2", 128, true);
            ASSERT_TRUE(rc == cps_api_ret_code_ERR);
            rc = nas_ut_validate_rt_cfg (vrf, AF_INET, "60.0.0.0", 8, vrf, "", "", true);
            ASSERT_TRUE(rc == cps_api_ret_code_ERR);
            rc = nas_ut_validate_rt_cfg (vrf, AF_INET6, "100::1", 128, vrf, "", "", false);
            ASSERT_TRUE(rc == cps_api_ret_code_ERR);
            rc = nas_ut_validate_rt_cfg (vrf, AF_INET6, "100::0", 64, vrf, "", "", true);
            ASSERT_TRUE(rc == cps_api_ret_code_ERR);
            rc = nas_ut_validate_neigh_cfg(vrf, AF_INET6, "100::2", 128, true);
            ASSERT_TRUE(rc == cps_api_ret_code_ERR);
            rc = nas_ut_validate_rt_cfg (vrf, AF_INET6, "60::0", 64, vrf, "", "", true);
            ASSERT_TRUE(rc == cps_api_ret_code_ERR);
            rc = nas_ut_validate_rt_cfg (vrf, AF_INET6, "fe80::", 10, vrf, "", "", true);
            ASSERT_TRUE(rc == cps_api_ret_code_OK);
        }

        nas_rt_scal_test(start_vrf_id, scal_limit, false, cps_api_ret_code_ERR);
    }
}

TEST(nas_rt_vrf_test, nas_rt_scal_neigh) {
    char vrf[10];
    uint32_t id = 0, start_vrf_id = 2, scal_limit = 10, loop_cnt = 3,
             scal_arp_limit = 10, scal_neigh_limit = 5;
    cps_api_return_code_t rc;

    nas_vrf_change_mode(false);
    while (loop_cnt--) {
        nas_rt_scal_neigh_test(start_vrf_id, scal_limit, scal_arp_limit,
                               scal_neigh_limit, true, cps_api_ret_code_OK, false, false);
        printf("Bringing down all the interfaces");
        system("ip link set dev br1 down");
        char vlan[10];
        for (id = start_vrf_id ;id < (start_vrf_id+scal_limit); id++) {
            memset(vrf, '\0', sizeof(vrf));
            snprintf(vrf, sizeof(vrf), "vrf%d", id);
            memset(vlan, '\0', sizeof(vlan));
            snprintf(vlan, sizeof(vlan), "br%d", id);
            char cmd [512];
            memset(cmd, '\0', sizeof(cmd));
            snprintf(cmd, 511, "ip -n %s link set dev v-%s down", vrf, vlan);
            system(cmd);
            printf("\r\n Bring down interface:v-%s in VRF:%s", vlan, vrf);
            if (loop_cnt == 2) {
                printf("\r\n Delete VRF:%s", vrf);
                rc = nas_ut_vrf_cfg(vrf,false);
                ASSERT_TRUE(rc == cps_api_ret_code_OK);
            }
        }

        nas_rt_scal_neigh_test(start_vrf_id, scal_limit, scal_arp_limit, scal_neigh_limit,
                               false, cps_api_ret_code_ERR, false, ((loop_cnt == 2) ? true : false));
        system("ip link set dev br1 up");
    }
}


TEST(nas_rt_vrf_test, nas_rt_scal_neigh_neg_test) {
    char vrf[10];
    uint32_t id = 0, start_vrf_id = 2, scal_limit = 10, loop_cnt = 2,
             scal_arp_limit = 10, scal_neigh_limit = 5;

    nas_vrf_change_mode(false);
    while (loop_cnt--) {
        nas_rt_scal_neigh_test(start_vrf_id, scal_limit, scal_arp_limit,
                               scal_neigh_limit, true, cps_api_ret_code_OK, true, false);
        nas_rt_scal_neigh_test(start_vrf_id, scal_limit, scal_arp_limit, scal_neigh_limit,
                               false, cps_api_ret_code_ERR, true, false);
        system("ip link set dev br1 down");
        char vlan[10];
        for (id = start_vrf_id ;id < (start_vrf_id+scal_limit); id++) {
            memset(vrf, '\0', sizeof(vrf));
            snprintf(vrf, sizeof(vrf), "vrf%d", id);
            memset(vlan, '\0', sizeof(vlan));
            snprintf(vlan, sizeof(vlan), "br%d", id);
            char cmd [512];
            memset(cmd, '\0', sizeof(cmd));
            snprintf(cmd, 511, "ip -n %s link set dev v-%s down", vrf, vlan);
            system(cmd);
        }

        nas_rt_scal_neigh_test(start_vrf_id, scal_limit, scal_arp_limit, scal_neigh_limit,
                               false, cps_api_ret_code_ERR, true, true);
        system("ip link set dev br1 up");
    }
}

TEST(nas_rt_vrf_test, nas_rt_perf_vrf) {
    cps_api_return_code_t rc;
    uint32_t no_of_intfs = 128;
    uint32_t id, start_intf_id = 2;
    char vlan[10];

    nas_vrf_change_mode(false);
    nas_rt_perf_test (no_of_intfs, true);

    char  start_time[50], end_time[50];
    int start_sec = 0, end_sec = 0, start_milli_sec = 0, end_milli_sec = 0;
    print_time(start_time, &start_sec, &start_milli_sec);

    for (id = start_intf_id; id < (start_intf_id + no_of_intfs); id++) {
        memset(vlan, '\0', sizeof(vlan));
        snprintf(vlan, sizeof(vlan), "br%d", id);
        rc = nas_ut_intf_vrf_cfg("blue", vlan, true);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);
    }

    print_time(end_time, &end_sec, &end_milli_sec);
    printf("\r\n Time taken start-time:%s end-time:%s diff-sec:%d diff-ms:%d "
           "for association %d interface to blue VRF", start_time, end_time,
           (end_sec-start_sec), (end_milli_sec-start_milli_sec), no_of_intfs);
    for (id = start_intf_id; id < (start_intf_id + no_of_intfs); id++) {
        memset(vlan, '\0', sizeof(vlan));
        snprintf(vlan, sizeof(vlan), "br%d", id);
        rc = nas_ut_intf_vrf_cfg("blue", vlan, false);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);
    }
    nas_rt_perf_test (no_of_intfs, false);

}

TEST(nas_rt_vrf_test, nas_rt_mgmt_vrf) {
    cps_api_return_code_t rc;
    rc = nas_ut_vrf_cfg("management",true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    rc = nas_ut_intf_mgmt_vrf_cfg("management","eth0",true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    nas_ut_rt_cfg ("management",1, "50.0.0.0", 24, AF_INET, NULL, NULL, "eth0");
    nas_ut_rt_cfg ("management",1, "5555::", 64, AF_INET6, NULL, NULL, "eth0");
    sleep(2);
    rc = nas_ut_validate_rt_cfg ("management", AF_INET, "50.0.0.0", 24, NULL, NULL, NULL, false);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    rc = nas_ut_validate_rt_cfg ("management", AF_INET6, "5555::", 64, NULL, NULL, NULL, false);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    rc = nas_ut_intf_mgmt_vrf_cfg("management","eth0",false);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    rc = nas_ut_vrf_cfg("management",false);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    sleep(2);
    rc = nas_ut_validate_rt_cfg ("management", AF_INET, "50.0.0.0", 24, NULL, NULL, NULL, false);
    ASSERT_TRUE(rc == cps_api_ret_code_ERR);
    rc = nas_ut_validate_rt_cfg ("management", AF_INET6, "5555::", 64, NULL, NULL, NULL, false);
    ASSERT_TRUE(rc == cps_api_ret_code_ERR);
    rc = nas_ut_intf_mgmt_vrf_cfg("management","eth0",false);
    ASSERT_TRUE(rc == cps_api_ret_code_ERR);
    rc = nas_ut_vrf_cfg("management",false);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
}

TEST(nas_rt_vrf_test, nas_rt_vrf_special_nh_route) {
    cps_api_return_code_t rc;
    rc = nas_ut_vrf_cfg("blue",true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    nas_rt_special_next_hop_config(true, "blue");
    nas_rt_special_next_hop_validate("blue", cps_api_ret_code_OK);

    rc = nas_ut_vrf_cfg("blue",false);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    nas_rt_special_next_hop_validate("blue", cps_api_ret_code_ERR);
}

TEST(nas_rt_vrf_test, nas_rt_vrf_neg_test) {
    cps_api_return_code_t rc;
    /* Reset the port-configs */
    nas_vrf_change_mode(false);
    /* Negative test to make sure L2 interface is not getting associated with VRF */
    rc = nas_ut_vrf_cfg("blue",true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    rc = nas_ut_intf_vrf_cfg("blue",b2b_intf2,true);
    ASSERT_TRUE(rc == cps_api_ret_code_ERR);

    /* configure the test pre-requisite */
    nas_vrf_change_mode(true);

    rc = nas_ut_intf_vrf_cfg("blue",b2b_intf2,true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    rc = nas_ut_vrf_cfg("red",true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    /* Verify that L3 interface is not associated with more than
     * one VRF any point in time */
    rc = nas_ut_intf_vrf_cfg("red",b2b_intf2,true);
    ASSERT_TRUE(rc == cps_api_ret_code_ERR);

    rc = nas_ut_intf_vrf_cfg("blue",b2b_intf2,false);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    rc = nas_ut_vrf_cfg("blue",false);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    rc = nas_ut_vrf_cfg("red",false);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);

    /* configure the test pre-requisite */
    nas_vrf_change_mode(true);

    printf("___________________________________________\n");

    return(RUN_ALL_TESTS());
}

