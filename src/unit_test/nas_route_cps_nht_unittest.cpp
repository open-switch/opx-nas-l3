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
 * nas_route_cps_nht_unittest.cpp
 *
 */



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


#include <ctime>
#include <chrono>

#include <gtest/gtest.h>
#include <iostream>
#include <iomanip>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include "nas_ndi_obj_id_table.h"

static const char *p_dut_intf1 = "e101-001-0";
static const char *p_dut_intf2 = "e101-004-0";
//const char *p_tr_intf1 = "e101-001-0";
//const char *p_tr_intf2 = "e101-004-0";

/* Constants for IPv4 NHT */
const char *p_dut_ip_intf1 = "20.0.0.1";
const char *p_dut_ip_intf2 = "30.0.0.1";
const char *p_tr_ip_intf1 = "20.0.0.2";
const char *p_tr_ip2_intf1 = "20.0.0.3";
const char *p_tr_ip3_intf1 = "20.0.0.4";
const char *p_tr_ip_intf2 = "30.0.0.2";
const char *p_tr_ip2_intf2 = "30.0.0.3";
const char *p_tr_ip3_intf2 = "30.0.0.4";
const char *p_tr_mpath_intf1 = "20.0.0.";
const char *p_tr_mpath_intf2 = "30.0.0.";

const char *nht1 = "40.0.0.1", *nht2 = "40.1.1.1", *nht3 = "40.1.1.2", *nht4 = "40.1.2.1",
     *nht5 = "40.2.0.1", *nht6 = "40.0.1.1", *rt1="40.0.0.0", *rt2 = "40.1.0.0", *rt3 = "40.1.1.0", *rt4 = "40.1.1.1", *rt5 = "0.0.0.0";
int pref_len1 = 8, pref_len2 = 16, pref_len3 = 24, pref_len4 = 32, pref_len5 = 20;
int af = AF_INET;

/* Constants for IPv6 NHT */
static const char *p_dut_ip6_intf1 = "2::1";
static const char *p_dut_ip6_intf2 = "3::1";
static const char *p_tr_ip6_intf1 = "2::2";
static const char *p_tr_ip6_2_intf1 = "2::3";
static const char *p_tr_ip6_3_intf1 = "2::4";
static const char *p_tr_ip6_intf2 = "3::2";
static const char *p_tr_ip6_2_intf2 = "3::2";
static const char *p_tr_ip6_3_intf2 = "3::2";
static const char *p_tr_mpath_ip6_intf1 = "2::";
static const char *p_tr_mpath_ip6_intf2 = "3::";

const char *nht6_1 = "4::1", *nht6_2 = "4:1:1::1", *nht6_3 = "4:1:1::2", *nht6_4 = "4:1:2::1",
      *nht6_5 = "4:2::1", *nht6_6= "4::3", *rt6_1="4::", *rt6_2 = "4:1::", *rt6_3 = "4:1:1::", *rt6_4 = "4:1:1::1", *rt6_5 = "::";
int pref_len6_1 = 16, pref_len6_2 = 32, pref_len6_3 = 48, pref_len6_4 = 128;
int af6 = AF_INET6;

bool g_scaled_test = false;
static char time_start[100] = "\0";


int nas_rt_nht_validate_util (const char *nht_dest, uint32_t nh_count,
                              const char *fib_best_match, uint32_t pref_len);

void nht_add_del(void *nht_dest, uint32_t af_family, bool is_add)
{
    uint32_t ip, vrf = 0;
    cps_api_transaction_params_t tr;

    cps_api_object_t obj = cps_api_object_create();
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_NH_TRACK_OBJ,cps_api_qualifier_TARGET);

    cps_api_set_key_data (obj, BASE_ROUTE_NH_TRACK_VRF_ID, cps_api_object_ATTR_T_U32,&vrf, sizeof(vrf));
    cps_api_set_key_data (obj, BASE_ROUTE_NH_TRACK_AF, cps_api_object_ATTR_T_U32,&af_family, sizeof(af_family));
    if (af_family == AF_INET6) {
        cps_api_set_key_data (obj, BASE_ROUTE_NH_TRACK_DEST_ADDR, cps_api_object_ATTR_T_BIN,
                              (struct in6_addr *) nht_dest,sizeof(struct in6_addr));
    } else {
        ip=((struct in_addr *) nht_dest)->s_addr;
        cps_api_set_key_data (obj, BASE_ROUTE_NH_TRACK_DEST_ADDR, cps_api_object_ATTR_T_BIN,&ip, sizeof(ip));
    }

    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    if (is_add) {
        cps_api_create(&tr,obj);
    } else {
        cps_api_delete(&tr,obj);
    }
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
}

void nht_config(const char *ip_str, uint32_t af_family, bool is_add)
{
    struct in_addr a;
    struct in6_addr a6;

    if (af_family == AF_INET6) {
        inet_pton(AF_INET6, ip_str, &a6);
        nht_add_del ((void *) &a6, af_family, is_add);
    } else {
        inet_aton(ip_str,&a);
        nht_add_del ((void *) &a, af_family, is_add);
    }
    if (g_scaled_test == false) sleep(2);
}

void nht_config_scale (const char *ip_str, uint32_t af_family, bool is_add, int num_entries)
{
    int cnt = 0;

    if (af_family == AF_INET6) {
        struct in6_addr a;
        unsigned char val = 0;
        inet_pton(AF_INET6, ip_str, &a);
        for (; cnt < num_entries; cnt++) {
            nht_add_del ((void *) &a, af_family, is_add);
            val = a.s6_addr[15];
            a.s6_addr[15] = ++val;
        }
    } else {
        struct in_addr a;
        inet_aton(ip_str,&a);
        for (; cnt < num_entries; cnt++) {
            nht_add_del ((void *) &a, af_family, is_add);
            a.s_addr = ntohl (a.s_addr);
            a.s_addr++;
            a.s_addr = htonl (a.s_addr);
        }
    }
}

void nht_config_scale_with_prefix (const char *ip_str, uint32_t af_family, bool is_add, int num_entries, int nht_pref_len)
{
    struct in_addr a;
    struct in_addr tmp_a;
    struct in6_addr a6;
    int cnt = 0;

    if (af_family == AF_INET6) {
        char route_str[INET6_ADDRSTRLEN];
        inet_pton(AF_INET6, ip_str, &a6);
        int len = strlen(ip_str);
        memcpy (route_str, ip_str, ((len > INET6_ADDRSTRLEN)?(INET6_ADDRSTRLEN):len));
        for (; cnt < num_entries; cnt++) {
            //printf ("nht_config_scale_with_prefix %s\r\n", route_str);
            nht_add_del ((void *) &a6, af_family, is_add);
            int val = a6.s6_addr[5];
            a6.s6_addr[5] = ++val;
            inet_ntop(af_family, &a6, route_str, INET6_ADDRSTRLEN);
        }
    } else {
        inet_aton(ip_str,&a);

        for (; cnt < num_entries; cnt++) {
            nht_add_del ((void *) &a, af_family, is_add);
            a.s_addr = ntohl (a.s_addr);
           // printf ("nht_config_scale_with_prefix 0x%x\r\n", a.s_addr);
            tmp_a.s_addr = a.s_addr << nht_pref_len;
            tmp_a.s_addr = tmp_a.s_addr >> nht_pref_len;
            a.s_addr = (a.s_addr >> (32-nht_pref_len));
            a.s_addr++;
            a.s_addr = (a.s_addr << (32-nht_pref_len));
            a.s_addr  = a.s_addr | tmp_a.s_addr;
            a.s_addr = htonl (a.s_addr);
        }
    }
}

void nht_add_route_2nh (const char *route_prefix, int pref_len, const char *next_hop_ip1, const char *next_hop_ip2)
{
    char cmd[512];
    memset(cmd, '\0', sizeof(cmd));
    snprintf(cmd, 511, "ip route add %s/%d scope global nexthop via %s nexthop via %s",
            route_prefix, pref_len, next_hop_ip1, next_hop_ip2);
    (void)system(cmd);

    if (g_scaled_test == false) sleep(2);
}

void nht_replace_route_2nh (const char *route_prefix, int pref_len, const char *next_hop_ip1, const char *next_hop_ip2)
{
    char cmd[512];
    memset(cmd, '\0', sizeof(cmd));
    snprintf(cmd, 511, "ip route replace %s/%d scope global nexthop via %s nexthop via %s",
            route_prefix, pref_len, next_hop_ip1, next_hop_ip2);
    (void)system(cmd);
    sleep(2);
}

void nht_del_route_2nh (const char *route_prefix, int pref_len, const char *next_hop_ip1, const char *next_hop_ip2)
{
    char cmd[512];
    memset(cmd, '\0', sizeof(cmd));
    snprintf(cmd, 511, "ip route del %s/%d scope global nexthop via %s nexthop via %s",
            route_prefix, pref_len, next_hop_ip1, next_hop_ip2);
    (void)system(cmd);
    if (g_scaled_test == false) sleep(2);
}

void nht_add_route (const char *route_prefix, int pref_len, const char *next_hop_ip)
{
    char cmd[512];
    memset(cmd, '\0', sizeof(cmd));
    if (af == AF_INET) {
        snprintf(cmd, 511, "ip route add %s/%d via %s",route_prefix, pref_len, next_hop_ip);
    } else {
        snprintf(cmd, 511, "ip -6 route add %s/%d via %s",route_prefix, pref_len, next_hop_ip);
    }
    (void)system(cmd);
    if (g_scaled_test == false) sleep(1);
}

void nht_add_route_scale (const char *route_prefix_str, int pref_len, const char *next_hop_ip, uint32_t af_family, int num_routes)
{
    int cnt = 0;

    if (af_family == AF_INET6) {
        char route_str[INET6_ADDRSTRLEN];
        struct in6_addr a;

        inet_pton(AF_INET6, route_prefix_str, &a);
        int len = strlen(route_prefix_str);
        memcpy (route_str, route_prefix_str, ((len > INET6_ADDRSTRLEN)?(INET6_ADDRSTRLEN):len));
        for (; cnt < num_routes; cnt++) {
            //printf ("add_route scale %s\r\n", route_str);
            nht_add_route (route_str, pref_len, next_hop_ip);
            int val = a.s6_addr[5];
            a.s6_addr[5] = ++val;
            inet_ntop(af_family, &a, route_str, INET_ADDRSTRLEN);
        }
    } else {
        char route_str[INET_ADDRSTRLEN];
        struct in_addr a;

        inet_aton(route_prefix_str,&a);
        int len = strlen(route_prefix_str);
        memcpy (route_str, route_prefix_str, ((len > INET_ADDRSTRLEN)?(INET_ADDRSTRLEN):len));
        for (; cnt < num_routes; cnt++) {
            //printf ("add_route scale %s\r\n", route_str);
            nht_add_route (route_str, pref_len, next_hop_ip);
            a.s_addr = ntohl (a.s_addr);
            a.s_addr = (a.s_addr >> (32-pref_len));
            a.s_addr++;
            a.s_addr = (a.s_addr << (32-pref_len));
            a.s_addr = htonl (a.s_addr);
            inet_ntop(af_family, &a, route_str, INET_ADDRSTRLEN);
        }
    }
}
void nht_del_route (const char *route_prefix, int pref_len, const char *next_hop_ip)
{
    char cmd[512];
    memset(cmd, '\0', sizeof(cmd));
    if (af == AF_INET) {
        snprintf(cmd, 511, "ip route del %s/%d via %s",route_prefix, pref_len, next_hop_ip);
    } else {
        snprintf(cmd, 511, "ip -6 route del %s/%d via %s",route_prefix, pref_len, next_hop_ip);
    }
    (void)system(cmd);
    if (g_scaled_test == false) sleep(1);
}

void nht_del_route_scale (const char *route_prefix_str, int pref_len, const char *next_hop_ip, uint32_t af_family, int num_routes)
{
    int cnt = 0;
    if (af_family == AF_INET6) {
        char route_str[INET6_ADDRSTRLEN];
        struct in6_addr a;

        inet_pton(AF_INET6, route_prefix_str, &a);
        int len = strlen(route_prefix_str);
        memcpy (route_str, route_prefix_str, ((len > INET6_ADDRSTRLEN)?(INET6_ADDRSTRLEN):len));
        for (; cnt < num_routes; cnt++) {
            printf ("del_route scale %s\r\n", route_str);
            nht_add_route (route_str, pref_len, next_hop_ip);
            int val = a.s6_addr[5];
            a.s6_addr[5] = ++val;
            inet_ntop(af_family, &a, route_str, INET_ADDRSTRLEN);
        }
    } else {
        struct in_addr a;
        int cnt = 0;
        char route_str[INET_ADDRSTRLEN];

        inet_aton(route_prefix_str,&a);
        int len = strlen(route_prefix_str);
        memcpy (route_str, route_prefix_str, ((len > INET_ADDRSTRLEN)?(INET_ADDRSTRLEN):len));
        for (; cnt < num_routes; cnt++) {
            //            printf ("del_route scale %s\r\n", route_str);
            nht_del_route (route_str, pref_len, next_hop_ip);
            a.s_addr = ntohl (a.s_addr);
            a.s_addr = (a.s_addr >> (32-pref_len));
            a.s_addr++;
            a.s_addr = (a.s_addr << (32-pref_len));
            a.s_addr = htonl (a.s_addr);
            inet_ntop(af_family, &a, route_str, INET_ADDRSTRLEN);
        }
    }
}

void nht_replace_route (const char *route_prefix, int pref_len, const char *next_hop_ip)
{
    char cmd[512];
    memset(cmd, '\0', sizeof(cmd));
    if (af == AF_INET) {
        snprintf(cmd, 511, "ip route replace %s/%d via %s",route_prefix, pref_len, next_hop_ip);
    } else {
        snprintf(cmd, 511, "ip -6 route del %s/%d",route_prefix, pref_len);
        (void)system(cmd);
        snprintf(cmd, 511, "ip -6 route add %s/%d via %s",route_prefix, pref_len, next_hop_ip);
    }
    (void)system(cmd);
    sleep(2);
}


void nht_add_static_arp (const char *ip, const char *mac, const char *intf)
{
    char cmd[512];
    memset(cmd, '\0', sizeof(cmd));
    if (af == AF_INET) {
        snprintf(cmd, 511, "arp -s %s %s",ip, mac);
    } else {
        snprintf(cmd, 511, "ip -6 neigh add %s lladdr %s dev %s",ip, mac, intf);
    }
    (void)system(cmd);
    sleep(2);
}

void nht_del_static_arp (const char *ip, const char *intf)
{
    char cmd[512];
    memset(cmd, '\0', sizeof(cmd));
    if (af == AF_INET) {
        snprintf(cmd, 511, "arp -d %s",ip);
    }
    else {
        snprintf(cmd, 511, "ip -6 neigh del %s dev %s",ip, intf);
    }
    (void)system(cmd);
    sleep(2);
}

void nht_resolve_nh(const char *ip)
{
    char cmd[512];
    memset(cmd, '\0', sizeof(cmd));
    if (af == AF_INET) {
        snprintf(cmd, 511, "ping -c 1 %s",ip);
    } else {
        snprintf(cmd, 511, "ping6 -c 1 %s",ip);
    }
    (void)system(cmd);
    sleep(2);
    return;
}

void nht_intf_admin_set(const char *p_b2b_intf, bool is_up)
{
    char cmd[512];

    memset(cmd, '\0', sizeof(cmd));
    snprintf(cmd, 511, "ifconfig %s %s",p_b2b_intf,
            ((is_up) ? "up" : "down"));
    (void)system(cmd);
    if ((af == AF_INET6) && is_up) {
        /* Incase of IPv6, admin down clears the ipv6 address on interface,
         * need to reconfigure on admin up again */
        snprintf(cmd, 511, "ifconfig %s inet6 add %s/64 up",p_dut_intf1, p_dut_ip_intf1);
        (void)system(cmd);
        snprintf(cmd, 511, "ifconfig %s inet6 add %s/64 up",p_dut_intf2, p_dut_ip_intf2);
        (void)system(cmd);
    }
    if (g_scaled_test == false) sleep(2);
}

int nas_nht_get_time_str (char *ts_start, int str_len)
{
    if (!ts_start)
        return 1;

    //current time
    std::chrono::time_point<std::chrono::system_clock> time_now = std::chrono::system_clock::now();
    std::time_t time_now_t = std::chrono::system_clock::to_time_t(time_now);

    //print time string
    std::tm now_tm = *std::localtime(&time_now_t);
    std::strftime(ts_start, str_len, "%Y-%m-%d %H:%M:%S", &now_tm);

    return 0;
}

void nht_log_clear()
{
    time_start[0] = '\0';
    if (nas_nht_get_time_str (time_start, 100))
        printf ("\r\n!!!Error in retrieving timestamp!!!\r\n");
}

int nas_rt_nht_validate(const char *nht_dest, uint32_t nh_count,
                         const char *fib_best_match, uint32_t pref_len) {
    sleep(5);
    return (nas_rt_nht_validate_util(nht_dest, nh_count, fib_best_match, pref_len));
}

int nas_rt_nht_validate_util (const char *nht_dest, uint32_t nh_count,
                         const char *fib_best_match, uint32_t pref_len) {
    int ret = 0;
    char pattern_str[50];
    char find_str[300];
    char cmd_str[500];

    if ((nh_count == 0) && (nht_dest == NULL)) {
        snprintf (find_str, 299, " "); /* for case where no event should be published */
    } else if (nh_count == 0) {
        snprintf (find_str, 299, "nht_dest:%s, nh_count:%d, nht_best_match_dest:-",
                  nht_dest, nh_count);
    } else {
        snprintf (find_str, 299, "%s%s, nh_count:%d, nht_best_match_dest:%s/%d",
                  ((nht_dest != NULL)?"nht_dest:":""), ((nht_dest != NULL)?nht_dest:""), nh_count, fib_best_match, pref_len);
    }
    snprintf (pattern_str, 49, "%s", "NHT Event publish for ");

    snprintf (cmd_str, 499, "journalctl --since \"%s\" -u base_nas_svc | grep -a \"%s\" |  grep \"%s\"", time_start, pattern_str, find_str);
    ret = system(cmd_str);
    return ret;
}


int nas_rt_nht_validate_util_acl_cleanup (const char *nht_dest, uint32_t nh_count,
                         const char *fib_best_match, uint32_t pref_len) {
    int ret = 0;
    char pattern_str[50];
    char find_str[300];
    char cmd_str[500];

    if (nht_dest == NULL) {
        snprintf (find_str, 199, " "); /* for case where no event should be published */
    } else {
        snprintf (find_str, 199, "%s/%d,", nht_dest, pref_len);
    }
    snprintf (pattern_str, 49, "%s", "Dependent ACLs cleanup successful for Addr");

    snprintf (cmd_str, 499, "journalctl --since \"%s\" -u base_nas_svc | grep -a \"%s\" |  grep \"%s\"", time_start, pattern_str, find_str);
    ret = system(cmd_str);
    return ret;
}

int nas_rt_nht_validate_acl_cleanup (const char *nht_dest, uint32_t nh_count,
                         const char *fib_best_match, uint32_t pref_len) {
    return (nas_rt_nht_validate_util_acl_cleanup(nht_dest, nh_count, fib_best_match, pref_len));
}

void nas_rt_nht_print_result (const char *tc_str, int ret) {
    if (ret == 0) {
        printf("\r %s : PASSED\r\n", tc_str);
    } else {
        printf("\r %s : FAILED\r\n", tc_str);
    }
    fflush(stdout);
}

int nas_rt_nht_validate_multi_nht_to_one_route (const char *nht_dest, uint32_t nh_count,
                         const char *fib_best_match, uint32_t pref_len, uint32_t af_family, uint32_t nht_count) {
    int ret = 0;

    char str[INET6_ADDRSTRLEN];
    struct in_addr a;
    struct in6_addr a6;

    if (af_family == AF_INET6) {
        unsigned char val = 0;
        inet_pton(AF_INET6, nht_dest, &a6);
        do {
            inet_ntop(AF_INET6, &a6, str, INET6_ADDRSTRLEN);

            ret = nas_rt_nht_validate_util ((const char *) str, nh_count, fib_best_match, pref_len);

            val = a6.s6_addr[15];
            a6.s6_addr[15] = ++val;
            nht_count--;
        } while (((nht_count) && (ret == 0)));
    } else {
        inet_pton(AF_INET, nht_dest, &a);

        do {
            inet_ntop(AF_INET, &a, str, INET_ADDRSTRLEN);

            ret = nas_rt_nht_validate_util ((const char *) str, nh_count, fib_best_match, pref_len);

            a.s_addr = ntohl (a.s_addr);
            a.s_addr++;
            a.s_addr = htonl (a.s_addr);
            nht_count--;
        } while (((nht_count) && (ret == 0)));
    }


    return ret;
}

int nas_rt_nht_validate_one_nht_to_one_route (const char *nht_dest, uint32_t nh_count,
                                              const char *fib_best_match_rt_prefix, uint32_t pref_len,
                                              uint32_t af_family, uint32_t nht_count) {
    int ret = 0;

    char nht_str[INET6_ADDRSTRLEN];
    char rt_str[INET6_ADDRSTRLEN];
    struct in_addr nht_a;
    struct in_addr tmp_a;
    struct in_addr rt_a;
    struct in6_addr nht_a6;
    struct in6_addr rt_a6;


    if (af_family == AF_INET6) {
        unsigned char val = 0;
        inet_pton(AF_INET6, nht_dest, &nht_a6);
        inet_pton(AF_INET6, fib_best_match_rt_prefix, &rt_a6);

        do {
            inet_ntop(AF_INET6, &nht_a6, nht_str, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &rt_a6, rt_str, INET6_ADDRSTRLEN);
            ret = nas_rt_nht_validate_util ((const char *) nht_str, nh_count, rt_str, pref_len);
//            printf ("nas_rt_nht_validate_one_nht_to_one_route nht:%s nh_count:%d, fib_match:%s, pref_len:%d\r\n",
//                    nht_str, nh_count, rt_str, pref_len);

            val = nht_a6.s6_addr[5];
            nht_a6.s6_addr[5] = ++val;

            val = rt_a6.s6_addr[5];
            rt_a6.s6_addr[5] = ++val;

            nht_count--;
        } while (((nht_count) && (ret == 0)));

    } else {
        inet_pton(AF_INET, nht_dest, &nht_a);
        inet_pton(AF_INET, fib_best_match_rt_prefix, &rt_a);

        do {
            inet_ntop(AF_INET, &nht_a, nht_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &rt_a, rt_str, INET_ADDRSTRLEN);

            ret = nas_rt_nht_validate_util ((const char *) nht_str, nh_count, rt_str, pref_len);
        //    printf ("nas_rt_nht_validate_one_nht_to_one_route nht:%s nh_count:%d, fib_match:%s, pref_len:%d\r\n",
        //            nht_str, nh_count, rt_str, pref_len);

            nht_a.s_addr = ntohl (nht_a.s_addr);
            tmp_a.s_addr = nht_a.s_addr << pref_len;
            tmp_a.s_addr = tmp_a.s_addr >> pref_len;
            nht_a.s_addr = (nht_a.s_addr >> (32-pref_len));
            nht_a.s_addr++;
            nht_a.s_addr = (nht_a.s_addr << (32-pref_len));
            nht_a.s_addr  = nht_a.s_addr | tmp_a.s_addr;
            nht_a.s_addr = htonl (nht_a.s_addr);

            rt_a.s_addr = ntohl (rt_a.s_addr);
            rt_a.s_addr = (rt_a.s_addr >> (32-pref_len));
            rt_a.s_addr++;
            rt_a.s_addr = (rt_a.s_addr << (32-pref_len));
            rt_a.s_addr = htonl (rt_a.s_addr);

            nht_count--;
        } while (((nht_count) && (ret == 0)));
    }


    return ret;
}


int nas_rt_nht_ut_1_1 (bool is_prereq) {
    int ret = 0;
    nht_log_clear();
    /* TC_1_1 Direct NH case (static arp) ARP add before NHT add */

    nht_add_static_arp (p_tr_ip_intf1, "00:20:00:00:02:00", p_dut_intf1);
    nht_config(p_tr_ip_intf1, af, 1);

    ret = nas_rt_nht_validate (p_tr_ip_intf1, 1, p_tr_ip_intf1, ((af == AF_INET) ? 32 : 128));

    nas_rt_nht_print_result ( "TC_1_1: Direct NH case (static arp) ARP add before NHT add", ret);
    if (is_prereq) {
        return ret;
    }

    /* clean-up */
    nht_config(p_tr_ip_intf1, af, 0);
    nht_del_route (rt1, pref_len2, p_tr_ip_intf1);
    nht_del_static_arp (p_tr_ip_intf1, p_dut_intf1);
    nht_intf_admin_set(p_dut_intf1,0);
    nht_intf_admin_set(p_dut_intf1,1);
    return ret;
}

int nas_rt_nht_ut_1_2 (bool is_prereq) {
    int ret = 0;
    nht_log_clear();

    nht_config(p_tr_ip2_intf1, af, 1);
    sleep(6);
    nht_add_static_arp (p_tr_ip2_intf1, "00:20:00:00:03:00", p_dut_intf1);

    ret = nas_rt_nht_validate (p_tr_ip2_intf1, 1, p_tr_ip2_intf1, ((af == AF_INET) ? 32 : 128));
    nas_rt_nht_print_result ( "TC_1_2: Direct NH case (static) ARP add after NHT add", ret);

    if (is_prereq)
        return ret;
    /* clean-up */
    nht_config(p_tr_ip2_intf1, af, 0);
    nht_del_route (rt1, pref_len2, p_tr_ip2_intf1);
    nht_del_static_arp (p_tr_ip2_intf1, p_dut_intf1);
    nht_intf_admin_set(p_dut_intf1,0);
    nht_intf_admin_set(p_dut_intf1,1);
    return ret;
}

int nas_rt_nht_ut_1_3 (bool is_prereq) {
    int ret = 0;
    nht_log_clear();

    nht_add_static_arp (p_tr_ip3_intf1, "00:20:00:00:04:00", p_dut_intf1);
    nht_config(p_tr_ip3_intf1, af, 1);

    ret = nas_rt_nht_validate (p_tr_ip3_intf1, 1, p_tr_ip3_intf1, ((af == AF_INET) ? 32 : 128));
    nas_rt_nht_print_result ( "TC_1_3: STEP-1 Direct NH case (static) ARP delete", ret);
    if (is_prereq)
        return ret;

    if (ret == 0) {
        nht_log_clear();
        nht_del_static_arp (p_tr_ip3_intf1, p_dut_intf1);
        ret = nas_rt_nht_validate (p_tr_ip3_intf1, 0, p_tr_ip3_intf1, ((af == AF_INET) ? 32 : 128));
        nas_rt_nht_print_result ( "TC_1_3: Direct NH case (static) ARP delete", ret);
    }

    /* clean-up */
    nht_config(p_tr_ip3_intf1, af, 0);
    nht_del_route (rt1, pref_len2, p_tr_ip3_intf1);
    nht_intf_admin_set(p_dut_intf1,0);
    nht_intf_admin_set(p_dut_intf1,1);
    return ret;
}

int nas_rt_nht_ut_1_4 (bool is_prereq) {
    int ret = 0;

    nht_log_clear();
    /* TC_1_4 Direct NH case (dynamic arp) ARP resolved before NHT add */

    nht_resolve_nh(p_tr_ip_intf2);
    nht_config(p_tr_ip_intf2, af, 1);

    ret = nas_rt_nht_validate (p_tr_ip_intf2, 1, p_tr_ip_intf2, ((af == AF_INET) ? 32 : 128));
    nas_rt_nht_print_result ("TC_1_4: STEP 1 Direct NH case (dynamic arp) ARP resolved before NHT add", ret);

    if (is_prereq)
        return ret;

    if (ret == 0) {
        nht_log_clear();
        nht_intf_admin_set(p_dut_intf2,0);
        ret = nas_rt_nht_validate (p_tr_ip_intf2, 0, p_tr_ip_intf2, ((af == AF_INET) ? 32 : 128));
        nas_rt_nht_print_result ("TC_1_4: Direct NH case (dynamic arp) ARP resolved before NHT add", ret);
    }

    /* clean-up */
    nht_intf_admin_set(p_dut_intf2,1);
    nht_config(p_tr_ip_intf2, af, 0);
    nht_del_route (rt1, pref_len1,p_tr_ip_intf2);
    return ret;
}

int nas_rt_nht_ut_1_5 (bool is_prereq) {
    int ret = 0;

    nht_log_clear();

    /* TC_1_5 Direct NH case (dynamic arp) ARP resolved after NHT add */

    nht_config(p_tr_ip_intf2, af, 1);
    nht_resolve_nh(p_tr_ip_intf2);

    ret = nas_rt_nht_validate (p_tr_ip_intf2, 1, p_tr_ip_intf2, ((af == AF_INET) ? 32 : 128));
    nas_rt_nht_print_result ("TC_1_5: STEP1 Direct NH case (dynamic arp) ARP resolved after NHT add", ret);

    if (is_prereq)
        return ret;

    if (ret == 0) {
        nht_log_clear();
        nht_del_route (rt1, pref_len1,p_tr_ip_intf2);

        ret = nas_rt_nht_validate (p_tr_ip_intf2, 0, p_tr_ip_intf2, ((af == AF_INET) ? 32 : 128));
        /* If there is no publish, mark as success */
        if (ret != 0)
            ret = 0;
        nas_rt_nht_print_result ("TC_1_5: STEP2 Direct NH case (dynamic arp) ARP resolved after NHT add", ret);

        nht_log_clear();
        nht_intf_admin_set(p_dut_intf2,0);
        ret = nas_rt_nht_validate (p_tr_ip_intf2, 0, p_tr_ip_intf2, ((af == AF_INET) ? 32 : 128));
        nas_rt_nht_print_result ("TC_1_5: Direct NH case (dynamic arp) ARP resolved after NHT add", ret);
    }

    /* clean-up */
    nht_config(p_tr_ip_intf2, af, 0);
    nht_intf_admin_set(p_dut_intf2,1);
    return ret;
}

int nas_rt_nht_ut_1_6 (bool is_prereq) {
    int ret = 0;

    nht_log_clear();

    nht_resolve_nh(p_tr_ip_intf2);
    nht_config(p_tr_ip_intf2, af, 1);

    ret = nas_rt_nht_validate (p_tr_ip_intf2, 1, p_tr_ip_intf2, ((af == AF_INET) ? 32 : 128));
    nas_rt_nht_print_result ("TC_1_6: STEP 1 Direct NH case (dynamic arp) ARP moved to unresolved (interface down)", ret);

    if (is_prereq)
        return ret;

    if (ret == 0) {
        nht_log_clear();
        nht_intf_admin_set(p_dut_intf2,0);
        ret = nas_rt_nht_validate (p_tr_ip_intf2, 0, p_tr_ip_intf2, ((af == AF_INET) ? 32 : 128));
        nas_rt_nht_print_result ("TC_1_6: Direct NH case (dynamic arp) ARP moved to unresolved (interface down)", ret);
    }

    /* clean-up */
    nht_intf_admin_set(p_dut_intf2,1);
    nht_config(p_tr_ip_intf2, af, 0);
    nht_del_route (rt1, pref_len1,p_tr_ip_intf2);
    return ret;
}

int nas_rt_nht_ut_1_7 (bool is_prereq) {
    int ret = 0;

    nht_log_clear();

    nht_config(p_tr_ip_intf2, af, 1);
    nht_resolve_nh(p_tr_ip_intf2);

    ret = nas_rt_nht_validate (p_tr_ip_intf2, 1, p_tr_ip_intf2, ((af == AF_INET) ? 32 : 128));
    nas_rt_nht_print_result ("TC_1_7: STEP1 Direct NH case (dynamic arp) NHT add for same dest from multiple clients", ret);

    nht_log_clear();
    nht_config(p_tr_ip_intf2, af, 1);
    ret = nas_rt_nht_validate (p_tr_ip_intf2, 1, p_tr_ip_intf2, ((af == AF_INET) ? 32 : 128));
    nas_rt_nht_print_result ("TC_1_7: STEP2 Direct NH case (dynamic arp) NHT add for same dest from multiple clients", !ret);

    nht_log_clear();
    nht_del_route (rt1, pref_len1,p_tr_ip_intf2);
    ret = nas_rt_nht_validate (p_tr_ip_intf2, 0, p_tr_ip_intf2, ((af == AF_INET) ? 32 : 128));
    /* If there is no publish, mark as success */
    if (ret != 0)
        ret = 0;
    nas_rt_nht_print_result ("TC_1_7: STEP3 Direct NH case (dynamic arp) NHT add for same dest from multiple clients", ret);
    nht_log_clear();
    nht_config(p_tr_ip_intf2, af, 0);
    ret = nas_rt_nht_validate (p_tr_ip_intf2, 0, p_tr_ip_intf2, ((af == AF_INET) ? 32 : 128));
    /* If there is no publish, mark as success */
    if (ret != 0)
        ret = 0;
    nas_rt_nht_print_result ("TC_1_7: STEP4 Direct NH case (dynamic arp) NHT add for same dest from multiple clients", ret);
    nht_log_clear();

    nht_intf_admin_set(p_dut_intf2,0);
    ret = nas_rt_nht_validate (p_tr_ip_intf2, 0, p_tr_ip_intf2, ((af == AF_INET) ? 32 : 128));
    nas_rt_nht_print_result ("TC_1_7: Direct NH case (dynamic arp) NHT add for same dest from multiple clients", ret);

    /* clean-up */
    nht_config(p_tr_ip_intf2, af, 0);
    nht_intf_admin_set(p_dut_intf2,1);
    return ret;
}

int nas_rt_nht_ut_1_8 (bool is_prereq) {
    int ret = 0;

    nht_log_clear();

    nht_add_static_arp (p_tr_ip3_intf2, "00:20:00:00:05:00", p_dut_intf2);
    nht_config(p_tr_ip3_intf2, af, 1);

    ret = nas_rt_nht_validate (p_tr_ip3_intf2, 1, p_tr_ip3_intf2, ((af == AF_INET) ? 32 : 128));
    nas_rt_nht_print_result ("TC_1_8: STEP1 Re-run TC_1_6", ret);

    if (is_prereq)
        return ret;

    if (ret == 0) {
        nht_log_clear();
        nht_intf_admin_set(p_dut_intf2,0);
        ret = nas_rt_nht_validate (p_tr_ip3_intf2, 0, p_tr_ip3_intf2, ((af == AF_INET) ? 32 : 128));
        nas_rt_nht_print_result ("TC_1_8: STEP 2 Re-run TC_1_6", ret);

        nht_log_clear();
        nht_intf_admin_set(p_dut_intf2,1);
        nht_add_static_arp (p_tr_ip3_intf2, "00:20:00:00:05:00", p_dut_intf2);
        ret = nas_rt_nht_validate (p_tr_ip3_intf2, 1, p_tr_ip3_intf2, ((af == AF_INET) ? 32 : 128));
        nas_rt_nht_print_result ("TC_1_8: STEP 3 Re-run TC_1_6", ret);

        nht_log_clear();
        nht_config(p_tr_ip3_intf2, af, 0);
        nht_intf_admin_set(p_dut_intf2,0);
        nht_intf_admin_set(p_dut_intf2,1);
        nht_add_static_arp (p_tr_ip3_intf2, "00:20:00:00:05:00", p_dut_intf2);
        ret = nas_rt_nht_validate (p_tr_ip3_intf2, 0, p_tr_ip3_intf2, ((af == AF_INET) ? 32 : 128));
        /* If there is no publish, mark as success */
        if (ret != 0)
            ret = 0;
        nas_rt_nht_print_result ("TC_1_8: Re-run TC_1_6", ret);
    }

    /* Cleanup */
    nht_del_static_arp (p_tr_ip3_intf2, p_dut_intf2);
    nht_del_route (rt1, pref_len1,p_tr_ip3_intf2);
    return ret;
}

int nas_rt_nht_ut_2_1(bool is_prereq) {
    int ret = 0;
    nht_log_clear();

    /* TC_2_1 Indirect NH case - Route added, ARP not resolved */
    nht_add_route (rt1,pref_len1, p_tr_ip_intf1);
    nht_config(nht1, af, 1);
    nht_resolve_nh(p_tr_ip_intf1);

    ret = nas_rt_nht_validate (nht1, 1, rt1, pref_len1);
    nas_rt_nht_print_result ("TC_2_1: Indirect NH case - Route added, ARP not resolved", ret);

    if (is_prereq)
        return ret;

    /* clean-up */
    nht_config(nht1, af, 0);
    nht_del_route (rt1,pref_len1, p_tr_ip_intf1);
    nht_intf_admin_set(p_dut_intf1,0);
    nht_intf_admin_set(p_dut_intf1,1);
    return ret;
}
int nas_rt_nht_ut_2_2(bool is_prereq) {
    int ret = 0;
    nht_log_clear();

    /* TC_2_2 Indirect NH case - Route added, ARP resolved */
    nht_add_route (rt1,pref_len1, p_tr_ip_intf1);
    nht_resolve_nh(p_tr_ip_intf1);
    nht_config(nht1, af, 1);

    ret = nas_rt_nht_validate (nht1, 1, rt1, pref_len1);
    nas_rt_nht_print_result ("TC_2_2: Indirect NH case - Route added, ARP resolved", ret);

    if (is_prereq)
        return ret;

    /* clean-up */
    nht_config(nht1, af, 0);
    nht_del_route (rt1,pref_len1, p_tr_ip_intf1);
    nht_intf_admin_set(p_dut_intf1,0);
    nht_intf_admin_set(p_dut_intf1,1);
    return ret;
}

int nas_rt_nht_ut_2_3(bool is_prereq) {
    int ret = 0;

    nht_log_clear();

    /* TC_2_3 Indirect NH case - TC_2_2 and then ARP becomes unresolved */
    ret = nas_rt_nht_ut_2_2 (true);
    if (ret == 0) {
        nht_del_static_arp(p_tr_ip_intf1, p_dut_intf1);
        ret = nas_rt_nht_validate (nht1, 0, NULL, 0);
        nas_rt_nht_print_result ("TC_2_3: Indirect NH case - TC_2_2 and then ARP becomes unresolved", ret);

        if (is_prereq)
            return ret;
    }
    /* clean-up */
    nht_config(nht1, af, 0);
    nht_del_route (rt1,pref_len1, p_tr_ip_intf1);
    nht_intf_admin_set(p_dut_intf1,0);
    nht_intf_admin_set(p_dut_intf1,1);
    return ret;
}

int nas_rt_nht_ut_2_4(bool is_prereq) {
    int ret = 0;

    nht_log_clear();
    /* TC_2_4 Indirect NH case - TC_2_2 and then route delete */
    ret = nas_rt_nht_ut_2_2 (true);
    if (ret == 0) {
        nht_del_route (rt1, pref_len1, p_tr_ip_intf1);
        ret = nas_rt_nht_validate (nht1, 0, NULL, 0);
        nas_rt_nht_print_result ("TC_2_4: Indirect NH case - TC_2_2 and then route delete", ret);

        if (is_prereq)
            return ret;
    }
    /* clean-up */
    nht_config(nht1, af, 0);
    nht_intf_admin_set(p_dut_intf1,0);
    nht_intf_admin_set(p_dut_intf1,1);
    return ret;
}

int nas_rt_nht_ut_2_5(bool is_prereq) {
    int ret = 0;

    nht_log_clear();

    /* TC_2_5 Indirect NH case - NHT add for same dest from multiple clients */
    nht_config(nht1, af, 1);
    nht_config(nht1, af, 1);
    nht_add_route (rt1,pref_len1, p_tr_ip_intf1);
    nht_resolve_nh(p_tr_ip_intf1);

    /* @@TODO: for multiple client case, this script cannot validate as such, as it is looking for the trace from nas-l3 only where it will send only one publish event */
    ret = nas_rt_nht_validate (nht1, 1, rt1, pref_len1);
    nas_rt_nht_print_result ("TC_2_5: STEP1 Indirect NH case - NHT add for same dest from multiple clients", ret);

    if (is_prereq)
        return ret;

    if (ret == 0) {
        nht_config(nht1, af, 0); /* delete nht */
        nht_log_clear();
        nht_config(nht1, af, 1); /* re-add nht */
        ret = nas_rt_nht_validate (nht1, 1, rt1, pref_len1);
        /* No NHT publish for NHT re-add case when there are multiple clients for same dest. */
        if (ret != 0)
            ret = 0;
        nas_rt_nht_print_result ("TC_2_5: Indirect NH case - NHT add for same dest from multiple clients", ret);
    }
    /* clean-up */
    nht_config(nht1, af, 0);
    nht_config(nht1, af, 0);
    nht_del_route (rt1,pref_len1, p_tr_ip_intf1);
    nht_intf_admin_set(p_dut_intf1,0);
    nht_intf_admin_set(p_dut_intf1,1);
    return ret;
}

int nas_rt_nht_ut_2_6(bool is_prereq) {
    int ret = 0;

    nht_log_clear();

    /* TC_2_6 Indirect NH case - TC_2_2 and then NHT delete and re-add */
    ret = nas_rt_nht_ut_2_2 (true);
    if (ret == 0) {
        nht_log_clear();
        nht_config(nht1, af, 0);
        ret = nas_rt_nht_validate (nht1, 1, rt1, pref_len1);
        nas_rt_nht_print_result ("TC_2_6: STEP1 Indirect NH case - TC_2_2 and then NHT delete and re-add", !ret);
        nht_log_clear();
        nht_config(nht1, af, 1);

        ret = nas_rt_nht_validate (nht1, 1, rt1, pref_len1);
        nas_rt_nht_print_result ("TC_2_6: Indirect NH case - TC_2_2 and then NHT delete and re-add", ret);
        if (is_prereq)
            return ret;
    }
    /* clean-up */
    nht_config(nht1, af, 0);
    nht_del_route (rt1,pref_len1, p_tr_ip_intf1);
    nht_intf_admin_set(p_dut_intf1,0);
    nht_intf_admin_set(p_dut_intf1,1);
    return ret;
}

int nas_rt_nht_ut_2_7(bool is_prereq) {
    int ret = 0;

    nht_log_clear();

    /* TC_2_7 - 2 NHT's pointing to same egress NH
     * 1) NHT pointing to directly connected neighbor
     * 2) NHT via recursive route resolution - Route with NH to directly connected neighbor
     */

    do {

        /* configure NHT to directly connected neighbor */
        nht_config(p_tr_ip_intf2, af, 1);
        nht_resolve_nh(p_tr_ip_intf2);
        ret = nas_rt_nht_validate (p_tr_ip_intf2, 1, p_tr_ip_intf2, ((af == AF_INET) ? 32 : 128));
        nas_rt_nht_print_result ("TC_2_7: Step 1 - NHT pointing to directly connected neighbor", ret);

        if (ret != 0)
            break;

        /* configure route via directly connected neighbor and NHT to a destination thru that route */
        nht_log_clear();
        nht_add_route (rt1,pref_len3, p_tr_ip_intf2);
        nht_config(nht1, af, 1);
        ret = nas_rt_nht_validate (nht1, 1, rt1, pref_len3);
        nas_rt_nht_print_result ("TC_2_7: Step 2 - NHT via recursive route resolution", ret);

        if (ret != 0)
            break;

        if (is_prereq)
            return ret;

        /* delete the route via directly connected neighbor and
         * check the NHT update happens only for that one thru that route and not for NHT pointing to the directly connected neighbor.
         */
        nht_log_clear();
        nht_del_route (rt1,pref_len3, p_tr_ip_intf2);
        ret = nas_rt_nht_validate (nht1, 0, NULL, 0);
        nas_rt_nht_print_result ("TC_2_7: Step 3 - route delete and NHT update for NHT via recursive route resolution", ret);

        if (ret != 0)
            break;

        /* also verify ACL cleanup was not triggered from NAS-L3 */
        ret = nas_rt_nht_validate_acl_cleanup (rt1, 1, NULL, pref_len3);
        ret = !ret;
        nas_rt_nht_print_result ("TC_2_7: Step 4 - validation for ACL cleanup from NAS", ret);

        if (ret != 0)
            break;

        ret = nas_rt_nht_validate (p_tr_ip_intf2, 1, p_tr_ip_intf2, ((af == AF_INET) ? 32 : 128));
        ret = !ret;
        nas_rt_nht_print_result ("TC_2_7: Step 5 - No updates to NHT pointing to directly connected neighbor", ret);

        if (ret != 0)
            break;

        /* also verify ACL cleanup was not triggered from NAS-L3 */
        ret = nas_rt_nht_validate_acl_cleanup (p_tr_ip_intf2, 1, p_tr_ip_intf2, ((af == AF_INET) ? 32 : 128));
        ret = !ret;
        nas_rt_nht_print_result ("TC_2_7: Step 6 - validation for ACL cleanup from NAS", ret);

        if (ret != 0)
            break;

    } while(0);

    /* clean-up */
    nht_config(p_tr_ip_intf2, af, 0);
    nht_config(nht1, af, 0);
    nht_del_route (rt1,pref_len3, p_tr_ip_intf2);
    nht_intf_admin_set(p_dut_intf1,0);
    nht_intf_admin_set(p_dut_intf2,0);

    nht_intf_admin_set(p_dut_intf1,1);
    nht_intf_admin_set(p_dut_intf2,1);
    return ret;
}

int nas_rt_nht_ut_3_1(bool is_prereq) {
    int ret = 0;

    nht_log_clear();

    /* TC_3_1 - ECMP case (2 NH) Route add + Arp not resolved for 2 NH */

    nht_add_route_2nh (rt1,pref_len1, p_tr_ip_intf1, p_tr_ip_intf2);

    nht_config(nht1, af, 1);

    /* Proactive ARP resolution is enabled for the NHs associated with the route */
    ret = nas_rt_nht_validate (nht1, 2, rt1, pref_len1);
    nas_rt_nht_print_result ("TC_3_1 - ECMP case (2 NH) Route add + Arp resolved for 2 NH", ret);

    if (is_prereq)
        return ret;

    nht_log_clear();
    nht_del_static_arp (p_tr_ip_intf1, p_dut_intf1);
    /* ARP should get unresolved for 1 nh */
    ret = nas_rt_nht_validate (nht1, 2, rt1, pref_len1);
    nas_rt_nht_print_result ("TC_3_1 - STEP3 1 Arp gets unresolved", ret);

    nht_log_clear();
    nht_del_static_arp (p_tr_ip_intf2, p_dut_intf2);
    /* ARP should get unresolved for 2nd nh */
    ret = nas_rt_nht_validate (nht1, 2, rt1, pref_len1);
    nas_rt_nht_print_result ("TC_3_1 - Arp gets unresolved", ret);

    /* clean-up */
    nht_config(nht1, af, 0);
    nht_del_route_2nh (rt1,pref_len1, p_tr_ip_intf1, p_tr_ip_intf2);
    nht_intf_admin_set(p_dut_intf1,0);
    nht_intf_admin_set(p_dut_intf1,1);
    nht_intf_admin_set(p_dut_intf2,0);
    nht_intf_admin_set(p_dut_intf2,1);

    return ret;
}

int nas_rt_nht_ut_3_2(bool is_prereq) {
    int ret = 0;

    nht_log_clear();

    ret = nas_rt_nht_ut_3_1 (true);
    if (ret == 0) {
        do {
            nht_log_clear();
            nht_replace_route (rt1,pref_len1, p_tr_ip_intf2);
            /* NHT tracked only for 1 nh */
            ret = nas_rt_nht_validate (nht1, 1, rt1, pref_len1);
            nas_rt_nht_print_result ("TC_3_2 - TC_3_1 and route delete with nh1", ret);
            if (ret != 0)
                break;

            nht_log_clear();
            nht_del_route (rt1,pref_len1, p_tr_ip_intf2);
            ret = nas_rt_nht_validate (nht1, 0, rt1, pref_len1);
            nas_rt_nht_print_result ("TC_3_2 - TC_3_1 and route delete with nh2", ret);
            if (ret != 0)
                break;

            nht_log_clear();
            nht_add_route (rt1,pref_len1, p_tr_ip_intf1);
            /* route is added with nh1 */
            ret = nas_rt_nht_validate (nht1, 1, rt1, pref_len1);
            nas_rt_nht_print_result ("TC_3_2 - TC_3_1 and route add with nh1", ret);
            if (ret != 0)
                break;

            nht_replace_route_2nh (rt1,pref_len1, p_tr_ip_intf1, p_tr_ip_intf2);
            ret = nas_rt_nht_validate (nht1, 2, rt1, pref_len1);
            nas_rt_nht_print_result ("TC_3_2 - TC_3_1 and route add with 2nd nh", ret);
        } while(0);
    }

    /* clean-up */
    nht_config(nht1, af, 0);
    nht_del_route_2nh (rt1,pref_len1, p_tr_ip_intf1, p_tr_ip_intf2);
    nht_intf_admin_set(p_dut_intf1,0);
    nht_intf_admin_set(p_dut_intf1,1);
    nht_intf_admin_set(p_dut_intf2,0);
    nht_intf_admin_set(p_dut_intf2,1);

    return ret;
}

int nas_rt_nht_ut_3_3(bool is_prereq) {
    int ret = 0;

    nht_log_clear();

    /* TC_3_1 - ECMP case (2 NH) Route add + Arp not resolved for 2 NH */

    nht_add_route_2nh (rt1,pref_len1, p_tr_ip_intf1, p_tr_ip_intf2);

    nht_config(nht1, af, 1);
    nht_config(nht2, af, 1);

    do {
        ret = nas_rt_nht_validate (nht1, 2, rt1, pref_len1);
        nas_rt_nht_print_result ("TC_3_3 - STEP3 Arp resolved for 2 NHs for NHT1", ret);
        if (ret != 0)
            break;
        ret = nas_rt_nht_validate (nht2, 2, rt1, pref_len1);
        nas_rt_nht_print_result ("TC_3_3 - STEP4 Arp resolved for 2 NHs for NHT2", ret);
        if (ret != 0)
            break;

        nht_log_clear();
        nht_add_route (rt2,pref_len2, p_tr_ip_intf2);
        ret = nas_rt_nht_validate (nht2, 1, rt2, pref_len2);
        nas_rt_nht_print_result ("TC_3_3 - STEP5 new 1 NH route for NHT2", ret);
        if (ret != 0)
            break;

        nht_log_clear();
        nht_del_route (rt2,pref_len2, p_tr_ip_intf2);
        ret = nas_rt_nht_validate (nht2, 2, rt1, pref_len1);
        nas_rt_nht_print_result ("TC_3_3 - STEP6 Arp resolved for 2 NHs for NHT2", ret);
        if (ret != 0)
            break;

        nht_log_clear();
        nht_del_static_arp (p_tr_ip_intf1, p_dut_intf1);
        /* ARP gets unresolved for 1st nh, but proactive resolution enabled,
         * so, NH count stay as is */
        ret = nas_rt_nht_validate (nht1, 2, rt1, pref_len1);
        nas_rt_nht_print_result ("TC_3_3 - STEP7", ret);
        if (ret != 0)
            break;
        ret = nas_rt_nht_validate (nht1, 2, rt1, pref_len1);
        nas_rt_nht_print_result ("TC_3_3 - STEP8", ret);
        if (ret != 0)
            break;

        nht_log_clear();
        nht_del_static_arp (p_tr_ip_intf2, p_dut_intf2);
        /* ARP gets unresolved for 2nd nh, but proactive resolution enabled,
         * so, NH count stay as is */
        ret = nas_rt_nht_validate (nht1, 2, rt1, pref_len1);
        nas_rt_nht_print_result ("TC_3_3 - STEP9", ret);
        if (ret != 0)
            break;
        ret = nas_rt_nht_validate (nht1, 2, rt1, pref_len1);
        nas_rt_nht_print_result ("TC_3_3 - STEP10", ret);
        if (ret != 0)
            break;

        nht_log_clear();
        nht_add_route (rt2,pref_len2, p_tr_ip_intf2);
        ret = nas_rt_nht_validate (nht2, 1, rt2, pref_len2);
        nas_rt_nht_print_result ("TC_3_3 - STEP11", ret);
        if (ret != 0)
            break;

        nht_log_clear();
        nht_del_route (rt2,pref_len2, p_tr_ip_intf2);
        ret = nas_rt_nht_validate (nht2, 2, rt1, pref_len1);
        nas_rt_nht_print_result ("TC_3_3 - STEP12", ret);
        if (ret != 0)
            break;

        nht_log_clear();
        nht_resolve_nh (p_tr_ip_intf1);
        ret = nas_rt_nht_validate (nht1, 2, rt1, pref_len1);
        nas_rt_nht_print_result ("TC_3_3 - STEP13", !ret);
        if (ret == 0)
            break;
        ret = nas_rt_nht_validate (nht2, 2, rt1, pref_len1);
        nas_rt_nht_print_result ("TC_3_3 - STEP14", !ret);
        if (ret == 0)
            break;

        nht_log_clear();
        nht_replace_route (rt1,pref_len1, p_tr_ip_intf1);
        ret = nas_rt_nht_validate (nht1, 1, rt1, pref_len1);
        nas_rt_nht_print_result ("TC_3_3 - STEP15", ret);
        if (ret != 0)
            break;
        ret = nas_rt_nht_validate (nht2, 1, rt1, pref_len1);
        nas_rt_nht_print_result ("TC_3_3 - STEP16", ret);
        if (ret != 0)
            break;
    } while(0);
    /* clean-up */
    nht_log_clear();
    nht_del_route (rt1,pref_len1, p_tr_ip_intf1);
    ret = nas_rt_nht_validate (nht1, 0, rt1, pref_len1);
    nas_rt_nht_print_result ("TC_3_3 - STEP17", ret);
    ret = nas_rt_nht_validate (nht2, 0, rt1, pref_len1);
    nas_rt_nht_print_result ("TC_3_3 - STEP18", ret);
    nas_rt_nht_print_result ("TC_3_3 - Best match between 1NH and 2NH(multipath) cases for NHT1 and NHT2", ret);

    nht_config(nht1, af, 0);
    nht_config(nht2, af, 0);
    nht_intf_admin_set(p_dut_intf1,0);
    nht_intf_admin_set(p_dut_intf1,1);
    nht_intf_admin_set(p_dut_intf2,0);
    nht_intf_admin_set(p_dut_intf2,1);

    return ret;
}

int nas_rt_nht_ut_4_1(bool is_prereq) {
    int ret = 0;

    nht_log_clear();

    nht_config(nht1, af, 1);
    nht_config(nht2, af, 1);
    nht_config(nht3, af, 1);
    nht_config(nht4, af, 1);
    nht_config(nht5, af, 1);
    nht_add_route (rt1, pref_len1, p_tr_ip_intf1);
    nht_resolve_nh(p_tr_ip_intf1);
    do {
        if ((ret = nas_rt_nht_validate(nht1, 1, rt1, pref_len1)) != 0)
            break;
        if ((ret = nas_rt_nht_validate(nht2, 1, rt1, pref_len1)) != 0)
            break;
        if ((ret = nas_rt_nht_validate(nht3, 1, rt1, pref_len1)) != 0)
            break;
        if ((ret = nas_rt_nht_validate(nht4, 1, rt1, pref_len1)) != 0)
            break;
        if ((ret = nas_rt_nht_validate(nht5, 1, rt1, pref_len1)) != 0)
            break;
    }while(0);

    nas_rt_nht_print_result("TC_4_1 - Best match change with more NHT's mapping to different route prefixes (prefix-len 8)", ret);

    if (is_prereq)
        return ret;
    /* clean-up */
    nht_config(nht1, af, 0);
    nht_config(nht2, af, 0);
    nht_config(nht3, af, 0);
    nht_config(nht4, af, 0);
    nht_config(nht5, af, 0);
    nht_del_route (rt1, pref_len1, p_tr_ip_intf1);
    nht_intf_admin_set(p_dut_intf1,0);
    nht_intf_admin_set(p_dut_intf1,1);
    nht_intf_admin_set(p_dut_intf2,0);
    nht_intf_admin_set(p_dut_intf2,1);
    return ret;
}

int nas_rt_nht_ut_4_2(bool is_prereq) {
    int ret = 0;

    if (nas_rt_nht_ut_4_1(true) == 0) {
        nht_log_clear();
        nht_add_route (rt2, pref_len2, p_tr_ip_intf2);
        nht_resolve_nh(p_tr_ip_intf2);
        do {
            if ((ret = nas_rt_nht_validate(nht1, 0, rt1, pref_len1)) == 0)
                break;
            if ((ret = nas_rt_nht_validate(nht2, 1, rt2, pref_len2)) != 0)
                break;
            if ((ret = nas_rt_nht_validate(nht3, 1, rt2, pref_len2)) != 0)
                break;
            if ((ret = nas_rt_nht_validate(nht4, 1, rt2, pref_len2)) != 0)
                break;
            if ((ret = nas_rt_nht_validate(nht5, 0, rt1, pref_len1)) == 0)
                break;
            /* Test case is passed */
            ret = 0;
        }while(0);

        nas_rt_nht_print_result("TC_4_2 - Best match change with more NHT's mapping to different TC_4_1 & with route prefixes (prefix-len 16)", ret);
        if (is_prereq)
            return ret;
    }

    /* clean-up */
    nht_config(nht1, af, 0);
    nht_config(nht2, af, 0);
    nht_config(nht3, af, 0);
    nht_config(nht4, af, 0);
    nht_config(nht5, af, 0);
    nht_del_route (rt1, pref_len1, p_tr_ip_intf1);
    nht_del_route (rt2, pref_len2, p_tr_ip_intf2);
    nht_intf_admin_set(p_dut_intf1,0);
    nht_intf_admin_set(p_dut_intf1,1);
    nht_intf_admin_set(p_dut_intf2,0);
    nht_intf_admin_set(p_dut_intf2,1);

    return ret;
}

int nas_rt_nht_ut_4_3(bool is_prereq) {
    int ret = 0;

    if (nas_rt_nht_ut_4_2(true) == 0) {
        nht_log_clear();
        nht_add_route (rt3, pref_len3, p_tr_ip_intf1);
        do {
            if ((ret = nas_rt_nht_validate(nht1, 0, rt1, pref_len1)) == 0)
                break;
            if ((ret = nas_rt_nht_validate(nht2, 1, rt3, pref_len3)) != 0)
                break;
            if ((ret = nas_rt_nht_validate(nht3, 1, rt3, pref_len3)) != 0)
                break;
            if ((ret = nas_rt_nht_validate(nht4, 0, rt1, pref_len1)) == 0)
                break;
            if ((ret = nas_rt_nht_validate(nht5, 0, rt1, pref_len1)) == 0)
                break;
            /* Test case is passed */
            ret = 0;
        }while(0);

        nas_rt_nht_print_result("TC_4_3 - Best match change with more NHT's mapping to different TC_4_2 & with route prefixes (prefix-len 24)", ret);
        if (is_prereq)
            return ret;
    }
    /* clean-up */
    nht_config(nht1, af, 0);
    nht_config(nht2, af, 0);
    nht_config(nht3, af, 0);
    nht_config(nht4, af, 0);
    nht_config(nht5, af, 0);
    nht_del_route (rt1, pref_len1, p_tr_ip_intf1);
    nht_del_route (rt2, pref_len2, p_tr_ip_intf2);
    nht_del_route (rt3, pref_len3, p_tr_ip_intf1);
    nht_intf_admin_set(p_dut_intf1,0);
    nht_intf_admin_set(p_dut_intf1,1);
    nht_intf_admin_set(p_dut_intf2,0);
    nht_intf_admin_set(p_dut_intf2,1);

    return ret;
}

int nas_rt_nht_ut_4_4(bool is_prereq) {
    int ret = 0;

    if (nas_rt_nht_ut_4_3(true) == 0) {
        nht_log_clear();
        nht_add_route (rt4, pref_len4, p_tr_ip_intf2);
        do {
            if ((ret = nas_rt_nht_validate(nht1, 0, rt1, pref_len1)) == 0)
                break;
            if ((ret = nas_rt_nht_validate(nht2, 1, rt4, pref_len4)) != 0)
                break;
            if ((ret = nas_rt_nht_validate(nht3, 0, rt1, pref_len1)) == 0)
                break;
            if ((ret = nas_rt_nht_validate(nht4, 0, rt1, pref_len1)) == 0)
                break;
            if ((ret = nas_rt_nht_validate(nht5, 0, rt1, pref_len1)) == 0)
                break;
            /* Test case is passed */
            ret = 0;
        }while(0);

        nas_rt_nht_print_result("TC_4_4 - Best match change with more NHT's mapping to different TC_4_3 & with route prefixes (prefix-len 32)", ret);
        if (is_prereq)
            return ret;
    }
    /* clean-up */
    nht_config(nht1, af, 0);
    nht_config(nht2, af, 0);
    nht_config(nht3, af, 0);
    nht_config(nht4, af, 0);
    nht_config(nht5, af, 0);
    nht_del_route (rt1, pref_len1, p_tr_ip_intf1);
    nht_del_route (rt2, pref_len2, p_tr_ip_intf2);
    nht_del_route (rt3, pref_len3, p_tr_ip_intf1);
    nht_del_route (rt4, pref_len4, p_tr_ip_intf2);
    nht_intf_admin_set(p_dut_intf1,0);
    nht_intf_admin_set(p_dut_intf1,1);
    nht_intf_admin_set(p_dut_intf2,0);
    nht_intf_admin_set(p_dut_intf2,1);

    return ret;
}

int nas_rt_nht_ut_4_5(bool is_prereq) {
    int ret = 0;

    nht_log_clear();

    nht_config(nht5, af, 1);
    nht_config(nht6, af, 1);
    nht_add_route (rt1, pref_len1, p_tr_ip_intf1);
    nht_resolve_nh(p_tr_ip_intf1);
    do {
        if ((ret = nas_rt_nht_validate(nht5, 1, rt1, pref_len1)) != 0)
            break;
        if ((ret = nas_rt_nht_validate(nht6, 1, rt1, pref_len1)) != 0)
            break;
    }while(0);

    nas_rt_nht_print_result("TC_4_5 - STEP1 Best match change with more NHT's mapping to same route but different prefix lens", ret);
    if (ret == 0) {
        nht_log_clear();
        nht_add_route (rt1, pref_len2, p_tr_ip_intf2);
        nht_resolve_nh(p_tr_ip_intf2);
        do {
            if ((ret = nas_rt_nht_validate(nht5, 1, rt1, pref_len1)) == 0)
                break;
            if ((ret = nas_rt_nht_validate(nht6, 1, rt1, pref_len2)) != 0)
                break;
        }while(0);

        nas_rt_nht_print_result("TC_4_5 - Best match change with more NHT's mapping to same route but different prefix lens", ret);
    }
    /* clean-up */
    nht_config(nht5, af, 0);
    nht_config(nht6, af, 0);
    nht_del_route (rt1, pref_len1, p_tr_ip_intf1);
    nht_del_route (rt1, pref_len2, p_tr_ip_intf2);
    nht_intf_admin_set(p_dut_intf1,0);
    nht_intf_admin_set(p_dut_intf1,1);
    nht_intf_admin_set(p_dut_intf2,0);
    nht_intf_admin_set(p_dut_intf2,1);
    return ret;
}


int nas_rt_nht_ut_5_1(bool is_prereq) {
    int ret = 0;

    nht_log_clear();

    nht_add_route (rt1, pref_len1, p_tr_ip_intf1);
    nht_add_route (rt2, pref_len2, p_tr_ip_intf2);
    nht_add_route (rt3, pref_len3, p_tr_ip_intf1);
    nht_add_route (rt4, pref_len4, p_tr_ip_intf2);
    nht_resolve_nh(p_tr_ip_intf1);
    nht_resolve_nh(p_tr_ip_intf2);

    nht_config(nht1, af, 1);
    nht_config(nht2, af, 1);
    nht_config(nht3, af, 1);
    nht_config(nht4, af, 1);
    nht_config(nht5, af, 1);
    do {
        if ((ret = nas_rt_nht_validate(nht1, 1, rt1, pref_len1)) != 0)
            break;
        if ((ret = nas_rt_nht_validate(nht2, 1, rt4, pref_len4)) != 0)
            break;
        if ((ret = nas_rt_nht_validate(nht3, 1, rt3, pref_len3)) != 0)
            break;
        if ((ret = nas_rt_nht_validate(nht4, 1, rt2, pref_len2)) != 0)
            break;
        if ((ret = nas_rt_nht_validate(nht5, 1, rt1, pref_len1)) != 0)
            break;
    }while(0);

    nas_rt_nht_print_result("TC_5_1 - Best match case with NHT added after NH resolved"
                            "- add NHT when all Route added & NH resolved", ret);
    if (is_prereq)
        return ret;

    /* clean-up */
    nht_config(nht1, af, 0);
    nht_config(nht2, af, 0);
    nht_config(nht3, af, 0);
    nht_config(nht4, af, 0);
    nht_config(nht5, af, 0);
    nht_del_route (rt1, pref_len1, p_tr_ip_intf1);
    nht_del_route (rt2, pref_len2, p_tr_ip_intf2);
    nht_del_route (rt3, pref_len3, p_tr_ip_intf1);
    nht_del_route (rt4, pref_len4, p_tr_ip_intf2);
    nht_intf_admin_set(p_dut_intf1,0);
    nht_intf_admin_set(p_dut_intf1,1);
    nht_intf_admin_set(p_dut_intf2,0);
    nht_intf_admin_set(p_dut_intf2,1);
    return ret;
}

int nas_rt_nht_ut_5_2(bool is_prereq) {
    int ret = 0;

    if (nas_rt_nht_ut_5_1(true) == 0) {
        nht_log_clear();

        nht_del_route (rt3, pref_len3, p_tr_ip_intf1);
        do {
            if ((ret = nas_rt_nht_validate(nht1, 0, rt1, pref_len1)) == 0)
                break;
            if ((ret = nas_rt_nht_validate(nht2, 0, rt1, pref_len1)) == 0)
                break;
            if ((ret = nas_rt_nht_validate(nht3, 1, rt2, pref_len2)) != 0)
                break;
            if ((ret = nas_rt_nht_validate(nht4, 0, rt1, pref_len1)) == 0)
                break;
            if ((ret = nas_rt_nht_validate(nht5, 0, rt1, pref_len1)) == 0)
                break;
            /* Test case is passed */
            ret = 0;
        }while(0);

        nas_rt_nht_print_result("TC_5_2 Best match case with NHT added after NH resolved"
                                "TC_5_1 and delete route 40.1.1.0/24 ", ret);
        if (is_prereq)
            return ret;
    }
    /* clean-up */
    nht_config(nht1, af, 0);
    nht_config(nht2, af, 0);
    nht_config(nht3, af, 0);
    nht_config(nht4, af, 0);
    nht_config(nht5, af, 0);
    nht_del_route (rt1, pref_len1, p_tr_ip_intf1);
    nht_del_route (rt2, pref_len2, p_tr_ip_intf2);
    nht_del_route (rt3, pref_len3, p_tr_ip_intf1);
    nht_del_route (rt4, pref_len4, p_tr_ip_intf2);
    nht_intf_admin_set(p_dut_intf1,0);
    nht_intf_admin_set(p_dut_intf1,1);
    nht_intf_admin_set(p_dut_intf2,0);
    nht_intf_admin_set(p_dut_intf2,1);
    return ret;
}

int nas_rt_nht_ut_5_3(bool is_prereq) {
    int ret = 0;
    nht_log_clear();

    /* TC_5_3 Indirect NH case - Route added, ARP not resolved */
    nht_add_route (rt1,pref_len1, p_tr_ip2_intf1);
    nht_add_route (rt2,pref_len2, p_tr_ip2_intf1);
    nht_add_route (rt3,pref_len3, p_tr_ip2_intf1);
    nht_add_route (rt2,pref_len5, p_tr_ip2_intf1);

    nht_config(nht3, af, 1);

    ret = nas_rt_nht_validate (nht3, 0, rt1, pref_len1);
    nas_rt_nht_print_result ("TC_5_3: Indirect NH case - Route added, ARP not resolved", ret);

    if (is_prereq)
        return ret;

    /* clean-up */
    nht_config(nht3, af, 0);
    nht_del_route (rt1,pref_len1, p_tr_ip2_intf1);
    nht_del_route (rt2,pref_len2, p_tr_ip2_intf1);
    nht_del_route (rt3,pref_len3, p_tr_ip2_intf1);
    nht_del_route (rt2,pref_len5, p_tr_ip2_intf1);
    nht_intf_admin_set(p_dut_intf1,0);
    nht_intf_admin_set(p_dut_intf1,1);
    return ret;
}

int nas_rt_nht_ut_5_4(bool is_prereq) {
    int ret = 0;
    nht_log_clear();

    /* TC_5_4 Indirect NH case - Route added, ARP resolved */
    nht_add_route (rt1,pref_len1, p_tr_ip_intf1);
    nht_add_route (rt2,pref_len2, p_tr_ip_intf1);
    nht_add_route (rt3,pref_len3, p_tr_ip_intf1);
    nht_add_route (rt2,pref_len5, p_tr_ip_intf1);
    nht_resolve_nh(p_tr_ip_intf1);
    nht_config(nht3, af, 1);

    do {
        if ((ret = nas_rt_nht_validate(nht3, 1, rt3, pref_len3)) != 0)
            break;
        nht_del_route (rt3, pref_len3, p_tr_ip_intf1);
        if ((ret = nas_rt_nht_validate(nht3, 1, rt2, pref_len5)) == 0)
            break;
        nht_del_route (rt2, pref_len5, p_tr_ip_intf1);
        if ((ret = nas_rt_nht_validate(nht3, 1, rt2, pref_len2)) == 0)
            break;
        nht_del_route (rt2, pref_len2, p_tr_ip_intf1);
        if ((ret = nas_rt_nht_validate(nht3, 1, rt1, pref_len1)) == 0)
            break;
        /* Test case is passed */
        ret = 0;
    }while(0);

    nas_rt_nht_print_result ("TC_5_4: Indirect NH case - Route added, ARP resolved", ret);

    if (is_prereq)
        return ret;

    /* clean-up */
    nht_config(nht3, af, 0);
    nht_del_route (rt1,pref_len1, p_tr_ip_intf1);
    nht_del_route (rt2,pref_len2, p_tr_ip_intf1);
    nht_del_route (rt3,pref_len3, p_tr_ip_intf1);
    nht_del_route (rt2,pref_len5, p_tr_ip_intf1);
    nht_intf_admin_set(p_dut_intf1,0);
    nht_intf_admin_set(p_dut_intf1,1);
    return ret;
}

int nas_rt_nht_ut_6_1(bool is_prereq) {
    int ret = 0;

    nht_log_clear();

    /* delete default management route if any */
    nht_add_route (rt5,0, p_tr_ip_intf1);

    nht_config(nht1, af, 1);
    nht_config(nht2, af, 1);
    do {
        if ((ret = nas_rt_nht_validate(nht1, 1, rt5, 0)) != 0)
            break;
        if ((ret = nas_rt_nht_validate(nht2, 1, rt5, 0)) != 0)
            break;
    }while(0);
    if (ret != 0) {
        nas_rt_nht_print_result("TC_6_1 STEP-1 - Default route coverage for best match case. Delete default management route if any.", ret);
    } else {
        nht_add_route (rt2, pref_len2, p_tr_ip_intf2);
        nht_resolve_nh(p_tr_ip_intf2);
        do {
            if ((ret = nas_rt_nht_validate(nht1, 0, rt5, 0)) == 0)
                break;
            if ((ret = nas_rt_nht_validate(nht2, 1, rt2, pref_len2)) != 0)
                break;
        }while(0);

        nas_rt_nht_print_result("TC_6_1 - Default route coverage for best match case", ret);

        if (is_prereq)
            return ret;
    }
    /* clean-up */
    nht_config(nht1, af, 0);
    nht_config(nht2, af, 0);
    nht_del_route (rt5,0, p_tr_ip_intf1);
    nht_del_route (rt2, pref_len2, p_tr_ip_intf2);
    nht_intf_admin_set(p_dut_intf1,0);
    nht_intf_admin_set(p_dut_intf1,1);
    nht_intf_admin_set(p_dut_intf2,0);
    nht_intf_admin_set(p_dut_intf2,1);
    return ret;
}

int nas_rt_nht_ut_6_2(bool is_prereq) {
    int ret = 0;

    if (nas_rt_nht_ut_6_1(true) == 0) {
        nht_log_clear();

        nht_intf_admin_set(p_dut_intf2,0);
        do {
            if ((ret = nas_rt_nht_validate(nht1, 1, rt5, 0)) == 0)
                break;
            if ((ret = nas_rt_nht_validate(nht2, 1, rt5, 0)) != 0)
                break;
        }while(0);

        nas_rt_nht_print_result("TC_6_2 - Default route coverage for best match case"
                                " TC_6_1 and bring down nextHop for best match", ret);
        if (is_prereq)
            return ret;
    }
    /* clean-up */
    nht_config(nht1, af, 0);
    nht_config(nht2, af, 0);
    nht_del_route (rt5,0, p_tr_ip_intf1);
    nht_del_route (rt2, pref_len2, p_tr_ip_intf2);
    nht_intf_admin_set(p_dut_intf1,0);
    nht_intf_admin_set(p_dut_intf1,1);
    nht_intf_admin_set(p_dut_intf2,0);
    nht_intf_admin_set(p_dut_intf2,1);
    return ret;
}


int nas_rt_nht_ut_8_1(bool is_prereq) {
    int num_nht = 255;
    const char *nht_network1 = "40.0.0.1", *nht_network2 = "40.0.1.1";
    const char *nht_network3 = "40.0.2.1", *nht_network4 = "40.0.3.1";
    const char *nht_network1_ip6 = "4::1", *nht_network2_ip6 = "4::1:1";
    const char *nht_network3_ip6 = "4::2:1", *nht_network4_ip6 = "4::3:1";
    int ret = 0;

    nht_log_clear();

    /* TC_8_1 Non-ECMP Scalability case - (1024) Multi NHT's to 1 route mapping */
    nht_add_route (rt1,pref_len2, p_tr_ip_intf1);

    if (af == AF_INET6) {
        nht_network1 = nht_network1_ip6; nht_network2 = nht_network2_ip6;
        nht_network3 = nht_network3_ip6; nht_network4 = nht_network4_ip6;
    }
    sleep (2);
    nht_config_scale (nht_network1, af, 1, num_nht);
    nht_config_scale (nht_network2, af, 1, num_nht);
    nht_config_scale (nht_network3, af, 1, num_nht);
    nht_config_scale (nht_network4, af, 1, num_nht);
    do {
        nht_resolve_nh(p_tr_ip_intf1);
        sleep (50);

        do {
            if ((ret = nas_rt_nht_validate_multi_nht_to_one_route (nht_network1, 1, rt1, pref_len2, af, num_nht)) != 0) break;
            if ((ret = nas_rt_nht_validate_multi_nht_to_one_route (nht_network2, 1, rt1, pref_len2, af, num_nht)) != 0) break;
            if ((ret = nas_rt_nht_validate_multi_nht_to_one_route (nht_network3, 1, rt1, pref_len2, af, num_nht)) != 0) break;
            if ((ret = nas_rt_nht_validate_multi_nht_to_one_route (nht_network4, 1, rt1, pref_len2, af, num_nht)) != 0) break;
        } while (0);
        sleep (2);

        if (ret != 0) {
            nas_rt_nht_print_result ("TC_8_1:  Non-ECMP Scalability case - (1024) Multi NHT's to 1 route mapping (step 2)", ret);
            break;
        }
    } while(0);
    nas_rt_nht_print_result ("\r\n\nTC_8_1:  Non-ECMP Scalability case - (1024) Multi NHT's to 1 route mapping", ret);

    /* clean-up */
    nht_config_scale (nht_network1, af, 0, num_nht);
    nht_config_scale (nht_network2, af, 0, num_nht);
    nht_config_scale (nht_network3, af, 0, num_nht);
    nht_config_scale (nht_network4, af, 0, num_nht);
    nht_del_route (rt1,pref_len2, p_tr_ip_intf1);
    nht_intf_admin_set(p_dut_intf1,0);
    nht_intf_admin_set(p_dut_intf1,1);
    return ret;
}


int nas_rt_nht_ut_8_2(bool is_prereq) {
    int num_nht = 255, num_routes = 255;
    const char *rt1_prefix  = "90.1.1.0", *rt2_prefix = "90.2.1.0";
    const char *rt3_prefix = "90.3.1.0", *rt4_prefix = "90.4.1.0";
    const char *nht_network1 = "90.1.1.1", *nht_network2 = "90.2.1.1";
    const char *nht_network3 = "90.3.1.1", *nht_network4 = "90.4.1.1";

    const char *rt1_prefix_ip6  = "9:1:1::", *rt2_prefix_ip6 = "9:2:1::";
    const char *rt3_prefix_ip6 = "9:3:1::", *rt4_prefix_ip6 = "9:4:1::";
    const char *nht_network1_ip6 = "9:1:1::1", *nht_network2_ip6 = "9:2:1::1";
    const char *nht_network3_ip6 = "9:3:1::1", *nht_network4_ip6 = "9:4:1::1";

    int ret = 0;

    if (af == AF_INET6) {
        rt1_prefix = rt1_prefix_ip6; rt2_prefix = rt2_prefix_ip6; rt3_prefix = rt3_prefix_ip6;
        rt4_prefix = rt4_prefix_ip6;
        nht_network1 = nht_network1_ip6; nht_network2 = nht_network2_ip6;
        nht_network3 = nht_network3_ip6; nht_network4 = nht_network4_ip6;
    }
    nht_log_clear();

    /* TC_8_2 Non-ECMP Scalability case - 1024 NHTs (1 NHT to 1 route mapping) */
    nht_add_route_scale (rt1_prefix,pref_len3, p_tr_ip_intf1, af, num_routes);
    nht_add_route_scale (rt2_prefix,pref_len3, p_tr_ip_intf1, af, num_routes);
    nht_add_route_scale (rt3_prefix,pref_len3, p_tr_ip_intf1, af, num_routes);
    nht_add_route_scale (rt4_prefix,pref_len3, p_tr_ip_intf1, af, num_routes);

    sleep (2);
    nht_log_clear();
    nht_config_scale_with_prefix (nht_network1, af, 1, num_nht, pref_len3);
    nht_config_scale_with_prefix (nht_network2, af, 1, num_nht, pref_len3);
    nht_config_scale_with_prefix (nht_network3, af, 1, num_nht, pref_len3);
    nht_config_scale_with_prefix (nht_network4, af, 1, num_nht, pref_len3);
    do {
        nht_resolve_nh(p_tr_ip_intf1);
        sleep (50);
        do {
            if ((ret = nas_rt_nht_validate_one_nht_to_one_route (nht_network1, 1, rt1_prefix, pref_len3, af, num_nht)) != 0)
                break;
            if ((ret = nas_rt_nht_validate_one_nht_to_one_route (nht_network2, 1, rt2_prefix, pref_len3, af, num_nht)) != 0)
                break;
            if ((ret = nas_rt_nht_validate_one_nht_to_one_route (nht_network3, 1, rt3_prefix, pref_len3, af, num_nht)) != 0)
                break;
            if ((ret = nas_rt_nht_validate_one_nht_to_one_route (nht_network4, 1, rt4_prefix, pref_len3, af, num_nht)) != 0)
                break;
        } while (0);
        sleep (2);

        if (ret != 0) {
            nas_rt_nht_print_result ("TC_8_2:  Non-ECMP Scalability case - 1000 NHTs (1 NHT to 1 route mapping) (step 2)", ret);
            break;
        }
    } while(0);
    nas_rt_nht_print_result ("\r\n\nTC_8_2:  Non-ECMP Scalability case - 1000 NHTs (1 NHT to 1 route mapping)", ret);

    /* clean-up */
    nht_config_scale_with_prefix (nht_network1, af, 0, num_nht, pref_len3);
    nht_config_scale_with_prefix (nht_network2, af, 0, num_nht, pref_len3);
    nht_config_scale_with_prefix (nht_network3, af, 0, num_nht, pref_len3);
    nht_config_scale_with_prefix (nht_network4, af, 0, num_nht, pref_len3);
    nht_del_route_scale (rt1_prefix,pref_len3, p_tr_ip_intf1, af, num_routes);
    nht_del_route_scale (rt2_prefix,pref_len3, p_tr_ip_intf1, af, num_routes);
    nht_del_route_scale (rt3_prefix,pref_len3, p_tr_ip_intf1, af, num_routes);
    nht_del_route_scale (rt4_prefix,pref_len3, p_tr_ip_intf1, af, num_routes);
    nht_intf_admin_set(p_dut_intf1,0);
    nht_intf_admin_set(p_dut_intf1,1);
    return ret;
}

int nas_rt_nht_ut_9_1 (bool is_prereq) {
    int ret = 0;
#define NAS_UT_NH_STR_LEN 64
    char nh_ip[NAS_UT_NH_STR_LEN], nh_mac[NAS_UT_NH_STR_LEN], rt_nh[NAS_UT_NH_STR_LEN];
    char *p_nh = NULL;
    char *p_cmd = NULL;
    int cnt, num_nh_entries = 32;
    int nh_cnt = num_nh_entries/2;

    p_nh = (char*)malloc(2048);
    if (p_nh == NULL)
        return ret;
    p_cmd = (char*)malloc(2048);
    if (p_cmd == NULL) {
        free(p_nh);
        return ret;
    }
    nht_log_clear();
    memset(p_nh, '\0', sizeof(2048));
    for (cnt = 2; cnt <= (nh_cnt + 1); cnt++) {
        memset(&nh_ip, '\0', sizeof(nh_ip));
        memset(&nh_mac, '\0', sizeof(nh_mac));

        if (af == AF_INET) {
            snprintf(nh_ip, NAS_UT_NH_STR_LEN-1, "%s%d", p_tr_mpath_intf1, cnt);
        } else {
            snprintf(nh_ip, NAS_UT_NH_STR_LEN-1, "%s%x", p_tr_mpath_intf1, cnt);
        }
        snprintf(nh_mac, NAS_UT_NH_STR_LEN-1, "00:20:00:00:02:%x", cnt);
        nht_add_static_arp(nh_ip, nh_mac, p_dut_intf1);
        snprintf(rt_nh, NAS_UT_NH_STR_LEN-1, "nexthop via %s ", nh_ip);
        strncat(p_nh, rt_nh, 2048);
        if (af == AF_INET) {
            snprintf(nh_ip, NAS_UT_NH_STR_LEN-1, "%s%d", p_tr_mpath_intf2, cnt);
        } else {
            snprintf(nh_ip, NAS_UT_NH_STR_LEN-1, "%s%x", p_tr_mpath_intf2, cnt);
        }
        snprintf(nh_mac, NAS_UT_NH_STR_LEN-1, "00:30:00:00:02:%x", cnt);
        nht_add_static_arp(nh_ip, nh_mac, p_dut_intf2);
        snprintf(rt_nh, NAS_UT_NH_STR_LEN-1, "nexthop via %s ", nh_ip);
        strncat(p_nh, rt_nh, 2048);
    }
    memset(p_cmd, '\0', sizeof(2048));
    if (af == AF_INET) {
        snprintf(p_cmd, 2047, "ip route add %s/%d %s",rt1, pref_len1, p_nh);
    } else {
        snprintf(p_cmd, 2047, "ip -6 route add %s/%d %s",rt1, pref_len1, p_nh);
    }
    printf("\r\n %s \r\n",p_cmd);
    (void)system(p_cmd);
    nht_config(nht1, af, 1);
    ret = nas_rt_nht_validate_util (nht1, num_nh_entries, rt1, pref_len1);
    nas_rt_nht_print_result ( "TC_9_1: multipath route for NHT", ret);
    if (is_prereq) {
        free(p_nh);
        free(p_cmd);
        return ret;
    }
    /* clean-up */
    nht_config(nht1, af, 0);
    for (cnt = 2; cnt <= (nh_cnt + 1); cnt++) {
        memset(&nh_ip, '\0', sizeof(nh_ip));

        if (af == AF_INET) {
            snprintf(nh_ip, NAS_UT_NH_STR_LEN-1, "%s%d", p_tr_mpath_intf1, cnt);
        } else {
            snprintf(nh_ip, NAS_UT_NH_STR_LEN-1, "%s%x", p_tr_mpath_intf1, cnt);
        }
        nht_del_static_arp(nh_ip, p_dut_intf1);
        if (af == AF_INET) {
            snprintf(nh_ip, NAS_UT_NH_STR_LEN-1, "%s%d", p_tr_mpath_intf2, cnt);
        } else {
            snprintf(nh_ip, NAS_UT_NH_STR_LEN-1, "%s%x", p_tr_mpath_intf2, cnt);
        }
        nht_del_static_arp(nh_ip, p_dut_intf2);
    }
    if (af == AF_INET) {
        snprintf(p_cmd, 2047, "ip route del %s/%d %s",rt1, pref_len1, p_nh);
    } else {
        snprintf(p_cmd, 2047, "ip -6 route del %s/%d %s",rt1, pref_len1, p_nh);
    }
    (void)system(p_cmd);

    nht_intf_admin_set(p_dut_intf1,0);
    nht_intf_admin_set(p_dut_intf1,1);
    nht_intf_admin_set(p_dut_intf2,0);
    nht_intf_admin_set(p_dut_intf2,1);
    free(p_nh);
    free(p_cmd);
    return ret;
}



TEST(std_nas_route_test, nas_nht_set_nh) {
    uint32_t vrf = 0, af = AF_INET;
    cps_api_object_t obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
              BASE_ROUTE_NH_TRACK_OBJ,cps_api_qualifier_TARGET);

    cps_api_set_key_data (obj, BASE_ROUTE_NH_TRACK_VRF_ID, cps_api_object_ATTR_T_U32,&vrf, sizeof(vrf));
    cps_api_set_key_data (obj, BASE_ROUTE_NH_TRACK_AF, cps_api_object_ATTR_T_U32,&af, sizeof(af));

    uint32_t ip;
    struct in_addr a;
    inet_aton("25.0.0.4",&a);
    ip=a.s_addr;

    cps_api_set_key_data (obj, BASE_ROUTE_NH_TRACK_DEST_ADDR, cps_api_object_ATTR_T_BIN,&ip, sizeof(ip));

    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_create(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
}

TEST(std_nas_route_test, nas_nht_delete_set_nh) {
    uint32_t vrf = 0, af = AF_INET;

    cps_api_object_t obj = cps_api_object_create();

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
              BASE_ROUTE_NH_TRACK_OBJ,cps_api_qualifier_TARGET);

    cps_api_set_key_data (obj, BASE_ROUTE_NH_TRACK_VRF_ID, cps_api_object_ATTR_T_U32,&vrf, sizeof(vrf));
    cps_api_set_key_data (obj, BASE_ROUTE_NH_TRACK_AF, cps_api_object_ATTR_T_U32,&af, sizeof(af));

    uint32_t ip;
    struct in_addr a;
    inet_aton("25.0.0.4",&a);
    ip=a.s_addr;

    cps_api_set_key_data (obj, BASE_ROUTE_NH_TRACK_DEST_ADDR, cps_api_object_ATTR_T_BIN,&ip, sizeof(ip));

    /*
     * CPS transaction
     */
    cps_api_transaction_params_t tr;
    ASSERT_TRUE(cps_api_transaction_init(&tr)==cps_api_ret_code_OK);
    cps_api_delete(&tr,obj);
    ASSERT_TRUE(cps_api_commit(&tr)==cps_api_ret_code_OK);
    cps_api_transaction_close(&tr);
}

void nas_route_dump_nht_object_content(cps_api_object_t obj){
    char str[INET6_ADDRSTRLEN];
    uint32_t addr_len = 0, af_data = 0;
    uint32_t nhc = 0, nh_itr = 0;
    char if_name[IFNAMSIZ];

    cps_api_object_attr_t af_attr = cps_api_get_key_data(obj, BASE_ROUTE_NH_TRACK_AF);
    if (af_attr != CPS_API_ATTR_NULL) {
        af_data = cps_api_object_attr_data_u32(af_attr) ;
        std::cout<<"Address Family "<<((af_data == AF_INET) ? "IPv4" : "IPv6")<<std::endl;
        addr_len = ((af_data == AF_INET) ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN);
    }

    cps_api_object_attr_t dest_attr = cps_api_get_key_data(obj, BASE_ROUTE_NH_TRACK_DEST_ADDR);
    if (dest_attr != CPS_API_ATTR_NULL) {
        std::cout<<"Dest Address "<<inet_ntop(af_data,cps_api_object_attr_data_bin(dest_attr),str,addr_len)<<std::endl;
    }

    cps_api_object_attr_t vrf_attr = cps_api_get_key_data(obj, BASE_ROUTE_NH_TRACK_VRF_ID);
    if (vrf_attr != CPS_API_ATTR_NULL) {
        std::cout<<"VRF Id "<<cps_api_object_attr_data_u32(vrf_attr)<<std::endl;
    }

    cps_api_object_attr_t nh_count_attr = cps_api_object_attr_get(obj, BASE_ROUTE_NH_TRACK_NH_COUNT);
    if (nh_count_attr != CPS_API_ATTR_NULL) {
        nhc = cps_api_object_attr_data_u32(nh_count_attr);
        std::cout<<"NH Count "<<nhc<<std::endl;
    }

    if (nhc) {
        cps_api_object_attr_t nh_handle_attr = cps_api_object_attr_get(obj, BASE_ROUTE_NH_TRACK_DATA);
        if (nh_handle_attr != CPS_API_ATTR_NULL) {
            nas::ndi_obj_id_table_t nh_opaque_data_table;
            cps_api_attr_id_t  attr_id_list[] = {BASE_ROUTE_NH_TRACK_DATA};
            nas::ndi_obj_id_table_cps_unserialize (nh_opaque_data_table, obj, attr_id_list,
                                                   sizeof(attr_id_list)/sizeof(attr_id_list[0]));
            auto it = nh_opaque_data_table.begin();
            std::cout<<"NPU-id/NH-id:\t";
            std::cout<<it->first<<"/0x" <<std::hex<<it->second;
            std::cout << std::resetiosflags(std::ios_base::basefield) << '\n' << std::endl;
        }
    }

    for (nh_itr = 0; nh_itr < nhc; nh_itr++)
    {
        cps_api_attr_id_t ids[3] = { BASE_ROUTE_NH_TRACK_NH_INFO,
            0, BASE_ROUTE_NH_TRACK_NH_INFO_ADDRESS};
        const int ids_len = sizeof(ids)/sizeof(*ids);

        ids[1] = nh_itr;

        cps_api_object_attr_t attr = cps_api_object_e_get(obj,ids,ids_len);
        if (attr != CPS_API_ATTR_NULL)
            std::cout<<"NextHop IP "<<inet_ntop(af_data,cps_api_object_attr_data_bin(attr),str,addr_len)<<std::endl;

        ids[2] = BASE_ROUTE_NH_TRACK_NH_INFO_MAC_ADDR;
        attr = cps_api_object_e_get(obj,ids,ids_len);
        if (attr != CPS_API_ATTR_NULL)
        {
            char mt[6];
            char mstring[20];
            memcpy(mt, cps_api_object_attr_data_bin(attr), 6);
            snprintf(mstring, 19, "%x:%x:%x:%x:%x:%x", mt[0], mt[1], mt[2], mt[3], mt[4], mt[5]);
            std::cout<<"NextHop MAC "<<mstring<<std::endl;
        }

        ids[2] = BASE_ROUTE_NH_TRACK_NH_INFO_VRF_ID;
        attr = cps_api_object_e_get(obj,ids,ids_len);
        if (attr != CPS_API_ATTR_NULL)
            std::cout<<"NextHop vrf id "<<cps_api_object_attr_data_u32(attr)<<std::endl;

//      ids[2] = BASE_ROUTE_NH_TRACK_NH_INFO_AF;
//      attr = cps_api_object_e_get(obj,ids,ids_len);
//      if (attr != CPS_API_ATTR_NULL)
//          std::cout<<"NextHop Address family "<<cps_api_object_attr_data_u32(attr)<<std::endl;


        ids[2] = BASE_ROUTE_NH_TRACK_NH_INFO_IFINDEX;
        attr = cps_api_object_e_get(obj,ids,ids_len);
        if (attr != CPS_API_ATTR_NULL) {
            if_indextoname((int)cps_api_object_attr_data_u32(attr), if_name);
            std::cout<<"IfIndex "<<if_name<<"("<<cps_api_object_attr_data_u32(attr)<<")"<<std::endl;
        }

        ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_RESOLVED;
        attr = cps_api_object_e_get(obj,ids,ids_len);
        if (attr != CPS_API_ATTR_NULL)
            std::cout<<"Is Next Hop Resolved "<<cps_api_object_attr_data_u32(attr)<<std::endl;
    }
}

TEST(std_nas_route_test, nas_nht_get_specific) {
    struct in_addr a;
    uint32_t ip, af = AF_INET;
    cps_api_get_params_t gp;
    cps_api_get_request_init(&gp);

    inet_aton("30.1.1.2",&a);

    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),BASE_ROUTE_NH_TRACK_OBJ,
                                        cps_api_qualifier_TARGET);

    cps_api_set_key_data (obj, BASE_ROUTE_NH_TRACK_AF, cps_api_object_ATTR_T_U32,&af, sizeof(af));
    ip=a.s_addr;
    cps_api_set_key_data (obj, BASE_ROUTE_NH_TRACK_DEST_ADDR, cps_api_object_ATTR_T_BIN,&ip, sizeof(ip));

    if (cps_api_get(&gp)==cps_api_ret_code_OK) {
        size_t mx = cps_api_object_list_size(gp.list);

        for ( size_t ix = 0 ; ix < mx ; ++ix ) {
            obj = cps_api_object_list_get(gp.list,ix);
            std::cout<<"NAS NHT ENTRY"<<std::endl;
            std::cout<<"============="<<std::endl;
            nas_route_dump_nht_object_content(obj);
            std::cout<<std::endl;
        }
    }

    cps_api_get_request_close(&gp);

}

void nas_route_nht_get (uint32_t af){

    cps_api_get_params_t gp;
    cps_api_get_request_init(&gp);

    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),BASE_ROUTE_NH_TRACK_OBJ,
                                        cps_api_qualifier_TARGET);

    cps_api_set_key_data (obj, BASE_ROUTE_NH_TRACK_AF, cps_api_object_ATTR_T_U32,&af, sizeof(af));

    if (cps_api_get(&gp)==cps_api_ret_code_OK) {
        size_t mx = cps_api_object_list_size(gp.list);

        for ( size_t ix = 0 ; ix < mx ; ++ix ) {
            obj = cps_api_object_list_get(gp.list,ix);
            std::cout<<"NAS NHT ENTRY"<<std::endl;
            std::cout<<"============="<<std::endl;
            nas_route_dump_nht_object_content(obj);
            std::cout<<std::endl;
        }
    }

    cps_api_get_request_close(&gp);
}

TEST(std_nas_route_test, nas_nht_ipv4_get) {
    nas_route_nht_get (AF_INET);
}

TEST(std_nas_route_test, nas_nht_ipv6_get) {
    nas_route_nht_get (AF_INET6);
}

/* NHT UT test cases */
#ifdef NHT_UT_INDIVIDUAL_TESTS
TEST(std_nas_route_test, nas_nht_ut_1_1) {
    nas_rt_nht_ut_1_1(false);
}

TEST(std_nas_route_test, nas_nht_ut_1_2) {
    nas_rt_nht_ut_1_2(false);
}

TEST(std_nas_route_test, nas_nht_ut_1_3) {
    nas_rt_nht_ut_1_3(false);
}

TEST(std_nas_route_test, nas_nht_ut_1_4) {
    nas_rt_nht_ut_1_4(false);
}

TEST(std_nas_route_test, nas_nht_ut_1_5) {
    nas_rt_nht_ut_1_5(false);
}

TEST(std_nas_route_test, nas_nht_ut_1_6) {
    nas_rt_nht_ut_1_6(false);
}

TEST(std_nas_route_test, nas_nht_ut_1_7) {
    nas_rt_nht_ut_1_7(false);
}

TEST(std_nas_route_test, nas_nht_ut_1_8) {
    nas_rt_nht_ut_1_8(false);
}

TEST(std_nas_route_test, nas_nht_ut_2_1) {
    nas_rt_nht_ut_2_1(false);
}

TEST(std_nas_route_test, nas_nht_ut_2_2) {
    nas_rt_nht_ut_2_2(false);
}

TEST(std_nas_route_test, nas_nht_ut_2_3) {
    nas_rt_nht_ut_2_3(false);
}

TEST(std_nas_route_test, nas_nht_ut_2_4) {
    nas_rt_nht_ut_2_4(false);
}

TEST(std_nas_route_test, nas_nht_ut_2_5) {
    nas_rt_nht_ut_2_5(false);
}

TEST(std_nas_route_test, nas_nht_ut_2_6) {
    nas_rt_nht_ut_2_6(false);
}

TEST(std_nas_route_test, nas_nht_ut_2_7) {
    nas_rt_nht_ut_2_7(false);
}

TEST(std_nas_route_test, nas_nht_ut_3_1) {
    nas_rt_nht_ut_3_1(false);
}

TEST(std_nas_route_test, nas_nht_ut_3_2) {
    nas_rt_nht_ut_3_2(false);
}

TEST(std_nas_route_test, nas_nht_ut_3_3) {
    nas_rt_nht_ut_3_3(false);
}

TEST(std_nas_route_test, nas_nht_ut_4_1) {
    nas_rt_nht_ut_4_1(false);
}

TEST(std_nas_route_test, nas_nht_ut_4_2) {
    nas_rt_nht_ut_4_2(false);
}

TEST(std_nas_route_test, nas_nht_ut_4_3) {
    nas_rt_nht_ut_4_3(false);
}

TEST(std_nas_route_test, nas_nht_ut_4_4) {
    nas_rt_nht_ut_4_4(false);
}

TEST(std_nas_route_test, nas_nht_ut_4_5) {
    nas_rt_nht_ut_4_5(false);
}

TEST(std_nas_route_test, nas_nht_ut_5_1) {
    nas_rt_nht_ut_5_1(false);
}

TEST(std_nas_route_test, nas_nht_ut_5_2) {
    nas_rt_nht_ut_5_2(false);
}

TEST(std_nas_route_test, nas_nht_ut_6_1) {
    nas_rt_nht_ut_6_1(false);
}

TEST(std_nas_route_test, nas_nht_ut_6_2) {
    nas_rt_nht_ut_6_2(false);
}

TEST(std_nas_route_test, nas_nht_ut_8_1) {
    g_scaled_test = true;
    nas_rt_nht_ut_8_1(false);
    g_scaled_test = false;
}

TEST(std_nas_route_test, nas_nht_ut_8_2) {
    g_scaled_test = true;
    nas_rt_nht_ut_8_2(false);
    g_scaled_test = false;
}

TEST(std_nas_route_test, nas_nht_ut_9_1) {
    nas_rt_nht_ut_9_1(false);
}
#endif

void nas_rt_nht_route_info() {

    if (af == AF_INET) {
        (void)system("ip route show");
        (void)system("ip neigh show");
    } else {
        (void)system("ip -6 route show");
        (void)system("ip -6 neigh show");
    }
}

TEST(std_nas_route_test, nas_nht_ut) {
    int ret_ut_1_1 = 0;
    int ret_ut_1_2 = 0;
    int ret_ut_1_3 = 0;
    int ret_ut_1_4 = 0;
    int ret_ut_1_5 = 0;
    int ret_ut_1_6 = 0;
    int ret_ut_1_7 = 0;
    int ret_ut_1_8 = 0;
    int ret_ut_2_1 = 0;
    int ret_ut_2_2 = 0;
    int ret_ut_2_3 = 0;
    int ret_ut_2_4 = 0;
    int ret_ut_2_5 = 0;
    int ret_ut_2_6 = 0;
    int ret_ut_2_7 = 0;
    int ret_ut_3_1 = 0;
    int ret_ut_3_2 = 0;
    int ret_ut_3_3 = 0;
    int ret_ut_4_1 = 0;
    int ret_ut_4_2 = 0;
    int ret_ut_4_3 = 0;
    int ret_ut_4_4 = 0;
    int ret_ut_4_5 = 0;
    int ret_ut_5_1 = 0;
    int ret_ut_5_2 = 0;
    int ret_ut_5_3 = 0;
    int ret_ut_5_4 = 0;
    int ret_ut_6_1 = 0;
    int ret_ut_6_2 = 0;
    int ret_ut_8_1 = 0;
    int ret_ut_8_2 = 0;
    int ret_ut_9_1 = 0;

    ret_ut_1_1 = nas_rt_nht_ut_1_1(false);
    ret_ut_1_2 = nas_rt_nht_ut_1_2(false);
    ret_ut_1_3 = nas_rt_nht_ut_1_3(false);
    ret_ut_1_4 = nas_rt_nht_ut_1_4(false);
    ret_ut_1_5 = nas_rt_nht_ut_1_5(false);
    ret_ut_1_6 = nas_rt_nht_ut_1_6(false);
    ret_ut_1_7 = nas_rt_nht_ut_1_7(false);
    ret_ut_1_8 = nas_rt_nht_ut_1_8(false);
    nas_route_nht_get (af);

    ret_ut_2_1 = nas_rt_nht_ut_2_1(false);
    ret_ut_2_2 = nas_rt_nht_ut_2_2(false);
    ret_ut_2_3 = nas_rt_nht_ut_2_3(false);
    ret_ut_2_4 = nas_rt_nht_ut_2_4(false);
    ret_ut_2_5 = nas_rt_nht_ut_2_5(false);
    ret_ut_2_6 = nas_rt_nht_ut_2_6(false);
    ret_ut_2_7 = nas_rt_nht_ut_2_7(false);
    nas_route_nht_get (af);

    ret_ut_3_1 = nas_rt_nht_ut_3_1(false);
    ret_ut_3_2 = nas_rt_nht_ut_3_2(false);
    ret_ut_3_3 = nas_rt_nht_ut_3_3(false);
    nas_route_nht_get (af);

    ret_ut_4_1 = nas_rt_nht_ut_4_1(false);
    ret_ut_4_2 = nas_rt_nht_ut_4_2(false);
    ret_ut_4_3 = nas_rt_nht_ut_4_3(false);
    ret_ut_4_4 = nas_rt_nht_ut_4_4(false);
    ret_ut_4_5 = nas_rt_nht_ut_4_5(false);
    nas_route_nht_get (af);

    ret_ut_5_1 = nas_rt_nht_ut_5_1(false);
    ret_ut_5_2 = nas_rt_nht_ut_5_2(false);
    ret_ut_5_3 = nas_rt_nht_ut_5_3(false);
    ret_ut_5_4 = nas_rt_nht_ut_5_4(false);
    nas_route_nht_get (af);

    ret_ut_6_1 = nas_rt_nht_ut_6_1(false);
    ret_ut_6_2 = nas_rt_nht_ut_6_2(false);
    nas_route_nht_get (af);

    g_scaled_test = true;
    ret_ut_8_1 = nas_rt_nht_ut_8_1(false);
    ret_ut_8_2 = nas_rt_nht_ut_8_2(false);
    g_scaled_test = false;
    nas_route_nht_get (af);

    ret_ut_9_1 = nas_rt_nht_ut_9_1(false);
    nas_route_nht_get (af);

    printf ("\r\n Test Summary\r\n");
    printf ("\r ============\r\n");
    nas_rt_nht_print_result ( "TC_1_1", ret_ut_1_1);
    nas_rt_nht_print_result ( "TC_1_2", ret_ut_1_2);
    nas_rt_nht_print_result ( "TC_1_3", ret_ut_1_3);
    nas_rt_nht_print_result ( "TC_1_4", ret_ut_1_4);
    nas_rt_nht_print_result ( "TC_1_5", ret_ut_1_5);
    nas_rt_nht_print_result ( "TC_1_6", ret_ut_1_6);
    nas_rt_nht_print_result ( "TC_1_7", ret_ut_1_7);
    nas_rt_nht_print_result ( "TC_1_8", ret_ut_1_8);
    nas_rt_nht_print_result ( "TC_2_1", ret_ut_2_1);
    nas_rt_nht_print_result ( "TC_2_2", ret_ut_2_2);
    nas_rt_nht_print_result ( "TC_2_3", ret_ut_2_3);
    nas_rt_nht_print_result ( "TC_2_4", ret_ut_2_4);
    nas_rt_nht_print_result ( "TC_2_5", ret_ut_2_5);
    nas_rt_nht_print_result ( "TC_2_6", ret_ut_2_6);
    nas_rt_nht_print_result ( "TC_2_7", ret_ut_2_7);
    nas_rt_nht_print_result ( "TC_3_1", ret_ut_3_1);
    nas_rt_nht_print_result ( "TC_3_2", ret_ut_3_2);
    nas_rt_nht_print_result ( "TC_3_3", ret_ut_3_3);
    nas_rt_nht_print_result ( "TC_4_1", ret_ut_4_1);
    nas_rt_nht_print_result ( "TC_4_2", ret_ut_4_2);
    nas_rt_nht_print_result ( "TC_4_3", ret_ut_4_3);
    nas_rt_nht_print_result ( "TC_4_4", ret_ut_4_4);
    nas_rt_nht_print_result ( "TC_4_5", ret_ut_4_5);
    nas_rt_nht_print_result ( "TC_5_1", ret_ut_5_1);
    nas_rt_nht_print_result ( "TC_5_2", ret_ut_5_2);
    nas_rt_nht_print_result ( "TC_5_3", ret_ut_5_3);
    nas_rt_nht_print_result ( "TC_5_4", ret_ut_5_4);
    nas_rt_nht_print_result ( "TC_6_1", ret_ut_6_1);
    nas_rt_nht_print_result ( "TC_6_2", ret_ut_6_2);
    nas_rt_nht_print_result ( "TC_8_1", ret_ut_8_1);
    nas_rt_nht_print_result ( "TC_8_2", ret_ut_8_2);
    nas_rt_nht_print_result ( "TC_9_1", ret_ut_9_1);
}


int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  /* Topology pre-requisite.
   * Configure ports p_dut_intf1 & p_dut_intf2 in DUT with IP address.
   * Configure ports p_tr_intf1 & p_tr_intf2 in TR with all primary & secondary address.
   */

  printf("___________________________________________\n");
  /* Incase of premium package, all the ports are part of default bridge,
   * remove it from the bridge to operate as the router intf. */

  char cmd[512];
  memset(cmd, '\0', sizeof(cmd));
  snprintf(cmd, 511, "brctl delif br1 %s",p_dut_intf1);
  (void)system(cmd);
  snprintf(cmd, 511, "brctl delif br1 %s",p_dut_intf2);
  (void)system(cmd);
  memset(cmd, '\0', sizeof(cmd));
  printf("\r\n argv[0]:%s argv[1]:%s argv[2]:%s\r\n", argv[0], argv[1], argv[2]);
  if ((argv[1] == NULL) || (strncmp(argv[1], "ipv4",4) == 0)){
      /* Default execution mode is IPv4 */
      printf("\r\n NHT for af-IPv4 execution started! \r\n");
      snprintf(cmd, 511, "ifconfig %s %s/16 up",p_dut_intf1, p_dut_ip_intf1);
      (void)system(cmd);
      snprintf(cmd, 511, "ifconfig %s %s/16 up",p_dut_intf2, p_dut_ip_intf2);
      (void)system(cmd);
  } else if ((argv[1]) && (strncmp(argv[1], "ipv6",4) == 0)) {
      printf("\r\n NHT for af-IPv6 execution started! \r\n");
      p_dut_ip_intf1 = p_dut_ip6_intf1; p_dut_ip_intf2 = p_dut_ip6_intf2;
      p_tr_ip_intf1  = p_tr_ip6_intf1; p_tr_ip_intf2 = p_tr_ip6_intf2;
      p_tr_ip2_intf1 = p_tr_ip6_2_intf1; p_tr_ip3_intf1 = p_tr_ip6_3_intf1;
      p_tr_ip2_intf2 = p_tr_ip6_2_intf2; p_tr_ip3_intf2 = p_tr_ip6_3_intf2;
      nht1 = nht6_1; nht2 = nht6_2; nht3 = nht6_3; nht4 = nht6_4; nht5 = nht6_5; nht6 = nht6_6;
      rt1 = rt6_1; rt2 = rt6_2; rt3 = rt6_3; rt4 = rt6_4; rt5 = rt6_5;
      pref_len1 = pref_len6_1; pref_len2 = pref_len6_2; pref_len3 = pref_len6_3;
      pref_len4 = pref_len6_4; p_tr_mpath_intf1 = p_tr_mpath_ip6_intf1; p_tr_mpath_intf2 = p_tr_mpath_ip6_intf2;
      af = af6;
      snprintf(cmd, 511, "ifconfig %s inet6 add %s/64 up",p_dut_intf1, p_dut_ip_intf1);
      (void)system(cmd);
      snprintf(cmd, 511, "ifconfig %s inet6 add %s/64 up",p_dut_intf2, p_dut_ip_intf2);
      (void)system(cmd);
  }
  printf("___________________________________________\n");

  /* Please update journal settings to disable log suppression/rate-limiting
   * so that the required logs are logged correctly.
   * Edit /etc/systemd/journald.conf for following settings to
   * disable rate-limiting and restart journal service
   * #RateLimitInterval=30s   ==> RateLimitInterval=0s
   * #RateLimitInterval=30s      ==> RateLimitBurst=0
   * SystemMaxUse=50M         ==> SystemMaxUse=250M
   */
  (void)system("sed -i '/SystemMaxUse=50M/c SystemMaxUse=250M' /etc/systemd/journald.conf");
  (void)system("sed -i '/#RateLimitInterval=30s/c RateLimitInterval=0s' /etc/systemd/journald.conf");
  (void)system("sed -i '/#RateLimitBurst=1000/c RateLimitBurst=0' /etc/systemd/journald.conf");
  (void)system("service systemd-journald restart");

  (void)system("os10-logging enable ROUTE INFO");
  (void)system("kill -USR1 `pidof base_nas`");

  if (RUN_ALL_TESTS())
  {
    printf ("\r\n Test Failed\r\n");
  }

  printf ("\r\n !!! Test Completed !!! \r\n");

  /* revert back logging related changes done for executing the UT */
  (void)system("os10-logging disable ROUTE INFO");
  (void)system("kill -USR1 `pidof base_nas`");

  (void)system("sed -i '/SystemMaxUse=250M/c SystemMaxUse=50M' /etc/systemd/journald.conf");
  (void)system("sed -i '/RateLimitInterval=0s/c #RateLimitInterval=30s' /etc/systemd/journald.conf");
  (void)system("sed -i '/RateLimitBurst=0/c #RateLimitBurst=1000' /etc/systemd/journald.conf");
  (void)system("service systemd-journald restart");
  return 0;
}
