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
#include "vrf-mgmt.h"

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <iostream>
#include "sys/time.h"
#include "math.h"

/* NOTE: Change the back to back connected ports here based on availability in the node, also,
 * if we are running this test in Enterprise package, make sure "no switchport" command is executed in CLI
 * on these two ports before running the script. */
static const char *b2b_intf1 = "e101-030-2";
static const char *b2b_intf2 = "e101-030-3";
static const char *DoD_b2b_intf1 = "1/1/30:2";
static const char *DoD_b2b_intf2 = "1/1/30:3";

static const char *b2b_leak_intf1 = "e101-001-0";
static const char *b2b_leak_vrf_intf1 = "v-e101-001-0";
static const char *DoD_b2b_leak_intf1 = "1/1/1";

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

        fclose(fp);
    }
}

static void nas_vrf_ip_config(bool is_add) {
    int ret = system("os10-show-version | grep \"OS_NAME.*Enterprise\"");
    if (ret == 0) {
        FILE *fp;

        fp = fopen("/tmp/test_pre_req","w");
        fprintf(fp, "configure terminal\n");
        fprintf(fp, "interface ethernet %s\n", DoD_b2b_intf1);
        if (is_add) {
            fprintf(fp, "ip address 30.0.0.1/16\n");
            fprintf(fp, "ipv6 address 3333::1/64\n");
        } else {
            fprintf(fp, "no ip address\n");
            fprintf(fp, "no ipv6 address\n");
        }
        fprintf(fp, "exit\n");
        fflush(fp);
        system("sudo -u admin clish --b /tmp/test_pre_req");

        fclose(fp);
    }
}


static void nas_rt_dump_nht_object_content(cps_api_object_t obj){
    char str[INET6_ADDRSTRLEN];
    uint32_t addr_len = 0, af_data = 0;
    uint32_t nhc = 0, nh_itr = 0;

    const char *vrf_name = (const char *)cps_api_object_get_data(obj, BASE_ROUTE_NH_TRACK_VRF_NAME);
    if (vrf_name) {
        std::cout<<"VRF name "<<vrf_name<<std::endl;
    }
    const char *nh_vrf_name = (const char *)cps_api_object_get_data(obj, BASE_ROUTE_NH_TRACK_NH_INFO_VRF_NAME);
    if (nh_vrf_name) {
        std::cout<<"NH VRF name "<<nh_vrf_name<<std::endl;
    }
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

    cps_api_object_attr_t nh_count_attr = cps_api_object_attr_get(obj, BASE_ROUTE_NH_TRACK_NH_COUNT);
    if (nh_count_attr != CPS_API_ATTR_NULL) {
        nhc = cps_api_object_attr_data_u32(nh_count_attr);
        std::cout<<"NH Count "<<nhc<<std::endl;
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

//      ids[2] = BASE_ROUTE_NH_TRACK_NH_INFO_AF;
//      attr = cps_api_object_e_get(obj,ids,ids_len);
//      if (attr != CPS_API_ATTR_NULL)
//          std::cout<<"NextHop Address family "<<cps_api_object_attr_data_u32(attr)<<std::endl;


        ids[2] = BASE_ROUTE_NH_TRACK_NH_INFO_IFINDEX;
        attr = cps_api_object_e_get(obj,ids,ids_len);
        if (attr != CPS_API_ATTR_NULL) {
            std::cout<<"IfIndex:" <<cps_api_object_attr_data_u32(attr)<<std::endl;
        }

        ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_RESOLVED;
        attr = cps_api_object_e_get(obj,ids,ids_len);
        if (attr != CPS_API_ATTR_NULL)
            std::cout<<"Is Next Hop Resolved "<<cps_api_object_attr_data_u32(attr)<<std::endl;
    }
}

static cps_api_return_code_t nas_rt_nht_validate(const char *vrf_name, const char *ip_str, uint32_t af_family, bool is_resolved) {
    cps_api_get_params_t gp;
    cps_api_get_request_init(&gp);

    cps_api_return_code_t rc = cps_api_ret_code_ERR;
    struct in_addr a;
    struct in6_addr a6;

    if (af_family == AF_INET6) {
        inet_pton(AF_INET6, ip_str, &a6);
    } else {
        inet_aton(ip_str,&a);
    }

    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),BASE_ROUTE_NH_TRACK_OBJ,
                                    cps_api_qualifier_TARGET);

    cps_api_object_attr_add(obj, BASE_ROUTE_NH_TRACK_VRF_NAME, vrf_name, strlen(vrf_name) + 1);

    cps_api_set_key_data (obj, BASE_ROUTE_NH_TRACK_AF, cps_api_object_ATTR_T_U32,&af_family, sizeof(af_family));
    if (af_family == AF_INET6) {
        cps_api_set_key_data (obj, BASE_ROUTE_NH_TRACK_DEST_ADDR, cps_api_object_ATTR_T_BIN,&a6, sizeof(a6));
    } else {
        cps_api_set_key_data (obj, BASE_ROUTE_NH_TRACK_DEST_ADDR, cps_api_object_ATTR_T_BIN,&a, sizeof(a));
    }

    if (cps_api_get(&gp)==cps_api_ret_code_OK) {
        size_t mx = cps_api_object_list_size(gp.list);
        for ( size_t ix = 0 ; ix < mx ; ++ix ) {
            rc = cps_api_ret_code_OK;
            obj = cps_api_object_list_get(gp.list,ix);
            std::cout<<"NAS NHT ENTRY"<<std::endl;
            std::cout<<"============="<<std::endl;
            nas_rt_dump_nht_object_content(obj);
            std::cout<<std::endl;

            cps_api_object_attr_t nh_count_attr = cps_api_object_attr_get(obj, BASE_ROUTE_NH_TRACK_NH_COUNT);
            if (nh_count_attr != CPS_API_ATTR_NULL) {
                uint32_t nhc = cps_api_object_attr_data_u32(nh_count_attr);
                if ((nhc && (is_resolved == false)) || (nhc == 0 && is_resolved)) {
                    std::cout<<"NAS NHT Error - NHC:"<<nhc<<"resolved:"<<is_resolved<<std::endl;
                    rc = cps_api_ret_code_ERR;
                    break;
                }
            } else if (is_resolved) {
                std::cout<<"NAS NHT Error nh_count is not present"<<std::endl;
                rc = cps_api_ret_code_ERR;
                break;
            }
        }
    }
    cps_api_get_request_close(&gp);
    return rc;
}

static void nas_rt_nht_add_del(const char *vrf_name, void *nht_dest, uint32_t af_family, bool is_add)
{
    uint32_t ip;
    cps_api_transaction_params_t tr;

    cps_api_object_t obj = cps_api_object_create();
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_NH_TRACK_OBJ,cps_api_qualifier_TARGET);

    cps_api_object_attr_add(obj, BASE_ROUTE_NH_TRACK_VRF_NAME,
                            vrf_name, strlen(vrf_name) + 1);
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

static void nas_rt_nht_config(const char *vrf_name, const char *ip_str, uint32_t af_family, bool is_add)
{
    struct in_addr a;
    struct in6_addr a6;

    if (af_family == AF_INET6) {
        inet_pton(AF_INET6, ip_str, &a6);
        nas_rt_nht_add_del (vrf_name, (void *) &a6, af_family, is_add);
    } else {
        inet_aton(ip_str,&a);
        nas_rt_nht_add_del (vrf_name, (void *) &a, af_family, is_add);
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
        rc = nas_ut_validate_neigh_cfg(vrf, AF_INET, "100.0.0.2", 128, true, NULL);
        ASSERT_TRUE(rc == rc_check);
        rc = nas_ut_validate_rt_cfg (vrf, AF_INET, "60.0.0.0", 8, vrf, "", "", true);
        ASSERT_TRUE(rc == rc_check);
        rc = nas_ut_validate_rt_cfg (vrf, AF_INET6, "100::1", 128, vrf, "", "", false);
        ASSERT_TRUE(rc == rc_check);
        rc = nas_ut_validate_rt_cfg (vrf, AF_INET6, "100::0", 64, vrf, "", "", true);
        ASSERT_TRUE(rc == rc_check);
        rc = nas_ut_validate_neigh_cfg(vrf, AF_INET6, "100::2", 128, true, NULL);
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
                    snprintf(cmd, 511, "/usr/bin/cps_config_mac.py delete vlan %d port %s 00:11:22:33:44:%02x static", id, b2b_intf1, itr);
                    system(cmd);
                }
            }
            rc = nas_ut_intf_vrf_cfg(vrf,vlan,false);
            if (!fail_ok) {
                ASSERT_TRUE(rc == cps_api_ret_code_OK);
            }
            rc = nas_ut_vrf_cfg(vrf,false);
            if (!fail_ok) {
                ASSERT_TRUE(rc == cps_api_ret_code_OK);
            }

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
            rc = nas_ut_validate_neigh_cfg(vrf, AF_INET, ip, 128, true, NULL);
            ASSERT_TRUE(rc == rc_check);
            if (itr <= (scal_neigh_limit+1)) {
                memset(ip, '\0', sizeof(ip));
                snprintf(ip, sizeof(ip), "100::%x", itr);
                rc = nas_ut_validate_neigh_cfg(vrf, AF_INET6, ip, 128, true, NULL);
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

static bool nas_vrf_src_ip_config (bool is_add, const char * vrf_name, uint32_t af, const char * ip_addr)
{
    cps_api_transaction_params_t params;
    cps_api_object_t             obj;
    cps_api_key_t                keys;
    bool                         rc = true;

    do {
        if ((obj = cps_api_object_create()) == NULL) {
            rc = false;
            break;
        }
        cps_api_object_guard obj_g (obj);
        if (cps_api_transaction_init(&params) != cps_api_ret_code_OK) {
            rc = false;
            break;
        }
        cps_api_transaction_guard tgd(&params);
        cps_api_key_from_attr_with_qual(&keys, VRF_MGMT_SRC_IP_CONFIG_OBJ,
                                        cps_api_qualifier_TARGET);
        cps_api_object_set_key(obj, &keys);

        cps_api_object_attr_add(obj, VRF_MGMT_SRC_IP_CONFIG_INPUT_NI_NAME,
                                vrf_name, strlen(vrf_name) + 1);
        cps_api_object_attr_add_u32(obj, VRF_MGMT_SRC_IP_CONFIG_INPUT_OPERATION,
                                    (is_add ? BASE_CMN_OPERATION_TYPE_CREATE : BASE_CMN_OPERATION_TYPE_DELETE));

        if (af == AF_INET) {
            cps_api_object_attr_add_u32(obj,VRF_MGMT_SRC_IP_CONFIG_INPUT_AF,AF_INET);

            uint32_t ip;
            struct in_addr a;
            inet_aton(ip_addr, &a);
            ip=a.s_addr;

            cps_api_object_attr_add(obj,VRF_MGMT_SRC_IP_CONFIG_INPUT_SRC_IP,&ip,sizeof(ip));
        } else if (af == AF_INET6) {
            cps_api_object_attr_add_u32(obj,VRF_MGMT_SRC_IP_CONFIG_INPUT_AF,AF_INET6);

            struct in6_addr a6;
            inet_pton(AF_INET6, ip_addr, &a6);

            cps_api_object_attr_add(obj,VRF_MGMT_SRC_IP_CONFIG_INPUT_SRC_IP,&a6,sizeof(struct in6_addr));
        }

        if (cps_api_action(&params, obj) != cps_api_ret_code_OK) {
            rc = false;
            break;
        }

        obj_g.release();

        if (cps_api_commit(&params) != cps_api_ret_code_OK) {
            rc = false;
            break;
        }

    } while (false);

    return rc;
}

static bool nas_vrf_neigh_flush (const char * vrf_name, uint32_t af, const char *if_name)
{
    cps_api_transaction_params_t params;
    cps_api_object_t             obj;
    cps_api_key_t                keys;
    bool                         rc = true;

    do {
        if ((obj = cps_api_object_create()) == NULL) {
            rc = false;
            break;
        }
        cps_api_object_guard obj_g (obj);
        if (cps_api_transaction_init(&params) != cps_api_ret_code_OK) {
            rc = false;
            break;
        }
        cps_api_transaction_guard tgd(&params);
        cps_api_key_from_attr_with_qual(&keys, BASE_ROUTE_NBR_FLUSH_OBJ,
                                        cps_api_qualifier_TARGET);
        cps_api_object_set_key(obj, &keys);

        cps_api_object_attr_add(obj, BASE_ROUTE_NBR_FLUSH_INPUT_VRF_NAME,
                                vrf_name, strlen(vrf_name) + 1);

        if (af == AF_INET) {
            cps_api_object_attr_add_u32(obj,BASE_ROUTE_NBR_FLUSH_INPUT_AF,AF_INET);
        } else if (af == AF_INET6) {
            cps_api_object_attr_add_u32(obj,BASE_ROUTE_NBR_FLUSH_INPUT_AF,AF_INET6);
        }

        if (if_name) {
            cps_api_object_attr_add(obj, BASE_ROUTE_NBR_FLUSH_INPUT_IFNAME,
                                    if_name, strlen(if_name) + 1);
        }

        if (cps_api_action(&params, obj) != cps_api_ret_code_OK) {
            rc = false;
            break;
        }

        obj_g.release();

        if (cps_api_commit(&params) != cps_api_ret_code_OK) {
            rc = false;
            break;
        }

    } while (false);

    return rc;
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

    rc = nas_ut_validate_neigh_cfg("default", 2, "30.0.0.2", 2, true, NULL);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_neigh_cfg("default", 10, "3333::2", 2, true, NULL);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_neigh_cfg("blue", 2, "30.0.0.1", 2, true, NULL);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_neigh_cfg("blue", 10, "3333::1", 2, true, NULL);
    ASSERT_TRUE(rc == rc_check);
}

void nas_rt_validate_red_vrf_config(cps_api_return_code_t rc_check) {
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

    rc = nas_ut_validate_neigh_cfg("red", 2, "30.0.0.2", 2, true, NULL);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_neigh_cfg("red", 10, "3333::2", 2, true, NULL);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_neigh_cfg("default", 2, "30.0.0.1", 2, true, NULL);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_neigh_cfg("default", 10, "3333::1", 2, true, NULL);
    ASSERT_TRUE(rc == rc_check);
}

void nas_rt_basic_red_vrf_vlan_cfg(bool is_add) {
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
    /* @@TODO Fix VLAN test case/
    nas_rt_basic_red_vrf_vlan_cfg(true);
    nas_rt_validate_red_vrf_config(cps_api_ret_code_OK);
    system("ip netns exec red ping -c 3 30.0.0.2");
    system("ip netns exec red ping6 -c 3 3333::2");
    system("ip netns exec red ping -c 3 50.0.0.1");
    system("ip netns exec red ping6 -c 3 5555::1");
    nas_rt_basic_red_vrf_vlan_cfg(false);
    nas_rt_validate_red_vrf_config(cps_api_ret_code_ERR);
    nas_rt_cleanup();
    */
    return;
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


static void nas_rt_validate_leak_from_default_vrf_parent_conn_rt(bool is_add) {
    cps_api_return_code_t rc, rc_check = (is_add ? cps_api_ret_code_OK : cps_api_ret_code_ERR);
    rc = nas_ut_validate_rt_cfg ("default", AF_INET, "20.0.0.0", 16, "default", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("default", AF_INET6, "20::", 64, "default", "", "", true);
    ASSERT_TRUE(rc == rc_check);
}

static void nas_rt_validate_leak_from_default_vrf_parent_reg_rt(bool is_add) {
    cps_api_return_code_t rc, rc_check = (is_add ? cps_api_ret_code_OK : cps_api_ret_code_ERR);
    rc = nas_ut_validate_rt_cfg ("default", AF_INET, "80.0.0.0", 16, "default", "20.0.0.2", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("default", AF_INET6, "80::", 64, "default", "20::2", "", true);
    ASSERT_TRUE(rc == rc_check);
}

static void nas_rt_validate_leak_from_default_vrf_leaked_rt_nh_ip(bool is_add) {
    cps_api_return_code_t rc, rc_check = (is_add ? cps_api_ret_code_OK : cps_api_ret_code_ERR);
    rc = nas_ut_validate_rt_cfg ("blue", AF_INET, "80.0.0.0", 16, "default", "20.0.0.2", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("blue", AF_INET6, "80::", 64, "default", "20::2", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("red", AF_INET, "80.0.0.0", 16, "default", "20.0.0.2", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("red", AF_INET6, "80::", 64, "default", "20::2", "", true);
    ASSERT_TRUE(rc == rc_check);
}

static void nas_rt_validate_leak_from_default_vrf_leaked_rt_nh_intf(bool is_add) {
    cps_api_return_code_t rc, rc_check = (is_add ? cps_api_ret_code_OK : cps_api_ret_code_ERR);

    rc = nas_ut_validate_rt_cfg ("blue", AF_INET, "20.0.0.0", 16, "default", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("blue", AF_INET6, "20::", 64, "default", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("red", AF_INET, "20.0.0.0", 16, "default", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("red", AF_INET6, "20::", 64, "default", "", "", true);
    ASSERT_TRUE(rc == rc_check);
}

static void nas_rt_validate_leak_from_default_vrf_leaked_rt_loopbk_intf(bool is_add) {
    cps_api_return_code_t rc, rc_check = (is_add ? cps_api_ret_code_OK : cps_api_ret_code_ERR);

    /* Loopback interface IPs */
    rc = nas_ut_validate_rt_cfg ("blue", AF_INET, "50.0.0.1", 32, "blue", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("blue", AF_INET6, "50::1", 128, "blue", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("red", AF_INET, "60.0.0.1", 32, "red", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("red", AF_INET6, "60::1", 128, "red", "", "", true);
    ASSERT_TRUE(rc == rc_check);

    /* Leak routes from blue and red VRFs to default */
    rc = nas_ut_validate_rt_cfg ("default", AF_INET, "50.0.0.1", 32, "blue", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("default", AF_INET6, "50::1", 128, "blue", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("default", AF_INET, "60.0.0.1", 32, "red", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("default", AF_INET6, "60::1", 128, "red", "", "", true);
    ASSERT_TRUE(rc == rc_check);
}

static void nas_rt_validate_leak_route_from_green_vrf(cps_api_return_code_t rc_check, cps_api_return_code_t leaked_rt_rc) {
    cps_api_return_code_t rc;
    sleep(5);
    rc = nas_ut_validate_rt_cfg ("green", AF_INET, "20.0.0.0", 16, "green", "", "", true);
    ASSERT_TRUE(rc == leaked_rt_rc);
    rc = nas_ut_validate_rt_cfg ("green", AF_INET6, "20::", 64, "green", "", "", true);
    ASSERT_TRUE(rc == leaked_rt_rc);
    rc = nas_ut_validate_rt_cfg ("green", AF_INET, "50.0.0.1", 32, "blue", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("green", AF_INET6, "50::1", 128, "blue", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("green", AF_INET, "60.0.0.1", 32, "red", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("green", AF_INET6, "60::1", 128, "red", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("green", AF_INET, "70.0.0.1", 32, "default", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("green", AF_INET6, "70::1", 128, "default", "", "", true);
    ASSERT_TRUE(rc == rc_check);

    rc = nas_ut_validate_rt_cfg ("blue", AF_INET, "20.0.0.0", 16, "green", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("blue", AF_INET6, "20::", 64, "green", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("blue", AF_INET, "50.0.0.1", 32, "blue", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("blue", AF_INET6, "50::1", 128, "blue", "", "", true);
    ASSERT_TRUE(rc == rc_check);

    rc = nas_ut_validate_rt_cfg ("red", AF_INET, "20.0.0.0", 16, "green", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("red", AF_INET6, "20::", 64, "green", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("red", AF_INET, "60.0.0.1", 32, "red", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("red", AF_INET6, "60::1", 128, "red", "", "", true);
    ASSERT_TRUE(rc == rc_check);

    rc = nas_ut_validate_rt_cfg ("default", AF_INET, "20.0.0.0", 16, "green", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("default", AF_INET6, "20::", 64, "green", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("default", AF_INET, "70.0.0.1", 32, "default", "", "", true);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_rt_cfg ("default", AF_INET6, "70::1", 128, "default", "", "", true);
    ASSERT_TRUE(rc == rc_check);
}

static void nas_rt_ping_from_leak_vrfs_via_default_vrf(bool ping_should_work, const char *nh_vrf_name,
                                                       bool clean_up = false, bool parent_nbr_chk = true) {
    if (ping_should_work) {
        printf("\r\nVerify that ping to [20.0.0.2 and 20::2] (leaked n/w) from blue and red VRF via default/green VRF working\r\n");
    } else {
        printf("\r\nVerify that ping to [20.0.0.2 and 20::2] (leaked n/w) from blue and red VRF via default/green VRF NOT working\r\n");
    }
    printf("ip netns exec blue ping -c 3 20.0.0.2\r\n");
    int val = system("ip netns exec blue ping -c 3 20.0.0.2");
    if (ping_should_work && (val !=0)) {
        ASSERT_TRUE(0);
    } else if (!ping_should_work && (val == 0)) {
        ASSERT_TRUE(0);
    }
    printf("ip netns exec blue ping -c 3 20::2\r\n");
    val = system("ip netns exec blue ping -c 3 20::2");
    if (ping_should_work && (val !=0)) {
        ASSERT_TRUE(0);
    } else if (!ping_should_work && (val == 0)) {
        ASSERT_TRUE(0);
    }

    printf("ip netns exec red ping -c 3 20.0.0.2\r\n");
    val = system("ip netns exec red ping -c 3 20.0.0.2");
    if (ping_should_work && (val !=0)) {
        ASSERT_TRUE(0);
    } else if (!ping_should_work && (val == 0)) {
        ASSERT_TRUE(0);
    }

    printf("ip netns exec red ping -c 3 20::2\r\n");
    val = system("ip netns exec red ping -c 3 20::2");
    if (ping_should_work && (val !=0)) {
        ASSERT_TRUE(0);
    } else if (!ping_should_work && (val == 0)) {
        ASSERT_TRUE(0);
    }


    printf("ip netns exec blue ping -c 3 80.0.0.2\r\n");
    val = system("ip netns exec blue ping -c 3 80.0.0.2");
    if (ping_should_work && (val !=0)) {
        ASSERT_TRUE(0);
    } else if (!ping_should_work && (val == 0)) {
        ASSERT_TRUE(0);
    }
    printf("ip netns exec blue ping -c 3 80::2\r\n");
    val = system("ip netns exec blue ping -c 3 80::2");
    if (ping_should_work && (val !=0)) {
        ASSERT_TRUE(0);
    } else if (!ping_should_work && (val == 0)) {
        ASSERT_TRUE(0);
    }

    printf("ip netns exec red ping -c 3 80.0.0.2\r\n");
    val = system("ip netns exec red ping -c 3 80.0.0.2");
    if (ping_should_work && (val !=0)) {
        ASSERT_TRUE(0);
    } else if (!ping_should_work && (val == 0)) {
        ASSERT_TRUE(0);
    }

    printf("ip netns exec red ping -c 3 80::2\r\n");
    val = system("ip netns exec red ping -c 3 80::2");
    if (ping_should_work && (val !=0)) {
        ASSERT_TRUE(0);
    } else if (!ping_should_work && (val == 0)) {
        ASSERT_TRUE(0);
    }

    sleep(5);
    cps_api_return_code_t rc = cps_api_ret_code_OK, rc_check = cps_api_ret_code_OK;
    if (!ping_should_work) {
        rc_check = cps_api_ret_code_ERR;
    }

    if (parent_nbr_chk) {
        rc = nas_ut_validate_neigh_cfg(nh_vrf_name, AF_INET, "20.0.0.2", 2, ping_should_work, nh_vrf_name);
        ASSERT_TRUE(rc == rc_check);
        rc = nas_ut_validate_neigh_cfg(nh_vrf_name, AF_INET6, "20::2", 2, ping_should_work, nh_vrf_name);
        ASSERT_TRUE(rc == rc_check);
    } else {
        return;
    }
    rc = nas_ut_validate_neigh_cfg("blue", AF_INET, "20.0.0.2", 2, ping_should_work, nh_vrf_name);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_neigh_cfg("red", AF_INET, "20.0.0.2", 2, ping_should_work, nh_vrf_name);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_neigh_cfg("blue", AF_INET6, "20::2", 2, ping_should_work, nh_vrf_name);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_neigh_cfg("red", AF_INET6, "20::2", 2, ping_should_work, nh_vrf_name);
    ASSERT_TRUE(rc == rc_check);

    cps_api_return_code_t nht_rc = cps_api_ret_code_OK;

    if (clean_up) {
        nht_rc = cps_api_ret_code_ERR;
    }
    rc = nas_rt_nht_validate("blue", "20.0.0.2", 2, ping_should_work);
    ASSERT_TRUE(rc == nht_rc);
    rc = nas_rt_nht_validate("blue", "20::2", 10, ping_should_work);
    ASSERT_TRUE(rc == nht_rc);
    rc = nas_rt_nht_validate("red", "20.0.0.2", 2, ping_should_work);
    ASSERT_TRUE(rc == nht_rc);
    rc = nas_rt_nht_validate("red", "20::2", 10, ping_should_work);
    ASSERT_TRUE(rc == nht_rc);

    if (parent_nbr_chk) {
        rc = nas_rt_nht_validate(nh_vrf_name, "20.0.0.2", 2, ping_should_work);
        ASSERT_TRUE(rc == nht_rc);
        rc = nas_rt_nht_validate(nh_vrf_name, "20::2", 10, ping_should_work);
        ASSERT_TRUE(rc == nht_rc);

        rc = nas_rt_nht_validate("blue", "80.0.0.2", 2, ping_should_work);
        ASSERT_TRUE(rc == nht_rc);
        rc = nas_rt_nht_validate("blue", "80::2", 10, ping_should_work);
        ASSERT_TRUE(rc == nht_rc);
        rc = nas_rt_nht_validate("red", "80.0.0.2", 2, ping_should_work);
        ASSERT_TRUE(rc == nht_rc);
        rc = nas_rt_nht_validate("red", "80::2", 10, ping_should_work);
        ASSERT_TRUE(rc == nht_rc);
    }
}

static void nas_rt_ping_from_leak_vrfs_via_default_vrf_ext(bool ping_should_work, const char *nh_vrf_name,
                                                           bool leak_neigh_should_present = true) {
    if (ping_should_work) {
        printf("\r\nVerify that ping to [20.0.0.2 and 20::2] (leaked n/w) from blue and red VRF via default/green VRF working\r\n");
    } else {
        printf("\r\nVerify that ping to [20.0.0.2 and 20::2] (leaked n/w) from blue and red VRF via default/green VRF NOT working\r\n");
    }
    printf("ip netns exec blue ping -c 3 20.0.0.2\r\n");
    int val = system("ip netns exec blue ping -c 3 20.0.0.2");
    if (ping_should_work && (val !=0)) {
        ASSERT_TRUE(0);
    } else if (!ping_should_work && (val == 0)) {
        ASSERT_TRUE(0);
    }
    printf("ip netns exec blue ping -c 3 20::2\r\n");
    val = system("ip netns exec blue ping -c 3 20::2");
    if (ping_should_work && (val !=0)) {
        ASSERT_TRUE(0);
    } else if (!ping_should_work && (val == 0)) {
        ASSERT_TRUE(0);
    }

    printf("ip netns exec red ping -c 3 20.0.0.2\r\n");
    val = system("ip netns exec red ping -c 3 20.0.0.2");
    if (ping_should_work && (val !=0)) {
        ASSERT_TRUE(0);
    } else if (!ping_should_work && (val == 0)) {
        ASSERT_TRUE(0);
    }

    printf("ip netns exec red ping -c 3 20::2\r\n");
    val = system("ip netns exec red ping -c 3 20::2");
    if (ping_should_work && (val !=0)) {
        ASSERT_TRUE(0);
    } else if (!ping_should_work && (val == 0)) {
        ASSERT_TRUE(0);
    }


    printf("ip netns exec blue ping -c 3 80.0.0.2\r\n");
    val = system("ip netns exec blue ping -c 3 80.0.0.2");
    if (ping_should_work && (val !=0)) {
        ASSERT_TRUE(0);
    } else if (!ping_should_work && (val == 0)) {
        ASSERT_TRUE(0);
    }
    printf("ip netns exec blue ping -c 3 80::2\r\n");
    val = system("ip netns exec blue ping -c 3 80::2");
    if (ping_should_work && (val !=0)) {
        ASSERT_TRUE(0);
    } else if (!ping_should_work && (val == 0)) {
        ASSERT_TRUE(0);
    }

    printf("ip netns exec red ping -c 3 80.0.0.2\r\n");
    val = system("ip netns exec red ping -c 3 80.0.0.2");
    if (ping_should_work && (val !=0)) {
        ASSERT_TRUE(0);
    } else if (!ping_should_work && (val == 0)) {
        ASSERT_TRUE(0);
    }

    printf("ip netns exec red ping -c 3 80::2\r\n");
    val = system("ip netns exec red ping -c 3 80::2");
    if (ping_should_work && (val !=0)) {
        ASSERT_TRUE(0);
    } else if (!ping_should_work && (val == 0)) {
        ASSERT_TRUE(0);
    }

    sleep(5);
    cps_api_return_code_t rc = cps_api_ret_code_OK, rc_check = cps_api_ret_code_OK;
    if (!ping_should_work) {
        rc_check = cps_api_ret_code_ERR;
    }
    rc = nas_ut_validate_neigh_cfg(nh_vrf_name, AF_INET, "20.0.0.2", 2, ping_should_work, nh_vrf_name);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    rc = nas_ut_validate_neigh_cfg(nh_vrf_name, AF_INET6, "20::2", 2, ping_should_work, nh_vrf_name);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    if (leak_neigh_should_present == false) {
        rc_check = cps_api_ret_code_ERR;
    }
    rc = nas_ut_validate_neigh_cfg("blue", AF_INET, "20.0.0.2", 2, ping_should_work, nh_vrf_name);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_neigh_cfg("red", AF_INET, "20.0.0.2", 2, ping_should_work, nh_vrf_name);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_neigh_cfg("blue", AF_INET6, "20::2", 2, ping_should_work, nh_vrf_name);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_neigh_cfg("red", AF_INET6, "20::2", 2, ping_should_work, nh_vrf_name);
    ASSERT_TRUE(rc == rc_check);

    cps_api_return_code_t nht_rc = cps_api_ret_code_OK;
    rc = nas_rt_nht_validate(nh_vrf_name, "20.0.0.2", 2, true);
    ASSERT_TRUE(rc == nht_rc);
    rc = nas_rt_nht_validate(nh_vrf_name, "20::2", 10, true);
    ASSERT_TRUE(rc == nht_rc);

    rc = nas_rt_nht_validate("blue", "20.0.0.2", 2, leak_neigh_should_present);
    ASSERT_TRUE(rc == nht_rc);
    rc = nas_rt_nht_validate("blue", "20::2", 10, leak_neigh_should_present);
    ASSERT_TRUE(rc == nht_rc);
    rc = nas_rt_nht_validate("red", "20.0.0.2", 2, leak_neigh_should_present);
    ASSERT_TRUE(rc == nht_rc);
    rc = nas_rt_nht_validate("red", "20::2", 10, leak_neigh_should_present);
    ASSERT_TRUE(rc == nht_rc);

    rc = nas_rt_nht_validate("blue", "80.0.0.2", 2, ping_should_work);
    ASSERT_TRUE(rc == nht_rc);
    rc = nas_rt_nht_validate("blue", "80::2", 10, ping_should_work);
    ASSERT_TRUE(rc == nht_rc);
    rc = nas_rt_nht_validate("red", "80.0.0.2", 2, ping_should_work);
    ASSERT_TRUE(rc == nht_rc);
    rc = nas_rt_nht_validate("red", "80::2", 10, ping_should_work);
    ASSERT_TRUE(rc == nht_rc);
}

static void nas_rt_ping_from_leak_vrfs_via_green_vrf(bool ping_should_work, const char *nh_vrf_name, bool clean_up = false) {
    if (ping_should_work) {
        printf("\r\nVerify that ping to [20.0.0.2 and 20::2] (leaked n/w) from blue, red and default VRF via green VRF working\r\n");
    } else {
        printf("\r\nVerify that ping to [20.0.0.2 and 20::2] (leaked n/w) from blue, red and default VRF via green VRF NOT working\r\n");
    }
    printf("ip netns exec blue ping -c 3 20.0.0.2\r\n");
    int val = system("ip netns exec blue ping -c 3 20.0.0.2");
    if (ping_should_work && (val !=0)) {
        ASSERT_TRUE(0);
    } else if (!ping_should_work && (val == 0)) {
        ASSERT_TRUE(0);
    }
    printf("ip netns exec blue ping -c 3 20::2\r\n");
    val = system("ip netns exec blue ping -c 3 20::2");
    if (ping_should_work && (val !=0)) {
        ASSERT_TRUE(0);
    } else if (!ping_should_work && (val == 0)) {
        ASSERT_TRUE(0);
    }

    printf("ip netns exec red ping -c 3 20.0.0.2\r\n");
    val = system("ip netns exec red ping -c 3 20.0.0.2");
    if (ping_should_work && (val !=0)) {
        ASSERT_TRUE(0);
    } else if (!ping_should_work && (val == 0)) {
        ASSERT_TRUE(0);
    }

    printf("ip netns exec red ping -c 3 20::2\r\n");
    val = system("ip netns exec red ping -c 3 20::2");
    if (ping_should_work && (val !=0)) {
        ASSERT_TRUE(0);
    } else if (!ping_should_work && (val == 0)) {
        ASSERT_TRUE(0);
    }

    printf("ping -c 3 20.0.0.2\r\n");
    val = system("ping -c 3 20.0.0.2");
    if (ping_should_work && (val !=0)) {
        ASSERT_TRUE(0);
    } else if (!ping_should_work && (val == 0)) {
        ASSERT_TRUE(0);
    }

    printf("ping -c 3 20::2\r\n");
    val = system("ping -c 3 20::2");
    if (ping_should_work && (val !=0)) {
        ASSERT_TRUE(0);
    } else if (!ping_should_work && (val == 0)) {
        ASSERT_TRUE(0);
    }
    cps_api_return_code_t rc = cps_api_ret_code_OK, rc_check = cps_api_ret_code_OK;
    if (!ping_should_work) {
        rc_check = cps_api_ret_code_ERR;
    }
    sleep(5);
    rc = nas_ut_validate_neigh_cfg("blue", AF_INET, "20.0.0.2", 2, ping_should_work, nh_vrf_name);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_neigh_cfg("red", AF_INET, "20.0.0.2", 2, ping_should_work, nh_vrf_name);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_neigh_cfg("blue", AF_INET6, "20::2", 2, ping_should_work, nh_vrf_name);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_neigh_cfg("red", AF_INET6, "20::2", 2, ping_should_work, nh_vrf_name);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_neigh_cfg(nh_vrf_name, AF_INET, "20.0.0.2", 2, ping_should_work, nh_vrf_name);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_neigh_cfg(nh_vrf_name, AF_INET6, "20::2", 2, ping_should_work, nh_vrf_name);
    ASSERT_TRUE(rc == rc_check);

    rc = nas_ut_validate_neigh_cfg("default", AF_INET, "20.0.0.2", 2, ping_should_work, nh_vrf_name);
    ASSERT_TRUE(rc == rc_check);
    rc = nas_ut_validate_neigh_cfg("default", AF_INET6, "20::2", 2, ping_should_work, nh_vrf_name);
    ASSERT_TRUE(rc == rc_check);
    cps_api_return_code_t nht_rc = cps_api_ret_code_OK;

    if (clean_up) {
        nht_rc = cps_api_ret_code_ERR;
    }
    rc = nas_rt_nht_validate(nh_vrf_name, "20.0.0.2", 2, ping_should_work);
    ASSERT_TRUE(rc == nht_rc);
    rc = nas_rt_nht_validate(nh_vrf_name, "20::2", 10, ping_should_work);
    ASSERT_TRUE(rc == nht_rc);
    rc = nas_rt_nht_validate("blue", "20.0.0.2", 2, ping_should_work);
    ASSERT_TRUE(rc == nht_rc);
    rc = nas_rt_nht_validate("blue", "20::2", 10, ping_should_work);
    ASSERT_TRUE(rc == nht_rc);
    rc = nas_rt_nht_validate("red", "20.0.0.2", 2, ping_should_work);
    ASSERT_TRUE(rc == nht_rc);
    rc = nas_rt_nht_validate("red", "20::2", 10, ping_should_work);
    ASSERT_TRUE(rc == nht_rc);
    rc = nas_rt_nht_validate("default", "20.0.0.2", 2, ping_should_work);
    ASSERT_TRUE(rc == nht_rc);
    rc = nas_rt_nht_validate("default", "20::2", 10, ping_should_work);
    ASSERT_TRUE(rc == nht_rc);
}

TEST(nas_rt_vrf_test, nas_rt_leak_intf_route_default_to_non_default_vrf) {
    cps_api_return_code_t rc;
    int ret = system("opx-show-version | grep \"OS_NAME.*Enterprise\"");
    if (ret != 0) {
        return;
    }
    FILE *fp;
    uint8_t iter = 2;

    while (iter--) {

        fp = fopen("/tmp/test_pre_req","w");
        fprintf(fp, "configure terminal\n");
        fprintf(fp, "ip vrf blue\n");
        fprintf(fp, "exit\n");
        fprintf(fp, "ip vrf red\n");
        fprintf(fp, "exit\n");
        fprintf(fp, "ip vrf green\n");
        fprintf(fp, "exit\n");
        fprintf(fp, "interface loopback 0\n");
        fprintf(fp, "no shutdown\n");
        fprintf(fp, "ip vrf forwarding blue\n");
        fprintf(fp, "ip address 50.0.0.1/32\n");
        fprintf(fp, "ipv6 address 50::1/128\n");
        fprintf(fp, "exit\n");
        fprintf(fp, "interface loopback 1\n");
        fprintf(fp, "no shutdown\n");
        fprintf(fp, "ip vrf forwarding red\n");
        fprintf(fp, "ip address 60.0.0.1/32\n");
        fprintf(fp, "ipv6 address 60::1/128\n");
        fprintf(fp, "exit\n");
        fprintf(fp, "interface loopback 3\n");
        fprintf(fp, "no shutdown\n");
        fprintf(fp, "ip vrf forwarding green\n");
        fprintf(fp, "ip address 70.0.0.1/32\n");
        fprintf(fp, "ipv6 address 70::1/128\n");
        fprintf(fp, "exit\n");
        fprintf(fp, "interface ethernet %s\n", DoD_b2b_leak_intf1);
        fprintf(fp, "no switchport\n");
        fprintf(fp, "ip address 20.0.0.1/16\n");
        fprintf(fp, "ipv6 address 20::1/64\n");
        fprintf(fp, "exit\n");
        fprintf(fp, "ip route 80.0.0.0/16 20.0.0.2\n");
        fprintf(fp, "ipv6 route 80::/64 20::2\n");
        fprintf(fp, "end\n");
        fflush(fp);
        system("sudo -u admin clish --b /tmp/test_pre_req");
        fclose(fp);

        printf("\r\n Step1 - Verify ping to 20.0.0.2 from default VRF\r\n");
        system("ping -c 3 20.0.0.2");

        sleep(2);
        rc = nas_ut_validate_neigh_cfg("default", AF_INET, "20.0.0.2", 2, true, "default");
        ASSERT_TRUE(rc == cps_api_ret_code_OK);

        nas_rt_nht_config("default", "20.0.0.2", 2, 1);
        nas_rt_nht_config("default", "20::2", 10, 1);
        nas_rt_nht_config("blue", "20.0.0.2", 2, 1);
        nas_rt_nht_config("blue", "20::2", 10, 1);
        nas_rt_nht_config("red", "20.0.0.2", 2, 1);
        nas_rt_nht_config("red", "20::2", 10, 1);
        nas_rt_nht_config("blue", "80.0.0.2", 2, 1);
        nas_rt_nht_config("blue", "80::2", 10, 1);
        nas_rt_nht_config("red", "80.0.0.2", 2, 1);
        nas_rt_nht_config("red", "80::2", 10, 1);
        nas_vrf_src_ip_config(1, "blue", 2, "50.0.0.1");
        nas_vrf_src_ip_config(1, "blue", 10, "50::1");
        printf("\r\nLeak the route 20.0.0.0/16 and 20::/64 from default VRF to blue and red VRFs\r\n");
        nas_ut_rt_cfg ("blue",1, "20.0.0.0", 16, AF_INET, "default", NULL, b2b_leak_intf1);
        nas_ut_rt_cfg ("blue",1, "20::", 64, AF_INET6, "default", NULL, b2b_leak_intf1);
        nas_ut_rt_cfg ("red",1, "20.0.0.0", 16, AF_INET, "default", NULL, b2b_leak_intf1);
        nas_ut_rt_cfg ("red",1, "20::", 64, AF_INET6, "default", NULL, b2b_leak_intf1);

        printf("\r\nLeak the route 80.0.0.0/16 and 80::/64 to reach via nexthop IP\r\n");
        nas_ut_rt_cfg ("blue",1, "80.0.0.0", 16, AF_INET, "default", "20.0.0.2", b2b_leak_intf1);
        nas_ut_rt_cfg ("blue",1, "80::", 64, AF_INET6, "default", "20::2", b2b_leak_intf1);
        nas_ut_rt_cfg ("red",1, "80.0.0.0", 16, AF_INET, "default", "20.0.0.2", b2b_leak_intf1);
        nas_ut_rt_cfg ("red",1, "80::", 64, AF_INET6, "default", "20::2", b2b_leak_intf1);

        nas_ut_rt_cfg ("blue",1, "0.0.0.0", 0, AF_INET, "default", "20.0.0.2", b2b_leak_intf1);
        nas_ut_rt_cfg ("blue",1, "::", 0, AF_INET6, "default", "20::2", b2b_leak_intf1);
        nas_ut_rt_cfg ("red",1, "0.0.0.0", 0, AF_INET, "default", "20.0.0.2", b2b_leak_intf1);
        nas_ut_rt_cfg ("red",1, "0::", 0, AF_INET6, "default", "20::2", b2b_leak_intf1);

        printf("Leak the route 50.0.0.1/32 50::1/128 from blue VRF to default VRF for return path reachability\r\n");
        nas_ut_rt_cfg ("default",1, "50.0.0.1", 32, AF_INET, "blue", NULL, "v-lo0");
        nas_ut_rt_cfg ("default",1, "50::1", 128, AF_INET6, "blue", NULL, "v-lo0");

        printf("Leak the route 60.0.0.1/32 60::1/128 from blue VRF to default VRF for return path reachability\r\n");
        nas_ut_rt_cfg ("default",1, "60.0.0.1", 32, AF_INET, "red", NULL, "v-lo1");
        nas_ut_rt_cfg ("default",1, "60::1", 128, AF_INET6, "red", NULL, "v-lo1");
        nas_vrf_src_ip_config(1, "red", 2, "60.0.0.1");
        nas_vrf_src_ip_config(1, "red", 10, "60::1");
        nas_vrf_src_ip_config(1, "green", 2, "70.0.0.1");
        nas_vrf_src_ip_config(1, "green", 10, "70::1");

        printf("\r\n Verify that ping is not affected after configuring the default route \r\n");

        sleep(5);
        nas_rt_validate_leak_from_default_vrf_parent_conn_rt(true);
        nas_rt_validate_leak_from_default_vrf_parent_reg_rt(true);
        nas_rt_validate_leak_from_default_vrf_leaked_rt_nh_ip(true);
        nas_rt_validate_leak_from_default_vrf_leaked_rt_nh_intf(true);
        nas_rt_validate_leak_from_default_vrf_leaked_rt_loopbk_intf (true);
        rc = nas_ut_validate_rt_cfg ("blue", AF_INET, "0.0.0.0", 0, "default", "20.0.0.2", "", true);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);
        rc = nas_ut_validate_rt_cfg ("blue", AF_INET6, "::", 0, "default", "20::2", "", true);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);
        rc = nas_ut_validate_rt_cfg ("red", AF_INET, "0.0.0.0", 0, "default", "20.0.0.2", "", true);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);
        rc = nas_ut_validate_rt_cfg ("red", AF_INET6, "::", 0, "default", "20::2", "", true);
        ASSERT_TRUE(rc == cps_api_ret_code_OK);
        nas_rt_ping_from_leak_vrfs_via_default_vrf(true, "default");

        nas_ut_rt_cfg ("blue",0, "20.0.0.0", 16, AF_INET, "default", NULL, b2b_leak_intf1);
        nas_ut_rt_cfg ("blue",0, "20::", 64, AF_INET6, "default", NULL, b2b_leak_intf1);
        nas_ut_rt_cfg ("red",0, "20.0.0.0", 16, AF_INET, "default", NULL, b2b_leak_intf1);
        nas_ut_rt_cfg ("red",0, "20::", 64, AF_INET6, "default", NULL, b2b_leak_intf1);

        nas_ut_rt_cfg ("blue",0, "80.0.0.0", 16, AF_INET, "default", "20.0.0.2", b2b_leak_intf1);
        nas_ut_rt_cfg ("blue",0, "80::", 64, AF_INET6, "default", "20::2", b2b_leak_intf1);
        nas_ut_rt_cfg ("red",0, "80.0.0.0", 16, AF_INET, "default", "20.0.0.2", b2b_leak_intf1);
        nas_ut_rt_cfg ("red",0, "80::", 64, AF_INET6, "default", "20::2", b2b_leak_intf1);
        printf("\r\nVerify that the ping is working with default route after deleting the exact route\r\n");
        nas_rt_ping_from_leak_vrfs_via_default_vrf_ext(true, "default", false);
        sleep(5);
        nas_rt_validate_leak_from_default_vrf_leaked_rt_nh_ip(false);
        nas_rt_validate_leak_from_default_vrf_leaked_rt_nh_intf(false);

        nas_ut_rt_cfg ("blue",0, "0.0.0.0", 0, AF_INET, "default", "20.0.0.2", b2b_leak_intf1);
        nas_ut_rt_cfg ("blue",0, "::", 0, AF_INET6, "default", "20::2", b2b_leak_intf1);
        nas_ut_rt_cfg ("red",0, "0.0.0.0", 0, AF_INET, "default", "20.0.0.2", b2b_leak_intf1);
        nas_ut_rt_cfg ("red",0, "0::", 0, AF_INET6, "default", "20::2", b2b_leak_intf1);
        sleep(2);
        rc = nas_ut_validate_rt_cfg ("blue", AF_INET, "0.0.0.0", 0, "default", "20.0.0.2", "", true);
        ASSERT_TRUE(rc == cps_api_ret_code_ERR);
        rc = nas_ut_validate_rt_cfg ("blue", AF_INET6, "::", 0, "default", "20::2", "", true);
        ASSERT_TRUE(rc == cps_api_ret_code_ERR);
        rc = nas_ut_validate_rt_cfg ("red", AF_INET, "0.0.0.0", 0, "default", "20.0.0.2", "", true);
        ASSERT_TRUE(rc == cps_api_ret_code_ERR);
        rc = nas_ut_validate_rt_cfg ("red", AF_INET6, "::", 0, "default", "20::2", "", true);
        ASSERT_TRUE(rc == cps_api_ret_code_ERR);
        printf("\r\n Verify that the ping is NOT working since default route is deleted!\r\n");
        nas_rt_ping_from_leak_vrfs_via_default_vrf_ext(false, "default", false);

        nas_ut_rt_cfg ("blue",1, "20.0.0.0", 16, AF_INET, "default", NULL, b2b_leak_intf1);
        nas_ut_rt_cfg ("blue",1, "20::", 64, AF_INET6, "default", NULL, b2b_leak_intf1);
        nas_ut_rt_cfg ("red",1, "20.0.0.0", 16, AF_INET, "default", NULL, b2b_leak_intf1);
        nas_ut_rt_cfg ("red",1, "20::", 64, AF_INET6, "default", NULL, b2b_leak_intf1);
        nas_ut_rt_cfg ("blue",1, "80.0.0.0", 16, AF_INET, "default", "20.0.0.2", b2b_leak_intf1);
        nas_ut_rt_cfg ("blue",1, "80::", 64, AF_INET6, "default", "20::2", b2b_leak_intf1);
        nas_ut_rt_cfg ("red",1, "80.0.0.0", 16, AF_INET, "default", "20.0.0.2", b2b_leak_intf1);
        nas_ut_rt_cfg ("red",1, "80::", 64, AF_INET6, "default", "20::2", b2b_leak_intf1);

        printf("\r\n Verify that the ping is working with exact route instead of default route \r\n");
        sleep(5);
        nas_rt_ping_from_leak_vrfs_via_default_vrf(true, "default");
        nas_rt_validate_leak_from_default_vrf_parent_conn_rt(true);
        nas_rt_validate_leak_from_default_vrf_parent_reg_rt(true);
        nas_rt_validate_leak_from_default_vrf_leaked_rt_nh_ip(true);
        nas_rt_validate_leak_from_default_vrf_leaked_rt_nh_intf(true);
        nas_rt_validate_leak_from_default_vrf_leaked_rt_loopbk_intf (true);

        if (iter != 0) {
            printf("Step 2 - Clear the neighbors in the parent VRF and check the ping from leaked VRFs\r\n");
            system("ip neigh del 20.0.0.2 dev e101-001-0");
            system("ip neigh del 20::2 dev e101-001-0");
            nas_rt_ping_from_leak_vrfs_via_default_vrf(true, "default");

            nas_vrf_neigh_flush("blue", AF_INET, NULL);
            nas_vrf_neigh_flush("blue", AF_INET6, NULL);
            nas_vrf_neigh_flush("red", AF_INET, b2b_leak_intf1);
            nas_vrf_neigh_flush("red", AF_INET6, b2b_leak_intf1);
            nas_rt_ping_from_leak_vrfs_via_default_vrf(true, "default");
            rc = nas_ut_validate_neigh_cfg("blue", AF_INET, "20.0.0.2", 2, true, "default");
            ASSERT_TRUE(rc == cps_api_ret_code_OK);
            rc = nas_ut_validate_neigh_cfg("red", AF_INET, "20.0.0.2", 2, true, "default");
            ASSERT_TRUE(rc == cps_api_ret_code_OK);
            rc = nas_ut_validate_neigh_cfg("blue", AF_INET6, "20::2", 2, true, "default");
            ASSERT_TRUE(rc == cps_api_ret_code_OK);
            rc = nas_ut_validate_neigh_cfg("red", AF_INET6, "20::2", 2, true, "default");
            ASSERT_TRUE(rc == cps_api_ret_code_OK);

            printf("Step 3 - Bring down the out interface in the parent VRF and check that ping is not working from leaked VRFs\r\n");
            fp = fopen("/tmp/test_pre_req","w");
            fprintf(fp, "configure terminal\n");
            fprintf(fp, "interface ethernet %s\n", DoD_b2b_leak_intf1);
            fprintf(fp, "shutdown\n");
            fprintf(fp, "end\n");
            fflush(fp);
            system("sudo -u admin clish --b /tmp/test_pre_req");
            fclose(fp);
            nas_rt_ping_from_leak_vrfs_via_default_vrf(false, "default");
            nas_rt_validate_leak_from_default_vrf_parent_conn_rt(false);
            nas_rt_validate_leak_from_default_vrf_parent_reg_rt(false);
            nas_rt_validate_leak_from_default_vrf_leaked_rt_nh_ip(false);
            nas_rt_validate_leak_from_default_vrf_leaked_rt_nh_intf(false);
            nas_rt_validate_leak_from_default_vrf_leaked_rt_loopbk_intf (true);
            printf("Step 4 - Bring up the out interface in the parent VRF and check that ping is working from leaked VRFs\r\n");
            fp = fopen("/tmp/test_pre_req","w");
            fprintf(fp, "configure terminal\n");
            fprintf(fp, "interface ethernet %s\n", DoD_b2b_leak_intf1);
            fprintf(fp, "no shutdown\n");
            fprintf(fp, "end\n");
            fflush(fp);
            system("sudo -u admin clish --b /tmp/test_pre_req");
            fclose(fp);

            printf("Step 3a Add the IP address on out interface in the parent VRF and check that ping is working from leaked VRFs\r\n");
            fp = fopen("/tmp/test_pre_req","w");
            fprintf(fp, "configure terminal\n");
            fprintf(fp, "interface ethernet %s\n", DoD_b2b_leak_intf1);
            fprintf(fp, "ip address 20.0.0.1/16\n");
            fprintf(fp, "ipv6 address 20::1/64\n");
            fprintf(fp, "end\n");
            fflush(fp);
            system("sudo -u admin clish --b /tmp/test_pre_req");
            fclose(fp);
            sleep(5);
            nas_rt_validate_leak_from_default_vrf_parent_conn_rt(true);
            nas_rt_validate_leak_from_default_vrf_parent_reg_rt(true);
            nas_rt_validate_leak_from_default_vrf_leaked_rt_nh_ip(false);
            nas_rt_validate_leak_from_default_vrf_leaked_rt_nh_intf(false);
            nas_rt_validate_leak_from_default_vrf_leaked_rt_loopbk_intf (true);
            printf("\r\nLeak the route 20.0.0.0/16 and 20::/64 from default VRF to blue and red VRFs\r\n");
            nas_ut_rt_cfg ("blue",1, "20.0.0.0", 16, AF_INET, "default", NULL, b2b_leak_intf1);
            nas_ut_rt_cfg ("blue",1, "20::", 64, AF_INET6, "default", NULL, b2b_leak_intf1);
            nas_ut_rt_cfg ("red",1, "20.0.0.0", 16, AF_INET, "default", NULL, b2b_leak_intf1);
            nas_ut_rt_cfg ("red",1, "20::", 64, AF_INET6, "default", NULL, b2b_leak_intf1);
            nas_ut_rt_cfg ("default",1, "80.0.0.0", 16, AF_INET, "default", "20.0.0.2", b2b_leak_intf1);
            nas_ut_rt_cfg ("default",1, "80::", 64, AF_INET6, "default", "20::2", b2b_leak_intf1);
            nas_ut_rt_cfg ("blue",1, "80.0.0.0", 16, AF_INET, "default", "20.0.0.2", b2b_leak_intf1);
            nas_ut_rt_cfg ("blue",1, "80::", 64, AF_INET6, "default", "20::2", b2b_leak_intf1);
            nas_ut_rt_cfg ("red",1, "80.0.0.0", 16, AF_INET, "default", "20.0.0.2", b2b_leak_intf1);
            nas_ut_rt_cfg ("red",1, "80::", 64, AF_INET6, "default", "20::2", b2b_leak_intf1);
            nas_rt_ping_from_leak_vrfs_via_default_vrf(true, "default");
            nas_rt_validate_leak_from_default_vrf_parent_conn_rt(true);
            nas_rt_validate_leak_from_default_vrf_parent_reg_rt(true);
            nas_rt_validate_leak_from_default_vrf_leaked_rt_nh_ip(true);
            nas_rt_validate_leak_from_default_vrf_leaked_rt_nh_intf(true);
            nas_rt_validate_leak_from_default_vrf_leaked_rt_loopbk_intf (true);

            printf("Step 5 - Remove the IP address from out interface in the parent VRF and check that ping is not working from leaked VRFs\r\n");
            fp = fopen("/tmp/test_pre_req","w");
            fprintf(fp, "configure terminal\n");
            fprintf(fp, "interface ethernet %s\n", DoD_b2b_leak_intf1);
            fprintf(fp, "no ip address\n");
            fprintf(fp, "no ipv6 address\n");
            fprintf(fp, "end\n");
            fflush(fp);
            system("sudo -u admin clish --b /tmp/test_pre_req");
            fclose(fp);
            /* @@TODO After IP address removal due to pro-active resolution, ARP is getting resolved even though
             * the connected route is not present, remove the last arg, once this issue is fixed. */
            //nas_rt_ping_from_leak_vrfs_via_default_vrf(false, "default", false, false);
            nas_rt_validate_leak_from_default_vrf_parent_conn_rt(false);
            nas_rt_validate_leak_from_default_vrf_parent_reg_rt(false);
            nas_rt_validate_leak_from_default_vrf_leaked_rt_nh_ip(true);
            nas_rt_validate_leak_from_default_vrf_leaked_rt_nh_intf(true);
            nas_rt_validate_leak_from_default_vrf_leaked_rt_loopbk_intf (true);

            printf("Step 6 - Add the IP address on out interface in the parent VRF and check that ping is working from leaked VRFs\r\n");
            fp = fopen("/tmp/test_pre_req","w");
            fprintf(fp, "configure terminal\n");
            fprintf(fp, "interface ethernet %s\n", DoD_b2b_leak_intf1);
            fprintf(fp, "ip address 20.0.0.1/16\n");
            fprintf(fp, "ipv6 address 20::1/64\n");
            fprintf(fp, "end\n");
            fflush(fp);
            system("sudo -u admin clish --b /tmp/test_pre_req");
            fclose(fp);
            nas_rt_ping_from_leak_vrfs_via_default_vrf(true, "default");
            nas_rt_validate_leak_from_default_vrf_parent_conn_rt(true);
            nas_rt_validate_leak_from_default_vrf_parent_reg_rt(true);
            nas_rt_validate_leak_from_default_vrf_leaked_rt_nh_ip(true);
            nas_rt_validate_leak_from_default_vrf_leaked_rt_nh_intf(true);
            nas_rt_validate_leak_from_default_vrf_leaked_rt_loopbk_intf (true);

            printf("Step 7 - Remove the IP address again from out interface in the parent VRF and check that ping is not working from leaked VRFs\r\n");
            fp = fopen("/tmp/test_pre_req","w");
            fprintf(fp, "configure terminal\n");
            fprintf(fp, "interface ethernet %s\n", DoD_b2b_leak_intf1);
            fprintf(fp, "no ip address\n");
            fprintf(fp, "no ipv6 address\n");
            fprintf(fp, "end\n");
            fflush(fp);
            system("sudo -u admin clish --b /tmp/test_pre_req");
            fclose(fp);
            //nas_rt_ping_from_leak_vrfs_via_default_vrf(false, "default", false, false);

            nas_ut_rt_cfg ("blue",0, "20.0.0.0", 16, AF_INET, "default", NULL, b2b_leak_intf1);
            nas_ut_rt_cfg ("blue",0, "20::", 64, AF_INET6, "default", NULL, b2b_leak_intf1);
            nas_ut_rt_cfg ("red",0, "20.0.0.0", 16, AF_INET, "default", NULL, b2b_leak_intf1);
            nas_ut_rt_cfg ("red",0, "20::", 64, AF_INET6, "default", NULL, b2b_leak_intf1);
            sleep(5);
            nas_rt_validate_leak_from_default_vrf_parent_conn_rt(false);
            nas_rt_validate_leak_from_default_vrf_parent_reg_rt(false);
            nas_rt_validate_leak_from_default_vrf_leaked_rt_nh_ip(true);
            nas_rt_validate_leak_from_default_vrf_leaked_rt_nh_intf(false);
            nas_rt_validate_leak_from_default_vrf_leaked_rt_loopbk_intf (true);

            printf("\r\nLeak the route 20.0.0.0/16 and 20::/64 from default VRF to blue and red VRFs\r\n");
            nas_ut_rt_cfg ("blue",1, "20.0.0.0", 16, AF_INET, "default", NULL, b2b_leak_intf1);
            nas_ut_rt_cfg ("blue",1, "20::", 64, AF_INET6, "default", NULL, b2b_leak_intf1);
            nas_ut_rt_cfg ("red",1, "20.0.0.0", 16, AF_INET, "default", NULL, b2b_leak_intf1);
            nas_ut_rt_cfg ("red",1, "20::", 64, AF_INET6, "default", NULL, b2b_leak_intf1);
            nas_ut_rt_cfg ("default",1, "80.0.0.0", 16, AF_INET, "default", "20.0.0.2", b2b_leak_intf1);
            nas_ut_rt_cfg ("default",1, "80::", 64, AF_INET6, "default", "20::2", b2b_leak_intf1);
            nas_ut_rt_cfg ("blue",1, "80.0.0.0", 16, AF_INET, "default", "20.0.0.2", b2b_leak_intf1);
            nas_ut_rt_cfg ("blue",1, "80::", 64, AF_INET6, "default", "20::2", b2b_leak_intf1);
            nas_ut_rt_cfg ("red",1, "80.0.0.0", 16, AF_INET, "default", "20.0.0.2", b2b_leak_intf1);
            nas_ut_rt_cfg ("red",1, "80::", 64, AF_INET6, "default", "20::2", b2b_leak_intf1);

            printf("Step 8 - Add the IP address on out interface in the parent VRF and check that ping is working from leaked VRFs\r\n");
            fp = fopen("/tmp/test_pre_req","w");
            fprintf(fp, "configure terminal\n");
            fprintf(fp, "interface ethernet %s\n", DoD_b2b_leak_intf1);
            fprintf(fp, "ip address 20.0.0.1/16\n");
            fprintf(fp, "ipv6 address 20::1/64\n");
            fprintf(fp, "end\n");
            fflush(fp);
            system("sudo -u admin clish --b /tmp/test_pre_req");
            fclose(fp);
            nas_rt_ping_from_leak_vrfs_via_default_vrf(true, "default");
            nas_rt_validate_leak_from_default_vrf_parent_conn_rt(true);
            nas_rt_validate_leak_from_default_vrf_parent_reg_rt(true);
            nas_rt_validate_leak_from_default_vrf_leaked_rt_nh_ip(true);
            nas_rt_validate_leak_from_default_vrf_leaked_rt_nh_intf(true);
            nas_rt_validate_leak_from_default_vrf_leaked_rt_loopbk_intf (true);
        }
        nas_vrf_src_ip_config(0, "blue", 2, "50.0.0.1");
        nas_vrf_src_ip_config(0, "blue", 10, "50::1");
        nas_vrf_src_ip_config(0, "red", 2, "60.0.0.1");
        nas_vrf_src_ip_config(0, "red", 10, "60::1");
        nas_vrf_src_ip_config(0, "green", 2, "70.0.0.1");
        nas_vrf_src_ip_config(0, "green", 10, "70::1");
        printf("\r\n Remove the route 20.0.0.0/16 and 20::/64 from default VRF to blue and red VRFs\r\n");
        nas_ut_rt_cfg ("blue",0, "20.0.0.0", 16, AF_INET, "default", NULL, b2b_leak_intf1);
        nas_ut_rt_cfg ("blue",0, "20::", 64, AF_INET6, "default", NULL, b2b_leak_intf1);
        nas_ut_rt_cfg ("red",0, "20.0.0.0", 16, AF_INET, "default", NULL, b2b_leak_intf1);
        nas_ut_rt_cfg ("red",0, "20::", 64, AF_INET6, "default", NULL, b2b_leak_intf1);

        printf("Remove the route 50.0.0.1/32 50::1/128 from blue VRF to default VRF for return path reachability\r\n");
        nas_ut_rt_cfg ("default",0, "50.0.0.1", 32, AF_INET, "blue", NULL, "v-lo0");
        nas_ut_rt_cfg ("default",0, "50::1", 128, AF_INET6, "blue", NULL, "v-lo0");

        printf("Remove the route 60.0.0.1/32 60::1/128 from blue VRF to default VRF for return path reachability\r\n");
        nas_ut_rt_cfg ("default",0, "60.0.0.1", 32, AF_INET, "red", NULL, "v-lo1");
        nas_ut_rt_cfg ("default",0, "60::1", 128, AF_INET6, "red", NULL, "v-lo1");

        nas_ut_rt_cfg ("blue",0, "80.0.0.0", 16, AF_INET, "default", "20.0.0.2", b2b_leak_intf1);
        nas_ut_rt_cfg ("blue",0, "80::", 64, AF_INET6, "default", "20::2", b2b_leak_intf1);
        nas_ut_rt_cfg ("red",0, "80.0.0.0", 16, AF_INET, "default", "20.0.0.2", b2b_leak_intf1);
        nas_ut_rt_cfg ("red",0, "80::", 64, AF_INET6, "default", "20::2", b2b_leak_intf1);

        nas_rt_nht_config("default", "20.0.0.2", 2, 0);
        nas_rt_nht_config("default", "20::2", 10, 0);
        nas_rt_nht_config("blue", "20.0.0.2", 2, 0);
        nas_rt_nht_config("blue", "20::2", 10, 0);
        nas_rt_nht_config("red", "20.0.0.2", 2, 0);
        nas_rt_nht_config("red", "20::2", 10, 0);
        nas_rt_nht_config("blue", "80.0.0.2", 2, 0);
        nas_rt_nht_config("blue", "80::2", 10, 0);
        nas_rt_nht_config("red", "80.0.0.2", 2, 0);
        nas_rt_nht_config("red", "80::2", 10, 0);
        fp = fopen("/tmp/test_pre_req","w");
        fprintf(fp, "configure terminal\n");
        fprintf(fp, "interface loopback 0\n");
        fprintf(fp, "no ip address 50.0.0.1/32\n");
        fprintf(fp, "no ipv6 address 50::1/128\n");
        fprintf(fp, "no ip vrf forwarding\n");
        fprintf(fp, "exit\n");
        fprintf(fp, "no interface loopback 0\n");
        fprintf(fp, "interface loopback 1\n");
        fprintf(fp, "no ip address 60.0.0.1/32\n");
        fprintf(fp, "no ipv6 address 60::1/128\n");
        fprintf(fp, "no ip vrf forwarding\n");
        fprintf(fp, "exit\n");
        fprintf(fp, "no interface loopback 1\n");
        fprintf(fp, "interface loopback 3\n");
        fprintf(fp, "no ip address 70.0.0.1/32\n");
        fprintf(fp, "no ipv6 address 70::1/128\n");
        fprintf(fp, "no ip vrf forwarding\n");
        fprintf(fp, "exit\n");
        fprintf(fp, "no interface loopback 3\n");
        fprintf(fp, "interface ethernet %s\n", DoD_b2b_leak_intf1);
        fprintf(fp, "no ip address 20.0.0.1/16\n");
        fprintf(fp, "no ipv6 address 20::1/64\n");
        fprintf(fp, "exit\n");
        fprintf(fp, "no ip vrf blue\n");
        fprintf(fp, "no ip vrf red\n");
        fprintf(fp, "no ip vrf green\n");
        fprintf(fp, "end\n");
        fflush(fp);
        system("sudo -u admin clish --b /tmp/test_pre_req");
        fclose(fp);

        nas_rt_ping_from_leak_vrfs_via_default_vrf(false, "default", true);
        nas_rt_validate_leak_from_default_vrf_parent_conn_rt(false);
        nas_rt_validate_leak_from_default_vrf_parent_reg_rt(false);
        nas_rt_validate_leak_from_default_vrf_leaked_rt_nh_ip(false);
        nas_rt_validate_leak_from_default_vrf_leaked_rt_nh_intf(false);
        nas_rt_validate_leak_from_default_vrf_leaked_rt_loopbk_intf (false);
        printf("\r\n ******************Iteration %d completed**********************", iter);
    }
}

TEST(nas_rt_vrf_test, nas_rt_leak_intf_route_non_default_to_non_default_vrf) {
    printf("\r\n Clear the neighbors in the peer node since with VRF, the MAC is changed, "
           "already learnt nbr should be cleared in the peer\r\n");
    cps_api_return_code_t rc;
    int ret = system("opx-show-version | grep \"OS_NAME.*Enterprise\"");
    if (ret != 0) {
        return;
    }
    FILE *fp;
    uint8_t iter = 2;

    while (iter--) {
        fp = fopen("/tmp/test_pre_req","w");
        fprintf(fp, "configure terminal\n");
        fprintf(fp, "ip vrf blue\n");
        fprintf(fp, "exit\n");
        fprintf(fp, "ip vrf red\n");
        fprintf(fp, "exit\n");
        fprintf(fp, "ip vrf green\n");
        fprintf(fp, "exit\n");
        fprintf(fp, "interface loopback 0\n");
        fprintf(fp, "no shutdown\n");
        fprintf(fp, "ip vrf forwarding blue\n");
        fprintf(fp, "ip address 50.0.0.1/32\n");
        fprintf(fp, "ipv6 address 50::1/128\n");
        fprintf(fp, "exit\n");
        fprintf(fp, "interface loopback 1\n");
        fprintf(fp, "no shutdown\n");
        fprintf(fp, "ip vrf forwarding red\n");
        fprintf(fp, "ip address 60.0.0.1/32\n");
        fprintf(fp, "ipv6 address 60::1/128\n");
        fprintf(fp, "exit\n");
        fprintf(fp, "interface loopback 2\n");
        fprintf(fp, "no shutdown\n");
        fprintf(fp, "ip address 70.0.0.1/32\n");
        fprintf(fp, "ipv6 address 70::1/128\n");
        fprintf(fp, "exit\n");
        fprintf(fp, "interface ethernet %s\n", DoD_b2b_leak_intf1);
        fprintf(fp, "no switchport\n");
        fprintf(fp, "ip vrf forwarding green\n");
        fprintf(fp, "exit\n");
        fprintf(fp, "end\n");
        fflush(fp);
        system("sudo -u admin clish --b /tmp/test_pre_req");
        fclose(fp);

        nas_rt_nht_config("green", "20.0.0.2", 2, 1);
        nas_rt_nht_config("green", "20::2", 10, 1);
        nas_rt_nht_config("blue", "20.0.0.2", 2, 1);
        nas_rt_nht_config("blue", "20::2", 10, 1);
        nas_rt_nht_config("red", "20.0.0.2", 2, 1);
        nas_rt_nht_config("red", "20::2", 10, 1);
        nas_rt_nht_config("default", "20.0.0.2", 2, 1);
        nas_rt_nht_config("default", "20::2", 10, 1);
        printf("\r\nLeak the route 20.0.0.0/16 and 20::/64 from green VRF to blue and red VRFs\r\n");
        nas_ut_rt_cfg ("blue",1, "20.0.0.0", 16, AF_INET, "green", NULL, b2b_leak_vrf_intf1);
        nas_ut_rt_cfg ("blue",1, "20::", 64, AF_INET6, "green", NULL, b2b_leak_vrf_intf1);
        nas_ut_rt_cfg ("red",1, "20.0.0.0", 16, AF_INET, "green", NULL, b2b_leak_vrf_intf1);
        nas_ut_rt_cfg ("red",1, "20::", 64, AF_INET6, "green", NULL, b2b_leak_vrf_intf1);
        nas_ut_rt_cfg ("default",1, "20.0.0.0", 16, AF_INET, "green", NULL, b2b_leak_vrf_intf1);
        nas_ut_rt_cfg ("default",1, "20::", 64, AF_INET6, "green", NULL, b2b_leak_vrf_intf1);

        printf("Leak the route 50.0.0.1/32 50::1/128 from blue VRF to green VRF for return path reachability\r\n");
        nas_ut_rt_cfg ("green",1, "50.0.0.1", 32, AF_INET, "blue", NULL, "v-lo0");
        nas_ut_rt_cfg ("green",1, "50::1", 128, AF_INET6, "blue", NULL, "v-lo0");

        printf("Leak the route 60.0.0.1/32 60::1/128 from blue VRF to green VRF for return path reachability\r\n");
        nas_ut_rt_cfg ("green",1, "60.0.0.1", 32, AF_INET, "red", NULL, "v-lo1");
        nas_ut_rt_cfg ("green",1, "60::1", 128, AF_INET6, "red", NULL, "v-lo1");

        printf("Leak the route 70.0.0.1/32 70::1/128 from blue VRF to green VRF for return path reachability\r\n");
        nas_ut_rt_cfg ("green",1, "70.0.0.1", 32, AF_INET, "default", NULL, "lo2");
        nas_ut_rt_cfg ("green",1, "70::1", 128, AF_INET6, "default", NULL, "lo2");
        nas_vrf_src_ip_config(1, "blue", 2, "50.0.0.1");
        nas_vrf_src_ip_config(1, "blue", 10, "50::1");
        nas_vrf_src_ip_config(1, "red", 2, "60.0.0.1");
        nas_vrf_src_ip_config(1, "red", 10, "60::1");
        nas_vrf_src_ip_config(1, "default", 2, "70.0.0.1");
        nas_vrf_src_ip_config(1, "default", 10, "70::1");


        fp = fopen("/tmp/test_pre_req","w");
        fprintf(fp, "configure terminal\n");
        fprintf(fp, "interface ethernet %s\n", DoD_b2b_leak_intf1);
        fprintf(fp, "ip address 20.0.0.1/16\n");
        fprintf(fp, "ipv6 address 20::1/64\n");
        fprintf(fp, "exit\n");
        fprintf(fp, "end\n");
        fflush(fp);
        system("sudo -u admin clish --b /tmp/test_pre_req");
        fclose(fp);
        sleep(2);
        printf("\r\n Step 1 - Verify ping to 20.0.0.2 from green VRF\r\n");
        system("ip netns exec green ping -c 3 20.0.0.2");
        sleep(2);
        rc = nas_ut_validate_neigh_cfg("green", AF_INET, "20.0.0.2", 2, true, "green");
        ASSERT_TRUE(rc == cps_api_ret_code_OK);


        sleep(5);
        nas_rt_validate_leak_route_from_green_vrf(cps_api_ret_code_OK, cps_api_ret_code_OK);
        nas_rt_ping_from_leak_vrfs_via_green_vrf(true, "green");

        if (iter != 0) {
            printf("Step 2 - Clear the neighbors in the parent VRF and check the ping from leaked VRFs\r\n");
            system("ip netns exec green ip neigh del 20.0.0.2 dev v-e101-001-0");
            system("ip netns exec green ip neigh del 20::2 dev v-e101-001-0");
            nas_rt_ping_from_leak_vrfs_via_green_vrf(true, "green");

            nas_vrf_neigh_flush("blue", AF_INET, NULL);
            nas_vrf_neigh_flush("blue", AF_INET6, NULL);
            nas_vrf_neigh_flush("red", AF_INET, b2b_leak_vrf_intf1);
            nas_vrf_neigh_flush("red", AF_INET6, b2b_leak_vrf_intf1);
            nas_vrf_neigh_flush("default", AF_INET, b2b_leak_vrf_intf1);
            nas_vrf_neigh_flush("default", AF_INET6, b2b_leak_vrf_intf1);
            sleep(2);
            rc = nas_ut_validate_neigh_cfg("blue", AF_INET, "20.0.0.2", 2, true, "green");
            ASSERT_TRUE(rc == cps_api_ret_code_OK);
            rc = nas_ut_validate_neigh_cfg("red", AF_INET, "20.0.0.2", 2, true, "green");
            ASSERT_TRUE(rc == cps_api_ret_code_OK);
            rc = nas_ut_validate_neigh_cfg("default", AF_INET, "20.0.0.2", 2, true, "green");
            ASSERT_TRUE(rc == cps_api_ret_code_OK);
            rc = nas_ut_validate_neigh_cfg("blue", AF_INET6, "20::2", 2, true, "green");
            ASSERT_TRUE(rc == cps_api_ret_code_OK);
            rc = nas_ut_validate_neigh_cfg("red", AF_INET6, "20::2", 2, true, "green");
            ASSERT_TRUE(rc == cps_api_ret_code_OK);
            rc = nas_ut_validate_neigh_cfg("default", AF_INET6, "20::2", 2, true, "green");
            ASSERT_TRUE(rc == cps_api_ret_code_OK);

            printf("Step 3 - Bring down the out interface in the parent VRF and check that ping is not working from leaked VRFs\r\n");
            fp = fopen("/tmp/test_pre_req","w");
            fprintf(fp, "configure terminal\n");
            fprintf(fp, "interface ethernet %s\n", DoD_b2b_leak_intf1);
            fprintf(fp, "shutdown\n");
            fprintf(fp, "end\n");
            fflush(fp);
            system("sudo -u admin clish --b /tmp/test_pre_req");
            fclose(fp);
            sleep(5);
            nas_rt_ping_from_leak_vrfs_via_green_vrf(false, "green");

            printf("Step 4 - Bring up the out interface in the parent VRF and check that ping is working from leaked VRFs\r\n");
            fp = fopen("/tmp/test_pre_req","w");
            fprintf(fp, "configure terminal\n");
            fprintf(fp, "interface ethernet %s\n", DoD_b2b_leak_intf1);
            fprintf(fp, "no shutdown\n");
            fprintf(fp, "end\n");
            fflush(fp);
            system("sudo -u admin clish --b /tmp/test_pre_req");
            fclose(fp);
            sleep(2);
            printf("\r\nLeak the route 20.0.0.0/16 and 20::/64 from green VRF to blue and red VRFs\r\n");
            nas_ut_rt_cfg ("blue",1, "20.0.0.0", 16, AF_INET, "green", NULL, b2b_leak_vrf_intf1);
            nas_ut_rt_cfg ("blue",1, "20::", 64, AF_INET6, "green", NULL, b2b_leak_vrf_intf1);
            nas_ut_rt_cfg ("red",1, "20.0.0.0", 16, AF_INET, "green", NULL, b2b_leak_vrf_intf1);
            nas_ut_rt_cfg ("red",1, "20::", 64, AF_INET6, "green", NULL, b2b_leak_vrf_intf1);
            nas_ut_rt_cfg ("default",1, "20.0.0.0", 16, AF_INET, "green", NULL, b2b_leak_vrf_intf1);
            nas_ut_rt_cfg ("default",1, "20::", 64, AF_INET6, "green", NULL, b2b_leak_vrf_intf1);
            sleep(5);
            nas_rt_ping_from_leak_vrfs_via_green_vrf(true, "green");

            printf("Step 5 - Remove the IP address from out interface in the parent VRF and check that ping is not working from leaked VRFs\r\n");
            fp = fopen("/tmp/test_pre_req","w");
            fprintf(fp, "configure terminal\n");
            fprintf(fp, "interface ethernet %s\n", DoD_b2b_leak_intf1);
            fprintf(fp, "no ip address\n");
            fprintf(fp, "no ipv6 address\n");
            fprintf(fp, "end\n");
            fflush(fp);
            system("sudo -u admin clish --b /tmp/test_pre_req");
            fclose(fp);
            sleep(5);
            nas_rt_ping_from_leak_vrfs_via_green_vrf(false, "green");
            nas_rt_validate_leak_route_from_green_vrf(cps_api_ret_code_OK, cps_api_ret_code_ERR);

            printf("Step 6 - Add the IP address on out interface in the parent VRF and check that ping is working from leaked VRFs\r\n");
            fp = fopen("/tmp/test_pre_req","w");
            fprintf(fp, "configure terminal\n");
            fprintf(fp, "interface ethernet %s\n", DoD_b2b_leak_intf1);
            fprintf(fp, "ip address 20.0.0.1/16\n");
            fprintf(fp, "ipv6 address 20::1/64\n");
            fprintf(fp, "end\n");
            fflush(fp);
            system("sudo -u admin clish --b /tmp/test_pre_req");
            fclose(fp);
            sleep(5);
            nas_rt_ping_from_leak_vrfs_via_green_vrf(true, "green");

            printf("Step 7 - Remove the IP address again from out interface in the parent VRF and check that ping is not working from leaked VRFs\r\n");
            fp = fopen("/tmp/test_pre_req","w");
            fprintf(fp, "configure terminal\n");
            fprintf(fp, "interface ethernet %s\n", DoD_b2b_leak_intf1);
            fprintf(fp, "no ip address\n");
            fprintf(fp, "no ipv6 address\n");
            fprintf(fp, "end\n");
            fflush(fp);
            system("sudo -u admin clish --b /tmp/test_pre_req");
            fclose(fp);
            sleep(5);
            nas_rt_ping_from_leak_vrfs_via_green_vrf(false, "green");
            nas_rt_validate_leak_route_from_green_vrf(cps_api_ret_code_OK, cps_api_ret_code_ERR);

            printf("\r\nLeak the route 20.0.0.0/16 and 20::/64 from green VRF to blue and red VRFs\r\n");
            nas_ut_rt_cfg ("blue",0, "20.0.0.0", 16, AF_INET, "green", NULL, b2b_leak_vrf_intf1);
            nas_ut_rt_cfg ("blue",0, "20::", 64, AF_INET6, "green", NULL, b2b_leak_vrf_intf1);
            nas_ut_rt_cfg ("red",0, "20.0.0.0", 16, AF_INET, "green", NULL, b2b_leak_vrf_intf1);
            nas_ut_rt_cfg ("red",0, "20::", 64, AF_INET6, "green", NULL, b2b_leak_vrf_intf1);
            nas_ut_rt_cfg ("default",0, "20.0.0.0", 16, AF_INET, "green", NULL, b2b_leak_vrf_intf1);
            nas_ut_rt_cfg ("default",0, "20::", 64, AF_INET6, "green", NULL, b2b_leak_vrf_intf1);
            sleep(5);
            rc = nas_ut_validate_rt_cfg ("blue", AF_INET, "20.0.0.0", 16, "green", "", "", true);
            ASSERT_TRUE(rc == cps_api_ret_code_ERR);
            rc = nas_ut_validate_rt_cfg ("blue", AF_INET6, "20::", 64, "green", "", "", true);
            ASSERT_TRUE(rc == cps_api_ret_code_ERR);

            rc = nas_ut_validate_rt_cfg ("red", AF_INET, "20.0.0.0", 16, "green", "", "", true);
            ASSERT_TRUE(rc == cps_api_ret_code_ERR);
            rc = nas_ut_validate_rt_cfg ("red", AF_INET6, "20::", 64, "green", "", "", true);
            ASSERT_TRUE(rc == cps_api_ret_code_ERR);

            rc = nas_ut_validate_rt_cfg ("default", AF_INET, "20.0.0.0", 16, "green", "", "", true);
            ASSERT_TRUE(rc == cps_api_ret_code_ERR);
            rc = nas_ut_validate_rt_cfg ("default", AF_INET6, "20::", 64, "green", "", "", true);
            ASSERT_TRUE(rc == cps_api_ret_code_ERR);

            printf("\r\nLeak the route 20.0.0.0/16 and 20::/64 from green VRF to blue and red VRFs\r\n");
            nas_ut_rt_cfg ("blue",1, "20.0.0.0", 16, AF_INET, "green", NULL, b2b_leak_vrf_intf1);
            nas_ut_rt_cfg ("blue",1, "20::", 64, AF_INET6, "green", NULL, b2b_leak_vrf_intf1);
            nas_ut_rt_cfg ("red",1, "20.0.0.0", 16, AF_INET, "green", NULL, b2b_leak_vrf_intf1);
            nas_ut_rt_cfg ("red",1, "20::", 64, AF_INET6, "green", NULL, b2b_leak_vrf_intf1);
            nas_ut_rt_cfg ("default",1, "20.0.0.0", 16, AF_INET, "green", NULL, b2b_leak_vrf_intf1);
            nas_ut_rt_cfg ("default",1, "20::", 64, AF_INET6, "green", NULL, b2b_leak_vrf_intf1);
            sleep(5);
            nas_rt_validate_leak_route_from_green_vrf(cps_api_ret_code_OK, cps_api_ret_code_ERR);

            printf("Step 8 - Add the IP address on out interface in the parent VRF and check that ping is working from leaked VRFs\r\n");
            fp = fopen("/tmp/test_pre_req","w");
            fprintf(fp, "configure terminal\n");
            fprintf(fp, "interface ethernet %s\n", DoD_b2b_leak_intf1);
            fprintf(fp, "ip address 20.0.0.1/16\n");
            fprintf(fp, "ipv6 address 20::1/64\n");
            fprintf(fp, "end\n");
            fflush(fp);
            system("sudo -u admin clish --b /tmp/test_pre_req");
            fclose(fp);
            sleep(5);
            nas_rt_ping_from_leak_vrfs_via_green_vrf(true, "green");
        }
        nas_vrf_src_ip_config(0, "blue", 2, "50.0.0.1");
        nas_vrf_src_ip_config(0, "blue", 10, "50::1");
        nas_vrf_src_ip_config(0, "red", 2, "60.0.0.1");
        nas_vrf_src_ip_config(0, "red", 10, "60::1");
        nas_vrf_src_ip_config(0, "default", 2, "70.0.0.1");
        nas_vrf_src_ip_config(0, "default", 10, "70::1");
        printf("\r\n Remove the route 20.0.0.0/16 and 20::/64 from green VRF to blue and red VRFs\r\n");
        nas_ut_rt_cfg ("blue",0, "20.0.0.0", 16, AF_INET, "green", NULL, b2b_leak_vrf_intf1);
        nas_ut_rt_cfg ("blue",0, "20::", 64, AF_INET6, "green", NULL, b2b_leak_vrf_intf1);
        nas_ut_rt_cfg ("red",0, "20.0.0.0", 16, AF_INET, "green", NULL, b2b_leak_vrf_intf1);
        nas_ut_rt_cfg ("red",0, "20::", 64, AF_INET6, "green", NULL, b2b_leak_vrf_intf1);
        nas_ut_rt_cfg ("default",0, "20.0.0.0", 16, AF_INET, "green", NULL, b2b_leak_vrf_intf1);
        nas_ut_rt_cfg ("default",0, "20::", 64, AF_INET6, "green", NULL, b2b_leak_vrf_intf1);

        printf("Remove the route 50.0.0.1/32 50::1/128 from blue VRF to green VRF for return path reachability\r\n");
        nas_ut_rt_cfg ("green",0, "50.0.0.1", 32, AF_INET, "blue", NULL, "v-lo0");
        nas_ut_rt_cfg ("green",0, "50::1", 128, AF_INET6, "blue", NULL, "v-lo0");

        printf("Remove the route 60.0.0.1/32 60::1/128 from blue VRF to green VRF for return path reachability\r\n");
        nas_ut_rt_cfg ("green",0, "60.0.0.1", 32, AF_INET, "red", NULL, "v-lo1");
        nas_ut_rt_cfg ("green",0, "60::1", 128, AF_INET6, "red", NULL, "v-lo1");

        printf("Remove the route 70.0.0.1/32 70::1/128 from default VRF to green VRF for return path reachability\r\n");
        nas_ut_rt_cfg ("green",0, "70.0.0.1", 32, AF_INET, "default", NULL, "lo2");
        nas_ut_rt_cfg ("green",0, "70::1", 128, AF_INET6, "default", NULL, "lo2");

        nas_rt_nht_config("green", "20.0.0.2", 2, 0);
        nas_rt_nht_config("green", "20::2", 10, 0);
        nas_rt_nht_config("blue", "20.0.0.2", 2, 0);
        nas_rt_nht_config("blue", "20::2", 10, 0);
        nas_rt_nht_config("red", "20.0.0.2", 2, 0);
        nas_rt_nht_config("red", "20::2", 10, 0);
        nas_rt_nht_config("default", "20.0.0.2", 2, 0);
        nas_rt_nht_config("default", "20::2", 10, 0);
        fp = fopen("/tmp/test_pre_req","w");
        fprintf(fp, "configure terminal\n");
        fprintf(fp, "interface loopback 0\n");
        fprintf(fp, "no ip address 50.0.0.1/32\n");
        fprintf(fp, "no ipv6 address 50::1/128\n");
        fprintf(fp, "no ip vrf forwarding\n");
        fprintf(fp, "exit\n");
        fprintf(fp, "no interface loopback 0\n");
        fprintf(fp, "interface loopback 1\n");
        fprintf(fp, "no ip address 60.0.0.1/32\n");
        fprintf(fp, "no ipv6 address 60::1/128\n");
        fprintf(fp, "no ip vrf forwarding\n");
        fprintf(fp, "exit\n");
        fprintf(fp, "no interface loopback 1\n");
        fprintf(fp, "interface loopback 2\n");
        fprintf(fp, "no ip address 70.0.0.1/32\n");
        fprintf(fp, "no ipv6 address 70::1/128\n");
        fprintf(fp, "exit\n");
        fprintf(fp, "no interface loopback 2\n");
        fprintf(fp, "interface ethernet %s\n", DoD_b2b_leak_intf1);
        fprintf(fp, "no ip address 20.0.0.1/16\n");
        fprintf(fp, "no ipv6 address 20::1/64\n");
        fprintf(fp, "no ip vrf forwarding\n");
        fprintf(fp, "exit\n");
        fprintf(fp, "no ip vrf blue\n");
        fprintf(fp, "no ip vrf red\n");
        fprintf(fp, "no ip vrf green\n");
        fprintf(fp, "end\n");
        fflush(fp);
        system("sudo -u admin clish --b /tmp/test_pre_req");
        fclose(fp);
        sleep(5);

        nas_rt_validate_leak_route_from_green_vrf(cps_api_ret_code_ERR, cps_api_ret_code_ERR);
        nas_rt_ping_from_leak_vrfs_via_green_vrf(false, "green", true);

        printf("\r\n ******************Iteration %d completed**********************", iter);
    }
}

TEST(nas_rt_vrf_test, nas_rt_leak_nh_route_default_to_blue) {
    int ret = system("opx-show-version | grep \"OS_NAME.*Enterprise\"");
    if (ret != 0) {
        return;
    }
    FILE *fp;

    fp = fopen("/tmp/test_pre_req","w");
    fprintf(fp, "configure terminal\n");
    fprintf(fp, "ip vrf blue\n");
    fprintf(fp, "exit\n");
    fprintf(fp, "interface loopback 0\n");
    fprintf(fp, "no shutdown\n");
    fprintf(fp, "ip vrf forwarding blue\n");
    fprintf(fp, "ip address 50.0.0.1/32\n");
    fprintf(fp, "ipv6 address 50::1/128\n");
    fprintf(fp, "exit\n");
    fprintf(fp, "interface ethernet %s\n", DoD_b2b_leak_intf1);
    fprintf(fp, "no switchport\n");
    fprintf(fp, "ip address 20.0.0.1/16\n");
    fprintf(fp, "ipv6 address 20::1/64\n");
    fprintf(fp, "exit\n");
    fprintf(fp, "ip route 60.0.0.0/8 20.0.0.2\n");
    fprintf(fp, "ipv6 route 60::/64 20::2\n");
    fprintf(fp, "end\n");
    fflush(fp);
    system("sudo -u admin clish --b /tmp/test_pre_req");
    fclose(fp);

    sleep(5);
    printf("\r\n Verify ping to 20.0.0.2 from default VRF\r\n");
    printf("\r\n ping -c 3 20.0.0.2\r\n");
    system("ping -c 3 20.0.0.2");

    printf("\r\n Leak the route 60.0.0.0/16 and 60::/64 from default VRF to blue VRF\r\n");
    nas_ut_rt_cfg ("blue",1, "60.0.0.0", 16, AF_INET, "default", "20.0.0.2", b2b_leak_intf1);
    nas_ut_rt_cfg ("blue",1, "60::", 64, AF_INET6, "default", "20::2", b2b_leak_intf1);
    printf("\r\n Leak the route 50.0.0.0/16 50::/64 from blue VRF to default VRF for return path reachability\r\n");
    nas_ut_rt_cfg ("default",1, "50.0.0.0", 16, AF_INET, "blue", NULL, "v-lo0");
    nas_ut_rt_cfg ("default",1, "50::", 64, AF_INET6, "blue", NULL, "v-lo0");
    sleep(5);

    printf("\r\n Verify ping to [60.0.0.2 and 60::2] (leaked n/w) from blue VRF via default VRF\r\n");
    system("ip netns exec blue ping -c 3 60.0.0.2 -I 50.0.0.1");
    system("ip netns exec blue ping -c 3 60::2 -I 50::1");
    system("ip neigh del 20.0.0.2 dev e101-001-0");
    system("ip neigh del 20::2 dev e101-001-0");
    printf("\r\n Verify ping again to [60.0.0.2 and 60::2] (leaked n/w) from blue VRF via default VRF after neighbor clear in default VRF\r\n");
    system("ip netns exec blue ping -c 3 60.0.0.2 -I 50.0.0.1");
    system("ip netns exec blue ping -c 3 60::2 -I 50::1");
    sleep(2);
    nas_ut_rt_cfg ("blue",0, "60.0.0.0", 16, AF_INET, "default", "20.0.0.2", b2b_leak_intf1);
    nas_ut_rt_cfg ("blue",0, "60::", 64, AF_INET6, "default", "20::2", b2b_leak_intf1);
    printf("\r\n Leak the route 50.0.0.0/16 50::/64 from blue VRF to default VRF for return path reachability\r\n");
    nas_ut_rt_cfg ("default",0, "50.0.0.0", 16, AF_INET, "blue", NULL, "v-lo0");
    nas_ut_rt_cfg ("default",0, "50::", 64, AF_INET6, "blue", NULL, "v-lo0");
    printf("\r\nThe below ping expected to fail\r\n");
    system("ip netns exec blue ping -c 1 20.0.0.2 -I 50.0.0.1");
    system("ip netns exec blue ping -c 1 20::2 -I 50::1");

    fp = fopen("/tmp/test_pre_req","w");
    fprintf(fp, "configure terminal\n");
    fprintf(fp, "interface loopback 0\n");
    fprintf(fp, "no ip address 50.0.0.1/32\n");
    fprintf(fp, "no ipv6 address 50::1/128\n");
    fprintf(fp, "no ip vrf forwarding\n");
    fprintf(fp, "exit\n");
    fprintf(fp, "no ip route 60.0.0.0/8 20.0.0.2\n");
    fprintf(fp, "no ipv6 route 60::/64 20::2\n");
    fprintf(fp, "no interface loopback 0\n");
    sleep(2);
    fprintf(fp, "interface ethernet %s\n", DoD_b2b_leak_intf1);
    fprintf(fp, "no ip address 20.0.0.1/16\n");
    fprintf(fp, "no ipv6 address 20::1/64\n");
    fprintf(fp, "exit\n");
    fprintf(fp, "no ip vrf blue\n");
    fprintf(fp, "end\n");
    fflush(fp);
    system("sudo -u admin clish --b /tmp/test_pre_req");
    fclose(fp);
}

TEST(nas_rt_vrf_test, nas_rt_leak_intf_route_red_to_blue) {
    int ret = system("opx-show-version | grep \"OS_NAME.*Enterprise\"");
    if (ret != 0) {
        return;
    }
    FILE *fp;

    fp = fopen("/tmp/test_pre_req","w");
    fprintf(fp, "configure terminal\n");
    fprintf(fp, "ip vrf blue\n");
    fprintf(fp, "exit\n");
    fprintf(fp, "ip vrf red\n");
    fprintf(fp, "exit\n");
    fprintf(fp, "interface loopback 0\n");
    fprintf(fp, "no shutdown\n");
    fprintf(fp, "ip vrf forwarding blue\n");
    fprintf(fp, "ip address 50.0.0.1/32\n");
    fprintf(fp, "ipv6 address 50::1/128\n");
    fprintf(fp, "exit\n");
    fprintf(fp, "interface ethernet %s\n", DoD_b2b_leak_intf1);
    fprintf(fp, "no shutdown\n");
    fprintf(fp, "no switchport\n");
    fprintf(fp, "ip vrf forwarding red\n");
    fprintf(fp, "ip address 20.0.0.1/16\n");
    fprintf(fp, "ipv6 address 20::1/64\n");
    fprintf(fp, "exit\n");
    fprintf(fp, "end\n");
    fflush(fp);
    system("sudo -u admin clish --b /tmp/test_pre_req");
    fclose(fp);

    sleep(2);
    printf("\r\n Verify ping to 20.0.0.2 from red VRF\r\n");
    system("ip netns exec red ping -c 3 20.0.0.2");

    printf("\r\n Leak the route 20.0.0.0/16 and 20::/64 from red VRF to blue VRF\r\n");
    nas_ut_rt_cfg ("blue",1, "20.0.0.0", 16, AF_INET, "red", NULL, b2b_leak_vrf_intf1);
    nas_ut_rt_cfg ("blue",1, "20::", 64, AF_INET6, "red", NULL, b2b_leak_vrf_intf1);
    printf("\r\n Leak the route 50.0.0.0/16 50::/64 from blue VRF to red VRF for return path reachability\r\n");
    nas_ut_rt_cfg ("red",1, "50.0.0.0", 16, AF_INET, "blue", NULL, "v-lo0");
    nas_ut_rt_cfg ("red",1, "50::", 64, AF_INET6, "blue", NULL, "v-lo0");
    sleep(5);
    printf("\r\n Verify ping to [20.0.0.2 and 20::2] (leaked n/w) from blue VRF via red VRF\r\n");
    system("ip netns exec blue ping -c 3 20.0.0.2 -I 50.0.0.1");
    system("ip netns exec blue ping -c 3 20::2 -I 50::1");

    system("ip netns exec red ip neigh del 20.0.0.2 dev e101-001-0");
    system("ip netns exec red ip neigh del 20::2 dev e101-001-0");
    printf("\r\n Verify ping again to [20.0.0.2 and 20::2] (leaked n/w) from blue VRF via red VRF after neighbor clear in default VRF\r\n");
    system("ip netns exec blue ping -c 3 20.0.0.2 -I 50.0.0.1");
    system("ip netns exec blue ping -c 3 20::2 -I 50::1");
    sleep(2);
    nas_ut_rt_cfg ("blue",0, "20.0.0.0", 16, AF_INET, "red", NULL, b2b_leak_vrf_intf1);
    nas_ut_rt_cfg ("blue",0, "20::", 64, AF_INET6, "red", NULL, b2b_leak_vrf_intf1);
    nas_ut_rt_cfg ("red",0, "50.0.0.0", 16, AF_INET, "blue", NULL, "v-lo0");
    nas_ut_rt_cfg ("red",0, "50::", 64, AF_INET6, "blue", NULL, "v-lo0");
    printf("\r\nThe below ping expected to fail\r\n");
    system("ip netns exec blue ping -c 1 20.0.0.2 -I 50.0.0.1");
    system("ip netns exec blue ping -c 1 20::2 -I 50::1");

    fp = fopen("/tmp/test_pre_req","w");
    fprintf(fp, "configure terminal\n");
    fprintf(fp, "interface loopback 0\n");
    fprintf(fp, "no ip address 50.0.0.1/32\n");
    fprintf(fp, "no ipv6 address 50::1/128\n");
    fprintf(fp, "no ip vrf forwarding\n");
    fprintf(fp, "exit\n");
    fprintf(fp, "no interface loopback 0\n");
    fprintf(fp, "interface ethernet %s\n", DoD_b2b_leak_intf1);
    fprintf(fp, "no ip address 20.0.0.1/16\n");
    fprintf(fp, "no ipv6 address 20::1/64\n");
    fprintf(fp, "no ip vrf forwarding\n");
    fprintf(fp, "exit\n");
    fprintf(fp, "no ip vrf blue\n");
    fprintf(fp, "no ip vrf red\n");
    fprintf(fp, "end\n");
    fflush(fp);
    system("sudo -u admin clish --b /tmp/test_pre_req");
    fclose(fp);

}

TEST(nas_rt_vrf_test, nas_rt_leak_nh_route_red_to_blue) {
    int ret = system("opx-show-version | grep \"OS_NAME.*Enterprise\"");
    if (ret != 0) {
        return;
    }
    FILE *fp;

    fp = fopen("/tmp/test_pre_req","w");
    fprintf(fp, "configure terminal\n");
    fprintf(fp, "ip vrf blue\n");
    fprintf(fp, "exit\n");
    fprintf(fp, "interface loopback 0\n");
    fprintf(fp, "no shutdown\n");
    fprintf(fp, "ip vrf forwarding blue\n");
    fprintf(fp, "ip address 50.0.0.1/32\n");
    fprintf(fp, "ipv6 address 50::1/128\n");
    fprintf(fp, "exit\n");
    fprintf(fp, "interface ethernet %s\n", DoD_b2b_leak_intf1);
    fprintf(fp, "no switchport\n");
    fprintf(fp, "ip address 20.0.0.1/16\n");
    fprintf(fp, "ipv6 address 20::1/64\n");
    fprintf(fp, "exit\n");
    fprintf(fp, "ip vrf blue ip route 60.0.0.0/8 20.0.0.2\n");
    fprintf(fp, "ipv6 vrf blue ipv6 route 60::/64 20::2\n");
    fprintf(fp, "end\n");
    fflush(fp);
    system("sudo -u admin clish --b /tmp/test_pre_req");
    fclose(fp);

    sleep(5);
    printf("\r\n Verify ping to 20.0.0.2 from red VRF\r\n");
    printf("\r\n ip netns exec red ping -c 3 20.0.0.2\r\n");
    system("ip netns exec red ping -c 3 20.0.0.2");

    printf("\r\n Leak the route 60.0.0.0/16 and 60::/64 from red VRF to blue VRF\r\n");
    nas_ut_rt_cfg ("blue",1, "60.0.0.0", 16, AF_INET, "red", "20.0.0.2", b2b_leak_intf1);
    nas_ut_rt_cfg ("blue",1, "60::", 64, AF_INET6, "red", "20::2", b2b_leak_intf1);
    printf("\r\n Leak the route 50.0.0.0/16 50::/64 from blue VRF to red VRF for return path reachability\r\n");
    nas_ut_rt_cfg ("red",1, "50.0.0.0", 16, AF_INET, "blue", NULL, "v-lo0");
    nas_ut_rt_cfg ("red",1, "50::", 64, AF_INET6, "blue", NULL, "v-lo0");
    sleep(5);

    printf("\r\n Verify ping to [60.0.0.2 and 60::2] (leaked n/w) from blue VRF via red VRF\r\n");
    system("ip netns exec blue ping -c 3 60.0.0.2 -I 50.0.0.1");
    system("ip netns exec blue ping -c 3 60::2 -I 50::1");
    system("ip netns exec blue ip neigh del 20.0.0.2 dev e101-001-0");
    system("ip netns exec blue ip neigh del 20::2 dev e101-001-0");
    printf("\r\n Verify ping again to [60.0.0.2 and 60::2] (leaked n/w) from blue VRF via red VRF after neighbor clear in default VRF\r\n");
    system("ip netns exec red ping -c 3 60.0.0.2 -I 50.0.0.1");
    system("ip netns exec red ping -c 3 60::2 -I 50::1");
    sleep(2);
    nas_ut_rt_cfg ("blue",0, "60.0.0.0", 16, AF_INET, "red", "20.0.0.2", b2b_leak_intf1);
    nas_ut_rt_cfg ("blue",0, "60::", 64, AF_INET6, "red", "20::2", b2b_leak_intf1);
    printf("\r\n Leak the route 50.0.0.0/16 50::/64 from blue VRF to red VRF for return path reachability\r\n");
    nas_ut_rt_cfg ("red",0, "50.0.0.0", 16, AF_INET, "blue", NULL, "v-lo0");
    nas_ut_rt_cfg ("red",0, "50::", 64, AF_INET6, "blue", NULL, "v-lo0");
    printf("\r\nThe below ping expected to fail\r\n");
    system("ip netns exec blue ping -c 1 20.0.0.2 -I 50.0.0.1");
    system("ip netns exec blue ping -c 1 20::2 -I 50::1");

    fp = fopen("/tmp/test_pre_req","w");
    fprintf(fp, "configure terminal\n");
    fprintf(fp, "interface loopback 0\n");
    fprintf(fp, "no ip address 50.0.0.1/32\n");
    fprintf(fp, "no ipv6 address 50::1/128\n");
    fprintf(fp, "no ip vrf forwarding\n");
    fprintf(fp, "exit\n");
    fprintf(fp, "no ip vrf blue ip route 60.0.0.0/8 20.0.0.2\n");
    fprintf(fp, "no ipv6 vrf blue ipv6 route 60::/64 20::2\n");
    fprintf(fp, "no interface loopback 0\n");
    fprintf(fp, "interface ethernet %s\n", DoD_b2b_leak_intf1);
    fprintf(fp, "no ip address 20.0.0.1/16\n");
    fprintf(fp, "no ipv6 address 20::1/64\n");
    fprintf(fp, "no ip vrf forwarding\n");
    fprintf(fp, "exit\n");
    fprintf(fp, "no ip vrf blue\n");
    fprintf(fp, "no ip vrf red\n");
    fprintf(fp, "end\n");
    fflush(fp);
    system("sudo -u admin clish --b /tmp/test_pre_req");
    fclose(fp);
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
            rc = nas_ut_validate_neigh_cfg(vrf, AF_INET, "100.0.0.2", 128, true, NULL);
            ASSERT_TRUE(rc == cps_api_ret_code_ERR);
            rc = nas_ut_validate_rt_cfg (vrf, AF_INET, "60.0.0.0", 8, vrf, "", "", true);
            ASSERT_TRUE(rc == cps_api_ret_code_ERR);
            rc = nas_ut_validate_rt_cfg (vrf, AF_INET6, "100::1", 128, vrf, "", "", false);
            ASSERT_TRUE(rc == cps_api_ret_code_ERR);
            rc = nas_ut_validate_rt_cfg (vrf, AF_INET6, "100::0", 64, vrf, "", "", true);
            ASSERT_TRUE(rc == cps_api_ret_code_ERR);
            rc = nas_ut_validate_neigh_cfg(vrf, AF_INET6, "100::2", 128, true, NULL);
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

TEST(nas_rt_vrf_test, nas_rt_vrf_vlan_del_test) {
    int ret = system("opx-show-version | grep \"OS_NAME.*Enterprise\"");
    if (ret != 0) {
        return;
    }
    FILE *fp;
    char cmd [512];

    fp = fopen("/tmp/test_pre_req","w");
    fprintf(fp, "configure terminal\n");
    fprintf(fp, "ip vrf blue\n");
    fprintf(fp, "exit\n");
    fprintf(fp, "interface vlan 100\n");
    fprintf(fp, "no shutdown\n");
    fprintf(fp, "ip vrf forwarding blue\n");
    fprintf(fp, "ip address 100.10.10.1/24\n");
    fprintf(fp, "exit\n");
    fprintf(fp, "interface ethernet %s\n", DoD_b2b_intf1);
    fprintf(fp, "switchport mode trunk\n");
    fprintf(fp, "switchport trunk allowed vlan 100\n");
    fprintf(fp, "exit\n");
    fprintf(fp, "mac address-table static 00:11:22:33:44:55 vlan 100 interface ethernet %s\n",
            DoD_b2b_intf1);
    fprintf(fp, "end\n");
    fflush(fp);
    system("sudo -u admin clish --b /tmp/test_pre_req");
    fclose(fp);

    memset(cmd, '\0', sizeof(cmd));
    snprintf(cmd, 511, "ip -n blue neigh add 100.10.10.2 lladdr 00:11:22:33:44:55 dev v-br100");
    system(cmd);

    system("sudo -u admin clish -c 'show ip arp vrf-name blue' | grep 100.10.10.2 > /tmp/check");
    sleep(3);
    FILE *result = fopen("/tmp/check", "r");
    char val1[50], val2[50];
    memset(val1, '\0', sizeof(val1));
    memset(val2, '\0', sizeof(val2));
    (void)fscanf(result, "%49s %49s", val1, val2);
    fclose(result);
    printf("\r\n val1:%s val2:%s\r\n", val1, val2);
    ASSERT_TRUE((strncmp(val2, "100.10.10.2", 50) == 0));

    fp = fopen("/tmp/test_pre_req","w");
    fprintf(fp, "configure terminal\n");
    fprintf(fp, "no mac address-table static 00:11:22:33:44:55 vlan 100\n");
    fprintf(fp, "no interface vlan 100\n");
    fprintf(fp, "end\n");
    fflush(fp);
    system("sudo -u admin clish --b /tmp/test_pre_req");
    fclose(fp);

    sleep(3);
    system("sudo -u admin clish -c 'show ip arp vrf-name blue' | grep 100.10.10.2 > /tmp/check");
    result = fopen("/tmp/check", "r");
    memset(val1, '\0', sizeof(val1));
    memset(val2, '\0', sizeof(val2));
    (void)fscanf(result, "%49s %49s", val1, val2);
    fclose(result);
    printf("\r\n val1:%s val2:%s\r\n", val1, val2);
    ASSERT_TRUE((strncmp(val2, "100.10.10.2", 50) != 0));

    fp = fopen("/tmp/test_pre_req","w");
    fprintf(fp, "configure terminal\n");
    fprintf(fp, "no ip vrf blue\n");
    fprintf(fp, "end\n");
    fflush(fp);
    system("sudo -u admin clish --b /tmp/test_pre_req");
    fclose(fp);
}

static void nas_rt_ecmp_config(bool is_add) {
    cps_api_return_code_t rc;
    int ret = system("opx-show-version | grep \"OS_NAME.*Enterprise\"");
    if (ret != 0) {
        return;
    }
    FILE *fp;
    char cmd [512];


    if (is_add == false) {
        fp = fopen("/tmp/test_pre_req","w");
        fprintf(fp, "configure terminal\n");
        fprintf(fp, "no mac address-table static 00:11:22:33:44:55 vlan 100\n");
        fprintf(fp, "no mac address-table static 00:11:22:33:44:66 vlan 101\n");
        fprintf(fp, "no interface vlan 100\n");
        fprintf(fp, "no interface vlan 101\n");
        fprintf(fp, "no ip vrf blue\n");
        fprintf(fp, "end\n");
        fflush(fp);
        system("sudo -u admin clish --b /tmp/test_pre_req");
        fclose(fp);

        sleep(3);
        rc = nas_ut_validate_neigh_cfg("blue", AF_INET, "100.10.10.2", 128, true, NULL);
        ASSERT_TRUE(rc != cps_api_ret_code_OK);
        rc = nas_ut_validate_neigh_cfg("blue", AF_INET, "101.10.10.2", 128, true, NULL);
        ASSERT_TRUE(rc != cps_api_ret_code_OK);
        rc = nas_ut_validate_neigh_cfg("blue", AF_INET6, "100::2", 128, true, NULL);
        ASSERT_TRUE(rc != cps_api_ret_code_OK);
        rc = nas_ut_validate_neigh_cfg("blue", AF_INET6, "101::2", 128, true, NULL);
        ASSERT_TRUE(rc != cps_api_ret_code_OK);
        return;
    }
    fp = fopen("/tmp/test_pre_req","w");
    fprintf(fp, "configure terminal\n");
    fprintf(fp, "ip vrf blue\n");
    fprintf(fp, "exit\n");

    fprintf(fp, "interface vlan 100\n");
    fprintf(fp, "no shutdown\n");
    fprintf(fp, "ip vrf forwarding blue\n");
    fprintf(fp, "ip address 100.10.10.1/24\n");
    fprintf(fp, "ipv6 address 100::1/64\n");
    fprintf(fp, "exit\n");
    fprintf(fp, "interface ethernet %s\n", DoD_b2b_intf1);
    fprintf(fp, "switchport mode trunk\n");
    fprintf(fp, "switchport trunk allowed vlan 100\n");
    fprintf(fp, "exit\n");
    fprintf(fp, "mac address-table static 00:11:22:33:44:55 vlan 100 interface ethernet %s\n",
            DoD_b2b_intf1);

    fprintf(fp, "interface vlan 101\n");
    fprintf(fp, "no shutdown\n");
    fprintf(fp, "ip vrf forwarding blue\n");
    fprintf(fp, "ip address 101.10.10.1/24\n");
    fprintf(fp, "ipv6 address 101::1/64\n");
    fprintf(fp, "exit\n");
    fprintf(fp, "interface ethernet %s\n", DoD_b2b_intf1);
    fprintf(fp, "switchport mode trunk\n");
    fprintf(fp, "switchport trunk allowed vlan 101\n");
    fprintf(fp, "exit\n");
    fprintf(fp, "mac address-table static 00:11:22:33:44:66 vlan 101 interface ethernet %s\n",
            DoD_b2b_intf1);
    fprintf(fp, "end\n");
    fflush(fp);
    system("sudo -u admin clish --b /tmp/test_pre_req");
    fclose(fp);

    sleep(5);
    memset(cmd, '\0', sizeof(cmd));
    snprintf(cmd, 511, "ip -n blue neigh add 100.10.10.2 lladdr 00:11:22:33:44:55 dev v-br100");
    system(cmd);
    memset(cmd, '\0', sizeof(cmd));
    snprintf(cmd, 511, "ip -n blue neigh add 101.10.10.2 lladdr 00:11:22:33:44:66 dev v-br101");
    system(cmd);

    memset(cmd, '\0', sizeof(cmd));
    snprintf(cmd, 511, "ip -n blue neigh add 100::2 lladdr 00:11:22:33:44:55 dev v-br100");
    system(cmd);
    memset(cmd, '\0', sizeof(cmd));
    snprintf(cmd, 511, "ip -n blue neigh add 101::2 lladdr 00:11:22:33:44:66 dev v-br101");
    system(cmd);

    sleep(5);
    rc = nas_ut_validate_neigh_cfg("blue", AF_INET, "100.10.10.2", 128, true, NULL);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    rc = nas_ut_validate_neigh_cfg("blue", AF_INET, "101.10.10.2", 128, true, NULL);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    rc = nas_ut_validate_neigh_cfg("blue", AF_INET6, "100::2", 128, true, NULL);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    rc = nas_ut_validate_neigh_cfg("blue", AF_INET6, "101::2", 128, true, NULL);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
}

TEST(nas_rt_vrf_test, nas_rt_vrf_ecmp_test) {
    cps_api_return_code_t rc;
    nas_rt_ecmp_config(true);
    FILE *fp = fopen("/tmp/test_pre_req","w");
    fprintf(fp, "configure terminal\n");
    fprintf(fp, "ip route vrf blue 30.0.0.0/16 100.10.10.2\n");
    fprintf(fp, "ip route vrf blue 30.0.0.0/16 101.10.10.2\n");
    fprintf(fp, "ipv6 route vrf blue 30::/64 100::2\n");
    fprintf(fp, "ipv6 route vrf blue 30::/64 101::2\n");
    fprintf(fp, "end\n");
    fflush(fp);
    system("sudo -u admin clish --b /tmp/test_pre_req");
    fclose(fp);

    std::cout<<"Sleeping to download the routes from RTM"<<std::endl;
    sleep(20);

    rc = nas_ut_validate_rt_ecmp_cfg ("blue", AF_INET, "30.0.0.0", 16, "blue", NULL, NULL, true, 2);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    rc = nas_ut_validate_rt_ecmp_cfg ("blue", AF_INET6,"30::", 64, "blue", NULL, NULL, true, 2);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    std::cout<<"Delete the routes"<<std::endl;
    fp = fopen("/tmp/test_pre_req","w");
    fprintf(fp, "configure terminal\n");
    fprintf(fp, "no ip route vrf blue 30.0.0.0/16 100.10.10.2\n");
    fprintf(fp, "no ip route vrf blue 30.0.0.0/16 101.10.10.2\n");
    fprintf(fp, "no ipv6 route vrf blue 30::/64 100::2\n");
    fprintf(fp, "no ipv6 route vrf blue 30::/64 101::2\n");
    fprintf(fp, "end\n");
    fflush(fp);
    system("sudo -u admin clish --b /tmp/test_pre_req");
    fclose(fp);

    sleep(3);
    rc = nas_ut_validate_rt_ecmp_cfg ("blue", AF_INET, "30.0.0.0", 16, "blue", NULL, NULL, true, 2);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);
    rc = nas_ut_validate_rt_ecmp_cfg ("blue", AF_INET6,"30::", 64, "blue", NULL, NULL, true, 2);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);
    nas_rt_ecmp_config(false);
}

TEST(nas_rt_vrf_test, nas_rt_vrf_ecmp_test_2nh) {

    cps_api_return_code_t rc;
    nas_rt_ecmp_config(true);
    nas_ut_rt_cfg ("blue",1, "30.0.0.0", 16, AF_INET, "blue", "100.10.10.2", "v-br100");
    nas_ut_rt_cfg ("blue",1, "30::", 64, AF_INET6, NULL, "100::2", "v-br100");
    /* Use IPv6 route next-hop update model */
    nas_ut_rt_ipv6_nh_cfg ("blue", true, "30.0.0.0", 16, AF_INET6, NULL, "101.10.10.2", "v-br101", NULL, NULL);
    nas_ut_rt_ipv6_nh_cfg ("blue", true, "30::", 64, AF_INET6, "blue", "101::2", "v-br101", NULL, NULL);
    sleep(5);

    rc = nas_ut_validate_rt_ecmp_cfg ("blue", AF_INET, "30.0.0.0", 16, "blue", NULL, NULL, true, 2);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    rc = nas_ut_validate_rt_ecmp_cfg ("blue", AF_INET6,"30::", 64, "blue", NULL, NULL, true, 2);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);

    std::cout<<"Delete the routes"<<std::endl;
    nas_ut_rt_ipv6_nh_cfg ("blue", false, "30.0.0.0", 16, AF_INET6, NULL, "101.10.10.2", "v-br101", NULL, NULL);
    nas_ut_rt_cfg ("blue",0, "30.0.0.0", 16, AF_INET, "blue", "100.10.10.2", "v-br100");
    nas_ut_rt_ipv6_nh_cfg ("blue", false, "30::", 64, AF_INET6, NULL, "101::2", "v-br101", NULL, NULL);
    nas_ut_rt_cfg ("blue",0, "30::", 64, AF_INET6, "blue", "100::2", "v-br100");
    sleep(3);
    rc = nas_ut_validate_rt_ecmp_cfg ("blue", AF_INET, "30.0.0.0", 16, "blue", NULL, NULL, true, 2);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);
    rc = nas_ut_validate_rt_ecmp_cfg ("blue", AF_INET6,"30::", 64, "blue", NULL, NULL, true, 2);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);
    nas_rt_ecmp_config(false);
}

TEST(nas_rt_vrf_test, nas_rt_vrf_verify_onlink_nh) {
    cps_api_return_code_t rc;
    nas_vrf_change_mode(true);
    nas_ut_rt_cfg (NULL,1, "50.0.0.0", 24, AF_INET, NULL, "30.0.0.2", b2b_intf1, true);
    /* Onlink NH flag seems to be not supported in kernel when it is supported enabled the below code
     * nas_ut_rt_cfg ("default",1, "5555::", 64, AF_INET6, NULL, "3333::2", b2b_intf1, true); */
    /* Verify that route is created with onlink flag. */
    sleep(5);
    rc = nas_ut_validate_rt_cfg ("default", AF_INET, "50.0.0.0", 24, "default", "30.0.0.2", b2b_intf1, true, true);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    /* Onlink NH flag seems to be not supported in kernel when it is supported enabled the below code
     * nas_ut_rt_cfg ("default",1, "5555::", 64, AF_INET6, NULL, "3333::2", b2b_intf1, true); */
    /* rc =  nas_ut_validate_rt_cfg ("default", AF_INET, "5555::", 64, "default", "3333::2", b2b_intf1, true, true);
       ASSERT_TRUE(rc == cps_api_ret_code_OK); */
    nas_vrf_ip_config(true);
    sleep(5);
    nas_ut_rt_cfg (NULL,1, "50.0.0.0", 24, AF_INET, NULL, "30.0.0.3", b2b_intf1, false, true);
    nas_ut_rt_cfg ("default",1, "5555::", 64, AF_INET6, NULL, "3333::3", b2b_intf1, false, true);
    /* Verify that nexthop with onlink flag is replaced with different nexthop with no onlink flag for a route. */
    sleep(5);
    rc = nas_ut_validate_rt_cfg ("default", AF_INET, "50.0.0.0", 24, "default", "30.0.0.3", b2b_intf1, true, false);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    rc =  nas_ut_validate_rt_cfg ("default", AF_INET6, "5555::", 64, "default", "3333::3", b2b_intf1, true, false);
    ASSERT_TRUE(rc == cps_api_ret_code_OK);
    nas_ut_rt_cfg (NULL,0, "50.0.0.0", 24, AF_INET, NULL, "30.0.0.3", b2b_intf1, true);
    nas_ut_rt_cfg ("default",0, "5555::", 64, AF_INET6, NULL, "3333::3", b2b_intf1, true);
    sleep(5);
    rc = nas_ut_validate_rt_cfg ("default", AF_INET, "50.0.0.0", 24, "default", "30.0.0.3", b2b_intf1, true, true);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);
    rc =  nas_ut_validate_rt_cfg ("default", AF_INET, "5555::", 64, "default", "3333::3", b2b_intf1, true, true);
    ASSERT_TRUE(rc != cps_api_ret_code_OK);
    nas_vrf_ip_config(false);
    nas_vrf_change_mode(false);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);

    /* configure the test pre-requisite */
    nas_vrf_change_mode(true);

    printf("___________________________________________\n");

    return(RUN_ALL_TESTS());
}

