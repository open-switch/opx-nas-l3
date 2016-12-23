#!/usr/bin/python
# Copyright (c) 2015 Dell Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
# LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
# FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
#
# See the Apache Version 2.0 License for specific language governing
# permissions and limitations under the License.

import struct
import socket
import cps_utils
import bytearray_utils as ba_utils
import netaddr as net

'''
Note: User need to install the python-netaddr
      package to use this script
'''
route_module_key = ['base-route/obj/entry']


def get_route_key():
    return route_module_key


def print_route_nhlist_func(dict):
    print 'base-route/obj/entry/nh-list/nh-addr = ',
    for k in dict:
        inner_dict = dict[k]
        ip_str = inner_dict['base-route/obj/entry/nh-list/nh-addr']
        print ba_utils.ba_to_ipv4str('', str(ip_str)),
    print ''


def print_route_prefix_func(data):
    print 'base-route/obj/entry/route-prefix = ', ba_utils.ba_to_ipv4str('', str(data))


def print_ipv6_route_prefix_func(data):
    print 'base-route/obj/entry/route-prefix = ', ba_utils.ba_to_ipv6str('', str(data))


def print_ipv6_route_nhlist_func(dict):
    print 'base-route/obj/entry/nh-list/nh-addr = ',
    for k in dict:
        inner_dict = dict[k]
        ip_str = inner_dict['base-route/obj/entry/nh-list/nh-addr']
        print ba_utils.ba_to_ipv6str('', str(ip_str)),
    print ''


def init(ver):
    if ver == 'ipv4':
        cps_utils.add_print_function(
            'base-route/obj/entry/nh-list',
            print_route_nhlist_func)
        cps_utils.add_print_function(
            'base-route/obj/entry/route-prefix',
            print_route_prefix_func)
    else:
        cps_utils.add_print_function(
            'base-route/obj/entry/nh-list',
            print_ipv6_route_nhlist_func)
        cps_utils.add_print_function(
            'base-route/obj/entry/route-prefix',
            print_ipv6_route_prefix_func)


def extract_ip_netmask(ip_addr):
    ip = net.IPNetwork(str(ip_addr))
    return ip.version, ip.prefixlen, ip.network
