#!/usr/bin/python
# Copyright (c) 2018 Dell Inc.
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
import sys
import getopt
import cps_utils
import socket
import nas_common_utils as nas_common
import nas_route_utils as nas_route
import netaddr as net
import time
from netaddr import *
'''
Note: User need to install the python-netaddr
      package to use this script
'''


IPV4_PREFIX_LEN = 24
IPV6_PREFIX_LEN = 64

def extract_version(ip_addr):
        ip = net.IPNetwork(str(ip_addr))
        return ip.version

def build_route_obj(route_prefix, prefix_len, version):
    ver = extract_version(route_prefix)

    if version != 'ipv' + str(ver):
        print 'Improper IP Address'
        print  str(ver)
        print version
        usage()

    obj = cps_utils.CPSObject(nas_route.get_route_key()[int(0)])
    obj.add_attr("vrf-id", 0)

    if version == 'ipv4':
        obj.add_attr("af", socket.AF_INET)
    elif version == 'ipv6':
        obj.add_attr("af", socket.AF_INET6)

    obj.add_attr_type("route-prefix", version)
    obj.add_attr("route-prefix", str(route_prefix))
    obj.add_attr("prefix-len", int(prefix_len))

#    print  "Configuring Route prefix:" + str(route_prefix),"pref_len:",prefix_len,"Version:"+ str(ver)

    return obj


def add_embd_param(obj, outer_param, inner_param, val_list, type=''):
    count = int(0)
    el = []
    el.append(outer_param)
    for val in val_list:
        el.append(str(count))
        el.append(inner_param)
        if type != '':
            param_list = []
            param_list.append(outer_param)
            param_list.append(inner_param)
            obj.add_attr_type(param_list, type)
        obj.add_embed_attr(el, val)
        count = count + 1
        del el[1:]


def nas_route_op(op, obj, ver):
    nas_route.init(ver)
    nas_common.get_cb_method(op)(obj)


def usage():
    ''' Usage Method '''

    print '< Usage >'
    print 'cps_config_route.py can be used to add/update/delete the route to the system\n'
    print '-h, --help: Show the option and usage'
    print '-a, --add : add new route '
    print '-d, --del : delete existing route'
    print '-i, --ip  : IP address that needs to be configured'
    print '    --ip6 : IP v6  address that needs to be configured'
    print '-n, --nh  : next-hop ip adress, needs ipv6 address if --ip6 used otherwise ipv4'
    print '            multiple ip address needs to supply as string separated by space'
    print '-c, --count : Route count'
    print '-u, --update: update existing route information\n'
    print 'Example:'
    print 'cps_config_route.py  --add --ip 192.168.10.2 --nh "127.0.0.1 127.0.0.2"'
    print 'cps_config_route.py  --add --ip 192.168.20.0/24 --nh "127.0.0.1 127.0.0.2"'
    print 'cps_config_route.py  --del --ip 192.168.10.2'
    print 'cps_config_route.py  --update --ip 192.168.10.2 --nh "127.0.0.1 127.0.0.3"'
    print 'cps_config_route.py  --add --ip6 192:168:10::2 --nh "127:0:0::1 127:0:0::2"'
    print 'cps_config_route.py  --add --ip6 192:168:20::0/24 --nh "127:0:0::1 127:0:0::2"'
    sys.exit(1)


def main(argv):
    ''' The main function will read the user input from the
        command line argument and  process the request  '''

    # used for storing the user input
    ip_addr = ''
    ver = 'ipv4'
    nh_ip_addr = ''
    choice = ''
    num_of_routes = 1

    try:
        opts, args = getopt.getopt(
            argv, "audhi:n:", ["add", "update", "del", "help", "ip=", "nh=", "ip6=","count="])

    except getopt.GetoptError:
        usage()

    for opt, arg in opts:

        if opt in ('-h', '--help'):
            choice = 'help'

        elif opt in ('-a', '--add'):
            choice = 'add'

        elif opt in ('-u', '--update'):
            choice = 'update'

        elif opt in ('-d', '--del'):
            choice = 'del'

        elif opt in ('-i', '--ip'):
            ip_addr = arg

        elif opt in ('-n', '--nh'):
            nh_ip_addr = arg

        elif opt in ('-c', '--count'):
           num_of_routes = arg

        elif opt == '--ip6':
            ip_addr = arg
            ver = 'ipv6'

    if choice == 'add' and ip_addr != '' and nh_ip_addr != '':
        start = time.time()
        nh_ip_list = str.split(nh_ip_addr)
        version, prefix_len, route_prefix = nas_route.extract_ip_netmask(ip_addr)
        for i in range(0,int(num_of_routes)):
            cps_obj = build_route_obj(route_prefix, prefix_len, ver)
            add_embd_param(cps_obj, "nh-list", "nh-addr", nh_ip_list, ver)
            cps_obj.add_attr("nh-count", len(nh_ip_list))
            nas_route_op("create", cps_obj, ver)
            if (ver == 'ipv6'):
                route_prefix += 2**(128-prefix_len)
            else:
                route_prefix += 2**(32-prefix_len)
        end = time.time()
        if (end > start):
            print 'Total time for adding %d routes = %f seconds' % (
                   int (num_of_routes),(end - start))
        else:
            print 'Total time for adding %d routes: Unknown' % (
                   int (num_of_routes))

    elif choice == 'update'and ip_addr != '' and nh_ip_addr != '':
        nh_ip_list = str.split(nh_ip_addr)
        version, prefix_len, route_prefix = nas_route.extract_ip_netmask(ip_addr)
        cps_obj = build_route_obj(route_prefix, prefix_len, ver)
        add_embd_param(cps_obj, "nh-list", "nh-addr", nh_ip_list, ver)
        cps_obj.add_attr("nh-count", len(nh_ip_list))
        nas_route_op("set", cps_obj, ver)

    elif choice == 'del'and ip_addr != '':
        start = time.time()
        nh_ip_list = str.split(nh_ip_addr)
        version, prefix_len, route_prefix = nas_route.extract_ip_netmask(ip_addr)
        for i in range(0,int(num_of_routes)):
            cps_obj = build_route_obj(route_prefix, prefix_len, ver)
            add_embd_param(cps_obj, "nh-list", "nh-addr", nh_ip_list, ver)
            cps_obj.add_attr("nh-count", len(nh_ip_list))
            nas_route_op("delete", cps_obj, ver)
            if (ver == 'ipv6'):
                route_prefix += 2**(128-prefix_len)
            else:
                route_prefix += 2**(32-prefix_len)
        end = time.time()
        if (end > start):
            print 'Total time for deleting %d routes = %f seconds' % (
                   int (num_of_routes), (end - start))
        else:
            print 'Total time for deleting %d routes: Unknown' % (
                   int (num_of_routes))

    else:
        usage()

# Calling the main method
if __name__ == "__main__":
    main(sys.argv[1:])
