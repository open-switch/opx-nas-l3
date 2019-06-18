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

import cps
from cps_utils import *
import sys
import subprocess

config_data = {
1: {'vrf-name':'default', 'af':10, 'ifname':'br100', 'ip':'fe8000000000000092b11cfffef49cc1'},
2: {'vrf-name':'default', 'af':10, 'ifname':'br110', 'ip':'fe8000000000000092b11cfffef49cc1'},
3: {'vrf-name':'default', 'af':10, 'ifname':'e101-015-0', 'ip':'fe8000000000000092b11cfffef49c8a'},
}

fail_data = {
1: {'vrf-name':'default', 'af':10, 'ifname':'br100', 'ip':'111100000000000092b11cfffef49cc1'},
2: {'vrf-name':'default', 'af':10, 'ifname':'e101-015-0', 'ip':'222200000000000092b11cfffef49c8a'},
}

def commit(obj, op):
    l = []
    obj_tup = (op, obj.get())
    l.append(obj_tup)
    t = CPSTransaction(l)
    ret = t.commit()
    if ret:
        print "Commit success"
    return ret


def usage():
    print"\n nas_rt_cps_virt_routing_ip_unittest.py run-test"
    print"\n nas_rt_cps_virt_routing_ip_unittest.py create vrf <name> af <af>] ifname <name> ip <address>"
    print" nas_rt_cps_virt_routing_ip_unittest.py delete vrf <name> af <af>] ifname <name> ip <address>"
    print" nas_rt_cps_virt_routing_ip_unittest.py show [vrf <name>] [af <af>] [ifname <name>] [ip <address>]"
    print"\n"


def exec_shell(cmd):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
    #print out
    return out


def handle_config(op, vrf, af, ifname, ip):
    #print(" vrf:", vrf)
    #print(" af:", af)
    #print(" ifname:", ifname)
    #print(" ip:", ip)
    obj = CPSObject('base-route/virtual-routing-config/virtual-routing-ip-config',
                     data= {"vrf-name" : vrf, "af" : af,
                       "ifname" : ifname,  "ip" : ip,  })
    ret = commit(obj, op)
    return ret



def handle_get(vrf, af, ifname, ip):
    get_list = []
    get_obj = CPSObject("base-route/virtual-routing-config/virtual-routing-ip-config")
    if vrf is not None:
        get_obj.add_attr("vrf-name", vrf)
    if (af != 0):
        get_obj.add_attr("af", af)
    if ifname is not None:
        get_obj.add_attr("ifname", ifname)
    if ip is not None:
        get_obj.add_attr("ip", ip)
    if cps.get([get_obj.get()], get_list):
        if not get_list:
            get_list = None
        return get_list
    else:
        return None

def handle_show(vrf, af, ifname, ip):
    get_list = handle_get(vrf, af, ifname, ip)
    if get_list is not None:
        for i in get_list:
            print_obj(i)
    else:
        print("\n no objects received")

def test_pre_req_cfg():
    #print("Test pre requisite config")
    mode = 'OPX'
    ret = exec_shell('os10-show-version | grep \"OS_NAME.*Enterprise\"')
    if ret:
        mode = 'DoD'

    if mode is 'DoD':
        #configure via CLI the test pre requisites
        cmd_list =  ['configure terminal',
                     'interface ethernet 1/1/15',
                     'no switchport',
                     'ip address 15.1.1.1/24',
                     'exit',
                     'interface vlan 100',
                     'ip address 100.1.1.1/24',
                     'exit',
                     'interface vlan 110',
                     'ip address 110.1.1.1/24',
                     'exit',
                     'interface range ethernet 1/1/9,1/1/19',
                     'switchport mode trunk',
                     'switchport trunk allowed vlan 100,110',
                     'exit']
        cfg_file = open('/tmp/test_pre_req', 'w')
        for item in cmd_list:
            print>>cfg_file, item
        cfg_file.close()
        exec_shell('sudo -u admin clish --b /tmp/test_pre_req')
    else:
        #configure via linux commands the test pre requisites
        exec_shell('brctl addbr br100 up')
        exec_shell('ifconfig br100 down')
        exec_shell('ip link add link e101-009-0 name e101-009-0.100 type vlan id 100')
        exec_shell('ip link add link e101-019-0 name e101-019-0.100 type vlan id 100')
        exec_shell('ifconfig e101-009-0 up')
        exec_shell('ifconfig e101-019-0 up')
        exec_shell('ip link set dev e101-009-0.100 up')
        exec_shell('ip link set dev e101-019-0.100 up')
        exec_shell('brctl addif br100 e101-009-0.100')
        exec_shell('brctl addif br100 e101-019-0.100')
        exec_shell('ip addr add 100.1.1.1/24 dev br100')
        exec_shell('ip addr add  100:1::1/64 dev br100')
        exec_shell('ifconfig br100 up')
        exec_shell('brctl stp br100 on')

        exec_shell('brctl addbr br110 up')
        exec_shell('ifconfig br110 down')
        exec_shell('ip link add link e101-009-0 name e101-009-0.110 type vlan id 110')
        exec_shell('ip link add link e101-019-0 name e101-019-0.110 type vlan id 110')
        exec_shell('ifconfig e101-009-0 up')
        exec_shell('ifconfig e101-019-0 up')
        exec_shell('ip link set dev e101-009-0.110 up')
        exec_shell('ip link set dev e101-019-0.110 up')
        exec_shell('brctl addif br100 e101-009-0.110')
        exec_shell('brctl addif br100 e101-019-0.110')
        exec_shell('ip addr add 110.1.1.1/24 dev br110')
        exec_shell('ip addr add  110:1::1/64 dev br110')
        exec_shell('ifconfig br110 up')
        exec_shell('brctl stp br110 on')

        exec_shell('ifconfig e101-015-0 up')
        exec_shell('ip addr add 15.1.1.1/24 dev e101-015-0')
        exec_shell('ip addr add 15:1::1/64 dev e101-015-0')


if __name__ == '__main__':
    vrf = None
    af = 0
    show = 0
    delete = 0
    create = 0
    ifname = None
    ip = None
    mac = ""
    ret = 0
    if len(sys.argv) == 1:
        usage()
    else:
        if (sys.argv[1] in ["show", "create", "delete"]):
            print("len = ", len(sys.argv))
            print("command : ", sys.argv[1])
            arglen = len(sys.argv)
            if (sys.argv[1] == "show"):
                show = 1
            elif (sys.argv[1] == "delete"):
                delete = 1
            elif (sys.argv[1] == "create"):
                create = 1
            i = 2
            while (i < arglen):
                print("\n iteration i", i)
                if (sys.argv[i] == "vrf"):
                    i = i + 1
                    if (i > arglen):
                        print"\n\n Please reenter vrf-name"
                    vrf = sys.argv[i]
                elif (sys.argv[i] == "af"):
                    i = i + 1
                    if (i > arglen):
                        print"\n\n please reenter with af"
                    af = sys.argv[i]
                elif (sys.argv[i] == "ifname"):
                    i = i + 1
                    if (i > arglen):
                        print"\n\n please enter ifname"
                    ifname = sys.argv[i]
                elif (sys.argv[i] == "ip"):
                    i = i + 1
                    if (i > arglen):
                        print"\n\n please enter ip in hex format ('fe8000000000000092b11cfffef49cc1')"
                    ip = sys.argv[i]
                i = i + 1
            print(
                "\n\n cmd with vrf, af, ifname, ip ",
                vrf,
                af,
                ifname,
                ip)
            if (show):
                handle_show(
                    vrf,
                    af,
                    ifname,
                    ip)
            elif (delete):
                handle_config(
                    "delete",
                    vrf,
                    af,
                    ifname,
                    ip)
            elif (create):
                handle_config(
                    "create",
                    vrf,
                    af,
                    ifname,
                    ip)
        elif (sys.argv[1] in ["run-test"]):
            test_pre_req_cfg()
            i = 1
            while(i<=3):
                entry = config_data[i]
                if not handle_config("create", entry['vrf-name'], entry['af'], entry['ifname'], entry['ip']):
                    ret = 1
                if handle_get(entry['vrf-name'], entry['af'], entry['ifname'], entry['ip']) is None:
                    ret = 1
                i+=1
            i = 1
            while(i<=3):
                entry = config_data[i]
                if not handle_config("delete", entry['vrf-name'], entry['af'], entry['ifname'], entry['ip']):
                    ret = 1
                if handle_get(entry['vrf-name'], entry['af'], entry['ifname'], entry['ip']) is not None:
                    ret = 1
                i+=1
            i = 1
            while(i<=3):
                entry = config_data[i]
                if handle_get(entry['vrf-name'], entry['af'], entry['ifname'], entry['ip']) is not None:
                    ret = 1
                i+=1
            i = 1
            while(i<=2):
                entry = fail_data[i]
                if handle_config("create", entry['vrf-name'], entry['af'], entry['ifname'], entry['ip']):
                    ret = 1
                if handle_get(entry['vrf-name'], entry['af'], entry['ifname'], entry['ip']) is not None:
                    ret = 1
                i+=1
        else:
            usage()
    sys.exit(ret)
