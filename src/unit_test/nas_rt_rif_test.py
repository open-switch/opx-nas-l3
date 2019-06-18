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
import nas_common_utils as nas_common
import cps_object
import nas_os_if_utils as nas_if
import sys
import binascii
import subprocess
import time

#Set following number according to NPU capability
#num rif for VLANs will be 2 less than max (512), as one is used for base mac and one for default vlan
num_vlans_to_test=510
start_vlan_id=2
mode='OPX'
member_port='ethernet1/1/9'
lnx_member_port='e101-009-0'

# attribute id's for VLAN config
intf_rpc_key_id = 'dell-base-if-cmn/set-interface'
intf_rpc_op_attr_id = 'dell-base-if-cmn/set-interface/input/operation'
intf_rpc_op_type_map = {'create': 1, 'delete': 2, 'set': 3}

name_attr_id = 'if/interfaces/interface/name'
type_attr_id = 'if/interfaces/interface/type'
admin_attr_id = 'if/interfaces/interface/enabled'
vlan_attr_id = 'base-if-vlan/if/interfaces/interface/id'
tagged_port_attr_id = 'dell-if/if/interfaces/interface/tagged-ports'
vlan_type_attr_id = 'dell-if/if/interfaces/interface/vlan-type'
vlan_if_type = 'ianaift:l2vlan'


def usage():
    print"\nnas_rt_rif_test.py run-test"
    print"nas_rt_rif_test.py create vlan-id <id> ip <address> <pref_len>"
    print"nas_rt_rif_test.py delete vlan-id <id>"
    print"nas_rt_rif_test.py show [ip <address> <pref_len>]"
    print"\n"

def nas_vlan_op(op, data_dict):
    if op == 'get':
        obj = cps_object.CPSObject( nas_if.get_if_key(), data=data_dict)
    else:
        if op in intf_rpc_op_type_map:
            data_dict[intf_rpc_op_attr_id] = intf_rpc_op_type_map[op]
        obj = cps_object.CPSObject( intf_rpc_key_id, data=data_dict)
        op = 'rpc'
    nas_common.get_cb_method(op)(obj)

def commit(obj, op):
    l = []
    obj_tup = (op, obj.get())
    l.append(obj_tup)
    t = CPSTransaction(l)
    ret = t.commit()
    return ret

def exec_shell(cmd):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
    return out

def get_sw_mode():
    global mode
    mode = 'OPX'
    ret = exec_shell('os10-show-version | grep \"OS_NAME.*Enterprise\"')
    if ret:
        mode = 'DoD'

def handle_get(vrf, af, ip, pref_len):
    get_list = []
    npu_prg_done = 0
    get_obj = CPSObject("base-route/obj/entry")
    if vrf is not None:
        get_obj.add_attr("vrf-name", vrf)
    if (af != 0):
        get_obj.add_attr("af", af)
    if ip is not None:
        addr = binascii.hexlify(socket.inet_pton(socket.AF_INET, ip))
        get_obj.add_attr("route-prefix", addr)
    if pref_len is not None:
        get_obj.add_attr("prefix-len", pref_len)
    if cps.get([get_obj.get()], get_list):
        if not get_list:
            get_list = None
        else:
            reply_obj = CPSObject(obj=get_list[0])
            npu_prg_done = reply_obj.get_attr_data('base-route/obj/entry/npu-prg-done')
        return get_list,npu_prg_done
    else:
        return None, npu_prg_done

def handle_show(vrf, ip, pref_len):
    get_list, npu_prg_done  = handle_get(vrf, 2, ip, pref_len)
    if get_list is not None:
        for i in get_list:
            print_obj(i)
        print"\n NPU program done:", npu_prg_done
    else:
        print("\n no objects received")

def ip_addr_config(ifname, ip_addr, pref_len):
    ret = 0
    if ip_addr is not None:
        addr = binascii.hexlify(socket.inet_pton(socket.AF_INET, ip_addr))
        obj = CPSObject('base-ip/ipv4/address',
                         data= {"base-ip/ipv4/name": ifname, "base-ip/ipv4/address/ip" : addr,
                           "base-ip/ipv4/address/prefix-length" : pref_len,  })
        ret = commit(obj, 'create')
    return ret

def vlan_cps_config(choice, vlan_id, mbr_port, ip_addr = None, pref_len = None):
    if choice == 'add' and vlan_id != '':
        vlan_type = 1
        ifname_list = []
        ifname_list.insert(0,mbr_port.strip())
        #create the VLAN
        nas_vlan_op("create",
            {vlan_attr_id: vlan_id, type_attr_id:vlan_if_type,
             tagged_port_attr_id: ifname_list,
             vlan_type_attr_id: vlan_type, admin_attr_id: 1})
        #configure IP address
        if ip_addr is not None:
            ifname='br'+str(vlan_id)
            ip_addr_config(ifname,ip_addr,pref_len)
    elif choice == 'del' and mbr_port != '':
        ifname='br'+str(vlan_id)
        nas_vlan_op("delete", {name_attr_id: ifname})

#Verify creation of RIF (my_station_tcam entry) beyond the the h/w limit (512)
#Expectation is, my_station_tcam entry should be optimized in SAI for VLAN entries.
#if NPU my_station _tcam entry creation is NOT optimized for VLANs,
#then this test would fail in verification when creating entries more than 512.
def run_tests():
    global num_vlans_to_test
    ret=0
    af=2
    pref_len = 24

    #configuration
    for i in range (num_vlans_to_test):
        vlan_id = start_vlan_id+i
        ip_addr_str="100."+str(vlan_id/250+1)+"."+str(vlan_id%250)+".1"
        vlan_cps_config('add', vlan_id, lnx_member_port, ip_addr_str,pref_len)

    #verification
    time.sleep (30)
    for i in range (num_vlans_to_test):
        vlan_id = start_vlan_id+i
        ip_addr_str="100."+str(vlan_id/250+1)+"."+str(vlan_id%250)+".0"
        get_list, npu_prg_done = handle_get(None, af, ip_addr_str, pref_len)
        if get_list is None or npu_prg_done is not 1:
            ret = 1
            print "validation failed for vlan-"+str(vlan_id)+" IP:"+ip_addr_str
            break
    if ret is 1:
        return ret

    #configure the VLAN entry beyond the max limit
    vlan_id=start_vlan_id+num_vlans_to_test
    ip_addr_str="100."+str(vlan_id/250+1)+"."+str(vlan_id%250)+".1"
    vlan_cps_config('add', vlan_id, lnx_member_port, ip_addr_str,pref_len)

    #verification - for entry beyond max limit
    time.sleep (10)
    ip_addr_str="100."+str(vlan_id/250+1)+"."+str(vlan_id%250)+".0"
    get_list, npu_prg_done = handle_get(None, af, ip_addr_str, pref_len)
    if get_list is None or npu_prg_done is 1:
        print "Test Pass: RIF entry/my_station_tcam entry created beyond 512 entries."
        print get_list
    else:
        print "Test Fail: RIF entry/my_station_tcam entry creation failed beyond 512 entries."
        ret = 1

    return ret

#cleanup
def run_tests_cleanup():
    global num_vlans_to_test

    for i in range (num_vlans_to_test):
        vlan_id = start_vlan_id+i
        vlan_cps_config('del', vlan_id, lnx_member_port, None, None)
    #cleanup the last entry created beyond max limit
    vlan_id=start_vlan_id+num_vlans_to_test
    vlan_cps_config('del', vlan_id, lnx_member_port, None,None)

def test_pre_req_cfg():
    global mode

    if mode is 'DoD':
        #configure via CLI the test pre requisites
        cfg_file = open('/tmp/test_pre_req', 'w')
        print>>cfg_file, "configure terminal"
        print>>cfg_file, "interface range ethernet 1/1/1-1/1/32"
        print>>cfg_file, "shutdown"
        print>>cfg_file, "interface "+member_port
        print>>cfg_file, "no shutdown"
        print>>cfg_file, "switchport mode trunk"
        cfg_file.close()
        exec_shell('sudo -u admin clish --b /tmp/test_pre_req')
    else:
        #configure via linux commands the test pre requisites
        print "UT test for BASE not supported yet"


if __name__ == '__main__':
    vrf = None
    vlan_id = 0
    af = 0
    show = 0
    delete = 0
    create = 0
    ifname = None
    ip = None
    pref_len = 0
    ret = 0
    if len(sys.argv) == 1:
        usage()
    else:
        get_sw_mode()
        #for now this UT is supported only for DoD
        if mode is not 'DoD':
            sys.exit(1)
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
                elif (sys.argv[i] == "vlan-id"):
                    i = i + 1
                    if (i > arglen):
                        print"\n\n Please reenter vlan-id"
                    vlan_id = sys.argv[i]
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
                        print"\n\n please enter ip in hex format ('64010203') prefix_length"
                    ip = sys.argv[i]
                    pref_len = sys.argv[i+1]
                    i = i + 1
                i = i + 1
            print(
                "\n\n cmd with vlan_id, ip, pref_len",
                vlan_id, ip, pref_len)
            if (show):
                handle_show(
                    vrf,
                    ip, pref_len)
            elif (delete):
                vlan_cps_config('del', vlan_id, member_port)
            elif (create):
                vlan_cps_config('add', vlan_id, lnx_member_port, ip, pref_len)
        elif (sys.argv[1] in ["run-test"]):
            test_pre_req_cfg()
            ret = run_tests()
            run_tests_cleanup()
        else:
            usage()
    sys.exit(ret)
