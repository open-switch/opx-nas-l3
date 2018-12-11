#
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
#

#!/usr/bin/python
import sys
import cps
import cps_object
import cps_utils
import nas_os_utils


print "NHT CPS registration..."
handle = cps.event_connect()
cps.event_register(handle,cps.key_from_name('observed','base-route/nh-track'))
while True:
    nht_event = cps_object.CPSObject(obj=cps.event_wait(handle))
    dest_addr = nht_event.get_attr_data('dest-addr')
    nh_count = 0
    nh_count  = nht_event.get_attr_data('nh-count')
    print "Received NHT Event for: ", dest_addr, nh_count
