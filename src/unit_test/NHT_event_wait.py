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
