/*
 * Copyright (c) 2016 Dell Inc.
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

#include <stdio.h>
#include <string.h>

ecmp_route_add( int add)  {

int i,j,p, len;

char buf[1000 * 1024], buf1[10 * 1024];
  char *ptr;

  memset(buf, ' ', sizeof(buf));
  buf[0] = '\0';
  ptr = &buf[0];

  for (i=1; i<100; i++) {

      for(j=2; j<200;j++) {
          memset(buf, ' ', sizeof(buf));
          buf[0] = '\0';
          ptr = &buf[0];

          for(p=2; p< (random(10000000)% 64);p++) {
              memset(buf1, ' ', sizeof(buf1));
              len =snprintf(buf1, 1024*10, "nexthop via 1.1.1.%d ",random(100000000) % 255);
              strncat(ptr, buf1, len);
              ptr += strlen(buf1);
          }

          printf("ip route %s 40.40.%d.%d scope global %s\n", (add ==1)? "add":"change", random(100000000) % 255,random(100000000) % 255, buf);
      }
  }
}

arp_add() {
int i,p;
   for(p=1; p<255;p++) {
         printf("arp -s 1.1.1.%d 90:b1:1c:f4:%d:%d\n",p,p,p);
   }

}
   main()
   {

    arp_add();
    ecmp_route_add(1);
    // random route update with random Nhs
    //ecmp_route_add(2);
   }

