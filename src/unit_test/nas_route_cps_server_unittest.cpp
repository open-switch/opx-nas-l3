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

/*
 * nas_rt_cps_server_unittest.cpp
 *
 *  Created on: May 20, 2015
 *      Author: Satish Mynam
 */



#include "std_mac_utils.h"
#include "std_ip_utils.h"

#include "ds_common_types.h"
#include "cps_class_map.h"
#include "cps_api_object.h"
#include "cps_api_object_key.h"
#include "cps_api_operation.h"
#include "cps_api_events.h"


#include <stdlib.h>

#include <gtest/gtest.h>
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

cps_api_object_list_t list_of_objects;


#ifdef __cplusplus
extern "C" {
#endif

#include "dell-base-routing.h"
#include "nas_rt_api.h"

cps_api_operation_handle_t nas_route_cps_handle;

static cps_api_return_code_t nas_route_filter_route_func(cps_api_object_t obj,
                    cps_api_transaction_params_t * param,size_t ix,
                    cps_api_operation_types_t op) {
    /*
     *  @@TODO     Call filter function to filter the route
     *  either as Management route, App route etc
     *
     */
    return cps_api_ret_code_OK;

}

/*
 * Temporary unit-test function calls until cps-api-linux: nas_os_route
 * functions are checked in
 */
static t_std_error nas_os_add_route (cps_api_object_t obj){
    return STD_ERR_OK;
}

static t_std_error nas_os_del_route (cps_api_object_t obj) {
    return STD_ERR_OK;
}

static t_std_error nas_os_set_route (cps_api_object_t obj){
    return STD_ERR_OK;
}
static inline bool nas_route_validate_route_attr(cps_api_object_t obj, bool del) {

    cps_api_object_attr_t af;
    cps_api_object_attr_t vrf_id;
    cps_api_object_attr_t prefix;
    cps_api_object_attr_t pref_len;
    cps_api_object_attr_t nh_count;

    /*
     * Check mandatory route attributes
     */
    af       = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_AF);
    vrf_id   = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_VRF_ID);
    prefix   = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX);
    pref_len = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN);

    /*
     * If route delete case, check the key mandatory attrs for delete case first
     */

    if  (af == CPS_API_ATTR_NULL || vrf_id == CPS_API_ATTR_NULL ||
            prefix == CPS_API_ATTR_NULL || pref_len == CPS_API_ATTR_NULL) {
        return false;
    }

    /*
     * Route delete case
     */
    if (del == true) {
        return true;
    }

    /*
     * If route add/update case, check for NH attributes also
     */
    nh_count = cps_api_object_attr_get(obj, BASE_ROUTE_OBJ_ENTRY_NH_COUNT);

    cps_api_attr_id_t ids[3] = { BASE_ROUTE_OBJ_ENTRY_NH_LIST, 0,
                                 BASE_ROUTE_OBJ_ENTRY_NH_LIST_NH_ADDR};
    const int ids_len = sizeof(ids)/sizeof(*ids);

    cps_api_object_attr_t gw = cps_api_object_e_get(obj, ids, ids_len);

    ids[2] = BASE_ROUTE_OBJ_ENTRY_NH_LIST_IFINDEX;
    cps_api_object_attr_t gwix = cps_api_object_e_get(obj, ids, ids_len);

    if (nh_count == CPS_API_ATTR_NULL  || gw == CPS_API_ATTR_NULL) {
        printf("NAS-RT-CPS-SET:Missing route nh params");
        if (gwix == CPS_API_ATTR_NULL)
           printf("NAS-RT-CPS-SET:Missing optional route ifindex params");
        return false;
    }

    return true;
}

cps_api_return_code_t  nas_route_process_cps_route(cps_api_transaction_params_t * param, size_t ix) {

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    cps_api_return_code_t rc = cps_api_ret_code_OK;
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    if (nas_route_validate_route_attr(obj, (op == cps_api_oper_DELETE)? true:false) == false) {
        printf("NAS-RT-CPS-SET:Missing route key params");
        return cps_api_ret_code_ERR;
    }

    /*
     *  Call filter function to filter the route
     *  either as Management route, App route and
     *  once conditions are satisfied, install the route into kernel
     *  via cps-api-os interface
     */
    if(nas_route_filter_route_func(obj, param, ix, op) != cps_api_ret_code_OK){
        rc = cps_api_ret_code_ERR;
    }

    cps_api_object_t cloned = cps_api_object_create();
    if (!cloned) {
        return cps_api_ret_code_ERR;
    }
    cps_api_object_clone(cloned,obj);
    cps_api_object_list_append(param->prev,cloned);

    if (op == cps_api_oper_CREATE) {
        printf("NAS-RT-CPS-SET:In OS Route CREATE ");
        if(nas_os_add_route(obj) != STD_ERR_OK){
            rc = cps_api_ret_code_ERR;
        }
    } else if (op == cps_api_oper_DELETE) {
        printf("NAS-RT-CPS-SET:In OS Route DEL ");
        if(nas_os_del_route(obj) != STD_ERR_OK){
            rc = cps_api_ret_code_ERR;
        }
    } else if (op == cps_api_oper_SET) {
        printf("NAS-RT-CPS-SET:In OS Route SET ");
        if(nas_os_set_route(obj) != STD_ERR_OK){
            rc = cps_api_ret_code_ERR;
        }
    }
    return rc;
}

BASE_ROUTE_OBJ_t nas_route_check_route_key_attr(cps_api_object_t obj) {

    BASE_ROUTE_OBJ_t  default_type = BASE_ROUTE_OBJ_ENTRY;

    /*
     * Route Key
     */
    cps_api_object_attr_t route_af;
    cps_api_object_attr_t prefix;
    cps_api_object_attr_t pref_len;
    /*
     * Nbr Key
     */
    cps_api_object_attr_t nbr_af;
    cps_api_object_attr_t nbr_addr;

    /*
     * Check mandatory key attributes
     */
    route_af     = cps_api_get_key_data(obj, BASE_ROUTE_OBJ_ENTRY_AF);
    prefix       = cps_api_get_key_data(obj, BASE_ROUTE_OBJ_ENTRY_ROUTE_PREFIX);
    pref_len     = cps_api_get_key_data(obj, BASE_ROUTE_OBJ_ENTRY_PREFIX_LEN);
    nbr_af       = cps_api_get_key_data(obj, BASE_ROUTE_OBJ_NBR_AF);
    nbr_addr     = cps_api_get_key_data(obj, BASE_ROUTE_OBJ_NBR_ADDRESS);

    /*
     * If route delete case, check the key mandatory attrs for delete case first
     */

    if  (route_af != CPS_API_ATTR_NULL && prefix != CPS_API_ATTR_NULL &&
         pref_len != CPS_API_ATTR_NULL) {
        return BASE_ROUTE_OBJ_ENTRY;
    } else if ((nbr_af != CPS_API_ATTR_NULL && nbr_addr != CPS_API_ATTR_NULL) ||
            (nbr_addr != CPS_API_ATTR_NULL)){
        return BASE_ROUTE_OBJ_NBR;
    }

    return default_type;
}


static cps_api_return_code_t nas_route_cps_route_set_func(void *ctx,
                             cps_api_transaction_params_t * param, size_t ix) {

    if(param == NULL){
       printf( "NAS-RT-CPS Route Set with no param: "
                 "nas_route_cps_route_set_func");
        return cps_api_ret_code_ERR;
    }

    cps_api_object_t obj = cps_api_object_list_get(param->change_list,ix);
    if (obj==NULL) {
        printf("NAS-RT-CPS nas_route_cps_route_set_func: "
                          "NULL obj");
        return cps_api_ret_code_ERR;
    }

    /*
     * Check for keys in filter either Route Key:BASE_ROUTE_OBJ_ENTRY or
     * Neighbor Key:BASE_ROUTE_OBJ_NBR
     *
     */
    cps_api_return_code_t rc =   cps_api_ret_code_OK;

    switch (nas_route_check_route_key_attr(obj)) {
          case BASE_ROUTE_OBJ_ENTRY:
              //printf("NAS-RT-CPS  nas_route_process_cps_route\n");
              break;

          case BASE_ROUTE_OBJ_NBR:
              //printf("NAS-RT-CPS  nas_route_process_cps_nbr\n");
              break;

          default:
              printf("NAS-RT-CPS base route obj type unknown %d",
                 cps_api_key_get_subcat(cps_api_object_key(obj)));
               rc =     cps_api_ret_code_ERR;
              break;
      }

    return rc;
}

static cps_api_return_code_t nas_route_cps_route_get_func (void *ctx,
                              cps_api_get_params_t * param, size_t ix) {

    printf("NAS-RT-CPS: Route Get function");
    return cps_api_ret_code_OK;
}

static cps_api_return_code_t nas_route_cps_route_rollback_func (void * ctx,
                              cps_api_transaction_params_t * param, size_t ix){

   printf("NAS-RT-CPS:Route Rollback function");
    return cps_api_ret_code_OK;
}


static t_std_error nas_routing_cps_server_init(cps_api_operation_handle_t nas_route_cps_handle ) {

    cps_api_registration_functions_t f;
    char buff[CPS_API_KEY_STR_MAX];

    memset(&f,0,sizeof(f));

    printf("NAS-RT-CPS: NAS Routing CPS Initialization");


    /*
     * Initialize Base Route object Entry
     */



    printf("NAS-RT-CPS: Registering for %s",
            cps_api_key_print(&f.key,buff,sizeof(buff)-1));


    f.handle                 = nas_route_cps_handle;
    f._read_function         = nas_route_cps_route_get_func;
    f._write_function         = nas_route_cps_route_set_func;
    f._rollback_function     = nas_route_cps_route_rollback_func;

   if (!cps_api_key_from_attr_with_qual(&f.key,BASE_ROUTE_OBJ_OBJ,cps_api_qualifier_TARGET)) {
        printf("NAS-RT-CPS: Could not translate %d to key %s",
                (int)(BASE_ROUTE_OBJ_OBJ),cps_api_key_print(&f.key,buff,sizeof(buff)-1));
           return STD_ERR(ROUTE,FAIL,0);
    }

    if (cps_api_register(&f)!=cps_api_ret_code_OK) {
            return STD_ERR(ROUTE,FAIL,0);
        }
    printf( "HAL-RT Registering for CPS for Routing Passed\n");
    return STD_ERR_OK;
}


t_std_error hal_rt_cps_thread(void)
{
    t_std_error     rc = STD_ERR_OK;

    //Create a handle for CPS objects
    if (cps_api_operation_subsystem_init(&nas_route_cps_handle,
            1)!=cps_api_ret_code_OK) {
        printf( "HAL-RT Initializing CPS  subsystem for Routing failed");
        return STD_ERR(CPSNAS,FAIL,0);
    }
        //Initialize CPS for Routing objects
    if((rc = nas_routing_cps_server_init(nas_route_cps_handle)) != STD_ERR_OK) {
        printf( "HAL-RT Initializing CPS for Routing failed");
        return rc;
    }
    printf( "HAL-RT Initializing CPS for Routing Passed\n");
    return STD_ERR_OK;
}

#ifdef __cplusplus
}
#endif


int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);


  hal_rt_cps_thread();

  sleep(10000000);
  return RUN_ALL_TESTS();
}
