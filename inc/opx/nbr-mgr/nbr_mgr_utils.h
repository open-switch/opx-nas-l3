/*
 * Copyright (c) 2018 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * THIS CODE IS PROVIDED ON AN  *AS IS* BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 * LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 * FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
 *
 * See the Apache Version 2.0 License for specific language governing
 * permissions and limitations under the License.
 */

/*
 * filename: nbr_mgr_utils.h
 *
 */

#ifndef _NBR_MGR_UTILS_H_
#define _NBR_MGR_UTILS_H_

#include "ds_common_types.h"
#include <string>

#define NBR_MGR_MAC_STR_LEN 20

std::string nbr_mac_addr_string (const hal_mac_addr_t& mac);
std::string nbr_ip_addr_string (const hal_ip_addr_t& ip);

#endif
