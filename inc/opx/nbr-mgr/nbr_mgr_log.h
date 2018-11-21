/*
 * Copyright (c) 2016 Dell Inc.
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
 * filename: nbr_mgr_log.h
 *
 */

#ifndef _NBR_MGR_LOG_H_
#define _NBR_MGR_LOG_H_

#include "event_log.h"
#define NBR_MGR_LOG_EMERG(ID, ...) EV_LOGGING(NBR_MGR, EMERG, ID, __VA_ARGS__)
#define NBR_MGR_LOG_ALERT(ID, ...) EV_LOGGING(NBR_MGR, ALERT, ID, __VA_ARGS__)
#define NBR_MGR_LOG_CRIT(ID, ...) EV_LOGGING(NBR_MGR, CRIT, ID, __VA_ARGS__)
#define NBR_MGR_LOG_ERR(ID, ...) EV_LOGGING(NBR_MGR, ERR, ID, __VA_ARGS__)
#define NBR_MGR_LOG_WARN(ID, ...) EV_LOGGING(NBR_MGR, WARN, ID, __VA_ARGS__)
#define NBR_MGR_LOG_NOTICE(ID, ...) EV_LOGGING(NBR_MGR, NOTICE, ID, __VA_ARGS__)
#define NBR_MGR_LOG_INFO(ID, ...) EV_LOGGING(NBR_MGR, INFO, ID, __VA_ARGS__)
#define NBR_MGR_LOG_DEBUG(ID, ...) EV_LOGGING(NBR_MGR, DEBUG, ID, __VA_ARGS__)
#define NBR_MGR_EXT_LOG_INFO(ID, ...) EV_LOGGING(NBR_MGR_EXT, INFO, ID, __VA_ARGS__)

#endif
