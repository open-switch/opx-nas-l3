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

/*!
 * \file   hal_rt_extn.h
 * \brief  Hal routing external header file
 * \date   04-2014
 * \author Prince Sunny and Satish Mynam
 */

#ifndef __HAL_ROUTING_H
#define __HAL_ROUTING_H

#include "std_error_codes.h"

/*!
 *  \fn      int hal_rt_init(void)
 *  \brief   Init function for HAL routing
 *  \warning none
 *  \param   void
 *  \return  success 0/failure -1
 *  \sa
 */
t_std_error hal_rt_init(void);

#endif
