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
 * filename: nbr_mgr_main.cpp
 */

#include "nbr_mgr_main.h"
#include "nbr_mgr_msgq.h"
#include "std_thread_tools.h"

#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <signal.h>             /* signal() */
#include <systemd/sd-daemon.h>  /* sd_notify() */
#include <stdbool.h>            /* bool, true, false */

static std_thread_create_param_t nbr_mgr_resolve_thr;
static std_thread_create_param_t nbr_mgr_delay_resolve_thr;
static std_thread_create_param_t nbr_mgr_instant_resolve_thr;

bool nbr_mgr_init() {
    /* Create message queues for nbr mgr threads communication */
    if (nbr_mgr_msgq_create() == false) return false;
    /* Init CPS for sending/receiving the CPS messages with external modules like NAS-L3 */
    if (nbr_mgr_cps_init() == false) return false;
    /* Init Process thread for processing all the nbr manager messages */
    nbr_mgr_process_main();

    /* Thread to process the messages from Q (posted by netlink thread (kernel)
     * and (CPS thread) NAS-L3) */
    std_thread_init_struct(&nbr_mgr_resolve_thr);
    nbr_mgr_resolve_thr.name = "nbr_mgr_rslv";
    nbr_mgr_resolve_thr.thread_function = (std_thread_function_t)nbr_mgr_resolve_main;
    if (std_thread_create(&nbr_mgr_resolve_thr)!=STD_ERR_OK) {
        return false;
    }

    /* Thread to read message from delay resolution Q (pushed by process thread) and
     * on delay time expiry, remove the blackhole in the NPU thru NAS-L3 to control
     * the DoS attack with the invalid destinations */
    std_thread_init_struct(&nbr_mgr_delay_resolve_thr);
    nbr_mgr_delay_resolve_thr.name = "nbr_mgr_drslv";
    nbr_mgr_delay_resolve_thr.thread_function = (std_thread_function_t)nbr_mgr_delay_resolve_main;
    if (std_thread_create(&nbr_mgr_delay_resolve_thr)!=STD_ERR_OK) {
        return false;
    }

    /* Thread to process the messages instantly (instead of rate-limit) from Q to get the response
     * from kernel quickly with ARP/Nbr failed state in the interface oper. down scenario. */
    std_thread_init_struct(&nbr_mgr_instant_resolve_thr);
    nbr_mgr_instant_resolve_thr.name = "nbr_mgr_irslv";
    nbr_mgr_instant_resolve_thr.thread_function = (std_thread_function_t)nbr_mgr_instant_resolve_main;
    if (std_thread_create(&nbr_mgr_instant_resolve_thr)!=STD_ERR_OK) {
        return false;
    }


#if 0 /* Enable this if netlink events get-all is supported in the NAS-linux */
    /* Get all the NHs to be resolved from NAS-L3 */
    nbr_mgr_get_all_nh(HAL_INET4_FAMILY);
    nbr_mgr_get_all_nh(HAL_INET6_FAMILY);
#endif
    return true;
}

volatile static bool shutdwn = false;
/************************************************************************
 *
 * Name: sigterm_hdlr
 *
 *      This function is to handle the SIGTERM signal
 *
 * Input: Integer signo
 *
 * Return Values: None
 * -------------
 *
 ************************************************************************/
static void sigterm_hdlr(int signo)
{
    /* Avoid system calls at all cost */
    shutdwn = true;
}

/* Nbr Mgr process entry function */
int main() {
    (void)signal(SIGTERM, sigterm_hdlr);

    if (!nbr_mgr_init()) {
        exit(1);
    }

    /* Service is in ready state */
    sd_notify(0, "READY=1");

    /* @@TODO threads join to be done */
    while (!shutdwn) {
        pause();
    }

    /* Let systemd know we got the shutdwn request
     * and that we're in the process of shutting down */
    sd_notify(0, "STOPPING=1");
    exit(EXIT_SUCCESS);
}
