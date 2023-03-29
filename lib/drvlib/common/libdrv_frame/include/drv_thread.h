/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#ifndef PLATDRV_DRV_THREAD_H
#define PLATDRV_DRV_THREAD_H
#include <alltypes.h>
#include <drv.h>

#define DRV_CALL_OK      0
#define DRV_CALL_ERROR  (-1)
intptr_t driver_dispatch(void *msg, cref_t *p_msg_hdl, struct hmcap_message_info *info);

#define DRV_THREAD_MAX 8
#define INVALID_CALLER_PID (-1)
#define TASK_MAX 20
#define REPLY_BUF_LEN 2048U
#define ULL_PERMISSIONS 0x0

struct syscaller_info {
    tid_t current_thread;
    pid_t caller_pid;
    uint64_t job_handler;
};

int32_t drv_thread_init(const char *name, uint32_t stack_size, uint32_t thread_limit);
int32_t multi_drv_framwork_init(uint32_t thread_limit, uint32_t stack_size, cref_t channel);
void update_callerpid_by_tid(tid_t tid, pid_t caller_pid);
int32_t get_callerpid_by_tid(tid_t tid, pid_t *caller_pid);
void update_caller_info_by_tid(tid_t tid, pid_t caller_pid, uint64_t job_handler);
int32_t get_callerpid_and_job_handler_by_tid(tid_t tid, pid_t *caller_pid, uint64_t *job_handler);
#endif
