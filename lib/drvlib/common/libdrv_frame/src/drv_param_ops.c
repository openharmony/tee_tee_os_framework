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

#include "drv_param_ops.h"
#include <stdio.h>
#include <drv_thread.h>
#include <tee_log.h>
#include <unistd.h>
#include <tee_sharemem_ops.h>

static int32_t get_drv_caller_taskid(uint32_t *taskid)
{
    tid_t tid;
    pid_t caller_pid;

    tid = gettid();
    if (tid < 0) {
        tloge("get tid failed\n");
        return -1;
    }

    int32_t ret = get_callerpid_by_tid(tid, &caller_pid);
    if (ret != 0) {
        tloge("get tid:0x%x caller pid failed\n", tid);
        return -1;
    }

    *taskid = (uint32_t)caller_pid;
    return 0;
}

int32_t copy_from_client(uint64_t src, uint32_t src_size, uintptr_t dst, uint32_t dst_size)
{
    uint32_t taskid;
    int32_t ret = get_drv_caller_taskid(&taskid);
    if (ret != 0)
        return -1;

    /* Parameters are checked in copy_from_sharemem */
    ret = copy_from_sharemem(taskid, src, src_size, dst, dst_size);
    if (ret != 0) {
        tloge("copy from task:0x%x failed\n", taskid);
        return -1;
    }

    return 0;
}

int32_t copy_to_client(uintptr_t src, uint32_t src_size, uint64_t dst, uint32_t dst_size)
{
    uint32_t taskid;
    int32_t ret = get_drv_caller_taskid(&taskid);
    if (ret != 0)
        return -1;

    /* Parameters are checked in copy_to_sharemem */
    ret = copy_to_sharemem(src, src_size, taskid, dst, dst_size);
    if (ret != 0) {
        tloge("copy to task:0x%x failed\n", taskid);
        return -1;
    }

    return 0;
}
