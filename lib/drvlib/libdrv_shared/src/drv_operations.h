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
#ifndef DRVMGR_SRC_DRV_FD_MANAGER_H
#define DRVMGR_SRC_DRV_FD_MANAGER_H

#include <dlist.h>
#include <stdint.h>
#include <pthread.h>
#include "tee_driver_module.h"
#include "drv_dispatch.h"

#define TASK_FD_COUNT_MAX 32U

#define CALLER_TASKID_INDEX 4

struct fd_data {
    struct dlist_node data_list;
    uint64_t cmd_perm;
    pthread_mutex_t ref_mtx;
    pthread_cond_t ref_cond;
    uint32_t ref_cnt; /* locked by ref_mtx */
    struct drv_data drv;
};

struct drv_task {
    struct dlist_node task_list;
    uint32_t task_pid;
    uint32_t task_count; /* locked by task_mtx */
    struct dlist_node data_head; /* fd_data list head */
    pthread_mutex_t task_mtx;
    uint32_t ref_cnt; /* locked by g_drv_mtx */
};

int64_t driver_open(const struct tee_drv_param *params, const struct tee_driver_module *drv_func);
int64_t driver_ioctl(uint64_t fd, struct tee_drv_param *params,
    const struct tee_driver_module *drv_func, int64_t *fn_ret);
int64_t driver_close(uint64_t fd, const struct tee_drv_param *params);
int32_t driver_close_by_pid(uint32_t pid);
void driver_dump(void);
int32_t drv_mutex_lock(pthread_mutex_t *mtx);
int32_t driver_register_cmd_perm(const struct tee_drv_param *params, int64_t *ret_val);
#endif
