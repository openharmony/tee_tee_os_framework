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
#ifndef DRVMGR_SRC_DRV_FD_OPS_H
#define DRVMGR_SRC_DRV_FD_OPS_H

#include <stdint.h>
#include <pthread.h>
#include "drv_dispatch.h"
#include "drvcall_dyn_conf_mgr.h"

#define TASK_FD_COUNT_MAX 32U

int32_t drv_mutex_lock(pthread_mutex_t *mtx);
int32_t drv_mutex_init(pthread_mutex_t *mtx);
struct fd_node *alloc_and_init_fd_node(void);
int32_t add_fd_to_drvcall_node(struct fd_node *data, struct task_node *node);
int32_t get_fd_count(struct task_node *node);
void put_fd_count(struct task_node *node);
struct fd_node *close_get_fd_node_with_lock(struct task_node *node, int64_t fd);
int32_t del_fd_to_drvcall_node(struct fd_node **fnode, struct task_node *node);

#ifdef TEE_SUPPORT_DYN_CONF_DEBUG
void dump_drvcall_fd(struct task_node *node);
#endif

uint32_t exception_close_handle(struct task_node *node);
#endif
