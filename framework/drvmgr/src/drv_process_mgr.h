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
#ifndef DRVMGR_SRC_DRV_PROCESS_MGR_H
#define DRVMGR_SRC_DRV_PROCESS_MGR_H
#include <stdint.h>
#include <tee_defines.h>
#include "drv_dyn_conf_mgr.h"
#include "task_mgr.h"

#define DRV_ELF_NAME_APPEND 4U /* reserved mem for ".elf" string */
#define DRV_TAFS_APPEND 6 /* reserved mem for "/tafs/" string */
#define DRV_DEFAULT_STACK_SIZE 0x4000
#define WAIT_DRV_MSG_MAX_TIME 2000 /* timeout is ms, 2000ms means 2s */

struct drv_spawn_param {
    struct tee_uuid uuid;
    char drv_name[DRV_NAME_MAX_LEN + DRV_ELF_NAME_APPEND + DRV_TAFS_APPEND];
    uint32_t thread_limit;
    uint32_t heap_size;
    uint32_t stack_size;
    uint32_t drv_index;
};

int32_t create_spawn_sync_msg_info(void);

void drv_kill_task(uint32_t taskid);

void release_driver(struct task_node *node);

int32_t spawn_driver_handle(struct task_node *node);

int32_t register_base_drv_node(void);
#endif
