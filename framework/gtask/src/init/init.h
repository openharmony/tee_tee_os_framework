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

#ifndef GTASK_INIT_H
#define GTASK_INIT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define SHELL_ENVP_LEN 2
#define MAX_RESPAWNS 3
#define SHELL        "/picosh.elf"

#define RESERVED_SYSMGR_CRED (-1) /* defined in kernel/boot.c create_process() */

int init_main(void);
void init_shell(void);
bool is_sys_task(uint32_t task_id);
uint32_t get_timer_pid(void);
int32_t get_drvmgr_pid(uint32_t *task_id);

#endif
