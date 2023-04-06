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
#ifndef GTASK_PARA_CONFIG_H
#define GTASK_PARA_CONFIG_H

#include <stdint.h>

#define HASH_FILE_MAX_SIZE (16 * 1024)
#define MAILBOX_POOL_SIZE  (4 * 1024 * 1024)

uint32_t get_hashfile_max_size(void);

uint32_t get_mailbox_size(void);
#endif
