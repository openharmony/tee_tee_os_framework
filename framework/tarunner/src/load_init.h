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
#ifndef TA_MT_LOAD_INIT_H
#define TA_MT_LOAD_INIT_H

#include <stdint.h>

#define DECIMAL_BASE 10

int32_t get_priority(void);
int32_t extend_utables(void);
void clear_libtee(void);
void *get_libtee_handle(void);
void *ta_mt_dlopen(const char *name, int32_t flag);

#endif
