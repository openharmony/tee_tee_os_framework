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
#ifndef DRV_PARAM_OPS_H
#define DRV_PARAM_OPS_H

#include <stdint.h>

int32_t copy_from_client(uint64_t src, uint32_t src_size, uintptr_t dst, uint32_t dst_size);
int32_t copy_to_client(uintptr_t src, uint32_t src_size, uint64_t dst, uint32_t dst_size);
#endif
