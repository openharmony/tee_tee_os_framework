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

#ifndef TEE_COMPAT_CHECK_H
#define TEE_COMPAT_CHECK_H

#include "tee_defines.h"

/*
 * this version number MAJOR.MINOR is used
 * to identify the compatibility of tzdriver and teeos
 */
#define TEEOS_COMPAT_LEVEL_MAJOR 2
#define TEEOS_COMPAT_LEVEL_MINOR 0

#define VER_CHECK_MAGIC_NUM 0x5A5A5A5A
#define COMPAT_LEVEL_BUF_LEN 12

void generate_teeos_compat_level(uint32_t *buffer, uint32_t size);
#endif
