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

#include "tee_compat_check.h"
#include "tee_log.h"

void generate_teeos_compat_level(uint32_t *buffer, uint32_t size)
{
    if (buffer == NULL || size != COMPAT_LEVEL_BUF_LEN) {
        tloge("get compat level failed, param invalid\n");
        return;
    }

    buffer[0] = VER_CHECK_MAGIC_NUM;
    buffer[1] = TEEOS_COMPAT_LEVEL_MAJOR;
    buffer[2] = TEEOS_COMPAT_LEVEL_MINOR;
    return;
}
