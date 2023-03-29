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
#include <tee_defines.h>
#include <tee_log.h>
#include "ta_load_key.h"

bool is_wb_protecd_ta_key(void)
{
    return false;
}

TEE_Result get_ta_load_key(struct key_data *key)
{
    (void)key;

    tloge("not support TA encrypt\n");
    return TEE_ERROR_BAD_PARAMETERS;
}
