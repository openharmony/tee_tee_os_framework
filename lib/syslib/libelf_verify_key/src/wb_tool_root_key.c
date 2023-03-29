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
#include "ta_load_key.h"

#include <tee_defines.h>
#include <tee_log.h>
#include <securec.h>
#ifdef CONFIG_GENERIC_LOAD_KEY
#include "wb_tool_128_root_key.h"
#endif

TEE_Result get_wb_tool_key(struct wb_tool_key *tool_key)
{
    if (tool_key == NULL) {
        tloge("check tool key params error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    tloge("error wb tool version: %d\n", tool_key->tool_ver);
    return TEE_ERROR_BAD_PARAMETERS;
}
