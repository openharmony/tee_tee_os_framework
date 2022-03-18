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

#include <base_cmdid.h>
#include <test_defines.h>

typedef enum {
    TEE_TEST_VALUE = 0,
    TEE_TEST_BUFFER,
    TEE_TEST_ALLTYPE,
    TEE_TEST_WRITE_OVERFOLW,
} CommCmdId;

#define GET_COMM_CMDID(inner) GET_CMD_ID(BASEID_COMMUNICATION, inner)
