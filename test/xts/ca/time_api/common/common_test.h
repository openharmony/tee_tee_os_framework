/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef __COMMON_TEST_H__
#define __COMMON_TEST_H__

#include <stdint.h>
#include <tee_client_type.h>

#define TIME_API_UUID                                \
    {                                                      \
        0xe7d4c078, 0xb19f, 0x4f97,                        \
        {                                                  \
            0xa2, 0x2d, 0xf4, 0xaf, 0xd6, 0xae, 0x7a, 0x0e \
        }                                                  \
    }

#define DATE_TIME_LENGTH 30
#define PRESET_ZERO "000000000000000000000000000000"

enum TEST_TIME_API_CMD_ID {
    CMD_ID_TEST_GET_SYSTEM_TIME = 0,
    CMD_ID_TEST_GET_REE_TIME,
    CMD_ID_TEST_TEE_WAIT,
    CMD_ID_ONLY_GET_PERSISTENT_TIME,
    CMD_ID_TEST_GET_PERSISTENT_TIME,
    CMD_ID_TEST_SET_PERSISTENT_TIME, // 5
    CMD_ID_TEST_PERSISTENT_TIME_WITH_EXCEPTION,
    CMD_ID_TEST_GET_REE_TIME_STR,
    CMD_ID_TEST_GET_SECURE_RTC_TIME,
    CMD_ID_TEST_OPERATE_TIMER,
};

#endif
