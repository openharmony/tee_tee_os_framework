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

#ifndef __TEST_TIME_API_FUNC_H__
#define __TEST_TIME_API_FUNC_H__

#include <tee_ext_api.h>

#define MILLISECOND 1000
#define PERSISTENT_TIME_BASE_FILE "sec_storage_data/persistent_time"
#define RESERVED10S 10
#define WAIT5S 5
#define DATE_TIME_LENGTH 30

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

TEE_Result TestTimeApi(uint32_t cmdId, TEE_Param params[4]);
#endif