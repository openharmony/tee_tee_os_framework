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

#ifdef __cplusplus
#include <string>
#endif

#define TEST_STR_LEN 256
#define TEST_SIZE512 512
#define SIZE16k ((16) * (1024))
// now not support 9999,so 9999 is invalid
#define TEEC_MEM_INVALID 9999
#define OFFSET100 100
#define OFFSET200 200
#define OFFSET300 300
#define SIZE10 10
#define SIZE20 20

#define CLIENTAPI_UUID_1                                   \
    {                                                      \
        0x534d4152, 0x542d, 0x4353,                        \
        {                                                  \
            0xb9, 0x19, 0xd3, 0x01, 0x6a, 0x17, 0x1f, 0xc5 \
        }                                                  \
    }

#define UUID_TA_NOT_EXIST                                  \
    {                                                      \
        0x534D4152, 0x542D, 0x4353,                        \
        {                                                  \
            0x4C, 0x54, 0x2D, 0x54, 0x41, 0x2D, 0x53, 0x5B \
        }                                                  \
    }

typedef struct SessionContextPacket {
    TEEC_Context *context;
    TEEC_Session *session;
    TEEC_Operation *operation;
    TEEC_SharedMemory *sharedMem;
    uint32_t id;
    TEEC_Result ret;
} DatePacket;
#endif
