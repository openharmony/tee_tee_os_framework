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

#ifndef TEEOS_UUID_H
#define TEEOS_UUID_H

#define TEE_SERVICE_SYSTEM                              \
{                                                      \
    0x00000000, 0x0000, 0x0000,                        \
    {                                                  \
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 \
    }                                                  \
}

#define TEE_SERVICE_ALL                                \
{                                                      \
    0xFFFFFFFF, 0xFFFF, 0xFFFF,                        \
    {                                                  \
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF \
    }                                                  \
}

#define NODE_LEN 8
typedef struct tee_uuid {
    uint32_t timeLow;
    uint16_t timeMid;
    uint16_t timeHiAndVersion;
    uint8_t clockSeqAndNode[NODE_LEN];
} TEE_UUID;

#endif
