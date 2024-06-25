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

#define DEVICE_API_UUID                                    \
    {                                                      \
        0x634D4152, 0x542D, 0x4353,                        \
        {                                                  \
            0x4C, 0x54, 0xd3, 0x01, 0x6a, 0x17, 0x1f, 0x11 \
        }                                                  \
    }

enum TEST_DEVICE_API_CMD_ID {
    CMD_ID_TEST_SE_API = 0,
    CMD_ID_TEST_SECHANNELSELECTNEXT_API = 1,
    CMD_ID_TEST_SESECURECHANNELOPENCLOSE_API = 2,
    CMD_ID_TEST_TUI_API = 3,
    CMD_ID_TEST_RPMB_API = 4,
    CMD_ID_TEST_HUK_API = 5,
};

#endif
