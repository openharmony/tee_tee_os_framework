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
    DRVTEST_COMMAND_DRVVIRTTOPHYS = 1,
    DRVTEST_COMMAND_COPYFROMCLIENT,
    DRVTEST_COMMAND_COPYTOCLIENT,
} DrvCmdId;

#define GET_DRV_CMDID(inner) GET_CMD_ID(BASEID_DRVTEST, inner)
