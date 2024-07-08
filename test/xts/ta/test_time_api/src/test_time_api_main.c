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

#include <tee_ext_api.h>
#include <tee_log.h>
#include <securec.h>
#include <tee_time_api.h>
#include <tee_trusted_storage_api.h>
#include "test_time_api_func.h"

#define CA_VENDOR "/vendor/bin/tee_test_time_api"
#define CA_SYSTEM "/system/bin/tee_test_time_api"
#define CA_DATA "./tee_test_time_api"
#define CA_UID 0

TEE_Result TA_CreateEntryPoint(void)
{
    tlogi("---- TA_CreateEntryPoint ---------");
    TEE_Result ret = AddCaller_CA_exec(CA_VENDOR, CA_UID);
    if (ret != TEE_SUCCESS) {
        tloge("Add caller failed, ret = 0x%x", ret);
        return ret;
    }

    ret = AddCaller_CA_exec(CA_SYSTEM, CA_UID);
    if (ret != TEE_SUCCESS) {
        tloge("Add caller failed, ret = 0x%x", ret);
        return ret;
    }

    ret = AddCaller_CA_exec(CA_DATA, CA_UID);
    if (ret != TEE_SUCCESS) {
        tloge("Add caller failed, ret = 0x%x", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t parmType, TEE_Param params[4], void **sessionContext)
{
    (void)parmType;
    (void)params;
    (void)sessionContext;
    tlogi("---- TA_OpenSessionEntryPoint --------");

    return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t cmdId, uint32_t parmType, TEE_Param params[4])
{
    (void)sessionContext;
    (void)parmType;
    TEE_Result ret = TestTimeApi(cmdId, params);
    if (ret != TEE_SUCCESS)
        tloge("invoke command for value failed! cmdId: %u, ret: 0x%x", cmdId, ret);

    return ret;
}

void TA_CloseSessionEntryPoint(void *sessionContext)
{
    (void)sessionContext;
    tlogi("---- TA_CloseSessionEntryPoint -----");
}

void TA_DestroyEntryPoint(void)
{
    tlogi("---- TA_DestroyEntryPoint ----");
}