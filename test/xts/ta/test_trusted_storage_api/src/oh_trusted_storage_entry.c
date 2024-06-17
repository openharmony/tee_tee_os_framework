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

#include "tee_ext_api.h"
#include "cases_entry.h"

#define SYSTEM_OH_TRUSTED_STORAGE "/system/bin/tee_test_store_api"
#define VENDOR_OH_TRUSTED_STORAGE "/vendor/bin/tee_test_store_api"
#define TEST_STORAGE_UID 0

// TA_INVOKE_CMD
enum {
    CMD_RUN_BY_FUN_SEQ = 0,
};

TEE_Result TA_CreateEntryPoint(void)
{
    tlogi("%s:start add caller info success\n", __func__);
    TEE_Result ret;

    ret = AddCaller_CA_exec(VENDOR_OH_TRUSTED_STORAGE, TEST_STORAGE_UID);
    if (ret != TEE_SUCCESS)
        return ret;
    ret = AddCaller_CA_exec(SYSTEM_OH_TRUSTED_STORAGE, TEST_STORAGE_UID);
    if (ret != TEE_SUCCESS)
        return ret;

    tlogi("%s:end add caller info success\n", __func__);
    return TEE_SUCCESS;
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param params[4], void **sessionContext)
{
    (void)paramTypes;
    (void)params;
    (void)sessionContext;
    tlogi("in %s\n", __func__);
    return TEE_SUCCESS;
}

#include <string.h>
char object_id1[] = "sec_storage_data/testfile";  //save in temporary partition
char rename_object_id1[] = "sec_storage_data/testfile_re";  //save in temporary partition

char object_init_data1[] = "Randomly assign a string of ints";


TEE_Result TA_InvokeCommandEntryPoint(void *session_context, uint32_t cmd_id, uint32_t paramTypes, TEE_Param params[4])
{
    (void)session_context;
    // check params
    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_MEMREF_INOUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        tloge("%s:error, invalid param_types\n", __func__);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    tlogi("%s:cmd_id is %d\n", __func__, cmd_id);

    int ret;
    switch (cmd_id) {
        case CMD_RUN_BY_FUN_SEQ: {
            ret = RunCaseEntryByName((const char *)params[0].memref.buffer, 1, 0);
            if (ret != 0) {
                tloge("[%s]:RunCaseEntryByName fail\n", __func__);
                return TEE_ERROR_GENERIC;
            }
            tlogi("[%s]:RunCaseEntryByName success\n", __func__);
            return 0;
        }
        default:
            return 0;
    }
}

void TA_CloseSessionEntryPoint(void *session_context)
{
    (void)session_context;
    tlogi("in %s.\n", __func__);
}

void TA_DestroyEntryPoint(void)
{
    tlogi("in %s.\n", __func__);
}