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

#include <securec.h>
#include <stdlib.h>
#include <string.h>
#include <tee_drv_client.h>
#include <tee_ext_api.h>
#include <tee_log.h>
#include <test_drv_cmdid.h>
#include <mem_ops.h>

#define CA_PKGN_VENDOR "/vendor/bin/tee_test_drv"
#define CA_PKGN_SYSTEM "/system/bin/tee_test_drv"
#define CA_UID 0

#define DRV_UUID1                                          \
    {                                                      \
        0x11112222, 0x0000, 0x0000,                        \
        {                                                  \
            0x00, 0x00, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 \
        }                                                  \
    }

#define BUFFER_SIZE 1024
struct share_buffer_arg {
    uint64_t addr;
    uint32_t len;
    uint32_t share_token;
};

static TEE_Result TeeTestDrive(uint32_t cmd)
{
    int ret;
    const char *drvName = "drv_test_module";
    uint32_t args = (uint32_t)(&drvName);
    const char drvcallerInput[] = "the param is drvcaller_input";
    char drvOutput[] = "DRVMEM_OUTPUT";

    uint32_t drvcallerInputLen = (uint32_t)strlen(drvcallerInput) + 1;
    uint32_t drvOutputLen = (uint32_t)strlen(drvOutput) + 1;
    TEE_UUID uuid = DRV_UUID1;

    int64_t fd = tee_drv_open(drvName, &args, sizeof(args));
    if (fd <= 0) {
        tloge("open %s for get fd failed\n", drvName);
        return TEE_ERROR_GENERIC;
    }

    char *tempBuffer = alloc_sharemem_aux(&uuid, BUFFER_SIZE);
    if (tempBuffer == NULL) {
        tloge("alloc share mem failed\n");
        return TEE_ERROR_GENERIC;
    }
    (void)memset_s(tempBuffer, BUFFER_SIZE, 0x0, BUFFER_SIZE);
    ret = strcpy_s(tempBuffer, drvcallerInputLen, drvcallerInput);
    if (ret != 0) {
        tloge("strcpy_s failed,ret = 0x%x\n", ret);
        return TEE_ERROR_GENERIC;
    }

    struct share_buffer_arg inputArg = { 0 };
#ifndef __aarch64__
    inputArg.addr = (uint64_t)(uint32_t)tempBuffer;
#else
    inputArg.addr = (uint64_t)tempBuffer;
#endif

    inputArg.len = BUFFER_SIZE;

    tlogi("%s drv test ioctl begin args:0x%x fd:%d\n", drvName, inputArg, (int32_t)fd);

    ret = (int)tee_drv_ioctl(fd, cmd, (const void *)(&inputArg), sizeof(inputArg));
    if (ret != 0) {
        tloge("%s drv test ioctl failed, fd:%d \n", drvName, (int32_t)fd);
    }
    if (cmd == DRVTEST_COMMAND_COPYTOCLIENT) {
        if (strncmp(drvOutput, (char *)tempBuffer, drvOutputLen) != 0) {
            tloge("%s drv copy_to_client test failed, fd:%d, heap_buffer is:%s \n", drvName, (int32_t)fd, tempBuffer);
            free_sharemem(tempBuffer, BUFFER_SIZE);
            return TEE_ERROR_GENERIC;
        }
    }

    ret |= (int)tee_drv_close(fd);
    if (ret != 0) {
        tloge("drv test fail!\n");
    }

    if (free_sharemem(tempBuffer, BUFFER_SIZE) != 0) {
        tloge("free sharemem failed\n");
        ret = -1;
    }
    return (TEE_Result)ret;
}

TEE_Result TA_CreateEntryPoint(void)
{
    tlogi("---- TA_CreateEntryPoint ----------- \n");
    TEE_Result ret;

    ret = AddCaller_CA_exec(CA_PKGN_VENDOR, CA_UID);
    if (ret != TEE_SUCCESS) {
        tloge("add caller failed, ret: 0x%x", ret);
        return ret;
    }

    ret = AddCaller_CA_exec(CA_PKGN_SYSTEM, CA_UID);
    if (ret != TEE_SUCCESS) {
        tloge("add caller failed, ret: 0x%x", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t parmType, TEE_Param params[4], void **sessionContext)
{
    (void)parmType;
    (void)sessionContext;
    tlogi("---- TA_OpenSessionEntryPoint -------- \n");
    if (params[0].value.b == 0xFFFFFFFE)
        return TEE_ERROR_GENERIC;
    else
        return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t cmd, uint32_t parmType, TEE_Param params[4])
{
    TEE_Result ret = TEE_SUCCESS;
    (void)sessionContext;
    (void)parmType;
    (void)params;
    tlogi("---- TA invoke command ----------- command id: %u\n", cmd);

    switch (cmd) {
        case DRVTEST_COMMAND_DRVVIRTTOPHYS:
        case DRVTEST_COMMAND_COPYFROMCLIENT:
        case DRVTEST_COMMAND_COPYTOCLIENT:
            ret = TeeTestDrive(cmd);
            if (ret != TEE_SUCCESS)
                tloge("invoke command for driver test failed! cmdId: %u, ret: 0x%x\n", cmd, ret);
            break;
        default:
            tloge("not support this invoke command! cmdId: %u\n", cmd);
            ret = TEE_ERROR_GENERIC;
            break;
    }

    return ret;
}

void TA_CloseSessionEntryPoint(void *sessionContext)
{
    (void)sessionContext;
    tlogi("---- TA_CloseSessionEntryPoint ----- \n");
}

void TA_DestroyEntryPoint(void)
{
    tlogi("---- TA_DestroyEntryPoint ---- \n");
}
