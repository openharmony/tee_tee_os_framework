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

#include <malloc.h>
#include <securec.h>
#include <string.h>
#include <sys/mman.h>

#include "drv_addr_share.h"
#include "drv_param_ops.h"
#include "drv_test_module.h"
#include "tee_log.h"
#include "test_drv_cmdid.h"

#define TOKEN_BUF_SIZE 0x1000
#define BUFFER_SIZE 1024

const char *g_log_tag = "[32-1 drv] ";

static int64_t virt2phys_test()
{
    uint64_t va;
    uint64_t pa = drv_virt_to_phys((uintptr_t)&va);
    if (pa == 0) {
        driver_log("drv virt_to phys failed\n");
        return -1;
    }

    driver_log("drv virt_to phys success\n");
    return 0;
}

static int32_t copy_from_client_exception_test(struct share_buffer_arg *input_arg, char *temp_buffer)
{
    driver_log("copy from client exception test begin\n");
    int32_t ret = copy_from_client(0, input_arg->len, (uintptr_t)temp_buffer, input_arg->len);
    ret &= copy_from_client(input_arg->addr, 0, (uintptr_t)temp_buffer, input_arg->len);
    ret &= copy_from_client(input_arg->addr, input_arg->len, 0, input_arg->len);
    ret &= copy_from_client(input_arg->addr, input_arg->len, (uintptr_t)temp_buffer, 0);
    ret &= copy_from_client(input_arg->addr, input_arg->len, (uintptr_t)temp_buffer, input_arg->len - 1);
    if (ret == 0) {
        driver_log("copy from client exception test FAIL\n");
        return -1;
    }

    driver_log("copy from client exception test SUCC\n");
    return 0;
}

static int32_t copy_from_client_test(struct share_buffer_arg *input_arg, char *temp_buffer, uint32_t size)
{
    driver_log("copy from client test begin\n");
    int32_t ret;
    char drvcaller_input[] = "the param is drvcaller_input";
    uint32_t drvcaller_input_len;
    drvcaller_input_len = strlen(drvcaller_input) + 1;

    ret = copy_from_client(input_arg->addr, input_arg->len, (uintptr_t)temp_buffer, size);
    if (ret != 0 || strncmp(drvcaller_input, (char *)temp_buffer, drvcaller_input_len) != 0 ||
        input_arg->len != BUFFER_SIZE) {
        driver_log("test copy_from_client failed,ret = 0x%x, received buffer is: %s, received lens is: %d\n", ret,
            temp_buffer, input_arg->len);
        return -1;
    }

    if (copy_from_client_exception_test(input_arg, temp_buffer) != 0) {
        return -1;
    }
    return ret;
}

static int32_t copy_to_client_exception_test(struct share_buffer_arg *input_arg, char *temp_buffer)
{
    driver_log("copy to client exception test begin\n");
    int32_t ret = copy_to_client(0, input_arg->len, input_arg->addr, input_arg->len);
    ret &= copy_to_client((uintptr_t)temp_buffer, 0, input_arg->addr, input_arg->len);
    ret &= copy_to_client((uintptr_t)temp_buffer, input_arg->len, 0, input_arg->len);
    ret &= copy_to_client((uintptr_t)temp_buffer, input_arg->len, input_arg->addr, 0);
    ret &= copy_to_client((uintptr_t)temp_buffer, input_arg->len, input_arg->addr, input_arg->len - 1);
    if (ret == 0) {
        driver_log("copy to client exception test FAIL\n");
        return -1;
    }

    driver_log("copy to client exception test SUCC\n");
    return 0;
}

static int32_t copy_to_client_test(struct share_buffer_arg *input_arg, char *temp_buffer, uint32_t size)
{
    driver_log("copy to client test begin\n");
    int32_t ret;
    static char drv_output[] = "DRVMEM_OUTPUT";
    uint32_t drv_output_len;
    drv_output_len = strlen(drv_output) + 1;
    ret = strcpy_s(temp_buffer, drv_output_len, drv_output);
    if (ret != 0) {
        driver_log("strcpy_s failed,ret = 0x%x\n", ret);
        return -1;
    }

    ret = copy_to_client((uintptr_t)temp_buffer, size, input_arg->addr, input_arg->len);
    if (ret != 0) {
        driver_log("test copy_to_client failed,ret = 0x%x\n", ret);
        return -1;
    }

    if (copy_to_client_exception_test(input_arg, temp_buffer) != 0) {
        return -1;
    }
    return ret;
}

int32_t init_test(void)
{
    driver_log("driver init test end\n");
    return 0;
}

int64_t ioctl_test(struct drv_data *drv, uint32_t cmd, unsigned long args, uint32_t args_len)
{
    (void)args;
    (void)args_len;
    int64_t ret = 0;
    if (drv == NULL) {
        driver_log("ioctl invalid drv\n");
        return -1;
    }

    struct share_buffer_arg *input_arg = (struct share_buffer_arg *)args;
    uint32_t size = input_arg->len;
    char *temp_buffer = malloc(size);
    if (temp_buffer == NULL) {
        driver_log("malloc temp buffer failed\n");
        return -1;
    }
    (void)memset_s(temp_buffer, size, 0x0, size);

    switch (cmd) {
        case DRVTEST_COMMAND_DRVVIRTTOPHYS:
            ret = virt2phys_test();
            break;
        case DRVTEST_COMMAND_COPYFROMCLIENT:
            ret = copy_from_client_test(input_arg, temp_buffer, size);
            break;
        case DRVTEST_COMMAND_COPYTOCLIENT:
            ret = copy_to_client_test(input_arg, temp_buffer, size);
            break;
        default:
            driver_log("cmd:0x%x not support\n", cmd);
            free(temp_buffer);
            return -1;
    }

    free(temp_buffer);
    return ret;
}

static uint32_t *buf_init(uint32_t args)
{
    uint32_t *buf = (uint32_t *)malloc(TOKEN_BUF_SIZE * sizeof(uint32_t));
    if (buf == NULL) {
        driver_log("alloc buf failed\n");
        return NULL;
    }
    (void)memset_s(buf, TOKEN_BUF_SIZE * sizeof(uint32_t), 0x0, TOKEN_BUF_SIZE * sizeof(uint32_t));

    int32_t i;
    for (i = 0; i < TOKEN_BUF_SIZE; i++)
        buf[i] = args;

    return buf;
}

int64_t open_test(struct drv_data *drv, unsigned long args, uint32_t args_len)
{
    if (drv == NULL) {
        driver_log("open invalid drv\n");
        return -1;
    }

    if (args == 0 && args_len == 0) {
        driver_log("input NULL param\n");
        return 0;
    }

    if (args_len < sizeof(uint32_t) || args == 0) {
        driver_log("open invalid drv\n");
        return -1;
    }

    char open_succ[10] = { "hello" };
    driver_log("%s", open_succ);

    uint32_t *input = (uint32_t *)(uintptr_t)args;
    if (*input == UINT32_MAX) {
        driver_log("open test input args is UINT32_MAX, just retrun -1\n");
        return -1;
    }

    uint32_t *buf = buf_init(*input);
    if (buf == NULL) {
        return -1;
    }
    drv->private_data = buf;
    driver_log("driver open test begin: fd=%d args=0x%x", drv->fd, *input);

    return 0;
}

int64_t close_test(struct drv_data *drv)
{
    if (drv == NULL) {
        driver_log("close invalid drv\n");
        return -1;
    }

    driver_log("driver close test begin: fd:%d", drv->fd);
    if (drv->private_data != NULL) {
        driver_log("free private data in close\n");
        free(drv->private_data);
        drv->private_data = NULL;
    }

    return 0;
}

int32_t suspend_test(void)
{
    driver_log("suspend test begin\n");
    return 0;
}

int32_t resume_test(void)
{
    driver_log("resume test begin\n");
    return 0;
}

int32_t suspend_s4_test(void)
{
    driver_log("suspend_s4 test begin\n");
    return 0;
}

int32_t resume_s4_test(void)
{
    driver_log("resume_s4 test begin\n");
    return 0;
}

tee_driver_declare(drv_test_module, init_test, open_test, ioctl_test, close_test, suspend_test, resume_test,
    suspend_s4_test, resume_s4_test);
