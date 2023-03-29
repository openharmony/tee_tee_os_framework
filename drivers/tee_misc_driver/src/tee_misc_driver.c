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
#include "tee_log.h"
#include "sys/mman.h"
#include "drv_module.h"
#include "drv_sharedmem.h"
#include "drv_param_type.h"
#include "drv_param_ops.h"
#include "tee_driver_module.h"
#include "boot_sharedmem.h"
#include "tee_oemkey_driver.h"
#include "drv_sharedmem.h"

const char *g_debug_prefix = "tee_misc_driver";
static struct tee_uuid g_current_uuid;

static int32_t init_sharedmem(void)
{
    int32_t ret = sharedmem_addr_init();
    if (ret != 0)
        tloge("init_sharedmem failed\n");
    return 0;
}

static int32_t get_shared_msg(unsigned long args, uint32_t args_len)
{
    int32_t ret;

    if (args_len != sizeof(struct shared_buffer_args)) {
        tloge("invalid input arg args_len:0x%x\n", args_len);
        return -1;
    }

    struct shared_buffer_args *input_arg = (struct shared_buffer_args *)(uintptr_t)args;
    if (input_arg->type_size > TYPE_LEN || input_arg->type_size == 0 ||
        input_arg->buffer_size + sizeof(input_arg->buffer_size) < input_arg->buffer_size) {
        tloge("the size is invalid\n");
        return -1;
    }

    void *type = malloc(input_arg->type_size);
    if (type == NULL)
        return -1;

    (void)memset_s(type, input_arg->type_size, 0, input_arg->type_size);
    ret = copy_from_client((uint64_t)(uintptr_t)input_arg->type_buffer,
                           input_arg->type_size, (uintptr_t)type, input_arg->type_size);
    if (ret != 0) {
        tloge("get type buffer error\n");
        free(type);
        return -1;
    }

    char *buffer = malloc(input_arg->buffer_size + sizeof(input_arg->buffer_size));
    if (buffer == NULL) {
        free(type);
        return -1;
    }

    (void)memset_s(buffer, input_arg->buffer_size + sizeof(input_arg->buffer_size), 0,
                   input_arg->buffer_size + sizeof(input_arg->buffer_size));

    uint32_t size = input_arg->buffer_size;
    ret = get_tlv_shared_mem((char *)type, input_arg->type_size, buffer,
                             &size, input_arg->clear_flag);
    if (ret != TLV_SHAREDMEM_SUCCESS) {
        tloge("get sharedmem error 0x%x\n", ret);
        goto end;
    }

    (void)memcpy_s((buffer + input_arg->buffer_size), sizeof(size), &size, sizeof(size));
    ret = copy_to_client((uintptr_t)buffer, input_arg->buffer_size + sizeof(size),
                         input_arg->buffer, input_arg->buffer_size + sizeof(size));
    if (ret != 0) {
        tloge("copy to client failed\n");
        goto end;
    }
end:
    free(type);
    (void)memset_s(buffer, input_arg->buffer_size + sizeof(size), 0, input_arg->buffer_size + sizeof(size));
    free(buffer);
    return ret;
}

void get_current_caller_uuid(TEE_UUID *uuid)
{
    *uuid = g_current_uuid;
    return;
}

static int64_t open_sharedmem(struct drv_data *drv, unsigned long args, uint32_t args_len)
{
    (void)args;
    (void)args_len;
    if (drv == NULL) {
        tloge("open invalid drv\n");
        return -1;
    }
    return 0;
}

static int64_t ioctl_sharedmem(struct drv_data *drv, uint32_t cmd, unsigned long args, uint32_t args_len)
{
    uint32_t ret = 0;
    if (drv == NULL || args == 0) {
        tloge("ioctl invalid drv\n");
        return -1;
    }

    g_current_uuid = drv->uuid;
    switch (cmd) {
    case IOCTRL_GET_TLV_SHARED_MEM:
        ret = get_shared_msg(args, args_len);
        break;
    case IOCTRL_GET_OEM_KEY:
        ret = get_oemkey_info(args, args_len);
        break;
    default:
        tloge("cmd:0x%x not support\n", cmd);
        return -1;
    }

    return ret;
}

static int64_t close_sharedmem(struct drv_data *drv)
{
    if (drv == NULL) {
        tloge("close invalid drv\n");
        return -1;
    }

    tloge("start close\n");
    return 0;
}

tee_driver_declare(tee_misc_driver, init_sharedmem, open_sharedmem, ioctl_sharedmem, close_sharedmem,
    NULL, NULL, NULL, NULL);
