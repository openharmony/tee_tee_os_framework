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
#include <stdio.h>
#include <inttypes.h>
#include <priorities.h>
#include <fileio.h>
#include "tee_driver_module.h"
#include "crypto_mgr_syscall.h"
#include <tee_log.h>
#include "drv_random.h"
#include "crypto_driver_adaptor.h"

const char *g_debug_prefix = "crypto_mgr";
uint8_t *g_src_ctx_buf = NULL;
uint8_t *g_dest_ctx_buf = NULL;
static int32_t g_src_fd = 0;
static int32_t g_dest_fd = 0;

#define TYPE_DRV_OPEN   2

int32_t crypto_mgr_init(void)
{
    return 0;
}

uint8_t *get_ctx_ctx_buf(void)
{
    return g_src_ctx_buf;
}

static int32_t crypto_ioctl_alloc_ctx_buf(struct drv_data *drv, uint32_t cmd, unsigned long args, uint32_t args_len)
{
    uint32_t ctx_size = crypto_ioctl_func(drv, IOCTRL_CRYPTO_GET_CTX_SIZE, args, args_len);
    bool check = ((ctx_size <= 0) || (ctx_size > MAX_CRYPTO_CTX_SIZE));
    if (check) {
        tloge("Get ctx size failed, ctx size=%d\n", ctx_size);
        return CRYPTO_BAD_PARAMETERS;
    }
    uint8_t *ctx_buffer = (uint8_t *)malloc((size_t)ctx_size);
    if (ctx_buffer == NULL) {
        tloge("Malloc ctx buffer failed, ctx size=%d\n", ctx_size);
        return CRYPTO_OVERFLOW;
    }
    if (memset_s(ctx_buffer, (size_t)ctx_size, 0, (size_t)ctx_size) != EOK) {
        tloge("memset ctx buffer failed\n");
        free(ctx_buffer);
        return CRYPTO_ERROR_SECURITY;
    }

    drv->private_data = ctx_buffer;
    if (cmd == 0) {
        g_src_ctx_buf = ctx_buffer;
        g_src_fd = drv->fd;
    } else {
        g_dest_ctx_buf = ctx_buffer;
        g_dest_fd = drv->fd;
    }

    return CRYPTO_SUCCESS;
}

int64_t crypto_mgr_ioctl(struct drv_data *drv, uint32_t cmd, unsigned long args, uint32_t args_len)
{
    if (drv == NULL) {
        tloge("ioctl invalid drv\n");
        return -1;
    }
    int32_t ret;
    if (cmd == IOCTRL_CRYPTO_CTX_COPY) {
        ret = crypto_ioctl_alloc_ctx_buf(drv, cmd, args, args_len);
        if (ret != CRYPTO_SUCCESS) {
            tloge("crypto_ioctl_alloc_ctx_buf fail\n");
            return -1;
        }
    }
    ret = crypto_ioctl_func(drv, cmd, args, args_len);

    tlogi("mgr ioctl load 0x%x ret 0x%x\n", cmd, ret);

    return ret;
}

int64_t crypto_mgr_open(struct drv_data *drv, unsigned long args, uint32_t args_len)
{
    if (drv == NULL) {
        tloge("open invalid drv\n");
        return -1;
    }

    if (args == 0 && args_len == 0)
        return 0;

    if (args_len < sizeof(uint32_t) || args == 0) {
        tloge("open invalid drv\n");
        return -1;
    }

    /* get the drv ability */
    if (args_len == sizeof(uint32_t) + TYPE_DRV_OPEN) {
        int32_t ret = crypto_ioctl_alloc_ctx_buf(drv, 0, args, sizeof(uint32_t));
        if (ret != CRYPTO_SUCCESS)
            return -1;
    }

    return 0;
}

int64_t crypto_mgr_close(struct drv_data *drv)
{
    if (drv == NULL) {
        tloge("close invalid drv\n");
        return -1;
    }

    if (drv->private_data != NULL) {
        free(drv->private_data);
        drv->private_data = NULL;
        if (g_src_fd == drv->fd) {
            if (g_dest_ctx_buf == NULL) {
                g_src_ctx_buf = NULL;
                g_src_fd = 0;
            } else {
                g_src_ctx_buf = g_dest_ctx_buf;
                g_dest_ctx_buf = NULL;
                g_src_fd = g_dest_fd;
                g_dest_fd = 0;
            }
        }
    }

    return 0;
}

int32_t crypto_mgr_suspend(void)
{
    tlogd("crypto_mgr_suspend\n");
    return crypto_ioctl_suspend();
}

int32_t crypto_mgr_resume(void)
{
    tlogd("crypto_mgr_resume\n");
    return crypto_ioctl_resume();
}

tee_driver_declare(crypto_mgr, crypto_mgr_init, crypto_mgr_open, crypto_mgr_ioctl, crypto_mgr_close, \
                   crypto_mgr_suspend, crypto_mgr_resume, NULL, NULL);
