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
#include "tee_drv_client.h"
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <malloc.h>
#include <securec.h>
#include <tee_log.h>
#include <drv.h>
#include <ipclib.h>
#include "tee_drv_internal.h"
#include "tee_drv_errno.h"

#if defined(TEE_SUPPORT_DRV_SERVER_64BIT) || defined(TEE_SUPPORT_DRV_SERVER_32BIT)
static int64_t tee_drv_close_handle(int64_t fd);

static struct dlist_node g_drv_channel = dlist_head_init(g_drv_channel);
static pthread_mutex_t g_drv_channel_mtx = PTHREAD_MUTEX_INITIALIZER;

static int32_t drv_mutex_lock(pthread_mutex_t *channel_mtx)
{
    int32_t ret = pthread_mutex_lock(channel_mtx);
    if (ret == EOWNERDEAD)
        return pthread_mutex_consistent(channel_mtx);

    return ret;
}

static struct drv_channel *alloc_and_init_channel(const char *drv_name, int64_t fd)
{
    struct drv_channel *new_ch = malloc(sizeof(*new_ch));
    if (new_ch == NULL) {
        tloge("alloc drv channel failed\n");
        return NULL;
    }

    if (memcpy_s(new_ch->drv_name, sizeof(new_ch->drv_name), drv_name, strlen(drv_name) + 1) != 0) {
        tloge("copy drv name:%s failed\n", drv_name);
        free(new_ch);
        return NULL;
    }

    cref_t ch;
    int32_t ret = ipc_get_ch_from_path(drv_name, &ch);
    if (ret != 0) {
        tloge("get drv:%s channel fail ret:0x%x\n", drv_name, ret);
        free(new_ch);
        return NULL;
    }

    tlogd("alloc drv:%s channel\n", drv_name);
    new_ch->ref_cnt = 1;
    new_ch->drv_index = (uint32_t)(((uint64_t)fd >> DRV_INDEX_OFFSET) & DRV_INDEX_MASK);
    new_ch->drv_channel = ch;
    dlist_init(&new_ch->drv_list);

    return new_ch;
}

static struct drv_channel *find_drv_channel(int64_t fd)
{
    struct dlist_node *pos = NULL;
    struct drv_channel *temp = NULL;
    struct drv_channel *drv_ch = NULL;

    uint32_t drv_index = (uint32_t)(((uint64_t)fd >> DRV_INDEX_OFFSET) & DRV_INDEX_MASK);
    dlist_for_each(pos, &g_drv_channel) {
        temp = dlist_entry(pos, struct drv_channel, drv_list);
        if (temp->drv_index == drv_index) {
            drv_ch = temp;
            break;
        }
    }

    return drv_ch;
}

static int32_t inc_drv_channel_ref(struct drv_channel *drv_ch)
{
    if (drv_ch == NULL) {
        tloge("inc invalid ch\n");
        return -1;
    }

    if (drv_ch->ref_cnt < UINT32_MAX) {
        drv_ch->ref_cnt++;
        return 0;
    }

    tloge("something wrong drv channel:0x%llx ref_cnt:0x%x overflow\n",
        drv_ch->drv_channel, drv_ch->ref_cnt);

    return -1;
}

static struct drv_channel *get_drv_channel(int64_t fd)
{
    int32_t ret = drv_mutex_lock(&g_drv_channel_mtx);
    if (ret != 0) {
        tloge("get drv channel mtx failed\n");
        return NULL;
    }

    struct drv_channel *drv_ch = find_drv_channel(fd);
    /*
     * two case:
     * 1. cannot find channel (drv_ch is NULL)
     * 2. channel ref_cnt is overflow
     */
    if (inc_drv_channel_ref(drv_ch) != 0)
        drv_ch = NULL;

    ret = pthread_mutex_unlock(&g_drv_channel_mtx);
    if (ret != 0)
        tloge("unlock drv channel mtx failed\n");

    return drv_ch;
}

static void dec_drv_channel_ref(struct drv_channel **chp)
{
    if (chp == NULL || *chp == NULL) {
        tloge("dec invalid ch\n");
        return;
    }

    struct drv_channel *ch = *chp;

    if (ch->ref_cnt == 0) {
        tloge("something wrong, ch:0x%llx ref_cnt is 0\n", ch->drv_channel);
    } else {
        ch->ref_cnt--;
        if (ch->ref_cnt == 0) {
            tlogd("release drv:%s channel\n", ch->drv_name);
            if (ipc_release_from_path(ch->drv_name, ch->drv_channel) != 0)
                tloge("release drv:%s channel:0x%llx failed\n", ch->drv_name, ch->drv_channel);
            dlist_delete(&ch->drv_list);
            free(ch);
            *chp = NULL;
        }
    }
}

static void put_drv_channel(struct drv_channel **chp)
{
    int32_t ret = drv_mutex_lock(&g_drv_channel_mtx);
    if (ret != 0) {
        tloge("get drv channel mtx failed\n");
        return;
    }

    dec_drv_channel_ref(chp);

    ret = pthread_mutex_unlock(&g_drv_channel_mtx);
    if (ret != 0)
        tloge("unlock drv channel mtx failed\n");
}

static int32_t alloc_and_get_drv_channel(int64_t fd, const char *drv_name)
{
    int32_t func_ret = -1;
    int32_t ret = drv_mutex_lock(&g_drv_channel_mtx);
    if (ret != 0) {
        tloge("get drv channel mtx failed\n");
        return func_ret;
    }

    struct drv_channel *drv_ch = find_drv_channel(fd);
    if (drv_ch != NULL) {
        func_ret = inc_drv_channel_ref(drv_ch);
    } else {
        struct drv_channel *new_ch = alloc_and_init_channel(drv_name, fd);
        if (new_ch == NULL)
            goto err_out;
        dlist_insert_tail(&new_ch->drv_list, &g_drv_channel);
        func_ret = 0;
    }

err_out:
    ret = pthread_mutex_unlock(&g_drv_channel_mtx);
    if (ret != 0)
        tloge("unlock drv channel mtx failed\n");

    return func_ret;
}

int64_t tee_drv_open(const char *drv_name, const void *param, uint32_t param_len)
{
#ifdef CONFIG_TEE_DRV_STUB
    (void)drv_name;
    (void)param;
    (void)param_len;
    return -1;
#else
    if (drv_name == NULL) {
        tloge("invalid drv name\n");
        return -1;
    }

    size_t name_len = strnlen(drv_name, DRV_NAME_MAX_LEN);
    if (name_len == 0 || name_len >= DRV_NAME_MAX_LEN) {
        tloge("drv_name len:%u is invalid, must be less than %u\n", name_len, DRV_NAME_MAX_LEN);
        return -1;
    }

    uint64_t args[] = {
        CALL_DRV_OPEN,
        (uintptr_t)param,
        param_len,
        (uintptr_t)drv_name,
        name_len,
    };

    uint32_t lens[] = {
        0,
        param_len,
        0,
        name_len,
        0,
    };
#ifndef CONFIG_DISABLE_MULTI_DRV
    int64_t fd = drv_call_new("drvmgr_multi", DRV_GENERAL_CMD_ID, args, lens, ARRAY_SIZE(args));
#else
    int64_t fd = drv_call_new("drvmgr", DRV_GENERAL_CMD_ID, args, lens, ARRAY_SIZE(args));
#endif
    if (fd <= 0) {
        tloge("alloc fd failed\n");
        return fd;
    }

    int32_t ret = alloc_and_get_drv_channel(fd, drv_name);
    if (ret != 0) {
        tloge("cannot get drv:%s channel, just close fd:0x%llx\n", drv_name, fd);
        (void)tee_drv_close_handle(fd);
        return -1;
    }

    return fd;
#endif
}

static int64_t send_ioctl_cmd(cref_t channel, int64_t fd, uint32_t cmd_id, const void *param, uint32_t param_len)
{
    char buf[SYSCAL_MSG_BUFFER_SIZE] = { 0 };
    struct drv_req_msg_t *msg = (struct drv_req_msg_t *)buf;
    struct drv_reply_msg_t *rmsg = (struct drv_reply_msg_t *)buf;
    uint32_t ext_data = SYSCAL_MSG_BUFFER_SIZE - sizeof(struct drv_req_msg_t);

    msg->args[DRV_FRAM_CMD_INDEX] = CALL_DRV_IOCTL;
    msg->args[DRV_PARAM_INDEX] = 0; /* param offset */
    msg->args[DRV_PARAM_LEN_INDEX] = param_len;
    msg->args[DRV_IOCTL_FD_INDEX] = (uint64_t)fd;
    msg->args[DRV_CMD_ID_INDEX] = cmd_id;

    if ((param == NULL) && (param_len != 0)) {
        tloge("invalid param\n");
        return -1;
    }

    if (param != NULL) {
        if ((param_len == 0) || (param_len > ext_data)) {
            tloge("invalid param_len:0x%x\n", param_len);
            return -1;
        }

        if (memcpy_s(msg->data, ext_data, param, param_len) != 0) {
            tloge("copy param to data fail\n");
            return -1;
        }
    }

    msg->header.send.msg_id = DRV_GENERAL_CMD_ID;
    msg->header.send.msg_size = sizeof(struct drv_req_msg_t) + param_len;

    int32_t ret = ipc_msg_call(channel, msg, msg->header.send.msg_size, rmsg, SYSCAL_MSG_BUFFER_SIZE, -1);
    if (ret != 0) {
        tloge("msg call fail ret:0x%x\n", ret);
        return -1;
    }

    return rmsg->header.reply.ret_val;
}

int64_t tee_drv_ioctl(int64_t fd, uint32_t cmd_id, const void *param, uint32_t param_len)
{
#ifdef CONFIG_TEE_DRV_STUB
    (void)cmd_id;
    (void)param;
    (void)param_len;
    return -1;
#else
    struct drv_channel *drv_ch = get_drv_channel(fd);
    if (drv_ch == NULL) {
        tloge("get fd:0x%llx channel failed\n", fd);
        return -1;
    }

    int64_t func_ret = send_ioctl_cmd(drv_ch->drv_channel, fd, cmd_id, param, param_len);
    put_drv_channel(&drv_ch);
    return func_ret;
#endif
}

static int64_t tee_drv_close_handle(int64_t fd)
{
    uint64_t args[] = {
        CALL_DRV_CLOSE,
        (uint64_t)fd,
    };

#ifndef CONFIG_DISABLE_MULTI_DRV
    int64_t ret = drv_call_new("drvmgr_multi", DRV_GENERAL_CMD_ID, args, NULL, ARRAY_SIZE(args));
#else
    int64_t ret = drv_call_new("drvmgr", DRV_GENERAL_CMD_ID, args, NULL, ARRAY_SIZE(args));
#endif

    if (ret != 0)
        tloge("close fd:0x%llx fail\n", fd);

    return ret;
}

int64_t tee_drv_close(int64_t fd)
{
#ifdef CONFIG_TEE_DRV_STUB
    (void)fd;
    return -1;
#else
    struct drv_channel *drv_ch = get_drv_channel(fd);
    if (drv_ch == NULL) {
        tloge("close get fd:0x%llx channel failed\n", fd);
        return -1;
    }

    int64_t ret = tee_drv_close_handle(fd);

    put_drv_channel(&drv_ch); /* pair with get */

    /*
     * condition means this fd is opened by this TA,
     * else declare this TA has opened the drv bind with fd drv_index,
     * but not open this fd
     */
    if ((ret == DRV_SUCCESS) || (ret == DRV_CLOSE_FD_FAIL))
        put_drv_channel(&drv_ch); /* pair with open */

    return ret;
#endif
}

void tee_drv_task_exit(uint32_t exit_pid)
{
    uint64_t args[] = {
        exit_pid,
    };

#ifndef CONFIG_DISABLE_MULTI_DRV
    int64_t ret = drv_call_new("drvmgr_multi", DRV_EXCEPTION_CMD_ID, args, NULL, ARRAY_SIZE(args));
#else
    int64_t ret = drv_call_new("drvmgr", DRV_EXCEPTION_CMD_ID, args, NULL, ARRAY_SIZE(args));
#endif

    if (ret != 0)
        tloge("call driver exception failed\n");
}

void tee_drv_task_dump(void)
{
#ifndef CONFIG_DISABLE_MULTI_DRV
    int64_t ret = drv_call_new("drvmgr_multi", DRV_DUMP_CMD_ID, NULL, NULL, 0);
#else
    int64_t ret = drv_call_new("drvmgr", DRV_DUMP_CMD_ID, NULL, NULL, 0);
#endif
    if (ret != 0)
        tloge("drv task dump drv call failed\n");
}

#else
int64_t tee_drv_open(const char *drv_name, const void *param, uint32_t param_len)
{
    (void)drv_name;
    (void)param;
    (void)param_len;
    tloge("drv open not support in this platform\n");
    return -1;
}

int64_t tee_drv_ioctl(int64_t fd, uint32_t cmd_id, const void *param, uint32_t param_len)
{
    (void)fd;
    (void)cmd_id;
    (void)param;
    (void)param_len;
    tloge("drv ioctl not support in this platform\n");
    return -1;
}

int64_t tee_drv_close(int64_t fd)
{
    (void)fd;
    tloge("drv close not support in this platform\n");
    return -1;
}

void tee_drv_task_exit(uint32_t exit_pid)
{
    (void)exit_pid;
}

void tee_drv_task_dump(void)
{
}

#endif
