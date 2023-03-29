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

#include "drv.h"
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <securec.h>
#include <ipclib.h>
#include <unistd.h>
#include <tee_log.h>
#include <pthread.h>
#include <tee_config.h>
#include "tee_msg_type.h"

#define DRIVER_FRAME_NR  10U
#define MAX_DRV_NAME_LEN 32
#define ARGS_NUM         16

struct drv_op_info {
    char name[MAX_DRV_NAME_LEN];
    cref_t channel;
    bool is_tbac_hooked;
};

static struct drv_op_info g_drv_op_info[DRIVER_FRAME_NR];
static uint32_t g_drv_frame_count;
static pthread_mutex_t g_framp_op_mutex = PTHREAD_MUTEX_INITIALIZER;

static int32_t mutex_lock_ops(pthread_mutex_t *mtx)
{
    int32_t ret = pthread_mutex_lock(mtx);
    if (ret == EOWNERDEAD) /* owner died, use consistent to recover and lock the mutex */
        return pthread_mutex_consistent(mtx);

    return ret;
}

static void mutex_unlock_ops(pthread_mutex_t *mtx)
{
    int32_t ret = pthread_mutex_unlock(mtx);
    if (ret != 0)
        tloge("mutex unlock failed with ret %d\n", ret);
}

static bool is_valid_name(const char *name)
{
    if (name == NULL) {
        tloge("name is NULL\n");
        return false;
    }

    if (strnlen(name, MAX_DRV_NAME_LEN) == MAX_DRV_NAME_LEN) {
        tloge("name len is too long\n");
        return false;
    }

    return true;
}

static int32_t get_info_idex_by_name(const char *name)
{
    uint32_t i;

    if (mutex_lock_ops(&g_framp_op_mutex) != 0) {
        tloge("mutex lock failed\n");
        return -1;
    }

    for (i = 0; i <= g_drv_frame_count; i++) {
        if (strncmp(name, g_drv_op_info[i].name, strlen(name) + 1) == 0) { /* check \0 */
            mutex_unlock_ops(&g_framp_op_mutex);
            return (int32_t)i;
        }
    }

    mutex_unlock_ops(&g_framp_op_mutex);
    return -1;
}

int32_t drv_init(const char *name)
{
    int32_t rc = -1;
    struct drv_op_info *op_info = NULL;

    /* check arg */
    if (!is_valid_name(name))
        return rc;

    if (mutex_lock_ops(&g_framp_op_mutex) != 0) {
        tloge("mutex lock failed\n");
        return rc;
    }

    if (g_drv_frame_count >= DRIVER_FRAME_NR) {
        tloge("drv frame count overflow: %u\n", g_drv_frame_count);
        goto unlock_out;
    }

    op_info = &g_drv_op_info[g_drv_frame_count];

    /* get channel according to path */
    rc = ipc_get_ch_from_path(name, &op_info->channel);
    if (rc != 0) {
        tloge("libdrv: get channel from pathmgr failed: %d\n", rc);
        goto unlock_out;
    }

    if (memcpy_s(op_info->name, MAX_DRV_NAME_LEN, name, strlen(name)) != EOK) {
        tloge("libdrv: %s memcpy name failed\n", name);
        (void)memset_s(op_info->name, MAX_DRV_NAME_LEN, 0, MAX_DRV_NAME_LEN);
        rc = -1;
        goto unlock_out;
    }

    g_drv_frame_count++;
    tlogd("libdrv: init ok for pid %d with s_rslot=0x%llx\n", getpid(), op_info->channel);

unlock_out:
    mutex_unlock_ops(&g_framp_op_mutex);
    return rc;
}

static int32_t try_get_info_idex(const char *name)
{
    int32_t idex;

    idex = get_info_idex_by_name(name);
    if (idex < 0) {
        if (drv_init(name) != 0) {
            tloge("%s init failed\n", name);
            return -1;
        }

        idex = get_info_idex_by_name(name);
        if (idex < 0) {
            tloge("%s failed to find info\n", name);
            return -1;
        }
    }
    return idex;
}

static int32_t param_check(const char *name, struct drv_call_params *params, int32_t *idex)
{
    if (params == NULL || !is_valid_name(name)) {
        tloge("invalid arguments\n");
        return -1;
    }

    if ((params->nr < 0) || (params->nr > ARGS_NUM)) {
        tloge("drv_call: invalid arguments\n");
        return -1;
    }

    if ((params->nr != 0) && (params->args == NULL)) {
        tloge("drv call nr and args not match\n");
        return -1;
    }

    if ((params->rdata == NULL && params->rdata_len != 0) ||
        (params->rdata != NULL && params->rdata_len == 0)) {
        tloge("drv_call: bad rdata or rdata_len\n");
        return -1;
    }

    *idex = try_get_info_idex(name);
    if (*idex < 0) {
        tloge("invalid idex, please check\n");
        return -1;
    }

    return 0;
}

static int32_t length_invalid(uint32_t ext_data_len, uint32_t rdata_len, uint32_t max_len)
{
    if ((ext_data_len + sizeof(struct drv_req_msg_t) < ext_data_len) ||
        (sizeof(struct drv_req_msg_t) + ext_data_len > max_len) ||
        (rdata_len + sizeof(struct drv_reply_msg_t) < rdata_len) ||
        (sizeof(struct drv_reply_msg_t) + rdata_len > max_len))
        return -1;

    return 0;
}

static int32_t calc_ext_data_len(const struct drv_call_params *params, uint32_t buf_size,
                                 uint32_t *ext_data_len)
{
    *ext_data_len = 0;
    /* allocate memory for req/reply, alloc ext data for both req&reply */
    if (params->lens != NULL) {
        for (int32_t i = 0; i < params->nr; i++) {
            /* data is 8-bytes aligned */
            if (*ext_data_len + params->lens[i] < *ext_data_len) {
                tloge("lens is overflow! lens[%d]=0x%x\n", i, params->lens[i]);
                return -1;
            }
            *ext_data_len += params->lens[i];
        }
    }

    if (length_invalid(*ext_data_len, params->rdata_len, buf_size) != 0) {
        tloge("Oops, ext_data or rdata too long len=0x%x rlen=0x%x\n", *ext_data_len, params->rdata_len);
        return -1;
    }

    return 0;
}

static int32_t calc_ext_data_offset(struct drv_req_msg_t *msg, const struct drv_call_params *params,
                                    uint32_t ext_data_len)
{
    uint32_t ext_remained;
    char *ext_ptr = msg->data;

    ext_remained  = ext_data_len;
    for (int32_t i = 0; i < params->nr; i++) {
        if ((params->lens == NULL) || params->lens[i] == 0) {
            msg->args[i] = params->args[i];
        } else {
            if ((void *)((uintptr_t)params->args[i]) == NULL) {
                tloge("drv args %d is NULL, please check\n", i);
                return -1;
            }

            if (memcpy_s(ext_ptr, ext_remained, (void *)((uintptr_t)params->args[i]), params->lens[i]) != EOK) {
                tloge("drv copy failed\n");
                return -1;
            }
            msg->args[i] = (uintptr_t)(ext_ptr - msg->data);
            ext_ptr += params->lens[i];
            ext_remained -= params->lens[i];
        }
    }

    return 0;
}


static int64_t drv_call_ex_new(const char *name, uint16_t id, struct drv_call_params *params)
{
    char buf[SYSCAL_MSG_BUFFER_SIZE] = { 0 };
    uint32_t ext_data_len;
    int32_t idex;
    /* msg_xfer_send_has_recv could handle send_buf and recv_buf point to the same addr */
    struct drv_req_msg_t *msg    = (struct drv_req_msg_t *)buf;
    struct drv_reply_msg_t *rmsg = (struct drv_reply_msg_t *)buf;
    int64_t func_ret = -1;

    if (param_check(name, params, &idex) != 0)
        return -1;

    int32_t ret = calc_ext_data_len(params, sizeof(buf), &ext_data_len);
    if (ret != 0)
        return -1;

    msg->header.send.msg_class = 0;
    msg->header.send.msg_flags = 0;
    msg->header.send.msg_id    = id;
    msg->header.send.msg_size  = sizeof(struct drv_req_msg_t) + ext_data_len;

    if (calc_ext_data_offset(msg, params, ext_data_len) != 0)
        goto err_msg_call;

    ret = ipc_msg_call(g_drv_op_info[idex].channel, msg, msg->header.send.msg_size, rmsg,
                      sizeof(struct drv_req_msg_t) + params->rdata_len, -1);
    if (ret != 0) {
        tloge("drv_call: ipc msg call 0x%llx failed: %d\n", (unsigned long long)g_drv_op_info[idex].channel, ret);
        goto err_msg_call;
    }

    if (params->rdata != NULL) {
        if (memcpy_s(params->rdata, params->rdata_len, rmsg->rdata, params->rdata_len) != EOK) {
            tloge("memcpy rdata failed\n");
            goto err_msg_call;
        }
    }

    func_ret = rmsg->header.reply.ret_val;

err_msg_call:

    return func_ret;
}

int64_t drv_call_new(const char *name, uint16_t id, uint64_t *args, uint32_t *lens, int32_t nr)
{
    struct drv_call_params params = {
        args, lens, nr, NULL, 0
    };

    return drv_call_ex_new(name, id, &params);
}
