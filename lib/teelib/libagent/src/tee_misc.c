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
#include "tee_misc.h"
#include <securec.h>
#include <tee_log.h>
#include <ta_framework.h>
#include <tee_agent.h>

#define BOOTLOADER_INFO_NUMS 68
#define TIME_STR_NUMS        30
#define ERROR_RET            (-1)
#define SUCC_RET             0

enum misc_cmd_t {
    SEC_GET_TIME = 1,
};

struct misc_control_t {
    enum misc_cmd_t cmd;
    int32_t ret;
    int32_t magic;
    union args {
        /* for bootloader lock status in nv partition */
        struct {
            uint8_t bootloader_info[BOOTLOADER_INFO_NUMS];
        } nv_info;
        struct {
            uint32_t seconds;
            uint32_t millis;
            char time_str[TIME_STR_NUMS];
        } get_time;
    } args;
};

static struct misc_control_t *g_trans_control = NULL; /* agent trans buffer */

/* before call this function, you should lock the agent fist */
int32_t tee_get_misc_buffer(void)
{
    TEE_Result ret;
    void *buffer    = NULL;
    uint32_t length = 0;

    ret = tee_get_agent_buffer(TEE_MISC_AGENT_ID, &buffer, &length);
    if (ret != TEE_SUCCESS || (buffer == NULL) || (length < sizeof(*g_trans_control))) {
        tloge("get misc agent buffer fail, ret=0x%x, length=%u\n", ret, length);
        return ERROR_RET;
    }

    g_trans_control        = buffer;
    g_trans_control->magic = TEE_MISC_AGENT_ID;

    return SUCC_RET;
}

static int32_t handle_time_str(char *time_str, uint32_t time_str_len)
{
    errno_t rc;

    if (time_str == NULL)
        return SUCC_RET;

    if (time_str_len < sizeof(g_trans_control->args.get_time.time_str)) {
        tloge("time str len %u is invalid\n", time_str_len);
        return ERROR_RET;
    }

    rc = strncpy_s(time_str, (size_t)time_str_len, g_trans_control->args.get_time.time_str,
                   sizeof(g_trans_control->args.get_time.time_str) - 1);
    if (rc != EOK) {
        tloge("str cpy failed\n");
        return ERROR_RET;
    }

    return SUCC_RET;
}

int32_t get_time_of_data(uint32_t *seconds, uint32_t *millis, char *time_str, uint32_t time_str_len)
{
    uint32_t sec;
    uint32_t mil_sec;
    int32_t ret = ERROR_RET;

    /* obtaion misc agent work lock */
    TEE_Result result = tee_agent_lock(TEE_MISC_AGENT_ID);
    if (result != TEE_SUCCESS) {
        tloge("get misc agent lock failed\n");
        return ERROR_RET;
    }
    if (tee_get_misc_buffer() != 0)
        goto END;

    g_trans_control->magic = 0;
    g_trans_control->cmd = SEC_GET_TIME;
    /* call ns agent */
    result = tee_send_agent_cmd(TEE_MISC_AGENT_ID);
    if (result != TEE_SUCCESS) {
        tloge("send cmd to misc agent failed\n");
        goto END;
    }
    if (g_trans_control->magic != TEE_MISC_AGENT_ID) {
        tloge("teecd was killed, just return error\n");
        g_trans_control->magic = 0;
        goto END;
    }

    if (g_trans_control->ret == 0) {
        sec     = g_trans_control->args.get_time.seconds;
        mil_sec = g_trans_control->args.get_time.millis;
        if (handle_time_str(time_str, time_str_len) != 0)
            goto END;
    } else {
        sec     = 0;
        mil_sec = 0;
    }

    if (seconds != NULL)
        *seconds = sec;
    if (millis != NULL)
        *millis = mil_sec;

    ret = g_trans_control->ret;
END:
    g_trans_control = NULL;
    /* we dont care return value here */
    (void)tee_agent_unlock(TEE_MISC_AGENT_ID);
    return ret;
}
