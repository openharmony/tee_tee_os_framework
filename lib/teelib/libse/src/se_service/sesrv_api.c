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
#include "sesrv_api.h"
#include <securec.h>
#include <pthread.h>
#include <mem_ops.h>
#include "errno.h"
#include "tee_defines.h"
#include "ipclib.h"
#include "tee_log.h"
#include "se_service.h"
#include "tee_ext_se_api.h"
#include "tee_inner_uuid.h"

#define ATR_LEN_MAX 32U

struct transmit_info_shared_t {
    uint8_t *data_shared;
    uint32_t data_len;
    uint8_t *rsp_shared;
    uint32_t rsp_len;
};

bool se_srv_exist(void)
{
    errno_t rc;
    cref_t rslot = 0;

    rc = ipc_get_ch_from_path(SE_PATH, &rslot);
    if (rc == -1) {
        tloge("sesrv: get channel from pathmgr failed\n");
        return false;
    }

    (void)ipc_release_from_path(SE_PATH, rslot);

    return true;
}

static void tee_free_shared_mem(void *p, uint32_t size)
{
    if (p == NULL)
        return;

    (void)memset_s(p, size, 0, size);
    if (free_sharemem(p, size) != 0)
        tloge("free shared mem failed\n");
}

static void *tee_alloc_shared_mem(uint32_t size)
{
    void *p = NULL;
    TEE_UUID uuid = TEE_SERVICE_SE;

    p = alloc_sharemem_aux(&uuid, size);
    if (p != NULL)
        (void)memset_s(p, size, 0, size);

    return p;
}

static void se_srv_init_msg(struct se_srv_msg_t *msg, struct se_srv_rsp_t *rsp)
{
    if (msg != NULL)
        (void)memset_s(msg, sizeof(*msg), 0, sizeof(*msg));
    if (rsp != NULL)
        (void)memset_s(rsp, sizeof(*rsp), 0, sizeof(*rsp));
}
static pthread_mutex_t g_msg_call_mutex = PTHREAD_MUTEX_INITIALIZER;
static int se_srv_msg_call(struct se_srv_msg_t *msg, struct se_srv_rsp_t *rsp)
{
    errno_t rc;
    cref_t rslot = 0;

    if (pthread_mutex_lock(&g_msg_call_mutex) != 0) {
        tloge("se msg call mutex lock failed\n");
        return -1;
    }
    rc = ipc_get_ch_from_path(SE_PATH, &rslot);
    if (rc == -1) {
        tloge("sesrv: get channel from pathmgr failed\n");
        if (pthread_mutex_unlock(&g_msg_call_mutex) != 0)
            tloge("se msg call mutex unlock failed\n");
        return rc;
    }

    rc = ipc_msg_call(rslot, msg, sizeof(*msg), rsp, sizeof(*rsp), -1);
    if (rc < 0)
        tloge("msg send 0x%llx failed: 0x%x\n", rslot, rc);

    (void)ipc_release_from_path(SE_PATH, rslot);
    if (pthread_mutex_unlock(&g_msg_call_mutex) != 0) {
        tloge("se msg call mutex unlock failed\n");
        return -1;
    }
    return rc;
}

int se_srv_get_ese_type(void)
{
    struct se_srv_msg_t msg;
    struct se_srv_rsp_t rsp;
    errno_t rc;

    se_srv_init_msg(&msg, &rsp);
    msg.header.send.msg_id = CMD_SESRV_GET_ESE_TYPE;
    rsp.data.ret = TEE_ERROR_GENERIC;

    rc = se_srv_msg_call(&msg, &rsp);
    if (rc < 0)
        return -1;

    if (rsp.data.ret == TEE_SUCCESS)
        return rsp.data.type_rsp.type;
    else
        return -1;
}

TEE_Result se_srv_connect(uint32_t reader_id, uint8_t *p_atr, uint32_t *atr_len)
{
    struct se_srv_msg_t msg;
    struct se_srv_rsp_t rsp;
    uint8_t *p_atr_shared = NULL;
    uint32_t original_atr_len;
    errno_t rc;

    se_srv_init_msg(&msg, &rsp);
    if ((p_atr == NULL) || (atr_len == NULL)) {
        tloge("params are null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((*atr_len == 0) || (*atr_len > ATR_LEN_MAX)) {
        tloge("invalid param\n");
        return TEE_ERROR_SHORT_BUFFER;
    }

    original_atr_len = *atr_len;
    p_atr_shared = tee_alloc_shared_mem(original_atr_len);
    if (p_atr_shared == NULL) {
        tloge("malloc buff shared failed, size = 0x%x\n", original_atr_len);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    msg.header.send.msg_id = CMD_SESRV_CONNECT;
    msg.data.connect_msg.reader_id = reader_id;
    msg.data.connect_msg.p_atr = (uintptr_t)p_atr_shared;
    msg.data.connect_msg.atr_len = original_atr_len;
    rsp.data.ret = TEE_ERROR_GENERIC;

    rc = se_srv_msg_call(&msg, &rsp);
    if (rc < 0)
        goto connect_clean;

    if (rsp.data.ret == TEE_SUCCESS) {
        if (rsp.data.connect_rsp.atr_len > original_atr_len) {
            tloge("atr len is too short\n");
            rsp.data.ret = TEE_ERROR_SHORT_BUFFER;
            goto connect_clean;
        }
        if (memcpy_s(p_atr, original_atr_len, p_atr_shared, rsp.data.connect_rsp.atr_len) != EOK)
            rsp.data.ret = TEE_ERROR_SECURITY;
        else
            *atr_len = rsp.data.connect_rsp.atr_len;
    }

connect_clean:
    tee_free_shared_mem(p_atr_shared, original_atr_len);
    return rsp.data.ret;
}

TEE_Result se_srv_disconnect(uint32_t reader_id)
{
    struct se_srv_msg_t msg;
    struct se_srv_rsp_t rsp;
    errno_t rc;

    se_srv_init_msg(&msg, &rsp);
    msg.header.send.msg_id = CMD_SESRV_DISCONNECT;
    msg.data.disconnect_msg.reader_id = reader_id;
    rsp.data.ret = TEE_ERROR_GENERIC;

    rc = se_srv_msg_call(&msg, &rsp);
    if (rc < 0)
        return TEE_ERROR_GENERIC;

    return rsp.data.ret;
}

static TEE_Result check_transmit_info(const struct se_transmit_info_t *transmit_info)
{
    if (transmit_info == NULL) {
        tloge("Invalid param\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((transmit_info->data == NULL) || (transmit_info->data_len == 0) || (transmit_info->data_len > APDU_LEN_MAX) ||
        (transmit_info->p_rsp == NULL) || (transmit_info->rsp_len == 0) || (transmit_info->rsp_len > APDU_LEN_MAX)) {
        tloge("Invalid param\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result check_open_channel_info(const struct se_transmit_info_t *transmit_info)
{
    bool is_good_param = false;

    if (transmit_info == NULL) {
        tloge("Invalid param\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // when data_len is 0, data is NULL, means choose default applet
    is_good_param = ((transmit_info->data == NULL && transmit_info->data_len == 0) ||
                     (transmit_info->data != NULL &&
                      transmit_info->data_len >= AID_LEN_MIN && transmit_info->data_len <= AID_LEN_MAX)) &&
                    (transmit_info->p_rsp != NULL &&
                     transmit_info->rsp_len > 0 && transmit_info->rsp_len <= APDU_LEN_MAX);
    if (!is_good_param) {
        tloge("Invalid param\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static errno_t send_transmit_msg(struct transmit_info_shared_t *transmit_info_shared,
                                 const struct se_transmit_info_t *transmit_info, struct se_srv_rsp_t *rsp)
{
    struct se_srv_msg_t msg;

    se_srv_init_msg(&msg, NULL);
    msg.header.send.msg_id = CMD_SESRV_TRANSMIT;
    msg.data.transmit_msg.reader_id = transmit_info->reader_id;
    msg.data.transmit_msg.p_cmd = (uintptr_t)(transmit_info_shared->data_shared);
    msg.data.transmit_msg.cmd_len = transmit_info_shared->data_len;
    msg.data.transmit_msg.p_rsp = (uintptr_t)(transmit_info_shared->rsp_shared);
    msg.data.transmit_msg.rsp_len = transmit_info_shared->rsp_len;
    msg.data.transmit_msg.channel_id = transmit_info->channel_id;
    rsp->data.ret = TEE_ERROR_GENERIC;

    return se_srv_msg_call(&msg, rsp);
}

TEE_Result tee_se_srv_transmit(struct se_transmit_info_t *transmit_info)
{
    struct se_srv_rsp_t rsp;
    struct transmit_info_shared_t transmit_info_shared = {0};
    errno_t rc;

    se_srv_init_msg(NULL, &rsp);
    if (check_transmit_info(transmit_info) != TEE_SUCCESS)
        return TEE_ERROR_BAD_PARAMETERS;

    transmit_info_shared.data_len = transmit_info->data_len;
    transmit_info_shared.rsp_len = transmit_info->rsp_len;
    transmit_info_shared.data_shared = tee_alloc_shared_mem(transmit_info_shared.data_len);
    transmit_info_shared.rsp_shared = tee_alloc_shared_mem(transmit_info_shared.rsp_len);
    if (transmit_info_shared.data_shared == NULL || transmit_info_shared.rsp_shared == NULL) {
        rsp.data.ret = TEE_ERROR_OUT_OF_MEMORY;
        goto transmit_clean;
    }

    (void)memcpy_s(transmit_info_shared.data_shared, transmit_info_shared.data_len,
                   transmit_info->data, transmit_info->data_len);

    rc = send_transmit_msg(&transmit_info_shared, transmit_info, &rsp);
    if (rc < 0)
        goto transmit_clean;

    if (rsp.data.ret == TEE_SUCCESS) {
        if (rsp.data.transmit_rsp.rsp_len > transmit_info->rsp_len) {
            tloge("rsp len is too short\n");
            rsp.data.ret = TEE_ERROR_SHORT_BUFFER;
            goto transmit_clean;
        }
        if (memcpy_s(transmit_info->p_rsp, transmit_info->rsp_len,
                     transmit_info_shared.rsp_shared, rsp.data.transmit_rsp.rsp_len) != EOK)
            rsp.data.ret = TEE_ERROR_SECURITY;
        else
            transmit_info->rsp_len = rsp.data.transmit_rsp.rsp_len;
    }

transmit_clean:
    tee_free_shared_mem(transmit_info_shared.data_shared, transmit_info_shared.data_len);
    tee_free_shared_mem(transmit_info_shared.rsp_shared, transmit_info_shared.rsp_len);
    return rsp.data.ret;
}

static errno_t send_open_basic_channel_msg(struct transmit_info_shared_t *transmit_info_shared,
                                           const struct se_transmit_info_t *transmit_info, struct se_srv_rsp_t *rsp)
{
    struct se_srv_msg_t msg;

    se_srv_init_msg(&msg, NULL);
    msg.header.send.msg_id = CMD_SESRV_OPEN_BASIC_CHANNEL;
    msg.data.open_basic_channel_msg.reader_id = transmit_info->reader_id;
    msg.data.open_basic_channel_msg.se_aid = (uintptr_t)(transmit_info_shared->data_shared);
    msg.data.open_basic_channel_msg.se_aid_len = transmit_info_shared->data_len;
    msg.data.open_basic_channel_msg.p_rsp = (uintptr_t)(transmit_info_shared->rsp_shared);
    msg.data.open_basic_channel_msg.rsp_len = transmit_info_shared->rsp_len;
    rsp->data.ret = TEE_ERROR_GENERIC;

    return se_srv_msg_call(&msg, rsp);
}

static TEE_Result channel_msg_init(struct se_transmit_info_t *transmit_info,
    struct transmit_info_shared_t *transmit_info_shared, struct se_srv_rsp_t *rsp)
{
    se_srv_init_msg(NULL, rsp);
    if (check_open_channel_info(transmit_info) != TEE_SUCCESS)
        return TEE_ERROR_BAD_PARAMETERS;

    transmit_info_shared->data_len = transmit_info->data_len;
    transmit_info_shared->rsp_len = transmit_info->rsp_len;
    if (transmit_info_shared->data_len != 0) {
        transmit_info_shared->data_shared = tee_alloc_shared_mem(transmit_info_shared->data_len);
        if (transmit_info_shared->data_shared == NULL) {
            tloge("alloc shared mem failed\n");
            return TEE_ERROR_OUT_OF_MEMORY;
        }
        (void)memcpy_s(transmit_info_shared->data_shared, transmit_info_shared->data_len,
                       transmit_info->data, transmit_info->data_len);
    }
    transmit_info_shared->rsp_shared = tee_alloc_shared_mem(transmit_info_shared->rsp_len);
    if (transmit_info_shared->rsp_shared == NULL) {
        tloge("alloc shared mem failed\n");
        tee_free_shared_mem(transmit_info_shared->data_shared, transmit_info_shared->data_len);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    return TEE_SUCCESS;
}

TEE_Result tee_se_srv_open_basic_channel(struct se_transmit_info_t *transmit_info)
{
    struct se_srv_rsp_t rsp;
    struct transmit_info_shared_t transmit_info_shared = {0};
    errno_t rc;

    rsp.data.ret = channel_msg_init(transmit_info, &transmit_info_shared, &rsp);
    if (rsp.data.ret != TEE_SUCCESS) {
        tloge("channel sharedmem init failed\n");
        return rsp.data.ret;
    }

    rc = send_open_basic_channel_msg(&transmit_info_shared, transmit_info, &rsp);
    if (rc < 0)
        goto open_basic_channel_clean;

    if (rsp.data.ret == TEE_SUCCESS) {
        if (rsp.data.open_basic_channel_rsp.rsp_len > transmit_info->rsp_len) {
            tloge("rsp len is too short\n");
            transmit_info->channel_id = CLA_BASIC_CHANNEL;
            (void)tee_se_srv_close_channel(transmit_info);
            rsp.data.ret = TEE_ERROR_SHORT_BUFFER;
            goto open_basic_channel_clean;
        }
        if (memcpy_s(transmit_info->p_rsp, transmit_info->rsp_len,
                     transmit_info_shared.rsp_shared, rsp.data.open_basic_channel_rsp.rsp_len) != EOK) {
            transmit_info->channel_id = CLA_BASIC_CHANNEL;
            (void)tee_se_srv_close_channel(transmit_info);
            rsp.data.ret = TEE_ERROR_SECURITY;
        } else {
            transmit_info->rsp_len = rsp.data.open_basic_channel_rsp.rsp_len;
        }
    }

open_basic_channel_clean:
    tee_free_shared_mem(transmit_info_shared.data_shared, transmit_info_shared.data_len);
    tee_free_shared_mem(transmit_info_shared.rsp_shared, transmit_info_shared.rsp_len);
    return rsp.data.ret;
}

static errno_t send_open_logical_channel_msg(struct transmit_info_shared_t *transmit_info_shared,
                                             const struct se_transmit_info_t *transmit_info, struct se_srv_rsp_t *rsp)
{
    struct se_srv_msg_t msg;

    se_srv_init_msg(&msg, NULL);
    msg.header.send.msg_id = CMD_SESRV_OPEN_LOGICAL_CHANNEL;
    msg.data.open_logical_channel_msg.reader_id = transmit_info->reader_id;
    msg.data.open_logical_channel_msg.se_aid = (uintptr_t)(transmit_info_shared->data_shared);
    msg.data.open_logical_channel_msg.se_aid_len = transmit_info_shared->data_len;
    msg.data.open_logical_channel_msg.p_rsp = (uintptr_t)(transmit_info_shared->rsp_shared);
    msg.data.open_logical_channel_msg.rsp_len = transmit_info_shared->rsp_len;
    rsp->data.ret = TEE_ERROR_GENERIC;

    return se_srv_msg_call(&msg, rsp);
}

TEE_Result tee_se_srv_open_logical_channel(struct se_transmit_info_t *transmit_info)
{
    struct se_srv_rsp_t rsp;
    struct transmit_info_shared_t transmit_info_shared = {0};
    errno_t rc;

    rsp.data.ret = channel_msg_init(transmit_info, &transmit_info_shared, &rsp);
    if (rsp.data.ret != TEE_SUCCESS) {
        tloge("channel sharedmem init failed\n");
        return rsp.data.ret;
    }

    rc = send_open_logical_channel_msg(&transmit_info_shared, transmit_info, &rsp);
    if (rc < 0)
        goto open_logical_channel_clean;

    if (rsp.data.ret == TEE_SUCCESS) {
        if (rsp.data.open_logical_channel_rsp.rsp_len > transmit_info->rsp_len) {
            tloge("rsp len is too short\n");
            transmit_info->channel_id = rsp.data.open_logical_channel_rsp.logic_channel_id;
            (void)tee_se_srv_close_channel(transmit_info);
            rsp.data.ret = TEE_ERROR_SHORT_BUFFER;
            goto open_logical_channel_clean;
        }
        if (memcpy_s(transmit_info->p_rsp, transmit_info->rsp_len,
                     transmit_info_shared.rsp_shared, rsp.data.open_logical_channel_rsp.rsp_len) != EOK) {
            transmit_info->channel_id = rsp.data.open_logical_channel_rsp.logic_channel_id;
            (void)tee_se_srv_close_channel(transmit_info);
            rsp.data.ret = TEE_ERROR_SECURITY;
        } else {
            transmit_info->rsp_len = rsp.data.open_logical_channel_rsp.rsp_len;
            transmit_info->channel_id = rsp.data.open_logical_channel_rsp.logic_channel_id;
        }
    }

open_logical_channel_clean:
    tee_free_shared_mem(transmit_info_shared.data_shared, transmit_info_shared.data_len);
    tee_free_shared_mem(transmit_info_shared.rsp_shared, transmit_info_shared.rsp_len);
    return rsp.data.ret;
}

TEE_Result tee_se_srv_close_channel(const struct se_transmit_info_t *transmit_info)
{
    struct se_srv_msg_t msg;
    struct se_srv_rsp_t rsp;
    errno_t rc;

    se_srv_init_msg(&msg, &rsp);
    if (transmit_info == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    msg.header.send.msg_id = CMD_SESRV_CLOSE_CHANNEL;
    msg.data.close_channel_msg.reader_id = transmit_info->reader_id;
    msg.data.close_channel_msg.channel_id = transmit_info->channel_id;
    rsp.data.ret = TEE_ERROR_GENERIC;

    rc = se_srv_msg_call(&msg, &rsp);
    if (rc < 0)
        return rsp.data.ret;

    if (rsp.data.ret != TEE_SUCCESS)
        tloge("se srv close channel failed\n");

    return rsp.data.ret;
}

static errno_t send_select_channel_msg(struct transmit_info_shared_t *transmit_info_shared,
                                       const struct se_transmit_info_t *transmit_info, struct se_srv_rsp_t *rsp)
{
    struct se_srv_msg_t msg;

    se_srv_init_msg(&msg, NULL);
    msg.header.send.msg_id = CMD_SESRV_SELECT_CHANNEL;
    msg.data.select_channel_msg.reader_id = transmit_info->reader_id;
    msg.data.select_channel_msg.se_aid = (uintptr_t)(transmit_info_shared->data_shared);
    msg.data.select_channel_msg.se_aid_len = transmit_info_shared->data_len;
    msg.data.select_channel_msg.channel_id = transmit_info->channel_id;
    msg.data.select_channel_msg.p_rsp = (uintptr_t)(transmit_info_shared->rsp_shared);
    msg.data.select_channel_msg.rsp_len = transmit_info_shared->rsp_len;
    rsp->data.ret = TEE_ERROR_GENERIC;

    return se_srv_msg_call(&msg, rsp);
}

TEE_Result tee_se_srv_select_channel(struct se_transmit_info_t *transmit_info)
{
    struct se_srv_rsp_t rsp;
    struct transmit_info_shared_t transmit_info_shared = {0};
    errno_t rc;

    rsp.data.ret = channel_msg_init(transmit_info, &transmit_info_shared, &rsp);
    if (rsp.data.ret != TEE_SUCCESS) {
        tloge("channel sharedmem init failed\n");
        return rsp.data.ret;
    }

    rc = send_select_channel_msg(&transmit_info_shared, transmit_info, &rsp);
    if (rc < 0)
        goto select_clean;

    if (rsp.data.ret == TEE_SUCCESS) {
        if (rsp.data.select_channel_rsp.rsp_len > transmit_info->rsp_len) {
            tloge("rsp len is too short\n");
            rsp.data.ret = TEE_ERROR_SHORT_BUFFER;
            goto select_clean;
        }
        if (memcpy_s(transmit_info->p_rsp, transmit_info->rsp_len,
                     transmit_info_shared.rsp_shared, rsp.data.select_channel_rsp.rsp_len) != EOK)
            rsp.data.ret = TEE_ERROR_SECURITY;
        else
            transmit_info->rsp_len = rsp.data.select_channel_rsp.rsp_len;
    }

select_clean:
    tee_free_shared_mem(transmit_info_shared.data_shared, transmit_info_shared.data_len);
    tee_free_shared_mem(transmit_info_shared.rsp_shared, transmit_info_shared.rsp_len);
    return rsp.data.ret;
}

bool se_srv_get_msp_status(void)
{
    struct se_srv_msg_t msg;
    struct se_srv_rsp_t rsp;
    errno_t rc;

    se_srv_init_msg(&msg, &rsp);
    msg.header.send.msg_id = CMD_SESRV_GET_MSP_STATUS;
    rsp.data.ret = TEE_ERROR_GENERIC;

    rc = se_srv_msg_call(&msg, &rsp);
    if (rc < 0)
        return false;

    if (rsp.data.ret == TEE_SUCCESS)
        return rsp.data.msp_status_rsp.msp_status;
    else
        return false;
}

bool se_srv_get_sec_flash_status(void)
{
    struct se_srv_msg_t msg;
    struct se_srv_rsp_t rsp;
    errno_t rc;

    se_srv_init_msg(&msg, &rsp);
    msg.header.send.msg_id = CMD_SESRV_GET_SEC_FLASH_STATUS;
    rsp.data.ret = TEE_ERROR_GENERIC;

    rc = se_srv_msg_call(&msg, &rsp);
    if (rc < 0)
        return false;

    if (rsp.data.ret == TEE_SUCCESS)
        return rsp.data.sec_flash_status_rsp.sec_flash_status;
    else
        return false;
}

void tee_se_set_aid(const struct seaid_switch_info *seaid_list, uint32_t seaid_list_len)
{
    struct se_srv_msg_t msg;
    struct se_srv_rsp_t rsp;
    uint8_t *seaid_list_shared = NULL;
    uint32_t seaid_msg_len;
    errno_t rc;

    se_srv_init_msg(&msg, &rsp);
    if ((seaid_list == NULL) || (seaid_list_len == 0)) {
        tloge("Invalid param\n");
        return;
    }

    if (seaid_list_len > SEAID_LIST_LEN_MAX) {
        tloge("seaid list len is too long\n");
        return;
    }

    seaid_msg_len = seaid_list_len * sizeof(seaid_list[0]);
    seaid_list_shared = tee_alloc_shared_mem(seaid_msg_len);
    if (seaid_list_shared == NULL) {
        tloge("malloc buff shared failed, size = 0x%x\n", seaid_msg_len);
        return;
    }

    if (memcpy_s(seaid_list_shared, seaid_msg_len, seaid_list, seaid_msg_len) != EOK) {
        tloge("cpy seaid list failed\n");
        goto set_aid_clean;
    }

    msg.header.send.msg_id = CMD_SESRV_SET_AID;
    msg.data.set_aid_msg.seaid_list = (uintptr_t)seaid_list_shared;
    msg.data.set_aid_msg.seaid_list_len = seaid_list_len;
    rsp.data.ret = TEE_ERROR_GENERIC;

    rc = se_srv_msg_call(&msg, &rsp);
    if (rc < 0)
        tloge("set aid failed %d\n", rc);

set_aid_clean:
    tee_free_shared_mem(seaid_list_shared, seaid_msg_len);
}

void tee_se_set_deactive(bool deactive)
{
    struct se_srv_msg_t msg;
    struct se_srv_rsp_t rsp;
    errno_t rc;

    se_srv_init_msg(&msg, &rsp);
    msg.header.send.msg_id = CMD_SESRV_SET_DEACTIVE;
    msg.data.set_deactive_msg.deactive = deactive;
    rsp.data.ret = TEE_ERROR_GENERIC;

    rc = se_srv_msg_call(&msg, &rsp);
    if (rc < 0)
        tloge("set deactivate failed %d\n", rc);
}
