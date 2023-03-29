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
#ifndef PERM_SRV_TA_CTRL_H
#define PERM_SRV_TA_CTRL_H

#include <dlist.h>
#include <tee_defines.h>
#include <pthread.h>

#define PADDING_SIZE          7
#define TA_CTRL_LIST_MAX_SIZE 8192
#define RSA2048_SIGNATURE_LEN 256
#define CERT_MAX_SIZE         2048
#define CERT_UNIVERSAL_LEN    64
#define TA_CTRL_MAGIC_NUM     0x12361215
#define TA_CTRL_CHIP_LEN      4

struct padding {
    uint16_t reserved[PADDING_SIZE];
};

struct ta_ctrl_node {
    struct dlist_node head;
    TEE_UUID uuid;
    uint16_t version;
    struct padding pad;
};

struct ta_ctrl_config_t {
    struct dlist_node ctrl_list;
    const char *file_name;
    uint16_t count;
    pthread_mutex_t lock;
};

struct ta_ctrl_list_hd_t {
    uint32_t magic_num;
    uint32_t version;
    uint32_t body_len;
    uint32_t signature_len;
    uint32_t cert_len;
};

TEE_Result perm_srv_global_ta_ctrl_list_loading(bool check_empty);
TEE_Result perm_srv_check_ta_deactivated(const TEE_UUID *uuid, uint16_t version);
TEE_Result perm_srv_ta_ctrl_buff_process(const uint8_t *ctrl_buff, uint32_t ctrl_buff_size);
#endif
