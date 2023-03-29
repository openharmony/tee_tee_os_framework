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
#ifndef HUK_SERVICE_HUK_SERVICE_MSG_H
#define HUK_SERVICE_HUK_SERVICE_MSG_H

#include <tee_defines.h>
#include <ipclib.h>
#include "tee_msg_type.h"

#define HUK_PATH "hukservice"

#define HUK_ERROR      (-1)
#define HUK_SUCCESS    0

#define AES_CMAC_RESULT_SIZE_IN_BYTES 0x10
#define CMAC_DERV_MAX_DATA_IN_SIZE    0x400
#define CMAC_DERV_MIX_DATA_IN_SIZE    0x10

#define HUK_MIX_TAKEY_SIZE 16U
#define HUK_MAX_TAKEY_SIZE 32U

#define SIZE_ECC256  32
#define SIZE_TEE_PRK 64 /* TEE platform root key size in bytes */
#define SIZE_TA_PRK  64 /* TA platform root key size in bytes  */
#define ATTR_BUFFER_SIZE_PUBLIC  2U
#define ATTR_BUFFER_SIZE_PAIR    3U

enum huk_commands_id {
    CMD_HUK_DERIVE_TAKEY = 0x100,
    CMD_HUK_GET_DEVICEID = 0x101,
    CMD_HUK_PROVISION_KEY = 0x102,
    CMD_HUK_DERIVE_PLAT_ROOT_KEY = 0x103,
    CMD_HUK_DERIVE_TAKEY2 = 0x104,
};

struct derive_key_msg {
    uint64_t salt_buf;
    uint32_t salt_size;
    uint64_t key_buf;
    uint32_t key_size;
    uint32_t outer_iter_num;
    uint32_t inner_iter_num;
};

struct get_info_msg {
    uint64_t buf;
    uint32_t size;
};

#define SIZE_MAX_EXINFO 64
struct derive_plat_key_msg {
    uint32_t keytype;
    uint32_t keysize;
    uint8_t exinfo[SIZE_MAX_EXINFO];
    uint32_t exinfo_size;
    uint32_t csc_type;
    TEE_UUID csc_uuid;
    uint32_t attri_size;
    uint64_t attri_buff;
};

union huk_srv_msg_data {
    struct derive_key_msg takey_msg;
    struct get_info_msg deviceid_msg;
    struct get_info_msg provisionkey_msg;
    struct derive_plat_key_msg  plat_key_msg;
};

struct get_info_rsp {
    uint32_t size;
};

struct huk_srv_rsp_data {
    TEE_Result ret;
    union {
        struct get_info_rsp provisionkey_rsp;
    };
};

struct huk_srv_msg {
    msg_header header;
    union huk_srv_msg_data data;
} __attribute__((__packed__));

struct huk_srv_rsp {
    msg_header header;
    struct huk_srv_rsp_data data;
} __attribute__((__packed__));

#endif
