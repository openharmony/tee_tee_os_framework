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
#ifndef __PERSRV_H__
#define __PERSRV_H__

#include <stdint.h>
#include "crypto_wrapper.h"
#include "tee_internal_task_pub.h"
#include "tee_elf_verify.h"
#include "tee_msg_type.h"

#define TA_CERT_MAX_SERVICE_NAME_LEN 27

#define TA_LOAD_PERM_ALLOW 1
#define TA_LOAD_PERM_DENY  0

#define REGISTER_TA   1
#define UNREGISTER_TA 0

#define CHECK_BY_UUID   0
#define CHECK_BY_TASKID 1
#define MAX_PUB_KEY_SIZE 2056
#define MAX_PERM_SRV_BUFF_SIZE (70 * 1024)

#define PERMSRV_FILE_OPT    "permsrv_file_operation"
#define PERMSRV_SAVE_FILE   "permsrv_save_file"
#define PERMSRV_ASYNC_OPT        "permsrv_async_operation"
#define PERMSRV_ASYNC_OPT_FILE   "permsrv_async_operation_file"

enum PERM_COMMANDS_ID {
    PERMSRV_QUERY_TA_PERMS          = 0x102,
    PERMSRV_SET_CRL_CERT            = 0x103,
    PERMSRV_SET_TA_CTRL_LIST        = 0x104,
    TEE_TASK_LOAD_CRL_AND_CTRL_LIST = 0x105,
    PERMSRV_QUERY_TA2TA_PERM        = 0x106,
    TEE_TASK_ELF_VERIFY             = 0x107,
    TEE_TASK_CMS_CRL_UPDATE         = 0x108,
    PERMSRV_CERT_VERIFY             = 0x109,
    PERMSRV_CERT_EXPORT             = 0x110,
    PERMSRV_CERT_REMOVE             = 0x111,
    TEE_TASK_CA_HASHFILE_VERIFY     = 0x112,
};

enum PERM_TYPE {
    PERM_TYPE_SE_CAPABILITY   = 0x04,
    PERM_TYPE_CERT_CAPABILITY = 0x07,
};

enum init_state {
    INIT_STATE_NOT_READY,
    INIT_STATE_READY,
};

typedef enum {
    TA_DEBUG_CERT,
    TA_RELEASE_CERT,
    TA_CERT_MAX,
} ta_cert_t;

typedef enum {
    CONF_DEBUG_CERT,
    CONF_RELEASE_CERT,
    CONF_CERT_MAX,
} conf_cert_t;

enum cert_product_type {
    TEE_CA_TYPE,
    OH_CA_TYPE,
    IMPORT_CA_TYPE,
};

typedef struct {
    ta_cert_t cert_type;
    uint8_t public_key[MAX_PUB_KEY_SIZE];
    uint8_t cert_product_type;
    bool sys_verify_ta;
} cert_param_t;

typedef struct perm_srv_set_config_st {
    uint64_t config_file; /* pointer */
    uint32_t len;
    uint64_t cert_param; /* cert_param_t pointer */
    TEE_UUID uuid;
    uint64_t service_name; /* pointer */
    uint32_t service_name_len;
} perm_srv_set_config_t;

typedef struct perm_srv_query_tarun_st {
    TEE_UUID uuid;
    uint64_t mani_val; /* pointer */
    uint32_t len;
    uint16_t distribution;
} perm_srv_query_tarun_t;

typedef struct perm_srv_query_perms_st {
    TEE_UUID uuid;
    uint32_t taskid;
    uint32_t checkby;
    uint32_t perm_type;
} perm_srv_query_perms_t;

typedef struct perm_srv_query_ta2ta_perm_st {
    TEE_UUID uuid;
    uint32_t cmd;
} perm_srv_query_ta2ta_perm_t;

typedef struct perm_srv_set_crl_cert_st {
    uint64_t crl_cert_buff; /* pointer */
    uint32_t crl_cert_size;
} perm_srv_set_crl_cert_t;

typedef struct perm_srv_set_ta_ctrl_list_st {
    uint64_t ctrl_list_buff; /* pointer */
    uint32_t ctrl_list_size;
} perm_srv_set_ta_ctrl_list_t;

typedef struct perm_srv_set_ta_cert_st {
    uint64_t ta_cert_buff; /* pointer */
    uint32_t ta_cert_size;
    uint64_t pub_key_buff; /* pointer */
    uint32_t pub_key_size;
} perm_srv_set_ta_cert_t;

typedef struct perm_srv_ta_unload {
    TEE_UUID uuid;
} perm_srv_ta_unload_t;

typedef struct perm_srv_crl_update {
    uint64_t buffer; /* pointer */
    uint32_t size;
} perm_srv_crl_update_t;

typedef struct perm_srv_ca_hashfile_verify {
    uint64_t buffer; /* pointer */
    uint32_t size;
}perm_srv_ca_hashfile_verify_t;

typedef union perm_srv_msgbody_st {
    perm_srv_set_config_t ta_config;
    perm_srv_query_tarun_t ta_run;
    perm_srv_query_perms_t query_perms;
    perm_srv_query_ta2ta_perm_t query_ta2ta_perm;
    struct reg_ta_info reg_ta;
    perm_srv_ta_unload_t ta_unload;
    perm_srv_set_crl_cert_t crl_cert;
    perm_srv_set_ta_ctrl_list_t ctrl_list;
    elf_verify_req verify_req;
    perm_srv_crl_update_t crl_update_req;
    perm_srv_set_ta_cert_t ta_cert;
    perm_srv_ca_hashfile_verify_t ca_hashfile_verify;
    struct {
        uint64_t dst; /* pointer */
        uint32_t len;
    } crt;
} perm_srv_msgbody_t;

typedef struct perm_srv_sharememrsp_st {
    uint32_t sharemem_index;
} perm_srv_sharememrsp_t;

typedef union perm_srv_permsrsp_st {
    uint32_t rpmb_size;
    uint64_t rpmb_capability;
    uint64_t sfs_capability;
    uint64_t se_capability;
    uint64_t tui_capability;
    uint32_t manager;
    struct {
        uint32_t len;
    } crt;
    uint64_t cert_capability;
} perm_srv_permsrsp_t;

typedef struct perm_srv_rspbody_st {
    TEE_Result ret;
    union {
        perm_srv_sharememrsp_t sharememrsp;
        perm_srv_permsrsp_t permsrsp;
    };
} perm_srv_rspbody_t;

/* struct for req msg and reply msg */
typedef struct perm_srv_req_msg_st {
    msg_header header;
    perm_srv_msgbody_t req_msg;
} __attribute__((__packed__)) perm_srv_req_msg_t;

typedef struct perm_srv_reply_msg_st {
    msg_header header;
    perm_srv_rspbody_t reply;
} __attribute__((__packed__)) perm_srv_reply_msg_t;

#endif // __PERSRV_H__
