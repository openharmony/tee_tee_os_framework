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

#ifndef TEE_EXT_API_H
#define TEE_EXT_API_H

/**
 * @addtogroup TeeTrusted
 * @{
 *
 * @brief TEE(Trusted Excution Environment) API.
 * Provides security capability APIs such as trusted storage, encryption and decryption,
 * and trusted time for trusted application development.
 *
 * @since 12
 */

/**
 * @file tee_ext_api.h
 *
 * @brief Provides extended interfaces.
 *
 * @library NA
 * @kit TEE Kit
 * @syscap SystemCapability.Tee.TeeClient
 * @since 12
 * @version 1.0
 */

#include "tee_defines.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cpluscplus */
#endif /* __cpluscplus */

#define TEE_RETURN_AGENT_BUFFER 0x99
#define TEE_INVALID_AGENT       0x66
#define TEE_AGENT_LOCK          0x33
#define TEE_GET_REEINFO_SUCCESS 0
#define TEE_GET_REEINFO_FAILED  1

#define INVALID_USERID 0xFFFFFFFU

#define TEE_SMC_FROM_USR 0

#define TEE_SMC_FROM_KERNEL 1

#define RESERVED_BUF_SIZE 32

typedef struct ta_caller_info {
    uint32_t session_type;
    union {
        struct {
            TEE_UUID caller_uuid;
            uint32_t group_id;
        };
        uint8_t ca_info[RESERVED_BUF_SIZE];
    } caller_identity;
    uint8_t smc_from_kernel_mode;
    uint8_t reserved[RESERVED_BUF_SIZE - 1];
} caller_info;

TEE_Result tee_ext_get_caller_info(caller_info *caller_info_data, uint32_t length);

TEE_Result tee_ext_get_caller_userid(uint32_t *user_id);

TEE_Result AddCaller_CA_exec(const char *ca_name, uint32_t ca_uid);

TEE_Result AddCaller_CA(const uint8_t *cainfo_hash, uint32_t length);

TEE_Result AddCaller_TA_all(void);

#define SESSION_FROM_CA   0

#define SESSION_FROM_TA   1

#define SESSION_FROM_NOT_SUPPORTED   0xFE

#define SESSION_FROM_UNKNOWN   0xFF

uint32_t tee_get_session_type(void);

TEE_Result TEE_EXT_CheckClientPerm(uint32_t param_types, const TEE_Param params[TEE_PARAMS_NUM]);

TEE_Result tee_ext_derive_ta_platfrom_keys(TEE_ObjectHandle object, uint32_t key_size, const TEE_Attribute *params,
    uint32_t param_count, const uint8_t *exinfo, uint32_t exinfo_size);
    
#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cpluscplus */
#endif /* __cpluscplus */

#endif
