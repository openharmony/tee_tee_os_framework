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
#include <openssl/aes.h>
#include <securec.h>
#include <tee_log.h>
#include "crypto_wrapper.h"

#define AES_KEY_128 16
#define AES_KEY_256 32
#define BYTE_TO_BIT 8
#define MIN_IV_LEN  8

TEE_Result aes_key_wrap(struct cdrm_params *params)
{
    AES_KEY aes_key = { { 0 }, 0 };

    bool check = ((params == NULL) ||
                  (params->pkey == NULL) || (params->input_buffer == NULL) ||
                  (params->output_buffer == NULL) || (params->output_len == NULL) ||
                  ((params->pkey_len != AES_KEY_128) && (params->pkey_len != AES_KEY_256)));
    if (check) {
        tloge("input buffer is invalid");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if ((params->iv != NULL) && (params->iv_len < MIN_IV_LEN)) {
        tloge("iv is not NULL but iv len is invalid\n");
        return TEE_ERROR_GENERIC;
    }

    int32_t rc = AES_set_encrypt_key(params->pkey, params->pkey_len * BYTE_TO_BIT, &aes_key);
    if (rc != 0) {
        tloge("set KEK error, rc = %d\n", rc);
        return TEE_ERROR_GENERIC;
    }

    rc = AES_wrap_key(&aes_key, params->iv, params->output_buffer, params->input_buffer, params->input_len);
    (void)memset_s(&aes_key, sizeof(aes_key), 0, sizeof(aes_key));
    if (rc == -1) {
        tloge("do aes wrap key failed\n");
        return TEE_ERROR_GENERIC;
    }
    *(params->output_len) = rc;
    return TEE_SUCCESS;
}

TEE_Result aes_key_unwrap(struct cdrm_params *params)
{
    bool check = ((params == NULL) || (params->pkey == NULL) ||
                  ((params->pkey_len != AES_KEY_128) && (params->pkey_len != AES_KEY_256)) ||
                  (params->input_buffer == NULL) || (params->output_buffer == NULL) || (params->output_len == NULL));
    if (check) {
        tloge("input is invalid");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if ((params->iv != NULL) && (params->iv_len < MIN_IV_LEN)) {
        tloge("iv is not NULL but iv len is invalid\n");
        return TEE_ERROR_GENERIC;
    }

    AES_KEY aes_key = { { 0 }, 0 };
    int32_t rc      = AES_set_decrypt_key(params->pkey, params->pkey_len * BYTE_TO_BIT, &aes_key);
    if (rc != 0) {
        tloge("set KEK error, rc = %d\n", rc);
        return TEE_ERROR_GENERIC;
    }

    rc = AES_unwrap_key(&aes_key, params->iv, params->output_buffer, params->input_buffer, params->input_len);
    (void)memset_s(&aes_key, sizeof(aes_key), 0, sizeof(aes_key));
    if (rc == -1) {
        tloge("do aes unwrap key failed\n");
        return TEE_ERROR_GENERIC;
    }
    *(params->output_len) = rc;
    return TEE_SUCCESS;
}
