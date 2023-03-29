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
#include "tee_crypto_api.h"
#include <string.h>
#include <securec.h>
#include <tee_log.h>
#include <ta_framework.h>
#include <tee_ext_api.h>
#include <tee_property_inner.h>
#include <tee_object_api.h>
#include <crypto_inner_defines.h>
#include <crypto_hal_cipher.h>
#include <crypto_driver_adaptor.h>
#include "tee_operation.h"

/* For GP compatible, we add some panic when there is some error, For common use, we need to disable this panic */
#ifndef GP_COMPATIBLE
#define TEE_Panic(x) \
    do {             \
    } while (0)
#endif

struct cipher_op_config_s {
    uint32_t expect_class;
    uint32_t expect_mode[MAX_MODE_NUM];
    uint32_t algorithm;
    uint32_t expect_iv_length;
};

static const struct cipher_op_config_s g_cipher_config[] = {
    { TEE_OPERATION_MAC, { TEE_MODE_MAC, 0xFFFFFFFF }, TEE_ALG_AES_CBC_MAC_NOPAD, AES_IV_LEN },
    { TEE_OPERATION_MAC, { TEE_MODE_MAC, 0xFFFFFFFF }, TEE_ALG_AES_CMAC, 0 },
    { TEE_OPERATION_MAC, { TEE_MODE_MAC, 0xFFFFFFFF }, TEE_ALG_DES_CBC_MAC_NOPAD, 0 },
    { TEE_OPERATION_MAC, { TEE_MODE_MAC, 0xFFFFFFFF }, TEE_ALG_DES3_CBC_MAC_NOPAD, 0 },
    { TEE_OPERATION_CIPHER, { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT }, TEE_ALG_AES_ECB_NOPAD, 0 },
    { TEE_OPERATION_CIPHER, { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT }, TEE_ALG_AES_ECB_PKCS5, 0 },
    { TEE_OPERATION_CIPHER, { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT }, TEE_ALG_AES_CBC_NOPAD, AES_IV_LEN },
    { TEE_OPERATION_CIPHER, { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT }, TEE_ALG_AES_CBC_PKCS5, AES_IV_LEN },
    { TEE_OPERATION_CIPHER, { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT }, TEE_ALG_AES_CTR, 0 },
    { TEE_OPERATION_CIPHER, { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT }, TEE_ALG_AES_CTS, 0 },
    { TEE_OPERATION_CIPHER, { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT }, TEE_ALG_AES_XTS, 0 },
    { TEE_OPERATION_CIPHER, { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT }, TEE_ALG_DES_ECB_NOPAD, 0 },
    { TEE_OPERATION_CIPHER, { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT }, TEE_ALG_DES_CBC_NOPAD, DES_IV_LEN },
    { TEE_OPERATION_CIPHER, { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT }, TEE_ALG_DES3_ECB_NOPAD, 0 },
    { TEE_OPERATION_CIPHER, { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT }, TEE_ALG_DES3_CBC_NOPAD, DES_IV_LEN },
    { TEE_OPERATION_CIPHER, { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT }, TEE_ALG_SM4_CBC_NOPAD, AES_IV_LEN },
    { TEE_OPERATION_CIPHER, { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT }, TEE_ALG_SM4_CBC_PKCS7, AES_IV_LEN },
    { TEE_OPERATION_CIPHER, { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT }, TEE_ALG_SM4_ECB_NOPAD, 0 },
    { TEE_OPERATION_CIPHER, { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT }, TEE_ALG_SM4_CTR, AES_IV_LEN },
    { TEE_OPERATION_CIPHER, { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT }, TEE_ALG_SM4_CFB128, AES_IV_LEN },
};

static const struct cipher_op_config_s *get_ae_config(uint32_t algorithm)
{
    uint32_t index;
    for (index = 0; index < ELEM_NUM(g_cipher_config); index++) {
        if (algorithm == g_cipher_config[index].algorithm)
            return &g_cipher_config[index];
    }
    return NULL;
}

static TEE_Result cipher_init_check_config(TEE_OperationHandle operation, const void *iv, size_t iv_len)
{
    const struct cipher_op_config_s *config = get_ae_config(operation->algorithm);

    bool check = (config == NULL || operation->operationClass != config->expect_class ||
        (operation->mode != config->expect_mode[0] && operation->mode != config->expect_mode[1]));
    if (check) {
        tloge("This operation is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    check = (config->expect_iv_length != 0 && (config->expect_iv_length != iv_len || iv == NULL));
    if (check) {
        tloge("This operation iv length is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result cipher_init_operation_state_check(TEE_OperationHandle operation, const void *iv, size_t iv_len)
{
    uint32_t api_level = tee_get_ta_api_level();
    if (api_level >= API_LEVEL1_1_1) {
        if ((operation->handleState & TEE_HANDLE_FLAG_KEY_SET) != TEE_HANDLE_FLAG_KEY_SET) {
            tloge("Invalid operation key state for this operation\n");
            TEE_Panic(TEE_ERROR_BAD_STATE);
            return TEE_ERROR_BAD_STATE;
        }
        operation->handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;

        if (operation->keyValue == NULL) {
            tloge("Please set up operation key first\n");
            return TEE_ERROR_BAD_PARAMETERS;
        }
    }

    return cipher_init_check_config(operation, iv, iv_len);
}

static void clear_operation_iv(TEE_OperationHandle operation)
{
    if (operation->IV == NULL)
        return;
    TEE_Free(operation->IV);
    operation->IV = NULL;
    operation->IVLen = 0;
}

static TEE_Result set_operation_iv(TEE_OperationHandle operation, const void *iv, size_t iv_len)
{
    clear_operation_iv(operation);
    bool no_need_set_iv = (operation->algorithm == TEE_ALG_AES_ECB_PKCS5 ||
        operation->algorithm == TEE_ALG_AES_ECB_NOPAD ||
        operation->algorithm == TEE_ALG_SM4_ECB_NOPAD ||
        operation->algorithm == TEE_ALG_DES3_ECB_NOPAD ||
        operation->algorithm == TEE_ALG_AES_CMAC ||
        operation->algorithm == TEE_ALG_AES_GMAC ||
        operation->algorithm == TEE_ALG_DES_ECB_NOPAD || iv_len == 0);
    if (no_need_set_iv)
        return TEE_SUCCESS;

    if (iv_len > MAX_IV_LEN)
        return TEE_ERROR_BAD_PARAMETERS;

    operation->IV = TEE_Malloc(iv_len, 0);
    if (operation->IV == NULL) {
        tloge("operation->IV malloc failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    errno_t rc = memcpy_s(operation->IV, iv_len, iv, iv_len);
    if (rc != EOK) {
        tloge("copy iv failed");
        TEE_Free(operation->IV);
        operation->IV = NULL;
        return TEE_ERROR_SECURITY;
    }
    operation->IVLen = (uint32_t)iv_len;

    return TEE_SUCCESS;
}

static TEE_Result set_aes_xts_key(struct symmerit_key_t *key, TEE_OperationHandle operation)
{
    bool check = (operation->keySize > UINT32_MAX - operation->keySize2 ||
        operation->keySize + operation->keySize2 > MALLOC_MAX_KEY_SIZE);
    if (check)
        return TEE_ERROR_BAD_PARAMETERS;

    key->key_buffer = (uint64_t)(uintptr_t)TEE_Malloc((operation->keySize + operation->keySize2), 0);
    if (key->key_buffer == 0) {
        tloge("malloc failed");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    key->key_size = operation->keySize + operation->keySize2;

    errno_t rc = memcpy_s((uint8_t *)(uintptr_t)(key->key_buffer), key->key_size,
        operation->keyValue, operation->keySize);
    if (rc != EOK) {
        (void)memset_s((uint8_t *)(uintptr_t)(key->key_buffer), key->key_size, 0, key->key_size);
        TEE_Free((void *)(uintptr_t)(key->key_buffer));
        key->key_buffer = 0;
        return TEE_ERROR_SECURITY;
    }

    rc = memcpy_s((uint8_t *)(uintptr_t)(key->key_buffer) + operation->keySize,
        (key->key_size - operation->keySize), operation->keyValue2, operation->keySize2);
    if (rc != EOK) {
        (void)memset_s((uint8_t *)(uintptr_t)(key->key_buffer), key->key_size, 0, key->key_size);
        TEE_Free((void *)(uintptr_t)(key->key_buffer));
        key->key_buffer = 0;
        return TEE_ERROR_SECURITY;
    }

    key->key_type = CRYPTO_KEYTYPE_USER;
    return TEE_SUCCESS;
}

static TEE_Result set_cipher_key(struct symmerit_key_t *key, TEE_OperationHandle operation)
{
    if (operation->algorithm == TEE_ALG_AES_XTS)
        return set_aes_xts_key(key, operation);

    key->key_buffer = (uint64_t)(uintptr_t)(operation->keyValue);
    key->key_size = operation->keySize;
    key->key_type = CRYPTO_KEYTYPE_USER;
    return TEE_SUCCESS;
}

static TEE_Result do_cipher_init(TEE_OperationHandle operation)
{
    struct symmerit_key_t key = {0};
    struct memref_t *iv = NULL;
    struct memref_t tmp_iv = {0};
    uint32_t direction = (operation->mode == TEE_MODE_DECRYPT) ? DEC_MODE : ENC_MODE;

    crypto_hal_info *crypto_hal_data = operation->hal_info;
    if (crypto_hal_data == NULL) {
        tloge("Invalid params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result ret = set_cipher_key(&key, operation);
    if (ret != TEE_SUCCESS) {
        tloge("set cipher key failed!");
        return ret;
    }

    if (operation->IV != NULL && operation->IVLen != 0) {
        tmp_iv.buffer = (uint64_t)(uintptr_t)(operation->IV);
        tmp_iv.size = operation->IVLen;
        iv = &tmp_iv;
    }

    free_operation_ctx(operation);
    operation->crypto_ctxt = tee_crypto_cipher_init(operation->algorithm, direction,
        &key, iv, crypto_hal_data->crypto_flag);
    if (operation->algorithm == TEE_ALG_AES_XTS) {
        (void)memset_s((void *)(uintptr_t)(key.key_buffer), key.key_size, 0, key.key_size);
        TEE_Free((void *)(uintptr_t)(key.key_buffer));
        key.key_buffer = 0;
    }

    if (operation->crypto_ctxt == NULL) {
        tloge("Cipher init failed\n");
        return TEE_ERROR_GENERIC;
    }
    operation->handleState |= TEE_HANDLE_FLAG_INITIALIZED;

    return TEE_SUCCESS;
}
void TEE_CipherInit(TEE_OperationHandle operation, const void *IV, size_t IVLen)
{
    bool check = (operation == NULL || (check_operation((const TEE_OperationHandle)operation) != TEE_SUCCESS));
    if (check) {
        tloge("bad params");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    if (crypto_lock_operation(operation) != TEE_SUCCESS)
        return;

    TEE_Result ret = cipher_init_operation_state_check(operation, IV, IVLen);
    if (ret != TEE_SUCCESS) {
        crypto_unlock_operation(operation);
        TEE_Panic(ret);
        return;
    }

    ret = set_operation_iv(operation, IV, IVLen);
    if (ret != TEE_SUCCESS) {
        crypto_unlock_operation(operation);
        TEE_Panic(ret);
        return;
    }

    ret = do_cipher_init(operation);
    clear_operation_iv(operation);
    crypto_unlock_operation(operation);
    if (ret != TEE_SUCCESS)
        TEE_Panic(ret);
}

static TEE_Result cipher_update_check_config(const TEE_OperationHandle operation)
{
    const struct cipher_op_config_s *config = get_ae_config(operation->algorithm);

    bool check = (config == NULL || operation->operationClass != config->expect_class ||
        (operation->mode != config->expect_mode[0] && operation->mode != config->expect_mode[1]));
    if (check) {
        tloge("This algorithm is invalid for this operation\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result cipher_update_final_operation_state_check(const TEE_OperationHandle operation)
{
    uint32_t api_level = tee_get_ta_api_level();
    if (api_level >= API_LEVEL1_1_1) {
        if ((operation->handleState & TEE_HANDLE_FLAG_KEY_SET) != TEE_HANDLE_FLAG_KEY_SET) {
            tloge("This operation key state is invalid\n");
            return TEE_ERROR_BAD_STATE;
        }

        if ((operation->handleState & TEE_HANDLE_FLAG_INITIALIZED) != TEE_HANDLE_FLAG_INITIALIZED) {
            tloge("This cipher is not initialized yet\n");
            return TEE_ERROR_BAD_STATE;
        }
    }

    return cipher_update_check_config(operation);
}

static TEE_Result check_dest_param_valid(uint32_t algorithm, size_t src_len,
    const void *dest_data, const size_t *dest_len)
{
    bool check = ((algorithm == TEE_ALG_AES_CBC_MAC_NOPAD) || (algorithm == TEE_ALG_DES_CBC_MAC_NOPAD) ||
        (algorithm == TEE_ALG_AES_CMAC) || (algorithm == TEE_ALG_DES3_CBC_MAC_NOPAD) ||
        (algorithm == TEE_ALG_SM4_CBC_PKCS7));
    if (check)
        return TEE_SUCCESS;

    check = (dest_len == NULL || (dest_data == NULL));
    if (check) {
        tloge("invalid params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (*dest_len < src_len) {
        tloge("output buffer is too small\n");
        return TEE_ERROR_SHORT_BUFFER;
    }

    return TEE_SUCCESS;
}

static TEE_Result do_cipher_update(TEE_OperationHandle operation, const void *src_data, size_t src_len,
    void *dest_data, size_t *dest_len)
{
    struct memref_t data_in = { 0 };
    data_in.buffer = (uint64_t)(uintptr_t)src_data;
    data_in.size = (uint32_t)src_len;

    struct memref_t data_out = { 0 };
    if (dest_data != NULL && dest_len != NULL) {
        data_out.buffer = (uint64_t)(uintptr_t)dest_data;
        data_out.size = (uint32_t)(*dest_len);
    }

    int32_t ret = tee_crypto_cipher_update(operation->crypto_ctxt, &data_in, &data_out);
    if (ret != TEE_SUCCESS) {
        tloge("Cipher update failed, ret=%d\n", ret);
        return change_hal_ret_to_gp(ret);
    }

    if (dest_len != NULL)
        *dest_len = (size_t)data_out.size;
    return TEE_SUCCESS;
}

TEE_Result TEE_CipherUpdate(TEE_OperationHandle operation, const void *srcData, size_t srcLen, void *destData,
    size_t *destLen)
{
    bool check = (operation == NULL || (srcLen > 0 && srcData == NULL) ||
        (check_operation((const TEE_OperationHandle)operation) != TEE_SUCCESS));
    if (check) {
        tloge("bad params");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (srcLen == 0) {
        if (destLen != NULL)
            *destLen = 0;
        return TEE_SUCCESS;
    }
    if (crypto_lock_operation(operation) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    TEE_Result ret = cipher_update_final_operation_state_check((const TEE_OperationHandle)operation);
    if (ret != TEE_SUCCESS) {
        crypto_unlock_operation(operation);
        TEE_Panic(ret);
        return ret;
    }

    ret = check_dest_param_valid(operation->algorithm, srcLen, destData, destLen);
    if (ret != TEE_SUCCESS) {
        crypto_unlock_operation(operation);
        TEE_Panic(ret);
        return ret;
    }

    ret = do_cipher_update(operation, srcData, srcLen, destData, destLen);
    if (ret != TEE_SUCCESS) {
        operation->handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;
        crypto_unlock_operation(operation);
        TEE_Panic(ret);
        return ret;
    }

    crypto_unlock_operation(operation);
    return ret;
}

#define DES3_CBC_MAC_NOPAD_RESULT_LENGTH 8
static int32_t get_padding_dest_len(const TEE_OperationHandle operation, size_t src_len)
{
    if (operation->mode == TEE_MODE_ENCRYPT) {
        bool check = ((src_len / PKCS5_PADDING_LEN + 1) > (UINT32_MAX / PKCS5_PADDING_LEN));
        if (check) {
            tloge("src Len is too large!");
            return -1;
        }
        return (src_len / PKCS5_PADDING_LEN + 1) * PKCS5_PADDING_LEN;
    }
    return src_len;
}

static int32_t get_cipher_dest_len(const TEE_OperationHandle operation, size_t src_len)
{
    switch (operation->algorithm) {
    case TEE_ALG_DES_CBC_MAC_NOPAD:
    case TEE_ALG_DES3_CBC_MAC_NOPAD:
        return DES3_CBC_MAC_NOPAD_RESULT_LENGTH;
    case TEE_ALG_AES_CBC_MAC_NOPAD:
    case TEE_ALG_AES_CMAC:
        return AES_MAC_LEN;
    case TEE_ALG_AES_ECB_PKCS5:
    case TEE_ALG_AES_CBC_PKCS5:
        return get_padding_dest_len(operation, src_len);
    default:
        return src_len;
    }
}

static TEE_Result check_cipher_destlen(const TEE_OperationHandle operation, size_t src_len, size_t *dest_len)
{
    int32_t length = get_cipher_dest_len(operation, src_len);
    if (length == -1)
        return TEE_ERROR_BAD_PARAMETERS;

    if (*dest_len < (uint32_t)length) {
        tloge("output buffer is too small, *dest_len = 0x%x, length = 0x%x\n", *dest_len, length);
        if (*dest_len == 0)
            *dest_len = src_len;
        return TEE_ERROR_SHORT_BUFFER;
    }
    return TEE_SUCCESS;
}

static TEE_Result do_cipher_final(TEE_OperationHandle operation, const void *src_data, size_t src_len,
    void *dest_data, size_t *dest_len)
{
    struct memref_t data_in = {0};
    data_in.size = (uint32_t)src_len;
    if (data_in.size == 0)
        data_in.buffer = 0;
    else
        data_in.buffer = (uint64_t)(uintptr_t)src_data;

    struct memref_t data_out = {0};
    data_out.buffer = (uint64_t)(uintptr_t)dest_data;
    data_out.size = (uint32_t)(*dest_len);

    int32_t ret = tee_crypto_cipher_dofinal(operation->crypto_ctxt, &data_in, &data_out);
    free_operation_ctx(operation);
    if (ret != TEE_SUCCESS) {
        tloge("Cipher dofinal failed, ret=%d\n", ret);
        return change_hal_ret_to_gp(ret);
    }
    *dest_len = (size_t)data_out.size;
    if (operation->algorithm == TEE_ALG_AES_CMAC || operation->algorithm == TEE_ALG_AES_CBC_MAC_NOPAD)
        operation->digestLength = data_out.size;

    return TEE_SUCCESS;
}

TEE_Result TEE_CipherDoFinal(TEE_OperationHandle operation, const void *srcData, size_t srcLen, void *destData,
    size_t *destLen)
{
    bool check = (operation == NULL || (srcLen > 0 && srcData == NULL) || (destLen == NULL) ||
        (check_operation((const TEE_OperationHandle)operation) != TEE_SUCCESS));
    if (check) {
        tloge("bad params");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (crypto_lock_operation(operation) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    TEE_Result ret = cipher_update_final_operation_state_check((const TEE_OperationHandle)operation);
    if (ret != TEE_SUCCESS) {
        crypto_unlock_operation(operation);
        TEE_Panic(ret);
        return ret;
    }

    ret = check_cipher_destlen(operation, srcLen, destLen);
    if (ret != TEE_SUCCESS) {
        crypto_unlock_operation(operation);
        if (ret == TEE_ERROR_BAD_PARAMETERS)
            TEE_Panic(ret);
        tloge("Invalid dest length 0x%x", *destLen);
        return ret;
    }
    operation->handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;

    ret = do_cipher_final(operation, srcData, srcLen, destData, destLen);
    crypto_unlock_operation(operation);
    if ((ret != TEE_SUCCESS) && (ret != TEE_ERROR_SHORT_BUFFER)) {
        TEE_Panic(ret);
    }

    return ret;
}
