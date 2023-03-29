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
#include <tee_log.h>
#include <crypto_driver_adaptor.h>
#include <crypto_inner_defines.h>
#include <crypto_hal_hmac.h>
#include <tee_property_inner.h>
#include <tee_object_api.h>
#include "tee_operation.h"

#ifndef GP_COMPATIBLE
#define TEE_Panic(x) \
    do {             \
    } while (0)
#endif

struct mac_op_config_s {
    uint32_t expect_class;
    uint32_t expect_mode;
    uint32_t algorithm;
    uint32_t expect_iv_length;
};

static const struct mac_op_config_s g_mac_config[] = {
    { TEE_OPERATION_MAC, TEE_MODE_MAC, TEE_ALG_HMAC_MD5, 0 },
    { TEE_OPERATION_MAC, TEE_MODE_MAC, TEE_ALG_HMAC_SHA1, 0 },
    { TEE_OPERATION_MAC, TEE_MODE_MAC, TEE_ALG_HMAC_SHA224, 0 },
    { TEE_OPERATION_MAC, TEE_MODE_MAC, TEE_ALG_HMAC_SHA256, 0 },
    { TEE_OPERATION_MAC, TEE_MODE_MAC, TEE_ALG_HMAC_SHA384, 0 },
    { TEE_OPERATION_MAC, TEE_MODE_MAC, TEE_ALG_HMAC_SHA512, 0 },
    { TEE_OPERATION_MAC, TEE_MODE_MAC, TEE_ALG_AES_CBC_MAC_NOPAD, 16 },
    { TEE_OPERATION_MAC, TEE_MODE_MAC, TEE_ALG_AES_CMAC, 0 },
    { TEE_OPERATION_MAC, TEE_MODE_MAC, TEE_ALG_DES_CBC_MAC_NOPAD, 8 },
    { TEE_OPERATION_MAC, TEE_MODE_MAC, TEE_ALG_DES3_CBC_MAC_NOPAD, 8 },
    { TEE_OPERATION_MAC, TEE_MODE_MAC, TEE_ALG_HMAC_SM3, 0 },
    { TEE_OPERATION_MAC, TEE_MODE_MAC, TEE_ALG_SIP_HASH, 0 },
};
static TEE_Result mac_init_check_config(TEE_OperationHandle operation, const void *iv, size_t iv_len)
{
    const struct mac_op_config_s *config = NULL;
    uint32_t index;

    for (index = 0; index < ELEM_NUM(g_mac_config); index++) {
        if (operation->algorithm == g_mac_config[index].algorithm) {
            config = &g_mac_config[index];
            break;
        }
    }

    bool check = (config == NULL || operation->operationClass != config->expect_class ||
        operation->mode != config->expect_mode ||
        (config->expect_iv_length != 0 && (config->expect_iv_length != iv_len || iv == NULL)));
    if (check) {
        tloge("This Operation is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result mac_init_operation_state_check(TEE_OperationHandle operation, const void *iv, size_t iv_len)
{
    uint32_t api_level = tee_get_ta_api_level();
    if (api_level >= API_LEVEL1_1_1) {
        if ((operation->handleState & TEE_HANDLE_FLAG_KEY_SET) != TEE_HANDLE_FLAG_KEY_SET) {
            tloge("Invalid operation key state for this operation\n");
            return TEE_ERROR_BAD_STATE;
        }

        operation->handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;

        if (operation->keyValue == NULL) {
            tloge("Operation key is uninitialized\n");
            return TEE_ERROR_BAD_PARAMETERS;
        }
    }

    return mac_init_check_config(operation, iv, iv_len);
}

static TEE_Result mac_init_set_key(uint64_t *key_ptr, uint32_t *key_size, TEE_OperationHandle operation,
    const void *iv, size_t iv_len)
{
    bool check = (key_ptr == NULL || key_size == NULL || operation == NULL);
    if (check) {
        tloge("input is invalid!");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (operation->keyValue != NULL && operation->keySize != 0) {
        *key_ptr = (uint64_t)(uintptr_t)(operation->keyValue);
        *key_size = operation->keySize;
    } else if ((iv != NULL) && iv_len <= (TEE_MAX_KEY_SIZE_IN_BITS / BIT_TO_BYTE) &&
        tee_get_ta_api_level() == API_LEVEL1_0) {
        *key_ptr = (uint64_t)(uintptr_t)iv;
        *key_size = iv_len;
    } else {
        tloge("Key is not set up yet, please set up the key before initialization, iv_len = 0x%x\n", iv_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

static TEE_Result hmac_init_hal(TEE_OperationHandle operation, const void *iv, size_t iv_len, uint32_t engine)
{
    struct symmerit_key_t hmac_key = {0};
    uint32_t temp_key_size = 0;
    TEE_Result ret = mac_init_set_key(&(hmac_key.key_buffer), &temp_key_size, operation, iv, iv_len);
    if (ret != TEE_SUCCESS)
        return ret;

    hmac_key.key_size = temp_key_size;
    hmac_key.key_type = CRYPTO_KEYTYPE_USER;

    free_operation_ctx(operation);
    operation->crypto_ctxt = tee_crypto_hmac_init(operation->algorithm, &hmac_key, engine);
    if (operation->crypto_ctxt == NULL)
        return TEE_ERROR_GENERIC;

    return TEE_SUCCESS;
}

static bool is_cipher_algorithm(uint32_t algorithm)
{
    bool check = (algorithm == TEE_ALG_AES_CBC_MAC_NOPAD || algorithm == TEE_ALG_AES_CMAC ||
        algorithm == TEE_ALG_DES_CBC_MAC_NOPAD || algorithm == TEE_ALG_DES3_CBC_MAC_NOPAD);
    if (check)
        return true;

    return false;
}

void TEE_MACInit(TEE_OperationHandle operation, void *IV, size_t IVLen)
{
    TEE_Result ret;

    bool check = (operation == NULL || (check_operation((const TEE_OperationHandle)operation) != TEE_SUCCESS));
    if (check) {
        tloge("bad params");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }
    if (crypto_lock_operation(operation) != TEE_SUCCESS)
        return;

    ret = mac_init_operation_state_check(operation, IV, IVLen);
    if (ret != TEE_SUCCESS) {
        crypto_unlock_operation(operation);
        TEE_Panic(ret);
        return;
    }
    crypto_hal_info *crypto_hal_data = (crypto_hal_info *)(operation->hal_info);
    if (crypto_hal_data == NULL) {
        tloge("Crypto hal data is NULL\n");
        crypto_unlock_operation(operation);
        TEE_Panic(ret);
        return;
    }

    if (is_cipher_algorithm(operation->algorithm)) {
        crypto_unlock_operation(operation);
        TEE_CipherInit(operation, IV, IVLen);
        tlogd("TEE_AES_MACInit success\n");
        return;
    }

    ret = hmac_init_hal(operation, IV, IVLen, crypto_hal_data->crypto_flag);
    operation->handleState |= TEE_HANDLE_FLAG_INITIALIZED;
    crypto_unlock_operation(operation);
    if (ret != TEE_SUCCESS)
        TEE_Panic(ret);

    return;
}

static TEE_Result mac_update_check_config(const TEE_OperationHandle operation)
{
    const struct mac_op_config_s *config = NULL;

    for (uint32_t index = 0; index < ELEM_NUM(g_mac_config); index++) {
        if (operation->algorithm == g_mac_config[index].algorithm) {
            config = &g_mac_config[index];
            break;
        }
    }

    if (config == NULL || operation->operationClass != config->expect_class ||
        operation->mode != config->expect_mode) {
        tloge("Invalid param for this operation!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result mac_update_final_operation_state_check(const TEE_OperationHandle operation)
{
    uint32_t api_level = tee_get_ta_api_level();
    if (api_level >= API_LEVEL1_1_1) {
        if ((operation->handleState & TEE_HANDLE_FLAG_KEY_SET) != TEE_HANDLE_FLAG_KEY_SET) {
            tloge("Invalid operation key state for this operation\n");
            return TEE_ERROR_BAD_STATE;
        }
        if (operation->keyValue == NULL) {
            tloge("Operation key is uninitialized\n");
            return TEE_ERROR_BAD_PARAMETERS;
        }
        if ((operation->handleState & TEE_HANDLE_FLAG_INITIALIZED) != TEE_HANDLE_FLAG_INITIALIZED) {
            tloge("Invalid operation state: 0x%x\n", operation->handleState);
            return TEE_ERROR_BAD_STATE;
        }
    }

    return mac_update_check_config(operation);
}

static TEE_Result hmac_update_hal(TEE_OperationHandle operation, const void *chunk, size_t chunk_size)
{
    struct memref_t data_in = {0};
    data_in.buffer = (uint64_t)(uintptr_t)chunk;
    data_in.size = (uint32_t)chunk_size;

    int32_t ret = tee_crypto_hmac_update(operation->crypto_ctxt, &data_in);
    return change_hal_ret_to_gp(ret);
}

void TEE_MACUpdate(TEE_OperationHandle operation, const void *chunk, size_t chunkSize)
{
    TEE_Result ret;

    bool check = (operation == NULL || chunk == NULL || chunkSize == 0 ||
        (check_operation((const TEE_OperationHandle)operation) != TEE_SUCCESS));
    if (check) {
        tloge("bad params");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    if (crypto_lock_operation(operation) != TEE_SUCCESS)
        return;

    ret = mac_update_final_operation_state_check((const TEE_OperationHandle)operation);
    if (ret != TEE_SUCCESS) {
        crypto_unlock_operation(operation);
        TEE_Panic(ret);
        return;
    }

    if (is_cipher_algorithm(operation->algorithm)) {
        crypto_unlock_operation(operation);
        ret = TEE_CipherUpdate(operation, chunk, chunkSize, NULL, NULL);
        if (ret != TEE_SUCCESS) {
            tloge("cipher update failed\n");
            TEE_Panic(ret);
        }
        return;
    }

    ret = hmac_update_hal(operation, chunk, chunkSize);
    if (ret != TEE_SUCCESS) {
        tloge("MACUpdate failed, ret is 0x%x\n", ret);
        operation->handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;
        crypto_unlock_operation(operation);
        TEE_Panic(ret);
        return;
    }
    crypto_unlock_operation(operation);
}

static TEE_Result hmac_dofinal_hal(TEE_OperationHandle operation, const void *message, size_t message_len,
    void *mac, size_t *mac_len)
{
    struct memref_t data_in = {0};
    data_in.buffer = (uint64_t)(uintptr_t)message;
    data_in.size = (uint32_t)message_len;

    struct memref_t data_out = {0};
    data_out.buffer = (uint64_t)(uintptr_t)mac;
    data_out.size = (uint32_t)(*mac_len);

    int32_t ret = tee_crypto_hmac_dofinal(operation->crypto_ctxt, &data_in, &data_out);
    free_operation_ctx(operation);
    if (ret != TEE_SUCCESS) {
        tloge("hmac dofinal failed");
        return change_hal_ret_to_gp(ret);
    }
    *mac_len = (size_t)data_out.size;
    operation->digestLength = data_out.size;

    return TEE_SUCCESS;
}

static TEE_Result crypto_output_buff_len_check(uint32_t algorithm, size_t output_len)
{
    for (uint32_t i = 0; i < ELEM_NUM(g_output_lower_limit); i++) {
        if (g_output_lower_limit[i].algorithm == algorithm) {
            if (output_len < g_output_lower_limit[i].output_lower_limit)
                return TEE_ERROR_SHORT_BUFFER;
            else
                return TEE_SUCCESS;
        }
    }

    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_MACComputeFinal(TEE_OperationHandle operation, const void *message, size_t messageLen, void *mac,
    size_t *macLen)
{
    bool check = (operation == NULL || mac == NULL || macLen == NULL || *macLen == 0 ||
        (check_operation((const TEE_OperationHandle)operation) != TEE_SUCCESS));
    if (check) {
        tloge("bad params");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (crypto_lock_operation(operation) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    TEE_Result ret = mac_update_final_operation_state_check((const TEE_OperationHandle)operation);
    if (ret != TEE_SUCCESS) {
        crypto_unlock_operation(operation);
        TEE_Panic(ret);
        return ret;
    }
    if (is_cipher_algorithm(operation->algorithm)) {
        crypto_unlock_operation(operation);
        return TEE_CipherDoFinal(operation, message, messageLen, mac, macLen);
    }

    if (crypto_output_buff_len_check(operation->algorithm, *macLen) != TEE_SUCCESS) {
        tloge("Output buffer is too short\n");
        crypto_unlock_operation(operation);
        return TEE_ERROR_SHORT_BUFFER;
    }
    ret = hmac_dofinal_hal(operation, message, messageLen, mac, macLen);
    operation->handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;
    crypto_unlock_operation(operation);
    if (ret != TEE_SUCCESS) {
        if (ret != TEE_ERROR_SHORT_BUFFER)
            TEE_Panic(ret);
    }
    return ret;
}

TEE_Result tee_mac_commare_final100(TEE_OperationHandle operation, const void *message, size_t message_len,
    const void *mac, const size_t *mac_len)
{
    if (mac_len == NULL)
        return TEE_ERROR_BAD_PARAMETERS;
    uint8_t hmac_result_buff_temp[MAX_HMAC_LEN] = { 0 };
    size_t size = *mac_len;

    TEE_Result ret = TEE_MACComputeFinal(operation, message, message_len, hmac_result_buff_temp, &size);
    if (ret != TEE_SUCCESS) {
        tloge("TEE_MACComputeFinal failed\n");
        return ret;
    }

    bool check = (size != *mac_len || TEE_MemCompare((void *)hmac_result_buff_temp, mac, (uint32_t)size) != 0);
    if (check) {
        tloge("size 0x%x != *mac_len 0x%x or compare failed!\n", size, *mac_len);
        return TEE_ERROR_MAC_INVALID;
    }

    return ret;
}

TEE_Result tee_mac_commare_final111(TEE_OperationHandle operation, const void *message, size_t message_len,
    const void *mac, const size_t mac_len)
{
    size_t len = mac_len;

    return tee_mac_commare_final100(operation, message, message_len, mac, &len);
}
