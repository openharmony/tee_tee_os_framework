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
#include <ta_framework.h>
#include <tee_ext_api.h>
#include <tee_property_inner.h>
#include <tee_object_api.h>
#include <crypto_inner_defines.h>
#include <crypto_hal_ae.h>
#include <crypto_hal.h>
#include <crypto_driver_adaptor.h>
#include "tee_operation.h"

#define MAX_TAG_NUM   7
#define MAX_NONCE_NUM 7

/* For GP compatible, we add some panic when there is some error, For common use, we need to disable this panic */
#ifndef GP_COMPATIBLE
#define TEE_Panic(x) \
    do {             \
    } while (0)
#endif

struct ae_op_config_s {
    uint32_t expect_class;
    uint32_t expect_mode[MAX_MODE_NUM];
    uint32_t algorithm;
    uint32_t nonce_count;
    uint32_t expect_nonce[MAX_NONCE_NUM];
    uint32_t tag_count;
    uint32_t expect_tag[MAX_TAG_NUM];
};

#define GCM_NOUNCE_NUM 2
#define GCM_TAG_NUM    5
#define CCM_NOUNCE_NUM 7
#define CCM_TAG_NUM    7
static const struct ae_op_config_s g_ae_config[] = {
    { TEE_OPERATION_AE,
        { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT },
        TEE_ALG_AES_GCM,
        GCM_NOUNCE_NUM,
        /* GCM nounce len: can be 7 or 12 bytes */
        { 7, 12 },
        GCM_TAG_NUM,
        /* tagLen: Size in bits of the tag. For AES-GCM, can be 128, 120, 112, 104, or 96. */
        { 96 / 8, 104 / 8, 112 / 8, 120 / 8, 128 / 8 } },
    { TEE_OPERATION_AE,
        { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT },
        TEE_ALG_AES_CCM,
        CCM_NOUNCE_NUM,
        /* CCM nounce len:can be 7 ~ 13 bytes */
        { 7, 8, 9, 10, 11, 12, 13 },
        CCM_TAG_NUM,
        /* tagLen: Size in bits of the tag. For AES-CCM, can be 128, 112, 96, 80, 64, 48, or 32 */
        { 32 / 8, 48 / 8, 64 / 8, 80 / 8, 96 / 8, 112 / 8, 128 / 8 } },
    { TEE_OPERATION_AE,
        { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT },
        TEE_ALG_SM4_GCM,
        GCM_NOUNCE_NUM,
        /* GCM nounce len: can be 7 or 12 bytes */
        { 7, 12 },
        GCM_TAG_NUM,
        /* tagLen: Size in bits of the tag. For SM4-GCM, can be 128, 120, 112, 104, or 96. */
        { 96 / 8, 104 / 8, 112 / 8, 120 / 8, 128 / 8 } },
};

static TEE_Result check_tag_length_valid(const uint32_t *valid_tag_array, uint32_t array_size, uint32_t tag_length)
{
    uint32_t index;

    for (index = 0; index < array_size; index++) {
        if (valid_tag_array[index] == tag_length)
            return TEE_SUCCESS;
    }

    return TEE_ERROR_NOT_SUPPORTED;
}

static TEE_Result check_nonce_length_valid(const uint32_t *valid_nonce_array, uint32_t array_size,
    uint32_t nonce_length)
{
    uint32_t index;
    for (index = 0; index < array_size; index++) {
        if (valid_nonce_array[index] == nonce_length)
            return TEE_SUCCESS;
    }

    return TEE_ERROR_BAD_PARAMETERS;
}

static TEE_Result ae_init_operation_error(const TEE_OperationHandle operation)
{
    if ((operation->handleState & TEE_HANDLE_FLAG_KEY_SET) != TEE_HANDLE_FLAG_KEY_SET) {
        tloge("Invalid operation key state for this operation\n");
        return TEE_ERROR_BAD_STATE;
    }

    if ((operation->handleState & TEE_HANDLE_FLAG_INITIALIZED) == TEE_HANDLE_FLAG_INITIALIZED) {
        tloge("Invalid operation state for this operation\n");
        return TEE_ERROR_BAD_STATE;
    }

    if (operation->keyValue == NULL) {
        tloge("Please initialize operation key first\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result ae_init_check_config(const TEE_OperationHandle operation, const struct ae_op_config_s *config,
    uint32_t tag_length, uint32_t nonce_length)
{
    if (operation->operationClass != config->expect_class) {
        tloge("This operationClass is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (operation->mode != config->expect_mode[0] && operation->mode != config->expect_mode[1]) {
        tloge("This operation mode is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result ret = check_nonce_length_valid(config->expect_nonce, config->nonce_count, nonce_length);
    if (ret != TEE_SUCCESS) {
        tloge("Invalid nonce length for this operation\n");
        return ret;
    }

    ret = check_tag_length_valid(config->expect_tag, config->tag_count, tag_length);
    if (ret != TEE_SUCCESS)
        tloge("Invalid tag length for this operation\n");

    return ret;
}

static TEE_Result ae_init_operation_state_check(const TEE_OperationHandle operation, uint32_t tag_length,
    uint32_t nonce_length)
{
    const struct ae_op_config_s *config = NULL;
    uint32_t index;
    TEE_Result ret;

    uint32_t api_level = tee_get_ta_api_level();
    if (api_level > API_LEVEL1_0) {
        ret = ae_init_operation_error(operation);
        if (ret != TEE_SUCCESS)
            return ret;
    }

    for (index = 0; index < ELEM_NUM(g_ae_config); index++) {
        if (operation->algorithm == g_ae_config[index].algorithm) {
            config = &g_ae_config[index];
            break;
        }
    }

    if (config == NULL) {
        tloge("This algorithm is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return ae_init_check_config(operation, config, tag_length, nonce_length);
}

static TEE_Result ae_init_hal(TEE_OperationHandle operation, const operation_ae_init *ae_init_param, uint32_t engine)
{
    uint32_t direction = (operation->mode == TEE_MODE_ENCRYPT) ? ENC_MODE : DEC_MODE;
    free_operation_ctx(operation);

    struct symmerit_key_t ae_key = {0};
    ae_key.key_buffer = (uint64_t)(uintptr_t)(operation->keyValue);
    ae_key.key_size = operation->keySize;
    ae_key.key_type = CRYPTO_KEYTYPE_USER;

    struct ae_init_data ae_init_param_hal = {0};
    ae_init_param_hal.nonce = (uint64_t)(uintptr_t)(ae_init_param->nonce);
    ae_init_param_hal.nonce_len = (uint32_t)ae_init_param->nonce_len;
    ae_init_param_hal.tag_len = ae_init_param->tag_len;
    ae_init_param_hal.aad_len = (uint32_t)ae_init_param->aad_len;
    ae_init_param_hal.payload_len = (uint32_t)ae_init_param->payload_len;
    operation->crypto_ctxt = tee_crypto_ae_init(operation->algorithm, direction, &ae_key,
        &ae_init_param_hal, engine);
    if (operation->crypto_ctxt == NULL)
        return TEE_ERROR_NOT_SUPPORTED;

    return TEE_SUCCESS;
}

TEE_Result TEE_AEInit(TEE_OperationHandle operation, void *nonce, size_t nonceLen, uint32_t tagLen, size_t AADLen,
    size_t payloadLen)
{
    bool check = (operation == NULL || (check_operation((const TEE_OperationHandle)operation) != TEE_SUCCESS) ||
        nonce == NULL);
    if (check) {
        tloge("bad params");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t api_level = tee_get_ta_api_level();
    if (api_level >= API_LEVEL1_1_1)
        tagLen = tagLen / BIT_TO_BYTE;

    if (crypto_lock_operation(operation) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    TEE_Result ret = ae_init_operation_state_check((const TEE_OperationHandle)operation, tagLen, nonceLen);
    if (ret != TEE_SUCCESS)
        goto end;

    operation->digestLength          = tagLen;

    crypto_hal_info *crypto_hal_data = (crypto_hal_info *)(operation->hal_info);
    if (crypto_hal_data == NULL) {
        tloge("Ae init call back is invalid\n");
        ret = TEE_ERROR_BAD_PARAMETERS;
        goto end;
    }

    operation_ae_init ae_init_param = { 0 };
    ae_init_param.nonce       = nonce;
    ae_init_param.nonce_len   = nonceLen;
    ae_init_param.tag_len     = tagLen;
    ae_init_param.aad_len     = AADLen;
    ae_init_param.payload_len = payloadLen;

    ret = ae_init_hal(operation, &ae_init_param, crypto_hal_data->crypto_flag);
    if (ret != TEE_SUCCESS)
        tloge("ae init hal failed, ret = 0x%x", ret);
end:
    crypto_unlock_operation(operation);
    if (ret != TEE_ERROR_NOT_SUPPORTED && ret != TEE_SUCCESS)
        TEE_Panic(ret);
    return ret;
}

static TEE_Result ae_update_check_config(const TEE_OperationHandle operation, const struct ae_op_config_s *config)
{
    if (operation->operationClass != config->expect_class) {
        tloge("This operationClass is invalid!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (operation->mode != config->expect_mode[0] && operation->mode != config->expect_mode[1]) {
        tloge("This operation mode is invalid!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result ae_update_operation_check(const TEE_OperationHandle operation)
{
    const struct ae_op_config_s *config = NULL;
    uint32_t index;
    for (index = 0; index < ELEM_NUM(g_ae_config); index++) {
        if (operation->algorithm == g_ae_config[index].algorithm) {
            config = &g_ae_config[index];
            break;
        }
    }

    if (config == NULL) {
        tloge("This algorithm is invalid!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return ae_update_check_config(operation, config);
}

static TEE_Result ae_update_aad_check(TEE_OperationHandle operation, uint32_t api_level)
{
    if (api_level > API_LEVEL1_1_1) {
        if ((operation->handleState & TEE_HANDLE_FLAG_INITIALIZED) == TEE_HANDLE_FLAG_INITIALIZED) {
            tloge("Invalid operation state for this operation\n");
            return TEE_ERROR_BAD_STATE;
        }
    }

    if ((operation->handleState & TEE_HANDLE_FLAG_KEY_SET) != TEE_HANDLE_FLAG_KEY_SET) {
        tloge("Invalid operation key state for this operation\n");
        return TEE_ERROR_BAD_STATE;
    }
    return ae_update_operation_check(operation);
}

static TEE_Result ae_update_check(TEE_OperationHandle operation)
{
    if ((operation->handleState & TEE_HANDLE_FLAG_KEY_SET) != TEE_HANDLE_FLAG_KEY_SET) {
        tloge("Invalid operation key state for this operation\n");
        return TEE_ERROR_BAD_STATE;
    }
    return ae_update_operation_check(operation);
}

static TEE_Result ae_update_aad_hal(TEE_OperationHandle operation, const void *data, size_t data_len)
{
    struct memref_t aad_data = {0};
    aad_data.buffer = (uint64_t)(uintptr_t)data;
    aad_data.size = (uint32_t)data_len;
    int32_t ret = tee_crypto_ae_update_aad(operation->crypto_ctxt, &aad_data);
    return change_hal_ret_to_gp(ret);
}

void TEE_AEUpdateAAD(TEE_OperationHandle operation, const void *AADdata, size_t AADdataLen)
{
    bool check = (operation == NULL || (check_operation((const TEE_OperationHandle)operation) != TEE_SUCCESS));
    if (check) {
        tloge("operation is invalid");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    if (pthread_mutex_lock(&(operation->operation_lock)) != TEE_SUCCESS) {
        tloge("crypto api pthread_mutex_lock failed\n");
        return;
    }

    uint32_t api_level = tee_get_ta_api_level();
    if ((operation->algorithm == TEE_ALG_AES_GCM || operation->algorithm == TEE_ALG_SM4_GCM)
        && api_level == API_LEVEL1_0)
        goto unlock;

    check = (AADdata == NULL || AADdataLen == 0);
    if (check) {
        tloge("Invalid aad data");
        goto unlock;
    }

    TEE_Result ret = ae_update_aad_check(operation, api_level);
    if (ret != TEE_SUCCESS)
        goto unlock_with_panic;

    ret = ae_update_aad_hal(operation, AADdata, AADdataLen);
    if (ret != TEE_SUCCESS) {
        tloge("AEUpdateAAD failed\n");
        goto unlock_with_panic;
    }

    if (api_level == API_LEVEL1_1_1)
        operation->handleState |= TEE_HANDLE_FLAG_INITIALIZED;

unlock:
    if (pthread_mutex_unlock(&(operation->operation_lock)) != TEE_SUCCESS)
        tloge("crypto api pthread_mutex_unlock failed\n");
    return;

unlock_with_panic:
    if (pthread_mutex_unlock(&(operation->operation_lock)) != TEE_SUCCESS)
        tloge("crypto api pthread_mutex_unlock failed\n");
    TEE_Panic(ret);
    return;
}

void fill_src_dest_param(operation_src_dest *src_dest_param, void *src_data_value, size_t src_len_value,
    void *dest_data_value, size_t *dest_len_value)
{
    if (src_dest_param == NULL || dest_len_value == NULL) {
        tloge("the input is invalid\n");
        return;
    }
    src_dest_param->src_data  = src_data_value;
    src_dest_param->src_len   = src_len_value;
    src_dest_param->dest_data = dest_data_value;
    src_dest_param->dest_len  = dest_len_value;
}

static TEE_Result ae_update_hal(TEE_OperationHandle operation, const void *src_data, size_t src_len,
    void *dest_data, size_t *dest_len)
{
    struct memref_t data_in = {0};
    struct memref_t data_out = {0};

    data_in.buffer = (uint64_t)(uintptr_t)src_data;
    data_in.size = (uint32_t)src_len;
    data_out.buffer = (uint64_t)(uintptr_t)dest_data;
    data_out.size = (uint32_t)(*dest_len);

    int32_t ret = tee_crypto_ae_update(operation->crypto_ctxt, &data_in, &data_out);
    if (ret != TEE_SUCCESS) {
        tloge("do ae update failed");
        return change_hal_ret_to_gp(ret);
    }
    *dest_len = (size_t)data_out.size;
    return TEE_SUCCESS;
}

TEE_Result TEE_AEUpdate(TEE_OperationHandle operation, void *srcData, size_t srcLen, void *destData, size_t *destLen)
{
    bool check = (operation == NULL || (srcData == NULL && srcLen > 0) || destLen == NULL ||
        (*destLen > 0 && destData == NULL) || (check_operation((const TEE_OperationHandle)operation) != TEE_SUCCESS));
    if (check) {
        tloge("bad params");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (*destLen < srcLen) {
        tloge("Output buffer is too short to hold the result\n");
        return TEE_ERROR_SHORT_BUFFER;
    }
    uint32_t api_level = tee_get_ta_api_level();
    if (crypto_lock_operation(operation) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    TEE_Result ret = ae_update_check(operation);
    if (ret != TEE_SUCCESS)
        goto end;

    crypto_hal_info *crypto_hal_data = (crypto_hal_info *)(operation->hal_info);
    if (crypto_hal_data == NULL) {
        tloge("Ae update call back is invalid\n");
        ret =  TEE_ERROR_BAD_PARAMETERS;
        goto end;
    }

    check = ((api_level == API_LEVEL1_1_1) || ((api_level > API_LEVEL1_1_1) && (srcLen != 0)));
    if (check)
        operation->handleState |= TEE_HANDLE_FLAG_INITIALIZED;

    ret = ae_update_hal(operation, srcData, srcLen, destData, destLen);
    if (ret != TEE_SUCCESS)
        tloge("Ae update failed, ret: 0x%x\n", ret);

end:
    if (ret != TEE_SUCCESS) {
        operation->handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;
        crypto_unlock_operation(operation);
        TEE_Panic(ret);
        return ret;
    }
    crypto_unlock_operation(operation);
    return ret;
}

static TEE_Result check_dest_data_old_level(const size_t *dest_len, const void *dest_data, size_t src_len)
{
    bool check = ((dest_len == NULL) || (dest_data == NULL) || (*dest_len == 0));
    if (check) {
        tloge("Invalid dest data/length");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (*dest_len < src_len) {
        tloge("Output buffer is too short to hold the result\n");
        return TEE_ERROR_SHORT_BUFFER;
    }
    return TEE_SUCCESS;
}

static TEE_Result check_dest_data_new_level(size_t *dest_len, const void *dest_data, size_t src_len, bool *flag)
{
    bool check_null         = ((dest_data == NULL) && (dest_len == NULL));
    bool check_short_buffer = (((dest_data == NULL) && (dest_len != NULL) && (*dest_len == 0)) ||
        ((dest_data != NULL) && (dest_len != NULL) && (*dest_len < src_len)));
    bool check_success      = ((dest_data != NULL) && (dest_len != NULL) && (*dest_len >= src_len));

    if (check_null) {
        *flag = true;
        return TEE_SUCCESS;
    } else if (check_short_buffer) {
        tloge("Output buffer is too short to hold the result\n");
        if (*dest_len == 0)
            *dest_len = src_len;
        return TEE_ERROR_SHORT_BUFFER;
    } else if (check_success) {
        return TEE_SUCCESS;
    } else {
        tloge("Invalid destdata or destlen");
        return TEE_ERROR_BAD_PARAMETERS;
    }
}

static TEE_Result ae_encrypt_check_dest_data(const void *dest_data, size_t *dest_len, size_t src_len,
    uint32_t api_level, bool *flag)
{
    if (api_level < API_LEVEL1_1_1)
        return check_dest_data_old_level(dest_len, dest_data, src_len);
    else
        return check_dest_data_new_level(dest_len, dest_data, src_len, flag);
}

static TEE_Result malloc_dest_data(void **dest_data, size_t *dest_len, size_t src_len,
    const TEE_OperationHandle operation)
{
    uint32_t malloc_size;
    if (((struct ctx_handle_t *)(operation->crypto_ctxt))->is_support_ae_update) {
        malloc_size = src_len + CTX_OFF_SET;
    } else {
        struct crypto_cache_t *cache =
            (struct crypto_cache_t *)(uintptr_t)(((struct ctx_handle_t *)(operation->crypto_ctxt))->cache_buffer);
        malloc_size = cache->effective_len + src_len;
    }

    bool check = (malloc_size < src_len || malloc_size > MAX_SRC_SIZE);
    if (check) {
        tloge("src len or update len is invalid");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (malloc_size != 0) {
        *dest_data = TEE_Malloc(malloc_size, 0);
        if (*dest_data == NULL) {
            tloge("malloc destData failed");
            return TEE_ERROR_OUT_OF_MEMORY;
        }
    }
    *dest_len = malloc_size;
    return TEE_SUCCESS;
}

void free_dest_data(void **dest_data)
{
    if (dest_data == NULL)
        return;
    TEE_Free(*dest_data);
    *dest_data = NULL;
    return;
}

static TEE_Result ae_encrypt_hal(TEE_OperationHandle operation, operation_src_dest *src_dest_param,
    void *tag, size_t *tag_len)
{
    struct memref_t data_in = {0};
    struct memref_t data_out = {0};
    struct memref_t tag_ref = {0};

    data_in.size = (uint32_t)(src_dest_param->src_len);
    if (data_in.size == 0)
        data_in.buffer = 0;
    else
        data_in.buffer = (uint64_t)(uintptr_t)(src_dest_param->src_data);

    data_out.buffer = (uint64_t)(uintptr_t)(src_dest_param->dest_data);
    data_out.size = (uint32_t)(*(src_dest_param->dest_len));

    tag_ref.buffer = (uint64_t)(uintptr_t)tag;
    tag_ref.size = (uint32_t)(*tag_len);

    int32_t ret = tee_crypto_ae_enc_final(operation->crypto_ctxt, &data_in, &data_out, &tag_ref);
    free_operation_ctx(operation);
    if (ret != TEE_SUCCESS) {
        tloge("ae encrypt failed");
        return change_hal_ret_to_gp(ret);
    }

    *(src_dest_param->dest_len) = (size_t)data_out.size;
    *tag_len = (size_t)tag_ref.size;
    operation->digestLength = tag_ref.size;
    return TEE_SUCCESS;
}

static TEE_Result ae_encrypt_final_param_check(TEE_OperationHandle operation, void *src_data, size_t src_len,
    void *tag, const size_t *tag_len)
{
    bool check = ((src_len > 0 && src_data == NULL) || tag_len == NULL || (*tag_len > 0 && tag == NULL) ||
        (check_operation((const TEE_OperationHandle)operation) != TEE_SUCCESS));
    if (check) {
        tloge("bad params");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_Result ret = ae_update_check(operation);
    if (ret != TEE_SUCCESS) {
        tloge("ae final check failed");
        return ret;
    }

    operation->handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;
    return TEE_SUCCESS;
}

TEE_Result TEE_AEEncryptFinal(TEE_OperationHandle operation, void *srcData, size_t srcLen, void *destData,
    size_t *destLen, void *tag, size_t *tagLen)
{
    bool check = (operation == NULL || crypto_lock_operation(operation) != TEE_SUCCESS);
    if (check)
        return TEE_ERROR_BAD_PARAMETERS;

    TEE_Result ret = ae_encrypt_final_param_check(operation, srcData, srcLen, tag, tagLen);
    if (ret != TEE_SUCCESS) {
        crypto_unlock_operation(operation);
        TEE_Panic(ret);
        return ret;
    }

    bool malloc_flag = false;
    uint32_t api_level = tee_get_ta_api_level();
    ret = ae_encrypt_check_dest_data(destData, destLen, srcLen, api_level, &malloc_flag);
    if (ret != TEE_SUCCESS)
        goto ae_encrypt_free_dest;

    size_t temp_dest_len = 0;
    void *temp_dest_data = NULL;
    uint32_t templen     = 0;
    if (malloc_flag) {
        ret = malloc_dest_data(&temp_dest_data, &temp_dest_len, srcLen, operation);
        if (ret != TEE_SUCCESS)
            goto ae_encrypt_free_dest;
    } else {
        templen = *destLen;
    }
    operation_src_dest src_dest_param = { 0 };
    if (malloc_flag)
        fill_src_dest_param(&src_dest_param, srcData, srcLen, temp_dest_data, &temp_dest_len);
    else
        fill_src_dest_param(&src_dest_param, srcData, srcLen, destData, destLen);

    ret = ae_encrypt_hal(operation, &src_dest_param, tag, tagLen);
    if (ret != TEE_SUCCESS) {
        tloge("Ae encrypt final failed, ret: 0x%x\n", ret);
        goto ae_encrypt_free_dest;
    }
    if (api_level < API_LEVEL1_1_1)
        *destLen = templen;
ae_encrypt_free_dest:
    if (malloc_flag)
        free_dest_data(&temp_dest_data);
    crypto_unlock_operation(operation);
    if (ret != TEE_SUCCESS)
        TEE_Panic(ret);
    return ret;
}

static TEE_Result ae_decrypt_hal(TEE_OperationHandle operation, operation_src_dest *src_dest_param,
    const void *tag, size_t tag_len)
{
    struct memref_t data_in = {0};
    struct memref_t data_out = {0};
    struct memref_t tag_ref = {0};

    data_in.size = (uint32_t)src_dest_param->src_len;
    if (data_in.size == 0)
        data_in.buffer = 0;
    else
        data_in.buffer = (uint64_t)(uintptr_t)(src_dest_param->src_data);

    data_out.buffer = (uint64_t)(uintptr_t)(src_dest_param->dest_data);
    data_out.size = (uint32_t)(*(src_dest_param->dest_len));

    tag_ref.buffer = (uint64_t)(uintptr_t)tag;
    tag_ref.size = (uint32_t)tag_len;

    int32_t ret = tee_crypto_ae_dec_final(operation->crypto_ctxt, &data_in, &tag_ref, &data_out);
    free_operation_ctx(operation);
    if (ret != TEE_SUCCESS) {
        tloge("ae decrypt failed");
        return change_hal_ret_to_gp(ret);
    }

    *(src_dest_param->dest_len) = (size_t)data_out.size;
    return TEE_SUCCESS;
}

static TEE_Result ae_decrypt_final_param_check(TEE_OperationHandle operation, void *src_data, size_t src_len,
    void *tag, size_t tag_len)
{
    bool check = ((src_len > 0 && src_data == NULL) || (tag_len > 0 && tag == NULL));
    if (check) {
        tloge("bad params");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_Result ret = ae_update_check(operation);
    if (ret != TEE_SUCCESS) {
        tloge("ae decrypt final check failed");
        return ret;
    }

    operation->handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;
    return TEE_SUCCESS;
}

TEE_Result TEE_AEDecryptFinal(TEE_OperationHandle operation, void *srcData, size_t srcLen, void *destData,
    size_t *destLen, void *tag, size_t tagLen)
{
    bool check = (operation == NULL || destLen == NULL || (*destLen > 0 && destData == NULL) ||
        (*destLen == 0 && destData != NULL) || (check_operation((const TEE_OperationHandle)operation) != TEE_SUCCESS));
    if (check)
        return TEE_ERROR_BAD_PARAMETERS;

    if (crypto_lock_operation(operation) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    bool malloc_flag = false;
    TEE_Result ret = ae_decrypt_final_param_check(operation, srcData, srcLen, tag, tagLen);
    if (ret != TEE_SUCCESS)
        goto free_dest;

    operation_src_dest src_dest_param = { 0 };
    uint32_t api_level = tee_get_ta_api_level();
    size_t temp_dest_len = 0;
    void *temp_dest_data = NULL;
    uint32_t templen = 0;

    if (*destLen == 0 && api_level > API_LEVEL1_0) {
        ret = malloc_dest_data(&temp_dest_data, &temp_dest_len, srcLen, operation);
        if (ret != TEE_SUCCESS)
            goto free_dest;
        malloc_flag = true;
    } else {
        templen = *destLen;
        if (*destLen < srcLen) {
            tloge("Output buffer is too short to hold the result\n");
            crypto_unlock_operation(operation);
            return TEE_ERROR_SHORT_BUFFER;
        }
    }

    if (malloc_flag)
        fill_src_dest_param(&src_dest_param, srcData, srcLen, temp_dest_data, &temp_dest_len);
    else
        fill_src_dest_param(&src_dest_param, srcData, srcLen, destData, destLen);

    ret = ae_decrypt_hal(operation, &src_dest_param, tag, tagLen);
    if (ret != TEE_SUCCESS) {
        tloge("ae decrypt final failed, ret: 0x%x\n", ret);
        goto free_dest;
    }

    if (api_level < API_LEVEL1_1_1)
        *destLen = templen;
free_dest:
    if (malloc_flag)
        free_dest_data(&temp_dest_data);
    crypto_unlock_operation(operation);
    if (ret != TEE_SUCCESS)
        TEE_Panic(ret);
    return ret;
}
