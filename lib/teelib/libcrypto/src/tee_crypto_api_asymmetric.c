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
#include <tee_property_inner.h>
#include <tee_object_api.h>
#include <crypto_inner_defines.h>
#include <crypto_hal_rsa.h>
#include <crypto_hal_ec.h>
#include <crypto_driver_adaptor.h>
#include "tee_operation.h"

#define ENCRYPT_TYPE 0
#define DECRYPT_TYPE 1
/* For GP compatible, we add some panic when there is some error, For common use, we need to disable this panic */
#ifndef GP_COMPATIBLE
#define TEE_Panic(x) \
    do {             \
    } while (0)
#endif

struct asymmetric_cipher_op_config_s {
    uint32_t expect_class;
    uint32_t expect_mode[MAX_MODE_NUM];
    uint32_t algorithm;
};

static const struct asymmetric_cipher_op_config_s g_asymmetric_cipher_config[] = {
    { TEE_OPERATION_ASYMMETRIC_CIPHER, { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT }, TEE_ALG_SM2_PKE },
    { TEE_OPERATION_ASYMMETRIC_CIPHER, { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT }, TEE_ALG_RSAES_PKCS1_V1_5 },
    { TEE_OPERATION_ASYMMETRIC_CIPHER, { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT }, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1 },
    { TEE_OPERATION_ASYMMETRIC_CIPHER, { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT }, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224 },
    { TEE_OPERATION_ASYMMETRIC_CIPHER, { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT }, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256 },
    { TEE_OPERATION_ASYMMETRIC_CIPHER, { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT }, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384 },
    { TEE_OPERATION_ASYMMETRIC_CIPHER, { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT }, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512 },
    { TEE_OPERATION_ASYMMETRIC_CIPHER, { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT }, TEE_ALG_RSA_NOPAD },
};

static TEE_Result asymmetric_cipher_operation_check_config(const TEE_OperationHandle operation, uint32_t type)
{
    const struct asymmetric_cipher_op_config_s *config = NULL;
    uint32_t index;

    for (index = 0; index < ELEM_NUM(g_asymmetric_cipher_config); index++) {
        if (operation->algorithm == g_asymmetric_cipher_config[index].algorithm) {
            config = &g_asymmetric_cipher_config[index];
            break;
        }
    }

    bool check = (config == NULL || operation->operationClass != config->expect_class ||
        type >= ELEM_NUM(config->expect_mode) || operation->mode != config->expect_mode[type]);
    if (check) {
        tloge("Invalid param of this operation!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result asymmetric_cipher_operation_state_check(const TEE_OperationHandle operation, uint32_t type)
{
    uint32_t api_level = tee_get_ta_api_level();
    if (api_level >= API_LEVEL1_1_1) {
        if ((operation->handleState & TEE_HANDLE_FLAG_KEY_SET) != TEE_HANDLE_FLAG_KEY_SET) {
            tloge("Invalid operation key state for this operation\n");
            return TEE_ERROR_BAD_STATE;
        }
    }

    bool check = (operation->publicKey == NULL && operation->privateKey == NULL);
    if (check) {
        tloge("Please setup the key first for this operation\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return asymmetric_cipher_operation_check_config(operation, type);
}

static void change_digest_mode(struct crypto_attribute_t *tmp_attribute, uint32_t i)
{
    crypto_uint2uint get_rsa_mgf1_hash[] = {
        { TEE_DH_HASH_SHA1_mode,   CRYPTO_TYPE_DIGEST_SHA1 },
        { TEE_DH_HASH_SHA224_mode, CRYPTO_TYPE_DIGEST_SHA224 },
        { TEE_DH_HASH_SHA256_mode, CRYPTO_TYPE_DIGEST_SHA256 },
        { TEE_DH_HASH_SHA384_mode, CRYPTO_TYPE_DIGEST_SHA384 },
        { TEE_DH_HASH_SHA512_mode, CRYPTO_TYPE_DIGEST_SHA512 },
    };

    for (uint32_t j = 0; j < ELEM_NUM(get_rsa_mgf1_hash); j++) {
        if (get_rsa_mgf1_hash[j].src == tmp_attribute[i].content.value.a) {
            tmp_attribute[i].content.value.a = get_rsa_mgf1_hash[j].dest;
            return;
        }
    }
}

static void refresh_attribute_value(struct asymmetric_params_t *rsa_params)
{
    if (rsa_params == NULL)
        return;
    if (rsa_params->param_count > TEE_PARAM_COUNT_MAX) {
        tloge("the param_count is too big param_count = %u", rsa_params->param_count);
        return;
    }

    struct crypto_attribute_t *tmp_attribute = NULL;
    tmp_attribute = (struct crypto_attribute_t *)(uintptr_t)(rsa_params->attribute);
    for (uint32_t i = 0; i < rsa_params->param_count; i++) {
        if (tmp_attribute[i].attribute_id != CRYPTO_ATTR_RSA_MGF1_HASH)
            continue;
        change_digest_mode(tmp_attribute, i);
        return;
    }
}

static void change_digest_mode_bak(struct crypto_attribute_t *tmp_attribute, uint32_t i)
{
    crypto_uint2uint get_rsa_mgf1_hash[] = {
        { CRYPTO_TYPE_DIGEST_SHA1,   TEE_DH_HASH_SHA1_mode },
        { CRYPTO_TYPE_DIGEST_SHA224, TEE_DH_HASH_SHA224_mode },
        { CRYPTO_TYPE_DIGEST_SHA256, TEE_DH_HASH_SHA256_mode },
        { CRYPTO_TYPE_DIGEST_SHA384, TEE_DH_HASH_SHA384_mode },
        { CRYPTO_TYPE_DIGEST_SHA512, TEE_DH_HASH_SHA512_mode },
    };

    for (uint32_t j = 0; j < ELEM_NUM(get_rsa_mgf1_hash); j++) {
        if (get_rsa_mgf1_hash[j].src == tmp_attribute[i].content.value.a) {
            tmp_attribute[i].content.value.a = get_rsa_mgf1_hash[j].dest;
            return;
        }
    }
}

static void refresh_attribute_value_back(struct asymmetric_params_t *rsa_params)
{
    if (rsa_params == NULL)
        return;

    struct crypto_attribute_t *tmp_attribute = NULL;
    tmp_attribute = (struct crypto_attribute_t *)(uintptr_t)(rsa_params->attribute);
    for (uint32_t i = 0; i < rsa_params->param_count; i++) {
        if (tmp_attribute[i].attribute_id != CRYPTO_ATTR_RSA_MGF1_HASH)
            continue;
        change_digest_mode_bak(tmp_attribute, i);
        return;
    }
}

static TEE_Result rsa_encrypt_hal(TEE_OperationHandle operation, struct asymmetric_params_t *extra_params,
    struct memref_t *data_in, struct memref_t *data_out, uint32_t engine)
{
    refresh_attribute_value(extra_params);
    int32_t ret = tee_crypto_rsa_encrypt(operation->algorithm,
        (const struct rsa_pub_key_t *)(operation->publicKey), extra_params, data_in, data_out, engine);
    refresh_attribute_value_back(extra_params);
    return change_hal_ret_to_gp(ret);
}

static TEE_Result sm2_encrypt_hal(TEE_OperationHandle operation, struct asymmetric_params_t *extra_params,
    struct memref_t *data_in, struct memref_t *data_out, uint32_t engine)
{
    int32_t ret = tee_crypto_ecc_encrypt(operation->algorithm,
        (const struct ecc_pub_key_t *)(operation->publicKey), extra_params, data_in, data_out, engine);
    return change_hal_ret_to_gp(ret);
}

static TEE_Result asymmetric_encrypt_hal(TEE_OperationHandle operation,
    struct asymmetric_params_t *extra_params,
    struct memref_t *data_in, struct memref_t *data_out)
{
    uint32_t engine = ((crypto_hal_info *)(operation->hal_info))->crypto_flag;

    switch (operation->algorithm) {
    case TEE_ALG_RSA_NOPAD:
    case TEE_ALG_RSAES_PKCS1_V1_5:
    case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
    case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
    case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
    case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
    case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
        return rsa_encrypt_hal(operation, extra_params, data_in, data_out, engine);
    case TEE_ALG_SM2_PKE:
        return sm2_encrypt_hal(operation, extra_params, data_in, data_out, engine);
    default:
        tloge("the algorithm is not support");
        break;
    }
    return TEE_ERROR_NOT_SUPPORTED;
}

static TEE_Result asymmetric_process_hal(TEE_OperationHandle operation, const TEE_Attribute *params,
    uint32_t param_count, operation_src_dest *data,
    TEE_Result (* asymmetric_hal_handle_ptr)(TEE_OperationHandle, struct asymmetric_params_t *,
        struct memref_t *, struct memref_t *))
{
    struct asymmetric_params_t *extra_params = NULL;
    struct crypto_attribute_t *tmp_attribute = NULL;
    TEE_Result ret;
    bool check = (params != NULL && param_count != 0);
    if (check) {
        extra_params = TEE_Malloc(sizeof(*extra_params), 0);
        if (extra_params == NULL) {
            tloge("malloc extra params failed!");
            return TEE_ERROR_SECURITY;
        }
        tmp_attribute = TEE_Malloc(param_count * sizeof(*tmp_attribute), 0);
        if (tmp_attribute == NULL) {
            tloge("malloc tmp attr failed!");
            TEE_Free(extra_params);
            return TEE_ERROR_SECURITY;
        }
        for (uint32_t i = 0; i < param_count; i++) {
            tmp_attribute[i].attribute_id = params[i].attributeID;
            tmp_attribute[i].content.value.a = params[i].content.value.a;
            tmp_attribute[i].content.value.b = params[i].content.value.b;
        }
        extra_params->attribute = (uint64_t)(uintptr_t)tmp_attribute;
        extra_params->param_count = param_count;
    }

    struct memref_t data_in = {0};
    data_in.buffer = (uint64_t)(uintptr_t)(data->src_data);
    data_in.size = (uint32_t)data->src_len;

    struct memref_t data_out = {0};
    data_out.buffer = (uint64_t)(uintptr_t)(data->dest_data);
    data_out.size = (uint32_t)(*(data->dest_len));

    ret = asymmetric_hal_handle_ptr(operation, extra_params, &data_in, &data_out);
    TEE_Free(extra_params);
    extra_params = NULL;
    TEE_Free(tmp_attribute);
    tmp_attribute = NULL;
    if (ret != TEE_SUCCESS) {
        tloge("asymmetric failed, ret is 0x%x", ret);
        return ret;
    }
    *(data->dest_len) = (size_t)data_out.size;
    return TEE_SUCCESS;
}

TEE_Result TEE_AsymmetricEncrypt(TEE_OperationHandle operation, const TEE_Attribute *params, uint32_t paramCount,
    void *srcData, size_t srcLen, void *destData, size_t *destLen)
{
    bool check = (operation == NULL || srcData == NULL || srcLen == 0 || destData == NULL || destLen == NULL ||
        *destLen == 0 || (check_operation((const TEE_OperationHandle)operation) != TEE_SUCCESS));
    if (check) {
        tloge("bad params");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (*destLen < srcLen) {
        tloge("Output buffer is too short\n");
        return TEE_ERROR_SHORT_BUFFER;
    }

    if (paramCount > MAX_EXTRA_PARAM_COUNT) {
        tloge("param count is invalid");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (crypto_lock_operation(operation) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    TEE_Result ret = asymmetric_cipher_operation_state_check((const TEE_OperationHandle)operation, ENCRYPT_TYPE);
    if (ret != TEE_SUCCESS) {
        crypto_unlock_operation(operation);
        TEE_Panic(ret);
        return ret;
    }

    operation_src_dest src_dest_param = { 0 };
    fill_src_dest_param(&src_dest_param, srcData, srcLen, destData, destLen);
    ret = asymmetric_process_hal(operation, params, paramCount, &src_dest_param, asymmetric_encrypt_hal);
    crypto_unlock_operation(operation);
    if (ret != TEE_SUCCESS) {
        if (ret != TEE_ERROR_SHORT_BUFFER)
            TEE_Panic(ret);
    }
    return ret;
}

static TEE_Result rsa_decrypt_hal(TEE_OperationHandle operation, struct asymmetric_params_t *extra_params,
    struct memref_t *data_in, struct memref_t *data_out, uint32_t engine)
{
    refresh_attribute_value(extra_params);
    int32_t ret = tee_crypto_rsa_decrypt(operation->algorithm,
        (const struct rsa_priv_key_t *)(operation->privateKey), extra_params, data_in, data_out, engine);
    refresh_attribute_value_back(extra_params);
    return change_hal_ret_to_gp(ret);
}

static TEE_Result sm2_decrypt_hal(TEE_OperationHandle operation, struct asymmetric_params_t *extra_params,
    struct memref_t *data_in, struct memref_t *data_out, uint32_t engine)
{
    int32_t ret = tee_crypto_ecc_decrypt(operation->algorithm,
        (const struct ecc_priv_key_t *)(operation->privateKey), extra_params, data_in, data_out, engine);
    return change_hal_ret_to_gp(ret);
}

static TEE_Result asymmetric_decrypt_hal(TEE_OperationHandle operation,
    struct asymmetric_params_t *extra_params,
    struct memref_t *data_in, struct memref_t *data_out)
{
    uint32_t engine = ((crypto_hal_info *)(operation->hal_info))->crypto_flag;

    switch (operation->algorithm) {
    case TEE_ALG_RSAES_PKCS1_V1_5:
    case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
    case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
    case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
    case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
    case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
    case TEE_ALG_RSA_NOPAD:
        return rsa_decrypt_hal(operation, extra_params, data_in, data_out, engine);
    case TEE_ALG_SM2_PKE:
        return sm2_decrypt_hal(operation, extra_params, data_in, data_out, engine);
    default:
        tloge("the algorithm is not support");
        break;
    }
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_AsymmetricDecrypt(TEE_OperationHandle operation, const TEE_Attribute *params, uint32_t paramCount,
    void *srcData, size_t srcLen, void *destData, size_t *destLen)
{
    bool check = (operation == NULL || srcData == NULL || srcLen == 0 || destData == NULL || destLen == NULL ||
        *destLen == 0 || (check_operation((const TEE_OperationHandle)operation) != TEE_SUCCESS));
    if (check) {
        tloge("bad params");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (*destLen <= 0) {
        tloge("Output buffer is too short\n");
        return TEE_ERROR_SHORT_BUFFER;
    }

    if (paramCount > MAX_EXTRA_PARAM_COUNT) {
        tloge("param count is invalid");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (crypto_lock_operation(operation) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    TEE_Result ret = asymmetric_cipher_operation_state_check((const TEE_OperationHandle)operation, DECRYPT_TYPE);
    if (ret != TEE_SUCCESS) {
        crypto_unlock_operation(operation);
        TEE_Panic(ret);
        return ret;
    }

    operation_src_dest src_dest_param = { 0 };
    fill_src_dest_param(&src_dest_param, srcData, srcLen, destData, destLen);
    ret = asymmetric_process_hal(operation, params, paramCount, &src_dest_param, asymmetric_decrypt_hal);
    crypto_unlock_operation(operation);
    if (ret != TEE_SUCCESS)
        TEE_Panic(ret);
    return ret;
}

static const uint32_t g_support_signature_algs[] = {
    TEE_ALG_RSASSA_PKCS1_V1_5_MD5,
    TEE_ALG_RSASSA_PKCS1_V1_5_SHA1,
    TEE_ALG_RSASSA_PKCS1_V1_5_SHA224,
    TEE_ALG_RSASSA_PKCS1_V1_5_SHA256,
    TEE_ALG_RSASSA_PKCS1_V1_5_SHA384,
    TEE_ALG_RSASSA_PKCS1_V1_5_SHA512,
    TEE_ALG_RSASSA_PKCS1_PSS_MGF1_MD5,
    TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1,
    TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224,
    TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256,
    TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384,
    TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512,
    TEE_ALG_ECDSA_SHA1,
    TEE_ALG_ECDSA_SHA224,
    TEE_ALG_ECDSA_SHA256,
    TEE_ALG_ECDSA_SHA384,
    TEE_ALG_ECDSA_SHA512,
    TEE_ALG_SM2_DSA_SM3,
    TEE_ALG_ED25519,
};

static TEE_Result signature_operation_state_check(const TEE_OperationHandle operation, uint32_t expect_mode)
{
    bool is_support_alg = false;
    if (tee_get_ta_api_level() >= API_LEVEL1_1_1) {
        if ((operation->handleState & TEE_HANDLE_FLAG_KEY_SET) != TEE_HANDLE_FLAG_KEY_SET) {
            tloge("Invalid operation key state for this operation\n");
            return TEE_ERROR_BAD_STATE;
        }
    }

    /* Some algorithm use only public key for sign and verify operation */
    bool check = ((operation->publicKey == NULL) && (operation->privateKey == NULL));
    if (check) {
        tloge("Please setup the key first for this operation\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    for (uint32_t i = 0; i < sizeof(g_support_signature_algs) / sizeof(g_support_signature_algs[0]); i++) {
        if (g_support_signature_algs[i] == operation->algorithm) {
            is_support_alg = true;
            break;
        }
    }

    check = (!is_support_alg || operation->operationClass != TEE_OPERATION_ASYMMETRIC_SIGNATURE ||
        operation->mode != expect_mode);
    if (check) {
        tloge("Invalid param for this operation\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static uint32_t get_expect_digest_len_from_algorithm(uint32_t algorithm, uint32_t api_level)
{
    size_t i = 0;
    crypto_uint2uint digest_len[] = { { TEE_ALG_RSASSA_PKCS1_V1_5_MD5, MD5_OUTPUT_LEN },
        { TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, SHA1_OUTPUT_LEN },
        { TEE_ALG_RSASSA_PKCS1_V1_5_SHA224, SHA224_OUTPUT_LEN },
        { TEE_ALG_RSASSA_PKCS1_V1_5_SHA256, SHA256_OUTPUT_LEN },
        { TEE_ALG_RSASSA_PKCS1_V1_5_SHA384, SHA384_OUTPUT_LEN },
        { TEE_ALG_RSASSA_PKCS1_V1_5_SHA512, SHA512_OUTPUT_LEN },
        { TEE_ALG_RSASSA_PKCS1_PSS_MGF1_MD5, MD5_OUTPUT_LEN },
        { TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1, SHA1_OUTPUT_LEN },
        { TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224, SHA224_OUTPUT_LEN },
        { TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256, SHA256_OUTPUT_LEN },
        { TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384, SHA384_OUTPUT_LEN },
        { TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512, SHA512_OUTPUT_LEN } };

    size_t total_map_num = sizeof(digest_len) / sizeof(digest_len[0]);
    for (; i < total_map_num; i++) {
        if (digest_len[i].src == algorithm)
            return digest_len[i].dest;
    }

    if (api_level > API_LEVEL1_0) {
        crypto_uint2uint get_ecc_digest_len[] = {
            { TEE_ALG_ECDSA_SHA1, SHA1_OUTPUT_LEN },
            { TEE_ALG_ECDSA_SHA224, SHA224_OUTPUT_LEN },
            { TEE_ALG_ECDSA_SHA256, SHA256_OUTPUT_LEN },
            { TEE_ALG_ECDSA_SHA384, SHA384_OUTPUT_LEN },
            { TEE_ALG_ECDSA_SHA512, SHA512_OUTPUT_LEN },
        };

        total_map_num = sizeof(get_ecc_digest_len) / sizeof(get_ecc_digest_len[0]);
        for (i = 0; i < total_map_num; i++) {
            if (get_ecc_digest_len[i].src == algorithm)
                return get_ecc_digest_len[i].dest;
        }
    }
    return 0;
}

/* This special procedure is just aim to rsa */
static TEE_Result pre_proc_digest_len(uint32_t algorithm, uint32_t digest_len, uint32_t *expect_digest_len,
    uint32_t api_level)
{
    *expect_digest_len = get_expect_digest_len_from_algorithm(algorithm, api_level);
    if (*expect_digest_len == 0) {
        *expect_digest_len = digest_len;
        return TEE_SUCCESS;
    }
    if (digest_len != *expect_digest_len) {
        if (api_level > API_LEVEL1_0) {
            tloge("The digest len is Invalid");
            return TEE_ERROR_BAD_PARAMETERS;
        }
        if (digest_len < *expect_digest_len) {
            tloge("The digest len is too small, digest_len = 0x%x, expect_digest_len = 0x%x\n", digest_len,
                *expect_digest_len);
            return TEE_ERROR_BAD_PARAMETERS;
        }
    }
    return TEE_SUCCESS;
}

static TEE_Result check_pss_param(const TEE_OperationHandle operation, const TEE_Attribute *params,
    uint32_t param_count, uint32_t api_level)
{
    /*
     * when params is not given, paramCount is 0
     * when params is given, paramCount is 1
     */
    if (api_level < API_LEVEL1_1_1)
        return TEE_SUCCESS;

    bool check = (params == NULL || param_count == 0 || param_count == 1);
    if (check)
        return TEE_SUCCESS;

    check = (operation->algorithm != TEE_ALG_RSASSA_PKCS1_PSS_MGF1_MD5 &&
        operation->algorithm != TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1 &&
        operation->algorithm != TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224 &&
        operation->algorithm != TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256 &&
        operation->algorithm != TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384 &&
        operation->algorithm != TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512);
    if (check)
        return TEE_SUCCESS;

    tloge("check pss param error!\n");
    return TEE_ERROR_BAD_PARAMETERS;
}

static TEE_Result asymmetric_sign_hal(TEE_OperationHandle operation,
    struct asymmetric_params_t *extra_params, struct memref_t *data_in, struct memref_t *data_out)
{
    int32_t ret;
    uint32_t engine = ((crypto_hal_info *)(operation->hal_info))->crypto_flag;

    switch (operation->algorithm) {
    case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_MD5:
    case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
    case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
    case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
    case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
    case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
    case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
    case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
    case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
    case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
    case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
    case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
        refresh_attribute_value(extra_params);
        ret = tee_crypto_rsa_sign_digest(operation->algorithm,
            (const struct rsa_priv_key_t*)(operation->privateKey), extra_params, data_in, data_out, engine);
        refresh_attribute_value_back(extra_params);
        return change_hal_ret_to_gp(ret);
    case TEE_ALG_ECDSA_SHA1:
    case TEE_ALG_ECDSA_SHA224:
    case TEE_ALG_ECDSA_SHA256:
    case TEE_ALG_ECDSA_SHA384:
    case TEE_ALG_ECDSA_SHA512:
    case TEE_ALG_SM2_DSA_SM3:
    case TEE_ALG_ED25519:
        ret = tee_crypto_ecc_sign_digest(operation->algorithm,
            (const struct ecc_priv_key_t*)(operation->privateKey), extra_params, data_in, data_out, engine);
        return change_hal_ret_to_gp(ret);
    default:
        tloge("the algorithm is not support");
        return TEE_ERROR_NOT_SUPPORTED;
    }
}

TEE_Result TEE_AsymmetricSignDigest(TEE_OperationHandle operation, const TEE_Attribute *params, uint32_t paramCount,
    void *digest, size_t digestLen, void *signature, size_t *signatureLen)
{
    bool check = (operation == NULL || digest == NULL || digestLen == 0 || signature == NULL || signatureLen == NULL ||
        *signatureLen == 0 || (check_operation((const TEE_OperationHandle)operation) != TEE_SUCCESS));
    if (check) {
        tloge("The params is invalid");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (paramCount > MAX_EXTRA_PARAM_COUNT) {
        tloge("The param count is invalid");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (crypto_lock_operation(operation) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    TEE_Result ret = signature_operation_state_check(operation, TEE_MODE_SIGN);
    if (ret != TEE_SUCCESS)
        goto exit;

    uint32_t api_level = tee_get_ta_api_level();
    ret = check_pss_param(operation, params, paramCount, api_level);
    if (ret != TEE_SUCCESS)
        goto exit;

    uint32_t expect_digest_len = digestLen;

    ret = pre_proc_digest_len(operation->algorithm, digestLen, &expect_digest_len, api_level);
    if (ret != TEE_SUCCESS)
        goto exit;

    operation_src_dest src_dest_param = { 0 };
    fill_src_dest_param(&src_dest_param, digest, expect_digest_len, signature, signatureLen);
    ret = asymmetric_process_hal(operation, params, paramCount, &src_dest_param, asymmetric_sign_hal);
    crypto_unlock_operation(operation);
    if (ret != TEE_SUCCESS)
        TEE_Panic(ret);
    return ret;

exit:
    crypto_unlock_operation(operation);
    TEE_Panic(ret);
    return ret;
}

static TEE_Result asymmetric_verify_hal(TEE_OperationHandle operation,
    struct asymmetric_params_t *extra_params, struct memref_t *data_in, struct memref_t *data_out)
{
    int32_t ret;
    uint32_t engine = ((crypto_hal_info *)(operation->hal_info))->crypto_flag;

    switch (operation->algorithm) {
    case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
    case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
    case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
    case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
    case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
    case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
    case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_MD5:
    case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
    case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
    case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
    case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
    case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
        refresh_attribute_value(extra_params);
        ret = tee_crypto_rsa_verify_digest(operation->algorithm,
            (const struct rsa_pub_key_t *)(operation->publicKey), extra_params, data_in, data_out, engine);
        refresh_attribute_value_back(extra_params);
        return change_hal_ret_to_gp(ret);
    case TEE_ALG_ECDSA_SHA1:
    case TEE_ALG_ECDSA_SHA224:
    case TEE_ALG_ECDSA_SHA256:
    case TEE_ALG_ECDSA_SHA384:
    case TEE_ALG_ECDSA_SHA512:
    case TEE_ALG_SM2_DSA_SM3:
    case TEE_ALG_ED25519:
        ret = tee_crypto_ecc_verify_digest(operation->algorithm,
            (const struct ecc_pub_key_t *)(operation->publicKey), extra_params, data_in, data_out, engine);
        return change_hal_ret_to_gp(ret);
    default:
        tloge("the algorithm is not support");
        return TEE_ERROR_NOT_SUPPORTED;
    }
}

TEE_Result TEE_AsymmetricVerifyDigest(TEE_OperationHandle operation, const TEE_Attribute *params, uint32_t paramCount,
    void *digest, size_t digestLen, void *signature, size_t signatureLen)
{
    bool check = (operation == NULL || digest == NULL || digestLen == 0 || signature == NULL || signatureLen == 0 ||
        (check_operation((const TEE_OperationHandle)operation) != TEE_SUCCESS));
    if (check) {
        tloge("bad params");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (paramCount > MAX_EXTRA_PARAM_COUNT) {
        tloge("param count is invalid");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (crypto_lock_operation(operation) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    TEE_Result ret = signature_operation_state_check(operation, TEE_MODE_VERIFY);
    if (ret != TEE_SUCCESS)
        goto exit;

    uint32_t api_level = tee_get_ta_api_level();
    ret                = check_pss_param(operation, params, paramCount, api_level);
    if (ret != TEE_SUCCESS)
        goto exit;

    crypto_hal_info *crypto_hal_data = (crypto_hal_info *)(operation->hal_info);
    if (crypto_hal_data == NULL) {
        ret = TEE_ERROR_BAD_PARAMETERS;
        goto exit;
    }
    uint32_t expect_digest_len = digestLen;

    ret = pre_proc_digest_len(operation->algorithm, digestLen, &expect_digest_len, api_level);
    if (ret != TEE_SUCCESS) {
        crypto_unlock_operation(operation);
        TEE_Panic(ret);
        return ret;
    }

    operation_src_dest src_dest_param = { 0 };
    fill_src_dest_param(&src_dest_param, digest, expect_digest_len, signature, &signatureLen);
    ret = asymmetric_process_hal(operation, params, paramCount, &src_dest_param, asymmetric_verify_hal);
    crypto_unlock_operation(operation);
    if (ret != TEE_SUCCESS)
        TEE_Panic(ret);
    return ret;
exit:
    crypto_unlock_operation(operation);
    TEE_Panic(ret);
    return ret;
}
