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
#include <tee_obj.h>
#include <tee_property_inner.h>
#include <tee_object_api.h>
#include <crypto_inner_defines.h>
#include <crypto_alg_config.h>
#include <crypto_hal_rsa.h>
#include <crypto_hal_ec.h>
#include <crypto_hal.h>
#include <crypto_driver_adaptor.h>
#include <crypto_manager.h>
#include "tee_operation.h"
#include "tee_crypto_hal.h"
#ifdef OPENSSL_ENABLE
#include "openssl/crypto.h"
#endif

/* For GP compatible, we add some panic when there is some error, For common use, we need to disable this panic */
#ifndef GP_COMPATIBLE
#define TEE_Panic(x) \
    do {             \
    } while (0)
#endif

TEE_Result crypto_lock_operation(TEE_OperationHandle operation)
{
    if (operation == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    int32_t ret = pthread_mutex_lock(&(operation->operation_lock));
    if (ret != 0)
        tloge("crypto api pthread mutex lock failed\n");
    return (TEE_Result)ret;
}

void crypto_unlock_operation(TEE_OperationHandle operation)
{
    if (operation == NULL)
        return;

    int32_t ret = pthread_mutex_unlock(&(operation->operation_lock));
    if (ret != 0)
        tloge("crypto api pthread mutex unlock failed\n");
}

TEE_Result crypto_lock_two_operation(TEE_OperationHandle op1, TEE_OperationHandle op2)
{
    if (crypto_lock_operation(op1) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    if (crypto_lock_operation(op2) != TEE_SUCCESS) {
        (void)pthread_mutex_unlock(&(op1->operation_lock));
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}
void crypyo_unlock_two_operation(TEE_OperationHandle op1, TEE_OperationHandle op2)
{
    if (op1 == NULL || op2 == NULL)
        return;

    if (pthread_mutex_unlock(&(op1->operation_lock)) != TEE_SUCCESS)
        tloge("crypto api pthread_mutex_unlock op1 failed\n");
    if (pthread_mutex_unlock(&(op2->operation_lock)) != TEE_SUCCESS)
        tloge("crypto api pthread_mutex_unlock op2 failed\n");
}

struct algo_key_size_low_s {
    uint32_t algo;
    uint32_t min_key_size;
};

static const struct algo_key_size_low_s g_algo_low_lev_key_size_config[] = {
    { TEE_ALG_RSASSA_PKCS1_V1_5_MD5, RSA_MIN_KEY_SIZE },
    { TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, RSA_MIN_KEY_SIZE },
    { TEE_ALG_RSASSA_PKCS1_V1_5_SHA224, RSA_MIN_KEY_SIZE },
    { TEE_ALG_RSASSA_PKCS1_V1_5_SHA256, RSA_MIN_KEY_SIZE },
    { TEE_ALG_RSASSA_PKCS1_V1_5_SHA384, RSA_MIN_KEY_SIZE },
    { TEE_ALG_RSASSA_PKCS1_V1_5_SHA512, RSA_MIN_KEY_SIZE },
    { TEE_ALG_RSASSA_PKCS1_PSS_MGF1_MD5, RSA_MIN_KEY_SIZE },
    { TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1, RSA_MIN_KEY_SIZE },
    { TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224, RSA_MIN_KEY_SIZE },
    { TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256, RSA_MIN_KEY_SIZE },
    { TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384, RSA_MIN_KEY_SIZE },
    { TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512, RSA_MIN_KEY_SIZE },
    { TEE_ALG_RSAES_PKCS1_V1_5, RSA_MIN_KEY_SIZE },
    { TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1, RSA_MIN_KEY_SIZE },
    { TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224, RSA_MIN_KEY_SIZE },
    { TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256, RSA_MIN_KEY_SIZE },
    { TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384, RSA_MIN_KEY_SIZE },
    { TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512, RSA_MIN_KEY_SIZE },
    { TEE_ALG_RSA_NOPAD, RSA_MIN_KEY_SIZE },
    { TEE_ALG_DH_DERIVE_SHARED_SECRET, DH_MIN_KEY_SIZE },
    { TEE_ALG_ECDSA_SHA1, ECDSA_MIN_KEY_SIZE },
    { TEE_ALG_ECDSA_SHA224, ECDSA_MIN_KEY_SIZE },
    { TEE_ALG_ECDSA_SHA256, ECDSA_MIN_KEY_SIZE },
    { TEE_ALG_ECDSA_SHA384, ECDSA_MIN_KEY_SIZE },
    { TEE_ALG_ECDSA_SHA512, ECDSA_MIN_KEY_SIZE },
    { TEE_ALG_ECDH_DERIVE_SHARED_SECRET, ECDH_MIN_KEY_SIZE },
    { TEE_ALG_ECDH_P224, ECDH_MIN_KEY_SIZE },
    { TEE_ALG_ECDH_P256, ECDH_MIN_KEY_SIZE },
    { TEE_ALG_ECDH_P384, ECDH_MIN_KEY_SIZE },
    { TEE_ALG_ECDH_P521, ECDH_MIN_KEY_SIZE },
};

static TEE_Result check_low_lev_key_size_for_alg(uint32_t algorithm, uint32_t key_size)
{
    for (size_t index = 0; index < ELEM_NUM(g_algo_low_lev_key_size_config); index++) {
        if (algorithm == g_algo_low_lev_key_size_config[index].algo) {
            if (key_size >= g_algo_low_lev_key_size_config[index].min_key_size) {
                return TEE_SUCCESS;
            } else {
                tloge("the key size is invalid\n");
                return TEE_ERROR_NOT_SUPPORTED;
            }
        }
    }
    return TEE_SUCCESS;
}

static TEE_Result check_valid_key_size_for_algorithm(uint32_t algorithm, uint32_t max_key_size)
{
    uint32_t api_level = tee_get_ta_api_level();
    if (api_level == API_LEVEL1_0)
        return check_low_lev_key_size_for_alg(algorithm, max_key_size);

    return crypto_check_keysize(algorithm, max_key_size);
}

struct error_code_t {
    int32_t hal_err;
    TEE_Result gp_err;
};

TEE_Result change_hal_ret_to_gp(int32_t error)
{
    struct error_code_t change_err[] = {
        { CRYPTO_NOT_SUPPORTED,       TEE_ERROR_NOT_SUPPORTED },
        { CRYPTO_CIPHERTEXT_INVALID,  TEE_ERROR_CIPHERTEXT_INVALID },
        { CRYPTO_BAD_FORMAT,          TEE_ERROR_BAD_FORMAT },
        { CRYPTO_BAD_PARAMETERS,      TEE_ERROR_BAD_PARAMETERS },
        { CRYPTO_BAD_STATE,           TEE_ERROR_BAD_STATE },
        { CRYPTO_SHORT_BUFFER,        TEE_ERROR_SHORT_BUFFER },
        { CRYPTO_OVERFLOW,            TEE_ERROR_OVERFLOW },
        { CRYPTO_MAC_INVALID,         TEE_ERROR_MAC_INVALID },
        { CRYPTO_SIGNATURE_INVALID,   TEE_ERROR_SIGNATURE_INVALID },
        { CRYPTO_ERROR_SECURITY,      TEE_ERROR_SECURITY },
        { CRYPTO_ERROR_OUT_OF_MEMORY, TEE_ERROR_OUT_OF_MEMORY },
        { CRYPTO_SUCCESS,             TEE_SUCCESS },
    };
    for (uint32_t i = 0; i < ELEM_NUM(change_err); i++) {
        if (error == change_err[i].hal_err)
            return change_err[i].gp_err;
    }
    return error;
}

static TEE_Result set_operation_hal_info(TEE_OperationHandle operation, uint32_t algorithm)
{
    operation->hal_info = TEE_Malloc(sizeof(crypto_hal_info), 0);
    if (operation->hal_info == NULL) {
        tloge("Malloc memory failed for crypto hal info\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    uint32_t engine = crypto_get_default_engine(algorithm);
    return TEE_SetCryptoFlag(operation, engine);
}

size_t crypto_get_output_length(uint32_t algorithm)
{
    for (uint32_t i = 0; i < ELEM_NUM(g_output_lower_limit); i++) {
        if (g_output_lower_limit[i].algorithm == algorithm)
            return g_output_lower_limit[i].output_lower_limit;
    }

    return 0;
}

static TEE_Result check_allocate_param(TEE_OperationHandle *operation, uint32_t algorithm, uint32_t max_keysize)
{
    bool check = (operation == NULL || max_keysize > TEE_MAX_KEY_SIZE_IN_BITS);
    if (check) {
        tloge("bad params");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result ret = check_valid_key_size_for_algorithm(algorithm, max_keysize);
    if (ret != TEE_SUCCESS) {
        if (ret == TEE_ERROR_BAD_PARAMETERS)
            tloge("max_keysize 0x%x is wrong or not supported now\n", max_keysize);
        else
            tloge("algorithm 0x%x is incorrect or not supported\n", algorithm);
        return TEE_ERROR_NOT_SUPPORTED;
    }
    uint32_t temp_key_size = max_keysize;
    uint32_t api_level = tee_get_ta_api_level();
    if (api_level == API_LEVEL1_0)
        temp_key_size *= BIT_TO_BYTE;
    ret = check_if_unsafe_alg(algorithm, temp_key_size);
    if (ret != TEE_SUCCESS)
        return ret;
    return TEE_SUCCESS;
}

static TEE_Result check_digest_alg_valid(uint32_t algorithm, TEE_OperationHandle operation_handle)
{
    if (!crypto_check_alg_valid(algorithm, TEE_MODE_DIGEST)) {
        tloge("TEE_MODE_DIGEST and algorithm are not match\n");
        return TEE_ERROR_NOT_SUPPORTED;
    }

    if (tee_get_ta_api_level() > API_LEVEL1_0)
        operation_handle->requiredKeyUsage = 0;
    else
        operation_handle->requiredKeyUsage = TEE_USAGE_MAC;
    operation_handle->handleState |= (TEE_HANDLE_FLAG_KEY_SET | TEE_HANDLE_FLAG_INITIALIZED);
    operation_handle->digestLength = crypto_get_output_length(algorithm);

    return TEE_SUCCESS;
}

static TEE_Result check_enc_dec_alg_valid(uint32_t algorithm, TEE_OperationHandle operation_handle, uint32_t mode)
{
    if (!crypto_check_alg_valid(algorithm, TEE_MODE_ENCRYPT)) {
        tloge("TEE_MODE_ENCRYPT TEE_MODE_DECRYPT and algorithm are not match\n");
        return TEE_ERROR_NOT_SUPPORTED;
    }

    operation_handle->publicKey      = NULL;
    operation_handle->privateKey     = NULL;
    if (mode == TEE_MODE_ENCRYPT)
        operation_handle->requiredKeyUsage = TEE_USAGE_ENCRYPT;
    if (mode == TEE_MODE_DECRYPT)
        operation_handle->requiredKeyUsage = TEE_USAGE_DECRYPT;
    if (algorithm == TEE_ALG_AES_XTS) {
        operation_handle->handleState |= TEE_HANDLE_FLAG_EXPECT_TWO_KEYS;
        if (tee_get_ta_api_level() > API_LEVEL1_0)
            operation_handle->requiredKeyUsage = 0;
    }
    return TEE_SUCCESS;
}

static TEE_Result check_sign_verify_alg_valid(uint32_t algorithm, TEE_OperationHandle operation_handle, uint32_t mode)
{
    if (!crypto_check_alg_valid(algorithm, TEE_MODE_SIGN)) {
        tloge("TEE_MODE_SIGN TEE_MODE_VERIFY and algorithm are not match\n");
        return TEE_ERROR_NOT_SUPPORTED;
    }
    operation_handle->publicKey      = NULL;
    operation_handle->privateKey     = NULL;
    if (mode == TEE_MODE_SIGN)
        operation_handle->requiredKeyUsage = TEE_USAGE_SIGN;
    if (mode == TEE_MODE_VERIFY)
        operation_handle->requiredKeyUsage = TEE_USAGE_VERIFY;
    return TEE_SUCCESS;
}

static TEE_Result check_mac_alg_valid(uint32_t algorithm, TEE_OperationHandle operation_handle)
{
    if (!crypto_check_alg_valid(algorithm, TEE_MODE_MAC)) {
        tloge("TEE_MODE_MAC and algorithm are not match\n");
        return TEE_ERROR_NOT_SUPPORTED;
    }
    operation_handle->requiredKeyUsage = TEE_USAGE_MAC;
    operation_handle->digestLength     = crypto_get_output_length(algorithm);
    return TEE_SUCCESS;
}

static TEE_Result check_derive_alg_valid(uint32_t algorithm, TEE_OperationHandle operation_handle)
{
    if (!crypto_check_alg_valid(algorithm, TEE_MODE_DERIVE)) {
        tloge("TEE_MODE_DERIVE and algorithm are not match\n");
        return TEE_ERROR_NOT_SUPPORTED;
    }
    operation_handle->requiredKeyUsage = TEE_USAGE_DERIVE;
    return TEE_SUCCESS;
}

static TEE_Result check_algorithm_valid(uint32_t mode, uint32_t algorithm, TEE_OperationHandle operation_handle)
{
    TEE_Result ret;
    switch (mode) {
    case TEE_MODE_DIGEST:
        ret = check_digest_alg_valid(algorithm, operation_handle);
        break;
    case TEE_MODE_DECRYPT:
    case TEE_MODE_ENCRYPT:
        ret = check_enc_dec_alg_valid(algorithm, operation_handle, mode);
        break;
    case TEE_MODE_SIGN:
    case TEE_MODE_VERIFY:
        ret = check_sign_verify_alg_valid(algorithm, operation_handle, mode);
        break;
    case TEE_MODE_MAC:
        ret = check_mac_alg_valid(algorithm, operation_handle);
        break;
    case TEE_MODE_DERIVE:
        ret = check_derive_alg_valid(algorithm, operation_handle);
        break;
    default:
        tloge("The mode isn't supported\n");
        return TEE_ERROR_NOT_SUPPORTED;
    }
    return ret;
}

TEE_Result TEE_AllocateOperation(TEE_OperationHandle *operation, uint32_t algorithm, uint32_t mode,
    uint32_t max_key_size)
{
    TEE_OperationHandle operation_handle = NULL;
    TEE_Result ret = check_allocate_param(operation, algorithm, max_key_size);
    if (ret != TEE_SUCCESS) {
        tloge("params is invalid, ret = 0x%x\n", ret);
        return ret;
    }

    operation_handle = TEE_Malloc(sizeof(*operation_handle), 0);
    if (operation_handle == NULL) {
        tloge("Allocate memory failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ret = check_algorithm_valid(mode, algorithm, operation_handle);
    if (ret != TEE_SUCCESS) {
        tloge("check algorithm failed, ret = 0x%x", ret);
        TEE_Free(operation_handle);
        return ret;
    }

    /* Once check algorithm valid, we will get operationClass successful */
    operation_handle->operationClass = crypto_get_op_class(algorithm);

    if (pthread_mutex_init(&operation_handle->operation_lock, NULL)) {
        tloge("init lock failed\n");
        ret = TEE_ERROR_GENERIC;
        goto error;
    }
    ret = set_operation_hal_info(operation_handle, algorithm);
    if (ret != TEE_SUCCESS) {
        goto error;
    }
    ret = add_operation(operation_handle);
    if (ret != TEE_SUCCESS) {
        tloge("Add operation to global list failed!\n");
        goto error;
    }
    operation_handle->algorithm  = algorithm;
    operation_handle->mode       = mode;
    operation_handle->maxKeySize = max_key_size;
    *operation = operation_handle;
    return TEE_SUCCESS;
error:
    TEE_Free(operation_handle->hal_info);
    operation_handle->hal_info = NULL;
    TEE_Free(operation_handle);
    operation_handle = NULL;
    if (ret != TEE_ERROR_OUT_OF_MEMORY)
        TEE_Panic(ret);
    return ret;
}

static void sensitive_information_cleanup(void **buff, uint32_t buff_size)
{
    if (*buff != NULL) {
        errno_t rc = memset_s(*buff, buff_size, 0, buff_size);
        if (rc != EOK)
            tloge("Clear sensitive information failed, rc 0x%x\n", rc);
        TEE_Free(*buff);
        *buff = NULL;
    }
}

static TEE_Result reset_operation_key(TEE_OperationHandle operation)
{
    if (operation == NULL) {
        tloge("Operation handle is NULL");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    sensitive_information_cleanup(&operation->keyValue, operation->keySize);
    sensitive_information_cleanup(&operation->keyValue2, operation->keySize2);

    sensitive_information_cleanup(&operation->privateKey, operation->privateKeyLen);
    if (operation->publicKey != NULL) {
        TEE_Free(operation->publicKey);
        operation->publicKey = NULL;
    }

    operation->keySize       = 0;
    operation->keySize2      = 0;
    operation->publicKeyLen  = 0;
    operation->privateKeyLen = 0;
    operation->handleState &= ~TEE_HANDLE_FLAG_KEY_SET;

    return TEE_SUCCESS;
}

static void free_crypto_hal_info(TEE_OperationHandle operation)
{
    crypto_hal_info *crypto_hal_data = (crypto_hal_info *)(operation->hal_info);

    if (crypto_hal_data == NULL)
        return;
    TEE_Free(crypto_hal_data);
    operation->hal_info = NULL;
    return;
}

void free_operation_ctx(TEE_OperationHandle operation)
{
    if (operation == NULL)
        return;

    tee_crypto_ctx_free(operation->crypto_ctxt);
    operation->crypto_ctxt = NULL;
}

void TEE_FreeOperation(TEE_OperationHandle operation)
{
    TEE_Result ret;
    if (operation == NULL) {
        tloge("Operation handle is NULL\n");
        if (tee_get_ta_api_level() < API_LEVEL1_2)
            TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }
    if (check_operation((const TEE_OperationHandle)operation) != TEE_SUCCESS) {
        tloge("operation handle is invalid");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    if (crypto_lock_operation(operation) != TEE_SUCCESS)
        return;

    free_operation_ctx(operation);

    TEE_Free(operation->IV);
    operation->IV = NULL;

    ret = reset_operation_key(operation);
    if (ret != TEE_SUCCESS) {
        tloge("reset_operation_key failed\n");
        crypto_unlock_operation(operation);
        TEE_Panic(ret);
    }

    free_crypto_hal_info(operation);

    crypto_unlock_operation(operation);

    if (pthread_mutex_destroy(&operation->operation_lock)) {
        tloge("destroy mutex failed\n");
        TEE_Panic(TEE_ERROR_GENERIC);
    }
    delete_operation((const TEE_OperationHandle)operation);
    TEE_Free(operation);
#ifdef OPENSSL_ENABLE
    tee_crypto_free_opensssl_drbg();
#endif
}

static void get_operation_key_size_in_byte(uint32_t in_key_size, uint32_t algorithm, uint32_t *out_key_size)
{
    bool check = ((in_key_size == ECC_SPECIAL_KEY_LEN_IN_BYTE) && (algorithm == TEE_ALG_ECDSA_SHA512 ||
            algorithm == TEE_ALG_ECDH_P521 || algorithm == TEE_ALG_ECDSA_P521 ||
            algorithm == TEE_ALG_ECDH_DERIVE_SHARED_SECRET));

    if (check)
        *out_key_size = ECC_SPECIAL_KEY_LEN_IN_BITS;
    else
        *out_key_size = in_key_size * BIT_TO_BYTE;
}

void TEE_GetOperationInfo(const TEE_OperationHandle operation, TEE_OperationInfo *operationInfo)
{
    bool check = (operation == NULL || operationInfo == NULL ||
        (check_operation((const TEE_OperationHandle)operation) != TEE_SUCCESS));
    if (check) {
        tloge("bad params");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    if (crypto_lock_operation(operation) != TEE_SUCCESS)
        return;

    if (operation->keySize > (UINT32_MAX / BIT_TO_BYTE)) {
        tloge("Operation key size is invalid\n");
        crypto_unlock_operation(operation);
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }
    operationInfo->algorithm      = operation->algorithm;
    operationInfo->mode           = operation->mode;
    operationInfo->operationClass = operation->operationClass;
    operationInfo->digestLength   = operation->digestLength;
    operationInfo->maxKeySize     = operation->maxKeySize;
    if (tee_get_ta_api_level() == API_LEVEL1_0) {
        operationInfo->keySize = operation->keySize;
    } else {
        if (operation->algorithm == TEE_ALG_AES_XTS)
            operationInfo->keySize = 0;
        else
            get_operation_key_size_in_byte(operation->keySize, operation->algorithm, &(operationInfo->keySize));
    }
    operationInfo->requiredKeyUsage = operation->requiredKeyUsage;
    operationInfo->handleState      = operation->handleState;
    crypto_unlock_operation(operation);
    return;
}

void TEE_ResetOperation(TEE_OperationHandle operation)
{
    bool check = (operation == NULL || (check_operation((const TEE_OperationHandle)operation) != TEE_SUCCESS));
    if (check) {
        tloge("bad params");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    if (crypto_lock_operation(operation) != TEE_SUCCESS)
        return;
    uint32_t api_level = tee_get_ta_api_level();
    if (api_level >= API_LEVEL1_1_1) {
        if ((operation->handleState & TEE_HANDLE_FLAG_KEY_SET) != TEE_HANDLE_FLAG_KEY_SET) {
            tloge("Invalid operation key state for this operation\n");
            crypto_unlock_operation(operation);
            TEE_Panic(TEE_ERROR_BAD_STATE);
            return;
        }
    }

    free_operation_ctx(operation);

    crypto_hal_info *crypto_hal_data = (crypto_hal_info *)(operation->hal_info);
    if (crypto_hal_data == NULL) {
        tloge("invalid params");
        crypto_unlock_operation(operation);
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }
    crypto_hal_data->digestalloc_flag = 0;

    if (operation->operationClass != TEE_OPERATION_DIGEST)
        operation->handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;
    crypto_unlock_operation(operation);
#ifdef OPENSSL_ENABLE
    tee_crypto_free_opensssl_drbg();
#endif
}

static bool check_is_ec_key_pair_algorithm(uint32_t algorithm)
{
    size_t i = 0;
    uint32_t ec_algorithm_set[] = {
        TEE_ALG_ECDSA_SHA1,
        TEE_ALG_ECDSA_SHA224,
        TEE_ALG_ECDSA_SHA256,
        TEE_ALG_ECDSA_SHA384,
        TEE_ALG_ECDSA_SHA512,
        TEE_ALG_ECDH_DERIVE_SHARED_SECRET,
        TEE_ALG_SM2_PKE,
        TEE_ALG_SM2_DSA_SM3
    };
    size_t total_set_num = sizeof(ec_algorithm_set) / sizeof(ec_algorithm_set[0]);
    for (; i < total_set_num; i++) {
        if (ec_algorithm_set[i] == algorithm)
            return true;
    }

    return false;
}

static bool check_is_rsa_algorithm(uint32_t algorithm)
{
    size_t i = 0;
    uint32_t rsa_algorithm_set[] = {
        TEE_ALG_RSASSA_PKCS1_V1_5_MD5,
        TEE_ALG_RSASSA_PKCS1_V1_5_SHA1,
        TEE_ALG_RSASSA_PKCS1_V1_5_SHA224,
        TEE_ALG_RSASSA_PKCS1_V1_5_SHA256,
        TEE_ALG_RSASSA_PKCS1_V1_5_SHA384,
        TEE_ALG_RSASSA_PKCS1_V1_5_SHA512,
        TEE_ALG_RSA_NOPAD,
        TEE_ALG_RSASSA_PKCS1_PSS_MGF1_MD5,
        TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1,
        TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224,
        TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256,
        TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384,
        TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512,
        TEE_ALG_RSAES_PKCS1_V1_5,
        TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1,
        TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224,
        TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256,
        TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384,
        TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512
    };
    size_t total_set_num = sizeof(rsa_algorithm_set) / sizeof(rsa_algorithm_set[0]);
    for (; i < total_set_num; i++) {
        if (rsa_algorithm_set[i] == algorithm)
            return true;
    }

    return false;
}

static uint32_t get_ecc_curve_from_alg(uint32_t algorithm)
{
    switch (algorithm) {
    case TEE_ALG_ECDSA_SHA1:
    case TEE_ALG_ECDSA_SHA224:
    case TEE_ALG_ECDSA_SHA256:
    case TEE_ALG_ECDSA_SHA384:
    case TEE_ALG_ECDSA_SHA512:
    case TEE_ALG_ECDH_DERIVE_SHARED_SECRET:
        return ECC_CURVE_NIST_P256;
    case TEE_ALG_SM2_PKE:
    case TEE_ALG_SM2_DSA_SM3:
        return ECC_CURVE_SM2;
    case TEE_ALG_X25519:
        return ECC_CURVE_X25519;
    case TEE_ALG_ED25519:
        return ECC_CURVE_ED25519;
    default:
        return 0;
    }
}

static TEE_Result generate_ecc_keypair(TEE_OperationHandle operation, uint32_t engine)
{
    TEE_Result ret;
    uint32_t curve = get_ecc_curve_from_alg(operation->algorithm);

    struct ecc_priv_key_t *private = TEE_Malloc(sizeof(*private), 0);
    if (private == NULL) {
        tloge("malloc private failed");
        return TEE_ERROR_SECURITY;
    }

    struct ecc_pub_key_t *public = TEE_Malloc(sizeof(*public), 0);
    if (public == NULL) {
        tloge("malloc public failed");
        TEE_Free(private);
        return TEE_ERROR_SECURITY;
    }

    int32_t rc = tee_crypto_ecc_generate_keypair(operation->keySize, curve, public,
        private, engine);
    if (rc != TEE_SUCCESS) {
        tloge("generate rsa keypair failed");
        ret = change_hal_ret_to_gp(rc);
        goto free_key;
    }

    operation->privateKey = private;
    operation->privateKeyLen = sizeof(*private);

    operation->publicKey = public;
    operation->publicKeyLen = sizeof(*public);

    return TEE_SUCCESS;

free_key:
    TEE_Free(public);
    public = NULL;
    (void)memset_s(private, sizeof(*private), 0, sizeof(*private));
    TEE_Free(private);
    private = NULL;
    return ret;
}

static TEE_Result copy_rsa_pub_key(TEE_OperationHandle operation, const struct rsa_priv_key_t *private_key)
{
    struct rsa_pub_key_t *public_key = TEE_Malloc(sizeof(*public_key), 0);
    if (public_key == NULL) {
        tloge("malloc public failed");
        return TEE_ERROR_SECURITY;
    }

    errno_t res = memcpy_s(public_key->n, RSA_EXPONENT_LEN, private_key->n, private_key->n_len);
    if (res != EOK) {
        tloge("copy key failed");
        TEE_Free(public_key);
        public_key = NULL;
        return TEE_ERROR_SECURITY;
    }
    public_key->n_len = private_key->n_len;

    res = memcpy_s(public_key->e, RSA_EXPONENT_LEN, private_key->e, private_key->e_len);
    if (res != EOK) {
        tloge("copy key failed");
        TEE_Free(public_key);
        public_key = NULL;
        return TEE_ERROR_SECURITY;
    }
    public_key->e_len = private_key->e_len;

    operation->publicKey = public_key;
    operation->publicKeyLen = sizeof(*public_key);

    return TEE_SUCCESS;
}

static TEE_Result generate_rsa_keypair(TEE_OperationHandle operation, uint32_t engine)
{
    TEE_Result ret;
    uint8_t key_e[] = { 0x01, 0x00, 0x01 }; /* default rsa exponent */
    struct memref_t e_data = {0};
    e_data.buffer = (uint64_t)(uintptr_t)key_e;
    e_data.size = sizeof(key_e);
    struct rsa_priv_key_t *private_key = TEE_Malloc(sizeof(*private_key), 0);
    if (private_key == NULL) {
        tloge("malloc private failed");
        return TEE_ERROR_SECURITY;
    }

    int32_t rc = tee_crypto_rsa_generate_keypair(operation->keySize, &e_data, false,
        private_key, engine);
    if (rc != TEE_SUCCESS) {
        tloge("generate rsa keypair failed");
        ret = change_hal_ret_to_gp(rc);
        goto free_key;
    }

    ret = copy_rsa_pub_key(operation, private_key);
    if (ret != TEE_SUCCESS) {
        tloge("copy rsa key failed");
        goto free_key;
    }

    operation->privateKey = private_key;
    operation->privateKeyLen = sizeof(*private_key);

    return TEE_SUCCESS;

free_key:
    (void)memset_s(private_key, sizeof(*private_key), 0, sizeof(*private_key));
    TEE_Free(private_key);
    private_key = NULL;
    return ret;
}

static TEE_Result TEE_GenKeyPair(TEE_OperationHandle operation, const TEE_ObjectHandle key)
{
    (void)key;
    crypto_hal_info *crypto_hal_data = (crypto_hal_info *)(operation->hal_info);
    if (crypto_hal_data == NULL) {
        tloge("invalid params");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t engine = crypto_hal_data->crypto_flag;

    /* 25519 not support keyobject is NULL */
    if (check_is_ec_key_pair_algorithm(operation->algorithm))
        return generate_ecc_keypair(operation, engine);
    else if (check_is_rsa_algorithm(operation->algorithm))
        return generate_rsa_keypair(operation, engine);
    else
        return TEE_ERROR_BAD_PARAMETERS;
}

int32_t get_attr_index_by_id(uint32_t id, const TEE_Attribute *attrs, uint32_t attr_count)
{
    uint32_t i;
    if (attrs == NULL)
        return -1;
    for (i = 0; i < attr_count; i++) {
        if (id == attrs[i].attributeID)
            return i;
    }
    return -1;
}

static TEE_Result copy_single_key_from_object(const TEE_ObjectHandle object,
    uint32_t id, uint8_t *key, uint32_t *key_len)
{
    int32_t index = get_attr_index_by_id(id, object->Attribute, object->attributesLen);
    if (index < 0) {
        tloge("invalid key, id = 0x%x", id);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    errno_t res = memcpy_s(key, *key_len,
        object->Attribute[index].content.ref.buffer, object->Attribute[index].content.ref.length);
    if (res != EOK) {
        tloge("memcpy failed");
        return TEE_ERROR_SECURITY;
    }
    *key_len = object->Attribute[index].content.ref.length;
    return TEE_SUCCESS;
}

static TEE_Result rsa_set_pub_key_hal(TEE_OperationHandle operation, const TEE_ObjectHandle key)
{
    TEE_Result ret;
    struct rsa_pub_key_t *rsa_public_key = TEE_Malloc(sizeof(*rsa_public_key), 0);
    if (rsa_public_key == NULL) {
        tloge("malloc Failed");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    rsa_public_key->n_len = RSA_MAX_KEY_SIZE;
    ret = copy_single_key_from_object(key, TEE_ATTR_RSA_MODULUS, rsa_public_key->n, &(rsa_public_key->n_len));
    if (ret != TEE_SUCCESS) {
        TEE_Free(rsa_public_key);
        return ret;
    }

    rsa_public_key->e_len = RSA_EXPONENT_LEN;
    ret = copy_single_key_from_object(key, TEE_ATTR_RSA_PUBLIC_EXPONENT, rsa_public_key->e, &(rsa_public_key->e_len));
    if (ret != TEE_SUCCESS) {
        TEE_Free(rsa_public_key);
        return ret;
    }
    operation->publicKey = rsa_public_key;
    operation->publicKeyLen = sizeof(*rsa_public_key);
    return TEE_SUCCESS;
}

uint32_t get_ecc_domain(uint32_t curve)
{
    switch (curve) {
    case TEE_ECC_CURVE_NIST_P192:
        return ECC_CURVE_NIST_P192;
    case TEE_ECC_CURVE_NIST_P224:
        return ECC_CURVE_NIST_P224;
    case TEE_ECC_CURVE_NIST_P256:
        return ECC_CURVE_NIST_P256;
    case TEE_ECC_CURVE_NIST_P384:
        return ECC_CURVE_NIST_P384;
    case TEE_ECC_CURVE_NIST_P521:
        return ECC_CURVE_NIST_P521;
    case TEE_ECC_CURVE_SM2:
        return ECC_CURVE_SM2;
    default:
        return 0;
    }
}

uint32_t get_sm2_domain(uint32_t curve)
{
    if (curve == SM2_GROUP_NOSTANDARD_USER)
        return SM2_GROUP_NOSTANDARD;
    return ECC_CURVE_SM2;
}
static TEE_Result ed25519_set_pub_key_hal(const TEE_ObjectHandle key, struct ecc_pub_key_t *ecc_pub_key)
{
    TEE_Result ret = copy_single_key_from_object(key, TEE_ATTR_ED25519_PUBLIC_VALUE,
        ecc_pub_key->x, &(ecc_pub_key->x_len));
    if (ret != TEE_SUCCESS)
        tloge("copy ec25519 pub key failed");
    return ret;
}

static TEE_Result x25519_set_pub_key_hal(const TEE_ObjectHandle key, struct ecc_pub_key_t *ecc_pub_key)
{
    TEE_Result ret = copy_single_key_from_object(key, TEE_ATTR_X25519_PUBLIC_VALUE,
        ecc_pub_key->x, &(ecc_pub_key->x_len));
    if (ret != TEE_SUCCESS)
        tloge("copy x25519 pub key failed");
    return ret;
}

static TEE_Result ecc_set_pub_key_hal(TEE_OperationHandle operation, const TEE_ObjectHandle key)
{
    TEE_Result ret;
    struct ecc_pub_key_t *ecc_pub_key = TEE_Malloc(sizeof(*ecc_pub_key), 0);
    if (ecc_pub_key == NULL) {
        tloge("malloc Failed");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ecc_pub_key->x_len = ECC_KEY_LEN;
    ecc_pub_key->y_len = ECC_KEY_LEN;
    if (operation->algorithm == TEE_ALG_ED25519) {
        ecc_pub_key->domain_id = ECC_CURVE_ED25519;
        ret = ed25519_set_pub_key_hal(key, ecc_pub_key);
    } else if (operation->algorithm == TEE_ALG_X25519) {
        ecc_pub_key->domain_id = ECC_CURVE_X25519;
        ret = x25519_set_pub_key_hal(key, ecc_pub_key);
    } else {
        int32_t index = get_attr_index_by_id(TEE_ATTR_ECC_CURVE, key->Attribute, key->attributesLen);
        if (index < 0) {
            tloge("no ecc curve attr");
            TEE_Free(ecc_pub_key);
            return TEE_ERROR_BAD_PARAMETERS;
        }
        bool check = (operation->algorithm == TEE_ALG_SM2_PKE || operation->algorithm == TEE_ALG_SM2_DSA_SM3);
        if (check)
            ecc_pub_key->domain_id = get_sm2_domain(key->Attribute[index].content.value.a);
        else
            ecc_pub_key->domain_id = get_ecc_domain(key->Attribute[index].content.value.a);

        ret = copy_single_key_from_object(key, TEE_ATTR_ECC_PUBLIC_VALUE_X, ecc_pub_key->x, &(ecc_pub_key->x_len));
        if (ret != TEE_SUCCESS) {
            TEE_Free(ecc_pub_key);
            return ret;
        }

        ret = copy_single_key_from_object(key, TEE_ATTR_ECC_PUBLIC_VALUE_Y, ecc_pub_key->y, &(ecc_pub_key->y_len));
    }
    if (ret != TEE_SUCCESS) {
        TEE_Free(ecc_pub_key);
        return ret;
    }

    operation->publicKey = ecc_pub_key;
    operation->publicKeyLen = sizeof(*ecc_pub_key);
    return TEE_SUCCESS;
}

static TEE_Result dh_set_public_key_hal(TEE_OperationHandle operation, const TEE_ObjectHandle key)
{
    int32_t index = get_attr_index_by_id(TEE_ATTR_DH_PUBLIC_VALUE, key->Attribute, key->attributesLen);
    if (index < 0) {
        tloge("invalid key");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (key->Attribute[index].content.ref.length > MALLOC_MAX_KEY_SIZE) {
        tloge("key length is too large!");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    operation->publicKey = TEE_Malloc(key->Attribute[index].content.ref.length, 0);
    if (operation->publicKey == NULL) {
        tloge("malloc failed");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    errno_t res = memcpy_s(operation->publicKey, key->Attribute[index].content.ref.length,
        key->Attribute[index].content.ref.buffer, key->Attribute[index].content.ref.length);
    if (res != EOK) {
        tloge("memcpy failed");
        TEE_Free(operation->publicKey);
        operation->publicKey = NULL;
        return TEE_ERROR_SECURITY;
    }
    operation->publicKeyLen = key->Attribute[index].content.ref.length;
    return TEE_SUCCESS;
}

static TEE_Result set_public_key_hal(TEE_OperationHandle operation, const TEE_ObjectHandle key)
{
    switch (key->ObjectInfo->objectType) {
    case TEE_TYPE_RSA_PUBLIC_KEY:
    case TEE_TYPE_RSA_KEYPAIR:
        return rsa_set_pub_key_hal(operation, key);
    case TEE_TYPE_ECDSA_PUBLIC_KEY:
    case TEE_TYPE_ECDSA_KEYPAIR:
    case TEE_TYPE_ECDH_PUBLIC_KEY:
    case TEE_TYPE_ECDH_KEYPAIR:
    case TEE_TYPE_SM2_DSA_PUBLIC_KEY:
    case TEE_TYPE_SM2_DSA_KEYPAIR:
    case TEE_TYPE_SM2_PKE_PUBLIC_KEY:
    case TEE_TYPE_SM2_PKE_KEYPAIR:
    case TEE_TYPE_SM2_KEP_PUBLIC_KEY:
    case TEE_TYPE_SM2_KEP_KEYPAIR:
    case TEE_TYPE_ED25519_PUBLIC_KEY:
    case TEE_TYPE_ED25519_KEYPAIR:
    case TEE_TYPE_X25519_PUBLIC_KEY:
    case TEE_TYPE_X25519_KEYPAIR:
        return ecc_set_pub_key_hal(operation, key);
    case TEE_TYPE_DH_KEYPAIR:
        return dh_set_public_key_hal(operation, key);
    default:
        tloge("invalid key type");
        return TEE_ERROR_NOT_SUPPORTED;
    }
}

static TEE_Result rsa_set_private_key_hal(TEE_OperationHandle operation, const TEE_ObjectHandle key)
{
    TEE_Result ret;
    struct rsa_priv_key_t *rsa_priv_key = TEE_Malloc(sizeof(*rsa_priv_key), 0);
    if (rsa_priv_key == NULL) {
        tloge("malloc failed");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    rsa_priv_key->n_len = RSA_MAX_KEY_SIZE;
    ret = copy_single_key_from_object(key, TEE_ATTR_RSA_MODULUS, rsa_priv_key->n, &(rsa_priv_key->n_len));
    if (ret != TEE_SUCCESS) {
        (void)memset_s(rsa_priv_key, sizeof(*rsa_priv_key), 0x0, sizeof(*rsa_priv_key));
        TEE_Free(rsa_priv_key);
        return ret;
    }

    rsa_priv_key->e_len = RSA_EXPONENT_LEN;
    ret = copy_single_key_from_object(key, TEE_ATTR_RSA_PUBLIC_EXPONENT, rsa_priv_key->e, &(rsa_priv_key->e_len));
    if (ret != TEE_SUCCESS) {
        (void)memset_s(rsa_priv_key, sizeof(*rsa_priv_key), 0x0, sizeof(*rsa_priv_key));
        TEE_Free(rsa_priv_key);
        return ret;
    }

    rsa_priv_key->d_len = RSA_MAX_KEY_SIZE;
    ret = copy_single_key_from_object(key, TEE_ATTR_RSA_PRIVATE_EXPONENT, rsa_priv_key->d, &(rsa_priv_key->d_len));
    if (ret != TEE_SUCCESS) {
        (void)memset_s(rsa_priv_key, sizeof(*rsa_priv_key), 0x0, sizeof(*rsa_priv_key));
        TEE_Free(rsa_priv_key);
        return ret;
    }

    operation->privateKey = rsa_priv_key;
    operation->privateKeyLen = sizeof(*rsa_priv_key);
    return TEE_SUCCESS;
}

#define ED25519_KEY_LEN 64
static TEE_Result ed25519_set_private_key_hal(const TEE_ObjectHandle key, struct ecc_priv_key_t *ecc_priv_key)
{
    TEE_Result ret = copy_single_key_from_object(key, TEE_ATTR_ED25519_PRIVATE_VALUE, ecc_priv_key->r,
        &(ecc_priv_key->r_len));
    if (ret != TEE_SUCCESS) {
        tloge("copy ed25519 private key failed");
        return ret;
    }
    ecc_priv_key->domain_id = ECC_CURVE_ED25519;

    /* BORINGSSL ED25519 private key is 64 bytes */
    if (ecc_priv_key->r_len == ED25519_KEY_LEN)
        return TEE_SUCCESS;

    if (ecc_priv_key->r_len > ECC_KEY_LEN) {
        tloge("ecc private key is too large");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t temp_len = ECC_KEY_LEN - ecc_priv_key->r_len;
    ret = copy_single_key_from_object(key, TEE_ATTR_ED25519_PUBLIC_VALUE, ecc_priv_key->r + ecc_priv_key->r_len,
        &temp_len);
    if (ret != TEE_SUCCESS) {
        tloge("copy ed25519 public key failed");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ecc_priv_key->r_len += temp_len;
    return TEE_SUCCESS;
}

static TEE_Result ecc_set_private_key_hal(TEE_OperationHandle operation, const TEE_ObjectHandle key)
{
    TEE_Result ret;
    struct ecc_priv_key_t *ecc_priv_key = TEE_Malloc(sizeof(*ecc_priv_key), 0);
    if (ecc_priv_key == NULL) {
        tloge("malloc failed");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    ecc_priv_key->r_len = ECC_KEY_LEN;

    if (operation->algorithm == TEE_ALG_ED25519) {
        ret = ed25519_set_private_key_hal(key, ecc_priv_key);
    } else if (operation->algorithm == TEE_ALG_X25519) {
        ecc_priv_key->domain_id = ECC_CURVE_X25519;
        ret = copy_single_key_from_object(key, TEE_ATTR_X25519_PRIVATE_VALUE, ecc_priv_key->r, &(ecc_priv_key->r_len));
    } else {
        ret = copy_single_key_from_object(key, TEE_ATTR_ECC_PRIVATE_VALUE, ecc_priv_key->r, &(ecc_priv_key->r_len));
        if (ret != TEE_SUCCESS) {
            (void)memset_s(ecc_priv_key, sizeof(*ecc_priv_key), 0x0, sizeof(*ecc_priv_key));
            TEE_Free(ecc_priv_key);
            return ret;
        }
        int32_t index = get_attr_index_by_id(TEE_ATTR_ECC_CURVE, key->Attribute, key->attributesLen);
        if (index < 0) {
            tloge("invalid key");
            (void)memset_s(ecc_priv_key, sizeof(*ecc_priv_key), 0x0, sizeof(*ecc_priv_key));
            TEE_Free(ecc_priv_key);
            return TEE_ERROR_BAD_PARAMETERS;
        }
        bool check = ((operation->algorithm == TEE_ALG_SM2_PKE || operation->algorithm == TEE_ALG_SM2_DSA_SM3) &&
            (key->Attribute[index].content.value.a == SM2_GROUP_NOSTANDARD_USER));
        if (check)
            ecc_priv_key->domain_id = get_sm2_domain(key->Attribute[index].content.value.a);
        else
            ecc_priv_key->domain_id = get_ecc_domain(key->Attribute[index].content.value.a);
    }
    if (ret != TEE_SUCCESS) {
        (void)memset_s(ecc_priv_key, sizeof(*ecc_priv_key), 0x0, sizeof(*ecc_priv_key));
        TEE_Free(ecc_priv_key);
        return ret;
    }

    operation->privateKey = ecc_priv_key;
    operation->privateKeyLen = sizeof(*ecc_priv_key);
    return TEE_SUCCESS;
}

static TEE_Result dh_set_private_key_hal(TEE_OperationHandle operation, const TEE_ObjectHandle key)
{
    int32_t index = get_attr_index_by_id(TEE_ATTR_DH_PRIVATE_VALUE, key->Attribute, key->attributesLen);
    if (index < 0) {
        tloge("invalid key");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (key->Attribute[index].content.ref.length > MALLOC_MAX_KEY_SIZE) {
        tloge("key length is too large!");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    operation->privateKey = TEE_Malloc(key->Attribute[index].content.ref.length, 0);
    if (operation->privateKey == NULL) {
        tloge("malloc failed");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    errno_t res = memcpy_s(operation->privateKey, key->Attribute[index].content.ref.length,
        key->Attribute[index].content.ref.buffer, key->Attribute[index].content.ref.length);
    if (res != EOK) {
        tloge("memcpy failed");
        TEE_Free(operation->privateKey);
        operation->privateKey = NULL;
        return TEE_ERROR_SECURITY;
    }
    operation->privateKeyLen = key->Attribute[index].content.ref.length;
    return TEE_SUCCESS;
}

static TEE_Result set_private_key_hal(TEE_OperationHandle operation, const TEE_ObjectHandle key)
{
    switch (key->ObjectInfo->objectType) {
    case TEE_TYPE_RSA_KEYPAIR:
        return rsa_set_private_key_hal(operation, key);
    case TEE_TYPE_ECDSA_KEYPAIR:
    case TEE_TYPE_ECDH_KEYPAIR:
    case TEE_TYPE_ED25519_KEYPAIR:
    case TEE_TYPE_X25519_KEYPAIR:
    case TEE_TYPE_SM2_DSA_KEYPAIR:
    case TEE_TYPE_SM2_PKE_KEYPAIR:
    case TEE_TYPE_SM2_KEP_KEYPAIR:
        return ecc_set_private_key_hal(operation, key);
    case TEE_TYPE_DH_KEYPAIR:
        return dh_set_private_key_hal(operation, key);
    default:
        tloge("invalid key type");
        return TEE_ERROR_NOT_SUPPORTED;
    }
}

static TEE_Result set_private_key_crt_hal(TEE_OperationHandle operation, const TEE_ObjectHandle key)
{
    TEE_Result ret;
    struct rsa_priv_key_t *rsa_priv_key = TEE_Malloc(sizeof(*rsa_priv_key), 0);
    if (rsa_priv_key == NULL) {
        tloge("malloc failed");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    rsa_priv_key->n_len = RSA_MAX_KEY_SIZE;
    ret = copy_single_key_from_object(key, TEE_ATTR_RSA_MODULUS, rsa_priv_key->n, &(rsa_priv_key->n_len));
    if (ret != TEE_SUCCESS)
        goto error;

    rsa_priv_key->e_len = RSA_EXPONENT_LEN;
    ret = copy_single_key_from_object(key, TEE_ATTR_RSA_PUBLIC_EXPONENT, rsa_priv_key->e, &(rsa_priv_key->e_len));
    if (ret != TEE_SUCCESS)
        goto error;

    rsa_priv_key->p_len = RSA_MAX_KEY_SIZE_CRT;
    ret = copy_single_key_from_object(key, TEE_ATTR_RSA_PRIME1, rsa_priv_key->p, &(rsa_priv_key->p_len));
    if (ret != TEE_SUCCESS)
        goto error;

    rsa_priv_key->q_len = RSA_MAX_KEY_SIZE_CRT;
    ret = copy_single_key_from_object(key, TEE_ATTR_RSA_PRIME2, rsa_priv_key->q, &(rsa_priv_key->q_len));
    if (ret != TEE_SUCCESS)
        goto error;

    rsa_priv_key->dp_len = RSA_MAX_KEY_SIZE_CRT;
    ret = copy_single_key_from_object(key, TEE_ATTR_RSA_EXPONENT1, rsa_priv_key->dp, &(rsa_priv_key->dp_len));
    if (ret != TEE_SUCCESS)
        goto error;

    rsa_priv_key->dq_len = RSA_MAX_KEY_SIZE_CRT;
    ret = copy_single_key_from_object(key, TEE_ATTR_RSA_EXPONENT2, rsa_priv_key->dq, &(rsa_priv_key->dq_len));
    if (ret != TEE_SUCCESS)
        goto error;

    rsa_priv_key->qinv_len = RSA_MAX_KEY_SIZE_CRT;
    ret = copy_single_key_from_object(key, TEE_ATTR_RSA_COEFFICIENT, rsa_priv_key->qinv, &(rsa_priv_key->qinv_len));
    if (ret != TEE_SUCCESS)
        goto error;

    rsa_priv_key->crt_mode = true;
    operation->privateKey = rsa_priv_key;
    operation->privateKeyLen = sizeof(*rsa_priv_key);
    return TEE_SUCCESS;
error:
    (void)memset_s(rsa_priv_key, sizeof(*rsa_priv_key), 0x0, sizeof(*rsa_priv_key));
    TEE_Free(rsa_priv_key);
    return ret;
}

static TEE_Result tee_keytype_and_attrilen_check(uint32_t attri_len, uint32_t obj_type)
{
    uint32_t index = 0;
    crypto_uint2uint obj_type_to_attri_len[] = {
        { TEE_TYPE_ECDSA_PUBLIC_KEY, 3 }, /* ecsda public key attr count */
        { TEE_TYPE_ECDSA_KEYPAIR, 4 }, /* ecsda keypaie attr count */
        { TEE_TYPE_ECDH_PUBLIC_KEY, 3 }, /* ecdh public key attr count */
        { TEE_TYPE_ECDH_KEYPAIR, 4 }, /* ecdh keypaie attr count */
        { TEE_TYPE_RSA_PUBLIC_KEY, 2 }, /* rsa public key attr count */
        { TEE_TYPE_RSA_KEYPAIR, 3 }, /* rsa keypaie attr count */
        { TEE_TYPE_RSA_KEYPAIR, 8 }, /* rsa keypaie attr count crt mode */
        { TEE_TYPE_ED25519_KEYPAIR, 2 }, /* ed25519 keypaie attr count */
        { TEE_TYPE_ED25519_PUBLIC_KEY, 1 }, /* ed25519 public key attr count */
        { TEE_TYPE_X25519_KEYPAIR, 2 }, /* x25519 keypaie attr count */
        { TEE_TYPE_X25519_PUBLIC_KEY, 1 }, /* x25519 public key attr count */
        { TEE_TYPE_SM2_DSA_PUBLIC_KEY, 3 }, /* sm2 dsa public key attr count */
        { TEE_TYPE_SM2_DSA_KEYPAIR, 4 }, /* sm2 dsa keypaie key attr count */
        { TEE_TYPE_SM2_PKE_PUBLIC_KEY, 3 }, /* sm2 pke public key attr count */
        { TEE_TYPE_SM2_PKE_KEYPAIR, 4 }, /* sm2 pke keypaie key attr count */
        { TEE_TYPE_SM2_KEP_PUBLIC_KEY, 3 }, /* sm2 kep public key attr count */
        { TEE_TYPE_SM2_KEP_KEYPAIR, 4 }, /* sm2 kep keypaie key attr count */
        { TEE_TYPE_DH_KEYPAIR, 4 }, /* dh keypair attr new api level */
        { TEE_TYPE_DH_KEYPAIR, 6 }, /* dh keypair attr old api level */
    };
    for (; index < sizeof(obj_type_to_attri_len) / sizeof(crypto_uint2uint); index++) {
        if (obj_type == obj_type_to_attri_len[index].src && attri_len == obj_type_to_attri_len[index].dest)
            return TEE_SUCCESS;
    }
    tloge("invalid obj_type 0x%x or attri_len 0x%x\n", obj_type, attri_len);
    return TEE_ERROR_BAD_PARAMETERS;
}

static bool is_no_need_set_private_key(const TEE_OperationHandle operation, const TEE_ObjectHandle key)
{
    bool is_key_pair = false;
    uint32_t key_pair_type_set[] = {
        TEE_TYPE_RSA_KEYPAIR,
        TEE_TYPE_DH_KEYPAIR,
        TEE_TYPE_ECDSA_KEYPAIR,
        TEE_TYPE_ECDH_KEYPAIR,
        TEE_TYPE_ED25519_KEYPAIR,
        TEE_TYPE_X25519_KEYPAIR,
        TEE_TYPE_SM2_DSA_KEYPAIR,
        TEE_TYPE_SM2_PKE_KEYPAIR,
        TEE_TYPE_SM2_KEP_KEYPAIR,
    };
    for (uint32_t i = 0; i < ELEM_NUM(key_pair_type_set); i++) {
        if (key->ObjectInfo->objectType == key_pair_type_set[i]) {
            is_key_pair = true;
            break;
        }
    }
    if (!is_key_pair)
        return true;
    if ((operation->mode == TEE_MODE_ENCRYPT) || (operation->mode == TEE_MODE_VERIFY))
        return true;
    return false;
}

static TEE_Result tee_get_asymmetric_keys(TEE_OperationHandle operation, const TEE_ObjectHandle key, uint32_t api_level)
{
    TEE_Result ret;

    operation->keySize = operation->maxKeySize;
    bool check =  ((key->Attribute == NULL) || (key->attributesLen == 0));
    if (check) {
        if (api_level <= API_LEVEL1_0)
            return TEE_GenKeyPair(operation, key);
        tloge("The key info is invalid");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (key->ObjectInfo == NULL) {
        tloge("key ObjectInfo is NULL!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = tee_keytype_and_attrilen_check(key->attributesLen, key->ObjectInfo->objectType);
    if (ret != TEE_SUCCESS)
        return ret;

    ret = set_public_key_hal(operation, key);
    if (ret != TEE_SUCCESS) {
        tloge("GenPubKey is error ret = 0x%x\n", ret);
        return ret;
    }

    if (is_no_need_set_private_key((const TEE_OperationHandle)operation, key))
        return TEE_SUCCESS;

    if (key->CRTMode)
        ret = set_private_key_crt_hal(operation, key);
    else
        ret = set_private_key_hal(operation, key);
    if (ret != TEE_SUCCESS) {
        tloge("generate key is error\n");
        TEE_Free(operation->publicKey);
        operation->publicKey = NULL;
        operation->publicKeyLen = 0;
        return ret;
    }
    return ret;
}

static TEE_Result set_operation_key_com_check(const TEE_OperationHandle operation, uint32_t api_level)
{
    if (operation->mode == TEE_MODE_DIGEST) {
        tloge("Digest operation expects no key\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (api_level < API_LEVEL1_1_1)
        return TEE_SUCCESS;

    if ((operation->handleState & TEE_HANDLE_FLAG_INITIALIZED) == TEE_HANDLE_FLAG_INITIALIZED) {
        tloge("Operation is not at initial state\n");
        return TEE_ERROR_BAD_STATE;
    }

    return TEE_SUCCESS;
}

static TEE_Result set_operation_key_state_check(const TEE_OperationHandle operation, uint32_t api_level)
{
    if (operation->algorithm == TEE_ALG_AES_XTS) {
        tloge("This algorithm expects two keys\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return set_operation_key_com_check(operation, api_level);
}

static TEE_Result set_symmetric_operation_key(TEE_OperationHandle operation, const TEE_ObjectHandle key)
{
    errno_t rc;

    bool check = (key->Attribute == NULL || key->Attribute->content.ref.length == 0 ||
        key->Attribute->content.ref.length > MAX_MALLOC_LEN);
    if (check) {
        tloge("key is invalid");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    operation->keyValue = TEE_Malloc(key->Attribute->content.ref.length, 0);
    if (operation->keyValue == NULL) {
        tloge("Failed to malloc memory for key value\n");
        return (TEE_ERROR_OUT_OF_MEMORY);
    }

    rc = memcpy_s(operation->keyValue, key->Attribute->content.ref.length, key->Attribute->content.ref.buffer,
        key->Attribute->content.ref.length);
    if (rc != EOK) {
        tloge("memcpy_s failed, rc %x\n", rc);
        TEE_Free(operation->keyValue);
        operation->keyValue = NULL;
        return TEE_ERROR_SECURITY;
    }
    operation->keySize = key->Attribute->content.ref.length;
    return TEE_SUCCESS;
}

#define SYMMETRIC_KEY_INDEX 0
#define INVALID_KEY_INDEX   (-1)
static int32_t get_asymmetric_key_index(const TEE_ObjectHandle key)
{
    bool check = (key == NULL || key->Attribute == NULL || key->attributesLen > MAX_ATTR_LEN);
    if (check)
        return INVALID_KEY_INDEX;

    uint32_t asymmetric_attr_id_set[] = {
        TEE_ATTR_RSA_MODULUS,
        TEE_ATTR_DH_PUBLIC_VALUE,
        TEE_ATTR_ECC_PUBLIC_VALUE_X,
        TEE_ATTR_ED25519_PUBLIC_VALUE,
        TEE_ATTR_X25519_PUBLIC_VALUE
    };
    for (uint32_t i = 0; i < key->attributesLen; i++) {
        for (uint32_t j = 0; j < ELEM_NUM(asymmetric_attr_id_set); j++) {
            if (key->Attribute[i].attributeID == asymmetric_attr_id_set[j])
                return (int32_t)i;
        }
    }

    return INVALID_KEY_INDEX;
}

static TEE_Result set_asymmetric_operation_key_size(TEE_OperationHandle operation, const TEE_ObjectHandle key)
{
    int32_t key_index = get_asymmetric_key_index(key);
    if (key_index == INVALID_KEY_INDEX) {
        tloge("The key index is invalid, set asym key size failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    operation->keySize = key->Attribute[key_index].content.ref.length;

    return TEE_SUCCESS;
}

static TEE_Result set_asymmetric_operation_key(TEE_OperationHandle operation, const TEE_ObjectHandle key,
    uint32_t api_level)

{
    TEE_Result ret;

    ret = tee_get_asymmetric_keys(operation, key, api_level);
    if (ret != TEE_SUCCESS) {
        tloge("Set asym operation key failed, ret=0x%x\n", ret);
        return ret;
    }
    if (api_level == API_LEVEL1_0)
        return TEE_SUCCESS;

    ret = set_asymmetric_operation_key_size(operation, key);
    if (ret != TEE_SUCCESS) {
        TEE_Free(operation->publicKey);
        operation->publicKey = NULL;
        operation->publicKeyLen = 0;
        (void)memset_s(operation->privateKey, operation->privateKeyLen, 0x0, operation->privateKeyLen);
        TEE_Free(operation->privateKey);
        operation->privateKey = NULL;
        operation->privateKeyLen = 0;
    }
    return ret;
}

#define TEE_MODE_INVALID 0xFFFFFFFF
struct obj_type_op_mode_config_s {
    uint32_t type;
    uint32_t mode[MAX_MODE_NUM];
};

static const struct obj_type_op_mode_config_s g_type_mode_config[] = {
    { TEE_TYPE_RSA_PUBLIC_KEY, { TEE_MODE_VERIFY, TEE_MODE_ENCRYPT } },
    { TEE_TYPE_DSA_PUBLIC_KEY, { TEE_MODE_VERIFY, TEE_MODE_INVALID } },
    { TEE_TYPE_ECDSA_PUBLIC_KEY, { TEE_MODE_VERIFY, TEE_MODE_INVALID } },
    { TEE_TYPE_ED25519_PUBLIC_KEY, { TEE_MODE_VERIFY, TEE_MODE_INVALID } },
    { TEE_TYPE_ECDH_PUBLIC_KEY, { TEE_MODE_DERIVE, TEE_MODE_INVALID } },
    { TEE_TYPE_X25519_PUBLIC_KEY, { TEE_MODE_DERIVE, TEE_MODE_INVALID } },
    { TEE_TYPE_SM2_DSA_PUBLIC_KEY, { TEE_MODE_VERIFY, TEE_MODE_INVALID } },
    { TEE_TYPE_SM2_PKE_PUBLIC_KEY, { TEE_MODE_ENCRYPT, TEE_MODE_DECRYPT } },
};

static TEE_Result operation_public_key_type_mode_check(uint32_t mode, uint32_t type)
{
    const struct obj_type_op_mode_config_s *config = NULL;
    uint32_t index;

    for (index = 0; index < ELEM_NUM(g_type_mode_config); index++) {
        if (type == g_type_mode_config[index].type) {
            config = &g_type_mode_config[index];
            break;
        }
    }

    if (config != NULL && mode != config->mode[0] && mode != config->mode[1])
        return TEE_ERROR_BAD_PARAMETERS;

    return TEE_SUCCESS;
}

#define TEE_ALG_ANY    0xFFFFFFFF
#define TEE_ALG_NONE   0x00000000
#define TEE_USAGE_NONE 0x00000000
struct mode_usage_conf_s {
    uint32_t mode;
    uint32_t algo;
    uint32_t usage;
};

static const struct mode_usage_conf_s g_mode_usage_conf[] = {
    { TEE_MODE_ENCRYPT, TEE_ALG_RSA_NOPAD, TEE_USAGE_ENCRYPT | TEE_USAGE_VERIFY },
    { TEE_MODE_DECRYPT, TEE_ALG_RSA_NOPAD, TEE_USAGE_DECRYPT | TEE_USAGE_SIGN },
    { TEE_MODE_ENCRYPT, TEE_ALG_ANY, TEE_USAGE_ENCRYPT },
    { TEE_MODE_DECRYPT, TEE_ALG_ANY, TEE_USAGE_DECRYPT },
    { TEE_MODE_SIGN, TEE_ALG_ANY, TEE_USAGE_SIGN },
    { TEE_MODE_VERIFY, TEE_ALG_ANY, TEE_USAGE_VERIFY },
    { TEE_MODE_MAC, TEE_ALG_ANY, TEE_USAGE_MAC },
    { TEE_MODE_DIGEST, TEE_ALG_NONE, TEE_USAGE_NONE },
    { TEE_MODE_DERIVE, TEE_ALG_ANY, TEE_USAGE_MAC },
};

// Some special check for TEE_ALG_RSA_NOPAD required by GP specification
static TEE_Result operation_mode_key_usage_check(uint32_t algorithm, uint32_t mode, uint32_t usage)
{
    const struct mode_usage_conf_s *config = NULL;
    uint32_t index;

    for (index = 0; index < ELEM_NUM(g_mode_usage_conf); index++) {
        if (g_mode_usage_conf[index].mode == mode && (algorithm & g_mode_usage_conf[index].algo) == algorithm) {
            config = &g_mode_usage_conf[index];
            break;
        }
    }

    if (config == NULL) {
        tloge("Failed to pass mode & algorithm usage check, algorithm: 0x%x, mode: 0x%x\n", algorithm, mode);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((usage & config->usage) != config->usage) {
        tloge("Key usage is not compatible with operation mode & algorithm, algorithm: 0x%x, mode: 0x%x, usage: 0x%x\n",
            algorithm, mode, usage);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

enum OP_SYMMETRIC_TYPE {
    SYMMETRIC_OP = 0x1001,
    ASYMMETRIC_OP = 0x1002,
    NO_KEY_OP = 0x1003,
    INVALID_OP = 0xFFFF
};

struct op_type_config_s {
    uint32_t op_class;
    uint32_t type;
};

static const struct op_type_config_s g_operation_type_config[] = {
    { TEE_OPERATION_CIPHER, SYMMETRIC_OP },
    { TEE_OPERATION_MAC, SYMMETRIC_OP },
    { TEE_OPERATION_AE, SYMMETRIC_OP },
    { TEE_OPERATION_DIGEST, NO_KEY_OP },
    { TEE_OPERATION_ASYMMETRIC_CIPHER, ASYMMETRIC_OP },
    { TEE_OPERATION_ASYMMETRIC_SIGNATURE, ASYMMETRIC_OP },
    { TEE_OPERATION_KEY_DERIVATION, ASYMMETRIC_OP }
};

static uint32_t get_op_class_type(uint32_t op_class)
{
    size_t index;

    for (index = 0; index < ELEM_NUM(g_operation_type_config); index++) {
        if (op_class == g_operation_type_config[index].op_class)
            return g_operation_type_config[index].type;
    }
    return INVALID_OP;
}

static TEE_Result check_object_key_size_valid(const TEE_OperationHandle operation, const TEE_ObjectHandle key,
    uint32_t type)
{
    uint32_t key_size_in_bits;

    if (key->Attribute == NULL) {
        tloge("The key attribute is NULL\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    int32_t index = (type == SYMMETRIC_OP) ? SYMMETRIC_KEY_INDEX : get_asymmetric_key_index(key);
    if (index == INVALID_KEY_INDEX) {
        tloge("The key info is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if ((key->Attribute[index].content.ref.length * BIT_TO_BYTE) < key->Attribute[index].content.ref.length) {
        tloge("The key len is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((key->Attribute[index].attributeID == TEE_ATTR_ECC_PUBLIC_VALUE_X) &&
        (key->Attribute[index].content.ref.length == ECC_SPECIAL_KEY_LEN_IN_BYTE))
        key_size_in_bits = ECC_SPECIAL_KEY_LEN_IN_BITS;
    else
        key_size_in_bits = key->Attribute[index].content.ref.length * BIT_TO_BYTE;
    if (key_size_in_bits > operation->maxKeySize) {
        tloge("The key size is invalid, object key size is %zu, operation key size is %u\n",
            key->Attribute[index].content.ref.length, operation->maxKeySize);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (crypto_check_keysize(operation->algorithm, key_size_in_bits) != TEE_SUCCESS) {
        tloge("The object key size is invalid, object key size is %u\n", key_size_in_bits);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result check_low_lev_key_size_valid(const TEE_OperationHandle operation, const TEE_ObjectHandle key,
    uint32_t type)
{
    uint32_t key_size_in_bits;

    if (key->Attribute == NULL) {
        tloge("The key info is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    int32_t index = (type == SYMMETRIC_OP) ? SYMMETRIC_KEY_INDEX : get_asymmetric_key_index(key);
    if (index == INVALID_KEY_INDEX) {
        tloge("The key info is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    key_size_in_bits = key->Attribute[index].content.ref.length;
    if (check_low_lev_key_size_for_alg(operation->algorithm, key_size_in_bits) != TEE_SUCCESS) {
        tloge("The object key size is invalid, object key size is %u\n", key_size_in_bits);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

/* Check the operation and key are compatible in mode, size, and usage */
static TEE_Result set_operation_key_compatible_check(const TEE_OperationHandle operation,
    const TEE_ObjectHandle key, uint32_t api_level, uint32_t type)
{
    TEE_Result ret;

    if (api_level == API_LEVEL1_0)
        return check_low_lev_key_size_valid(operation, key, type);

    if (key->ObjectInfo == NULL) {
        tloge("No key object information found\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (check_object_key_size_valid(operation, key, type) != TEE_SUCCESS) {
        tloge("The key obj key size is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* The key object must be initialize */
    if ((key->ObjectInfo->handleFlags & TEE_HANDLE_FLAG_INITIALIZED) != TEE_HANDLE_FLAG_INITIALIZED) {
        tloge("Failed to pass key initialize state check, handleFlags: 0x%x\n", key->ObjectInfo->handleFlags);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* The key object usage must contain the operation mode */
    ret = operation_mode_key_usage_check(operation->algorithm, operation->mode, key->ObjectInfo->objectUsage);
    if (ret != TEE_SUCCESS)
        return TEE_ERROR_BAD_PARAMETERS;

    /* The key object type must compatible with operation algorithm */
    if (!crypto_check_keytype_valid(operation->algorithm, key->ObjectInfo->objectType)) {
        tloge("Failed to pass algorithm & type check, algorithm: 0x%x, type: 0x%x\n", operation->algorithm,
            key->ObjectInfo->objectType);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Check if operation mode is compatible for public key object type */
    ret = operation_public_key_type_mode_check(operation->mode, key->ObjectInfo->objectType);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to pass public key & mode check, mode: 0x%x, type: 0x%x, ret: 0x%x\n", operation->mode,
            key->ObjectInfo->objectType, ret);
        return ret;
    }

    return TEE_SUCCESS;
}

TEE_Result TEE_SetOperationKey(TEE_OperationHandle operation, const TEE_ObjectHandle key)
{
    bool check = (operation == NULL || check_operation((const TEE_OperationHandle)operation) != TEE_SUCCESS);
    if (check) {
        tloge("bad params");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (crypto_lock_operation(operation) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    uint32_t api_level = tee_get_ta_api_level();
    TEE_Result ret = set_operation_key_state_check(operation, api_level);
    if (ret != TEE_SUCCESS)
        goto exit;

    ret = reset_operation_key(operation);
    if (ret != TEE_SUCCESS)
        goto exit;

    if (key == NULL) {
        crypto_unlock_operation(operation);
        return TEE_SUCCESS;
    }

    if ((api_level > API_LEVEL1_0) && (check_object(key) != TEE_SUCCESS)) {
        tloge("The key is invalid object\n");
        ret = TEE_ERROR_BAD_PARAMETERS;
        goto exit;
    }

    uint32_t type = get_op_class_type(operation->operationClass);
    ret = set_operation_key_compatible_check(operation, key, api_level, type);
    if (ret != TEE_SUCCESS) {
        goto exit;
    }
    if (type == SYMMETRIC_OP) {
        ret = set_symmetric_operation_key(operation, key);
    } else if (type == ASYMMETRIC_OP) {
        ret = set_asymmetric_operation_key(operation, key, api_level);
    } else {
        tloge("invalid operationClass for this operation, operation class: 0x%x\n", operation->operationClass);
        ret = TEE_ERROR_BAD_PARAMETERS;
    }

    if (ret != TEE_SUCCESS)
        goto exit;
    operation->handleState |= TEE_HANDLE_FLAG_KEY_SET;
    crypto_unlock_operation(operation);
    return TEE_SUCCESS;
exit:
    crypto_unlock_operation(operation);
    TEE_Panic(ret);
    return ret;
}

static TEE_Result check_operation_key_equal(const TEE_ObjectHandle key1, const TEE_ObjectHandle key2)
{
    bool check = (key1->Attribute == NULL || key2->Attribute == NULL);
    if (check) {
        tloge("bad params");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t api_level = tee_get_ta_api_level();
    if (api_level <= API_LEVEL1_1_1)
        return TEE_ERROR_GENERIC;

    if (key1->Attribute->content.ref.length != key2->Attribute->content.ref.length)
        return TEE_ERROR_GENERIC;

    if (key1->Attribute->content.ref.length == 0)
        return TEE_SUCCESS;

    if (TEE_MemCompare(key1->Attribute->content.ref.buffer, key2->Attribute->content.ref.buffer,
        key1->Attribute->content.ref.length) != 0)
        return TEE_ERROR_GENERIC;

    return TEE_SUCCESS;
}

static TEE_Result copy_key_value_to_operation(TEE_OperationHandle operation, const TEE_ObjectHandle key1,
    const TEE_ObjectHandle key2)
{
    errno_t rc = memcpy_s(operation->keyValue, key1->Attribute->content.ref.length,
        key1->Attribute->content.ref.buffer, key1->Attribute->content.ref.length);
    if (rc != EOK) {
        tloge("memcpy_s failed, rc 0x%x\n", rc);
        return TEE_ERROR_SECURITY;
    }
    operation->keySize = key1->Attribute->content.ref.length;

    rc = memcpy_s(operation->keyValue2, key2->Attribute->content.ref.length, key2->Attribute->content.ref.buffer,
        key2->Attribute->content.ref.length);
    if (rc != EOK) {
        tloge("memcpy_s failed, rc 0x%x\n", rc);
        return TEE_ERROR_SECURITY;
    }
    operation->keySize2 = key2->Attribute->content.ref.length;
    return TEE_SUCCESS;
}

static TEE_Result set_operation_key_2(TEE_OperationHandle operation, const TEE_ObjectHandle key1,
    const TEE_ObjectHandle key2)
{
    bool check = (operation == NULL || key1 == NULL || key2 == NULL || key1->Attribute == NULL ||
        key1->Attribute->content.ref.buffer == NULL || key2->Attribute == NULL ||
        key2->Attribute->content.ref.buffer == NULL);
    if (check) {
        tloge("bad params");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (key1->Attribute->content.ref.length <= 0) {
        tloge("Invalid first key value size\n");
        return (TEE_ERROR_BAD_PARAMETERS);
    }

    if (key2->Attribute->content.ref.length <= 0) {
        tloge("Invalid second key value size\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    operation->keyValue = TEE_Malloc(key1->Attribute->content.ref.length, 0);
    if (operation->keyValue == NULL) {
        tloge("Failed to malloc buffer for first key value\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    operation->keyValue2 = TEE_Malloc(key2->Attribute->content.ref.length, 0);
    if (operation->keyValue2 == NULL) {
        tloge("Failed to malloc buffer for second key value\n");
        TEE_Free(operation->keyValue);
        operation->keyValue = NULL;
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_Result ret = copy_key_value_to_operation(operation, key1, key2);
    if (ret != TEE_SUCCESS) {
        sensitive_information_cleanup(&operation->keyValue, operation->keySize);
        TEE_Free(operation->keyValue);
        operation->keyValue = NULL;
        sensitive_information_cleanup(&operation->keyValue2, operation->keySize);
        TEE_Free(operation->keyValue2);
        operation->keyValue2 = NULL;
    }

    operation->handleState |= TEE_HANDLE_FLAG_KEY_SET;
    return TEE_SUCCESS;
}

static TEE_Result set_operation_key2_state_check(const TEE_OperationHandle operation, uint32_t api_level)
{
    if (operation->algorithm != TEE_ALG_AES_XTS) {
        tloge("The api only valid for TEE_ALG_AES_XTS , algorithm: 0x%x\n", operation->algorithm);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return set_operation_key_com_check(operation, api_level);
}

static TEE_Result check_two_keys_valid(const TEE_ObjectHandle key1, const TEE_ObjectHandle key2, uint32_t api_level)
{
    bool check = ((key1 == NULL) && (key2 == NULL));
    if (check)
        return TEE_SUCCESS;

    check = ((key1 == NULL) || (key2 == NULL));
    if (check) {
        tloge("The key is invalid object\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    check = ((api_level > API_LEVEL1_0) && ((check_object(key1) != TEE_SUCCESS) ||
            (check_object(key2) != TEE_SUCCESS)));
    if (check) {
        tloge("The key is invalid object\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    check = ((key1->Attribute == NULL) || (key2->Attribute == NULL));
    if (check) {
        tloge("The key is invalid object\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

TEE_Result TEE_SetOperationKey2(TEE_OperationHandle operation, const TEE_ObjectHandle key1, const TEE_ObjectHandle key2)
{
    bool check = (operation == NULL || check_operation((const TEE_OperationHandle)operation) != TEE_SUCCESS);
    if (check) {
        tloge("bad params");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result ret;
    uint32_t api_level = tee_get_ta_api_level();
    if (check_two_keys_valid(key1, key2, api_level) != TEE_SUCCESS) {
        tloge("The key is invalid object\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (crypto_lock_operation(operation) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    /* Check the operation if in the suitable state */
    ret = set_operation_key2_state_check(operation, api_level);
    if (ret != TEE_SUCCESS)
        goto exit;

    /* Clean up the operation key first */
    ret = reset_operation_key(operation);
    if (ret != TEE_SUCCESS)
        goto exit;

    /* If key1 & key2 both NULL, clean up the operation key */
    if (key1 == NULL && key2 == NULL) {
        tlogd("Clear up the key1 & key2 in operation only\n");
        goto out;
    }

    /* if key1 & key2 not NULL, they are not alllowed to be the same */
    ret = check_operation_key_equal(key1, key2);
    if (ret == TEE_SUCCESS) {
        tloge("There will be security problems if key1 and key2 are the same\n");
        ret = TEE_ERROR_SECURITY;
        goto exit;
    }

    /* Check if key1 & key2 are compatible with operation */
    if (set_operation_key_compatible_check(operation, key1, api_level, SYMMETRIC_OP) != TEE_SUCCESS ||
        set_operation_key_compatible_check(operation, key2, api_level, SYMMETRIC_OP) != TEE_SUCCESS) {
        ret = TEE_ERROR_BAD_PARAMETERS;
        goto exit;
    }

    /* Dump key1 & key2 to operation */
    ret = set_operation_key_2(operation, key1, key2);
    if (ret != TEE_SUCCESS)
        goto exit;
out:
    crypto_unlock_operation(operation);
    return (TEE_SUCCESS);
exit:
    crypto_unlock_operation(operation);
    TEE_Panic(ret);
    return (ret);
}

static TEE_Result check_and_copy_hal_info(const TEE_OperationHandle dst_operation,
    const TEE_OperationHandle src_operation)
{
    bool check = ((dst_operation->hal_info == NULL) || (src_operation->hal_info == NULL));
    if (check) {
        tloge("Dest or src crypto hal data is NULL \n");
        return TEE_ERROR_GENERIC;
    }

    check = ((dst_operation->mode != src_operation->mode) ||
        (dst_operation->algorithm != src_operation->algorithm));
    if (check) {
        tloge("mode or algorithm is not match\n");
        return TEE_ERROR_GENERIC;
    }

    if (src_operation->keySize > dst_operation->maxKeySize) {
        tloge("src_operation->keySize > dst_operation->maxKeySize\n");
        return TEE_ERROR_GENERIC;
    }

    crypto_hal_info *dst_crypto_hal_data = (crypto_hal_info *)(dst_operation->hal_info);
    crypto_hal_info *src_crypto_hal_data = (crypto_hal_info *)(src_operation->hal_info);

    dst_crypto_hal_data->crypto_flag = src_crypto_hal_data->crypto_flag;
    dst_crypto_hal_data->digestalloc_flag = src_crypto_hal_data->digestalloc_flag;
    dst_crypto_hal_data->cipher_update_len = src_crypto_hal_data->cipher_update_len;

    return TEE_SUCCESS;
}

#define MAX_SYMMETRIC_BUF_SIZE 1024
static TEE_Result copy_symmetric_buf_info(void **dst_buf, uint32_t *dst_size, const void *src_buf, uint32_t src_size)
{
    TEE_Free(*dst_buf);
    *dst_buf          = NULL;
    *dst_size         = 0;
    bool is_need_copy = ((src_buf != NULL) && (src_size != 0) && (src_size <= MAX_SYMMETRIC_BUF_SIZE));
    if (!is_need_copy)
        return TEE_SUCCESS;

    *dst_buf = TEE_Malloc(src_size, TEE_MALLOC_FILL_ZERO);
    if (*dst_buf == NULL) {
        tloge("dst_buf malloc failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    (void)memcpy_s(*dst_buf, src_size, src_buf, src_size);
    *dst_size         = src_size;

    return TEE_SUCCESS;
}

static void clear_key_info(uint8_t *key_buf, uint32_t key_size)
{
    if (key_buf == NULL)
        return;
    errno_t rc = memset_s(key_buf, key_size, 0, key_size);
    if (rc != EOK)
        tloge("clear key info failed, rc=0x%x\n", rc);
}

static TEE_Result copy_symmetric_key_iv(TEE_OperationHandle dst_operation, const TEE_OperationHandle src_operation)
{
    TEE_Result ret = copy_symmetric_buf_info(&dst_operation->keyValue, &dst_operation->keySize, src_operation->keyValue,
        src_operation->keySize);
    if (ret != TEE_SUCCESS) {
        tloge("Copy sym key info failed\n");
        return ret;
    }
    ret = copy_symmetric_buf_info(&dst_operation->keyValue2, &dst_operation->keySize2, src_operation->keyValue2,
        src_operation->keySize2);
    if (ret != TEE_SUCCESS) {
        tloge("Copy sym key2 info failed\n");
        clear_key_info(dst_operation->keyValue, dst_operation->keySize);
        TEE_Free(dst_operation->keyValue);
        dst_operation->keyValue = NULL;
        return ret;
    }
    ret = copy_symmetric_buf_info(&dst_operation->IV, &dst_operation->IVLen, src_operation->IV, src_operation->IVLen);
    if (ret != TEE_SUCCESS) {
        tloge("Copy sym iv info failed\n");
        clear_key_info(dst_operation->keyValue, dst_operation->keySize);
        TEE_Free(dst_operation->keyValue);
        dst_operation->keyValue = NULL;
        clear_key_info(dst_operation->keyValue2, dst_operation->keySize2);
        TEE_Free(dst_operation->keyValue2);
        dst_operation->keyValue2 = NULL;
        return ret;
    }

    return TEE_SUCCESS;
}

static TEE_Result clean_operation_key(TEE_OperationHandle operation)
{
    errno_t rc;

    if (operation->publicKey != NULL && operation->publicKeyLen != 0) {
        rc = memset_s(operation->publicKey, operation->publicKeyLen, 0x0, operation->publicKeyLen);
        if (rc != EOK) {
            tloge("memset operation pub key failed\n");
            return TEE_ERROR_SECURITY;
        }
        TEE_Free(operation->publicKey);
        operation->publicKey = NULL;
    }
    if (operation->privateKey != NULL && operation->privateKeyLen != 0) {
        rc = memset_s(operation->privateKey, operation->privateKeyLen, 0x0, operation->privateKeyLen);
        if (rc != EOK) {
            tloge("memset operation prv key failed\n");
            return TEE_ERROR_SECURITY;
        }
        TEE_Free(operation->privateKey);
        operation->privateKey = NULL;
    }

    return TEE_SUCCESS;
}

static TEE_Result copy_crypto_keypair(TEE_OperationHandle dst_operation, const TEE_OperationHandle src_operation)
{
    TEE_Result ret;

    ret = clean_operation_key(dst_operation);
    if (ret != TEE_SUCCESS) {
        tloge("clean operation key failed\n");
        return ret;
    }

    if (src_operation->publicKey != NULL && src_operation->publicKeyLen != 0) {
        void *pub_key = TEE_Malloc(src_operation->publicKeyLen, 0);
        if (pub_key == NULL) {
            tloge("Malloc rsa pub key failed\n");
            return TEE_ERROR_OUT_OF_MEMORY;
        }
        (void)memcpy_s(pub_key, src_operation->publicKeyLen, src_operation->publicKey, src_operation->publicKeyLen);
        dst_operation->publicKey = pub_key;
        dst_operation->publicKeyLen = src_operation->publicKeyLen;
    }
    if (src_operation->privateKey != NULL && src_operation->privateKeyLen != 0) {
        void *prv_key = TEE_Malloc(src_operation->privateKeyLen, 0);
        if (prv_key == NULL) {
            tloge("Malloc rsa prv key failed\n");
            goto clean_pub_key;
        }
        (void)memcpy_s(prv_key, src_operation->privateKeyLen, src_operation->privateKey, src_operation->privateKeyLen);
        dst_operation->privateKey = prv_key;
        dst_operation->privateKeyLen = src_operation->privateKeyLen;
    }

    return TEE_SUCCESS;

clean_pub_key:
    if (src_operation->publicKey != NULL && src_operation->publicKeyLen != 0 &&
        dst_operation->publicKey != NULL && dst_operation->publicKeyLen != 0) {
        (void)memset_s(dst_operation->publicKey, dst_operation->publicKeyLen, 0x0, dst_operation->publicKeyLen);
        TEE_Free(dst_operation->publicKey);
        dst_operation->publicKey = NULL;
        dst_operation->publicKeyLen = 0;
    }

    return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result copy_crypto_hal_ctx(TEE_OperationHandle dst_operation, const TEE_OperationHandle src_operation)
{
    free_operation_ctx(dst_operation);

    if (src_operation->crypto_ctxt == NULL)
        return TEE_SUCCESS;

    dst_operation->crypto_ctxt = TEE_Malloc(sizeof(struct ctx_handle_t), 0);
    if (dst_operation->crypto_ctxt == NULL) {
        tloge("malloc destoperation ctx failed");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    int32_t ret = tee_crypto_ctx_copy(src_operation->crypto_ctxt, dst_operation->crypto_ctxt);
    if (ret != TEE_SUCCESS) {
        TEE_Free(dst_operation->crypto_ctxt);
        dst_operation->crypto_ctxt = 0;
    }
    return change_hal_ret_to_gp(ret);
}

static TEE_Result copy_crypto_hal_operation(TEE_OperationHandle dst_operation, const TEE_OperationHandle src_operation)
{
    TEE_Result ret;

    ret = copy_crypto_keypair(dst_operation, src_operation);
    if (ret != TEE_SUCCESS)
        return ret;

    ret = copy_crypto_hal_ctx(dst_operation, src_operation);
    if (ret != TEE_SUCCESS)
        goto clean_key;

    return TEE_SUCCESS;
clean_key:
    TEE_Free(dst_operation->publicKey);
    dst_operation->publicKey = NULL;
    dst_operation->publicKeyLen = 0;

    (void)memset_s(dst_operation->privateKey, dst_operation->privateKeyLen, 0x0, dst_operation->privateKeyLen);
    TEE_Free(dst_operation->privateKey);
    dst_operation->privateKey = NULL;
    dst_operation->privateKeyLen = 0;
    return ret;
}

static void clear_all_info(TEE_OperationHandle dst_operation)
{
    clear_key_info(dst_operation->keyValue, dst_operation->keySize);
    TEE_Free(dst_operation->keyValue);
    dst_operation->keyValue = NULL;
    clear_key_info(dst_operation->keyValue2, dst_operation->keySize2);
    TEE_Free(dst_operation->keyValue2);
    dst_operation->keyValue2 = NULL;
    TEE_Free(dst_operation->IV);
    dst_operation->IV = NULL;
    free_operation_ctx(dst_operation);
}

static TEE_Result tee_copy_operation_check(TEE_OperationHandle dst_operation, const TEE_OperationHandle src_operation)
{
    if (dst_operation == NULL || src_operation == NULL) {
        tloge("operation is invalid");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (dst_operation == src_operation) {
        tloge("Src operation handle is equal to the dest handle\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (check_operation((const TEE_OperationHandle)src_operation) != TEE_SUCCESS) {
        tloge("Src operation handle is invalid handle\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (check_operation((const TEE_OperationHandle)dst_operation) != TEE_SUCCESS) {
        tloge("Dst operation handle is invalid handle\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

void TEE_CopyOperation(TEE_OperationHandle dst_operation, const TEE_OperationHandle src_operation)
{
    if (tee_copy_operation_check(dst_operation, src_operation) != TEE_SUCCESS) {
        tloge("tee copy operation check failed\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    if (crypto_lock_two_operation(dst_operation, src_operation) != TEE_SUCCESS)
        return;

    TEE_Result ret = check_and_copy_hal_info(dst_operation, src_operation);
    if (ret != TEE_SUCCESS) {
        tloge("Check copy operation failed\n");
        crypyo_unlock_two_operation(dst_operation, src_operation);
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    ret = copy_symmetric_key_iv(dst_operation, src_operation);
    if (ret != TEE_SUCCESS)
        goto error;

    ret = copy_crypto_hal_operation(dst_operation, src_operation);
    if (ret != TEE_SUCCESS) {
        tloge("Copy sysmmetric key iv failed\n");
        goto error;
    }

    dst_operation->operationClass   = src_operation->operationClass;
    dst_operation->digestLength     = src_operation->digestLength;
    dst_operation->requiredKeyUsage = src_operation->requiredKeyUsage;
    dst_operation->handleState      = src_operation->handleState;
    dst_operation->keySize          = src_operation->keySize;
    crypyo_unlock_two_operation(dst_operation, src_operation);
    return;
error:
    clear_all_info(dst_operation);
    crypyo_unlock_two_operation(dst_operation, src_operation);
    TEE_Panic(TEE_ERROR_BAD_STATE);
    return;
}

#define MAX_RANDOM_SIZE 0x100000
void TEE_GenerateRandom(void *randomBuffer, size_t randomBufferLen)
{
    if (randomBuffer == NULL || randomBufferLen == 0) {
        tloge("bad params");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    if (randomBufferLen > MAX_RANDOM_SIZE) {
        tloge("this random size is too large!");
        return;
    }
    size_t left = 0;
    while (randomBufferLen > UINT16_MAX) {
        tee_crypto_generate_random(randomBuffer + left, UINT16_MAX, false);
        left += UINT16_MAX;
        randomBufferLen -= UINT16_MAX;
    }
    tee_crypto_generate_random(randomBuffer + left, randomBufferLen, false);
#ifdef OPENSSL_ENABLE
    tee_crypto_free_opensssl_drbg();
#endif
    return;
}

static void set_operation_info(TEE_OperationInfoMultiple *operation_info, TEE_OperationHandle operation)
{
    operation_info->algorithm      = operation->algorithm;
    operation_info->mode           = operation->mode;
    operation_info->operationClass = operation->operationClass;
    operation_info->digestLength   = operation->digestLength;
    operation_info->maxKeySize     = operation->maxKeySize;
    operation_info->handleState    = operation->handleState;
}

static TEE_Result check_level(void)
{
    uint32_t api_level = tee_get_ta_api_level();
    if (api_level <= API_LEVEL1_0) {
        tloge("in api level %u not support this function\n", api_level);
        return TEE_ERROR_NOT_SUPPORTED;
    }
    return TEE_SUCCESS;
}

static void clear_key(TEE_OperationInfoMultiple *opr_info_multiple, uint32_t num_of_keys)
{
    for (uint32_t n = 0; n < num_of_keys; n++) {
        opr_info_multiple->keyInformation[n].keySize          = 0;
        opr_info_multiple->keyInformation[n].requiredKeyUsage = 0;
    }
}

#define XTS_KEY_NUM 2
TEE_Result TEE_GetOperationInfoMultiple(TEE_OperationHandle operation, TEE_OperationInfoMultiple *operationInfoMultiple,
    const size_t *operationSize)
{
    if (check_level() != TEE_SUCCESS)
        return TEE_ERROR_NOT_SUPPORTED;

    bool check = (operation == NULL || operationInfoMultiple == NULL || operationSize == NULL ||
        (check_operation((const TEE_OperationHandle)operation) != TEE_SUCCESS));
    if (check) {
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t num_of_keys = (*operationSize - sizeof(TEE_OperationInfoMultiple)) / sizeof(TEE_OperationInfoKey);
    if (num_of_keys > XTS_KEY_NUM) {
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (crypto_lock_operation(operation) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    /* Two keys flag (TEE_ALG_AES_XTS only) */
    if (((operation->handleState & TEE_HANDLE_FLAG_EXPECT_TWO_KEYS) != 0) && (num_of_keys != XTS_KEY_NUM)) {
        crypto_unlock_operation(operation);
        return TEE_ERROR_SHORT_BUFFER;
    }

    /* Clear */
    clear_key(operationInfoMultiple, num_of_keys);

    if ((operation->keySize > (UINT32_MAX / BIT_TO_BYTE)) || (operation->keySize2 > (UINT32_MAX / BIT_TO_BYTE))) {
        tloge("Operation key size is invalid\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        crypto_unlock_operation(operation);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (tee_get_ta_api_level() == API_LEVEL1_0)
        operationInfoMultiple->keyInformation[0].keySize = operation->keySize;
    else
        get_operation_key_size_in_byte(operation->keySize, operation->algorithm,
            &(operationInfoMultiple->keyInformation[0].keySize));

    operationInfoMultiple->keyInformation[0].requiredKeyUsage = operation->requiredKeyUsage;
    if (num_of_keys == XTS_KEY_NUM) {
        operationInfoMultiple->keyInformation[1].keySize          = operation->keySize2 * BIT_TO_BYTE;
        operationInfoMultiple->keyInformation[1].requiredKeyUsage = operation->requiredKeyUsage;
    }

    /* No key */
    set_operation_info(operationInfoMultiple, operation);
    operationInfoMultiple->numberOfKeys   = num_of_keys;

    if ((operation->handleState & TEE_HANDLE_FLAG_INITIALIZED) == TEE_HANDLE_FLAG_INITIALIZED)
        operationInfoMultiple->operationState = TEE_OPERATION_STATE_ACTIVE;
    else
        operationInfoMultiple->operationState = TEE_OPERATION_STATE_INITIAL;
    crypto_unlock_operation(operation);

    return TEE_SUCCESS;
}

TEE_Result TEE_IsAlgorithmSupported(uint32_t algId, uint32_t element)
{
    uint32_t api_level = tee_get_ta_api_level();
    if (api_level <= API_LEVEL1_1_1) {
        tloge("in api level %u not support this function\n", api_level);
        return TEE_ERROR_NOT_SUPPORTED;
    }
    if (crypto_check_alg_supported(algId, element))
        return TEE_SUCCESS;
    return TEE_ERROR_NOT_SUPPORTED;
}
