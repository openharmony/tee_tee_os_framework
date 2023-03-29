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
#include <securec.h>
#include <tee_log.h>
#include <tee_object_api.h>
#include <crypto_hal_derive_key.h>
#include <crypto_driver_adaptor.h>
#include <crypto_inner_defines.h>
#include <tee_property_inner.h>
#include "tee_operation.h"

#ifndef GP_COMPATIBLE
#define TEE_Panic(x) \
    do {             \
    } while (0)
#endif

static TEE_Result get_ecdh_public_key_hal(TEE_OperationHandle operation, const TEE_Attribute *params,
    uint32_t param_count, struct ecc_pub_key_t *client_key)
{
    int32_t index;
    errno_t res;
    if (operation->algorithm == TEE_ALG_X25519) {
        index = get_attr_index_by_id(TEE_ATTR_X25519_PUBLIC_VALUE, params, param_count);
        if (index < 0) {
            tloge("invalid key");
            return TEE_ERROR_BAD_PARAMETERS;
        }
        res = memcpy_s(client_key->x, client_key->x_len, params[index].content.ref.buffer,
            params[index].content.ref.length);
        if (res != EOK)
            return TEE_ERROR_SECURITY;
        client_key->x_len = params[index].content.ref.length;
        client_key->domain_id = ECC_CURVE_X25519;
        return TEE_SUCCESS;
    }

    index = get_attr_index_by_id(TEE_ATTR_ECC_PUBLIC_VALUE_X, params, param_count);
    if (index < 0) {
        tloge("invalid key");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    res = memcpy_s(client_key->x, client_key->x_len, params[index].content.ref.buffer,
        params[index].content.ref.length);
    if (res != EOK)
        return TEE_ERROR_SECURITY;
    client_key->x_len = params[index].content.ref.length;

    index = get_attr_index_by_id(TEE_ATTR_ECC_PUBLIC_VALUE_Y, params, param_count);
    if (index < 0) {
        tloge("invalid key");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    res = memcpy_s(client_key->y, client_key->y_len, params[index].content.ref.buffer,
        params[index].content.ref.length);
    if (res != EOK)
        return TEE_ERROR_SECURITY;
    client_key->y_len = params[index].content.ref.length;

    index = get_attr_index_by_id(TEE_ATTR_ECC_CURVE, params, param_count);
    if (index < 0) {
        tloge("invalid key");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    client_key->domain_id = params[index].content.value.a;
    return TEE_SUCCESS;
}

static TEE_Result tee_derive_key_ecdh_hal(TEE_OperationHandle operation, const TEE_Attribute *params,
    uint32_t param_count, TEE_ObjectHandle derived_key, uint32_t engine)
{
    struct ecc_pub_key_t client_key = {0};
    client_key.x_len = sizeof(client_key.x);
    client_key.y_len = sizeof(client_key.y);
    TEE_Result ret = get_ecdh_public_key_hal(operation, params, param_count, &client_key);
    if (ret != TEE_SUCCESS) {
        tloge("get ecdh public key failed");
        return ret;
    }

    struct memref_t secret = {0};
    secret.buffer = (uint64_t)(uintptr_t)TEE_Malloc(client_key.x_len, 0);
    if (secret.buffer == 0) {
        tloge("malloc failed");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    secret.size = client_key.x_len;
    int32_t res = tee_crypto_ecdh_derive_key(operation->algorithm, &client_key, operation->privateKey, NULL,
        &secret, engine);
    ret = change_hal_ret_to_gp(res);
    if (ret != TEE_SUCCESS) {
        tloge("ecdh derive key failed");
        TEE_Free((void *)(uintptr_t)(secret.buffer));
        return ret;
    }
    TEE_Attribute secret_attr = {0};
    secret_attr.attributeID = TEE_ATTR_SECRET_VALUE;
    secret_attr.content.ref.length = (size_t)secret.size;
    secret_attr.content.ref.buffer = (void *)(uintptr_t)(secret.buffer);

    ret = TEE_PopulateTransientObject(derived_key, &secret_attr, 1);
    (void)memset_s(&secret_attr, sizeof(secret_attr), 0x0, sizeof(secret_attr));
    TEE_Free((void *)(uintptr_t)(secret.buffer));
    secret.buffer = 0;
    if (ret != TEE_SUCCESS) {
        tloge("Populate object failed\n");
        return ret;
    }

    return TEE_SUCCESS;
}

static void tee_derive_key_ecdh(TEE_OperationHandle operation, const TEE_Attribute *params, uint32_t param_count,
    TEE_ObjectHandle derived_key)
{
    if (operation->operationClass != TEE_OPERATION_KEY_DERIVATION) {
        tloge("operationClass isn't TEE_OPERATION_KEY_DERIVATION, it is 0x%x\n", operation->operationClass);
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }
    if (operation->algorithm != (uint32_t)TEE_ALG_ECDH_DERIVE_SHARED_SECRET &&
        operation->algorithm != (uint32_t)TEE_ALG_X25519) {
        tloge("algorithm error 0x%x\n", operation->algorithm);
        TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
        return;
    }
    if (operation->mode != TEE_MODE_DERIVE) {
        tloge("mode is not TEE_MODE_DERIVE\n");
        TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
        return;
    }
    bool check = (derived_key == NULL || derived_key->Attribute == NULL || param_count == 0 || params == NULL);
    if (check) {
        tloge("Attribute of derivedKey or param is null\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    crypto_hal_info *crypto_hal_data = (crypto_hal_info *)(operation->hal_info);
    if (crypto_hal_data == NULL) {
        tloge("invalid params");
        return;
    }

    TEE_Result ret = tee_derive_key_ecdh_hal(operation, params, param_count, derived_key, crypto_hal_data->crypto_flag);
    if (ret != TEE_SUCCESS) {
        tloge("DeriveKey_ECDH failed\n");
        TEE_Panic(change_hal_ret_to_gp(ret));
    }
    return;
}

static TEE_Result get_private_key(TEE_OperationHandle operation, const TEE_Attribute *params,
    uint32_t param_count, struct dh_key_t *dh_derive_key_data)
{
    uint32_t api_level = tee_get_ta_api_level();
    if (api_level >= API_LEVEL1_1_1) {
        dh_derive_key_data->dh_param.derive_key_t.priv_key = (uint64_t)(uintptr_t)operation->privateKey;
        dh_derive_key_data->dh_param.derive_key_t.priv_key_size = operation->privateKeyLen;
        return TEE_SUCCESS;
    }
    int32_t index = get_attr_index_by_id(TEE_ATTR_DH_PRIVATE_VALUE, params, param_count);
    if (index < 0) {
        tloge("dh param is invalid");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    dh_derive_key_data->dh_param.derive_key_t.priv_key = (uint64_t)(uintptr_t)params[index].content.ref.buffer;
    dh_derive_key_data->dh_param.derive_key_t.priv_key_size = params[index].content.ref.length;
    return TEE_SUCCESS;
}

static TEE_Result get_public_key(const TEE_Attribute *params, uint32_t param_count,
    struct dh_key_t *dh_derive_key_data)
{
    int32_t index = get_attr_index_by_id(TEE_ATTR_DH_PRIME, params, param_count);
    if (index < 0) {
        tloge("dh param is invalid");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    dh_derive_key_data->prime = (uint64_t)(uintptr_t)params[index].content.ref.buffer;
    dh_derive_key_data->prime_size = params[index].content.ref.length;

    index = get_attr_index_by_id(TEE_ATTR_DH_PUBLIC_VALUE, params, param_count);
    if (index < 0) {
        tloge("dh param is invalid");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    dh_derive_key_data->dh_param.derive_key_t.pub_key = (uint64_t)(uintptr_t)params[index].content.ref.buffer;
    dh_derive_key_data->dh_param.derive_key_t.pub_key_size = params[index].content.ref.length;
    return TEE_SUCCESS;
}

static TEE_Result tee_derive_key_dh_hal(TEE_OperationHandle operation, const TEE_Attribute *params,
    uint32_t param_count, TEE_ObjectHandle derived_key, uint32_t engine)
{
    struct dh_key_t dh_derive_key_data = {0};

    TEE_Result ret = get_public_key(params, param_count, &dh_derive_key_data);
    if (ret != TEE_SUCCESS) {
        tloge("get public key failed");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = get_private_key(operation, params, param_count, &dh_derive_key_data);
    if (ret != TEE_SUCCESS) {
        tloge("get private key failed");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t api_level = tee_get_ta_api_level();

    struct memref_t secret = {0};
    secret.buffer = (uint64_t)(uintptr_t)TEE_Malloc(derived_key->Attribute->content.ref.length, 0);
    if (secret.buffer == 0) {
        tloge("malloc failed");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    secret.size = (uint32_t)derived_key->Attribute->content.ref.length;

    ret = (TEE_Result)tee_crypto_dh_derive_key(&dh_derive_key_data, &secret, engine);
    if (ret != TEE_SUCCESS) {
        tloge("dh derive key failed");
        ret = change_hal_ret_to_gp(ret);
        goto out;
    }

    if (api_level < API_LEVEL1_1_1) {
        errno_t rc = memmove_s(derived_key->Attribute->content.ref.buffer, derived_key->Attribute->content.ref.length,
            (void *)(uintptr_t)secret.buffer, secret.size);
        if (rc != EOK) {
            tloge("memmove_s dh derive key failed\n");
            ret = TEE_ERROR_SECURITY;
        }
        goto out;
    }

    TEE_Attribute dh_attr = {0};
    dh_attr.attributeID = TEE_ATTR_SECRET_VALUE;
    dh_attr.content.ref.length = (size_t)secret.size;
    dh_attr.content.ref.buffer = (void *)(uintptr_t)(secret.buffer);

    ret = TEE_PopulateTransientObject(derived_key, &dh_attr, 1);
    (void)memset_s(&dh_attr, sizeof(dh_attr), 0x0, sizeof(dh_attr));
    if (ret != TEE_SUCCESS)
        tloge("dh populate object failed! ret = 0x%x\n", ret);

out:
    TEE_Free((void *)(uintptr_t)(secret.buffer));
    return ret;
}

static void tee_derive_key_dh(TEE_OperationHandle operation, const TEE_Attribute *params, uint32_t param_count,
    TEE_ObjectHandle derived_key)
{
    if (operation->operationClass != TEE_OPERATION_KEY_DERIVATION) {
        tloge("operationClass isn't TEE_OPERATION_KEY_DERIVATION, it is 0x%x\n", operation->operationClass);
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }
    if (operation->algorithm != (uint32_t)TEE_ALG_DH_DERIVE_SHARED_SECRET) {
        tloge("algorithm isn't TEE_ALG_DH_DERIVE_SHARED_SECRET\n");
        TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
        return;
    }
    if (operation->mode != TEE_MODE_DERIVE) {
        tloge("mode is not TEE_MODE_DERIVE\n");
        TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
        return;
    }
    bool check = (derived_key == NULL || derived_key->Attribute == NULL || param_count == 0 ||
        param_count > DH_ATTRIBUTE_TOTAL || params == NULL);
    if (check) {
        tloge("Attribute of derived_key or params is null\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    crypto_hal_info *crypto_hal_data = (crypto_hal_info *)(operation->hal_info);
    if (crypto_hal_data == NULL) {
        tloge("invalid params");
        return;
    }

    TEE_Result ret = tee_derive_key_dh_hal(operation, params, param_count, derived_key, crypto_hal_data->crypto_flag);
    if (ret != TEE_SUCCESS) {
        tloge("DeriveKey_DH failed\n");
        TEE_Panic(change_hal_ret_to_gp(ret));
    }
    return;
}

#define DH_MIN_L 2048
static bool dh_param_check(const TEE_Attribute *params, uint32_t param_count)
{
    bool check = (params == NULL || param_count == 0);
    if (check)
        return false;
    for (uint32_t i = 0; i < param_count; i++) {
        if (params[i].attributeID == TEE_ATTR_DH_X_BITS) {
            if (params[i].content.value.a < DH_MIN_L) {
                tloge("the parameter L should >= 2048\n");
                return false;
            }
        }
    }

    return true;
}

#define ECDH_MIN_LEN 28
static bool ecdh_param_check(const TEE_Attribute *params, uint32_t param_count)
{
    if (params == NULL || param_count == 0)
        return false;
    int32_t index_x = get_attr_index_by_id(TEE_ATTR_ECC_PUBLIC_VALUE_X, params, param_count);
    if (index_x < 0) {
        tloge("invalid key");
        return false;
    }

    int32_t index_y = get_attr_index_by_id(TEE_ATTR_ECC_PUBLIC_VALUE_Y, params, param_count);
    if (index_y < 0) {
        tloge("invalid key");
        return false;
    }

    if (params[index_x].content.ref.length < ECDH_MIN_LEN ||
        params[index_y].content.ref.length < ECDH_MIN_LEN) {
        tloge("the ECDH public key x len %u or y len %u is invalid\n",
              params[index_x].content.ref.length, params[index_y].content.ref.length);
        return false;
    }
    return true;
}

void TEE_DeriveKey(TEE_OperationHandle operation, const TEE_Attribute *params, uint32_t paramCount,
    TEE_ObjectHandle derivedKey)
{
    bool check = (operation == NULL || (check_operation((const TEE_OperationHandle)operation) != TEE_SUCCESS));
    if (check) {
        tloge("bad params");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    if (crypto_lock_operation(operation) != TEE_SUCCESS)
        return;

    if (tee_get_ta_api_level() > API_LEVEL1_0) {
        check = (derivedKey == NULL || derivedKey->ObjectInfo == NULL);
        if (check) {
            tloge("Invalid object handle!");
            crypto_unlock_operation(operation);
            return;
        }
        check = (operation->operationClass != TEE_OPERATION_KEY_DERIVATION ||
            operation->mode != TEE_MODE_DERIVE || derivedKey->ObjectInfo->objectType != TEE_TYPE_GENERIC_SECRET);
        if (check) {
            tloge("operation state is invalid");
            crypto_unlock_operation(operation);
            TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
            return;
        }
    }

    if (operation->algorithm == TEE_ALG_DH_DERIVE_SHARED_SECRET) {
        if (dh_param_check(params, paramCount))
            tee_derive_key_dh(operation, params, paramCount, derivedKey);
        crypto_unlock_operation(operation);
        return;
    } else if (operation->algorithm == TEE_ALG_ECDH_DERIVE_SHARED_SECRET) {
        if (ecdh_param_check(params, paramCount))
            tee_derive_key_ecdh(operation, params, paramCount, derivedKey);
        crypto_unlock_operation(operation);
        return;
    } else if (operation->algorithm == TEE_ALG_X25519) {
        tee_derive_key_ecdh(operation, params, paramCount, derivedKey);
        crypto_unlock_operation(operation);
        return;
    } else {
        tloge("not support DH algorithm 0x%x\n", operation->algorithm);
        crypto_unlock_operation(operation);
        TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
        return;
    }
}
