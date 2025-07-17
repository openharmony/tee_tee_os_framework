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
#include "tee_object_api.h"
#include <stdarg.h>
#include "ta_framework.h"
#include "tee_ss_agent_api.h"
#include "tee_log.h"
#include "tee_obj.h"
#include "securec.h"
#include "tee_property_inner.h"
#include <crypto_inner_defines.h>
#include <crypto_hal_derive_key.h>
#include <crypto_hal_rsa.h>
#include <crypto_hal_ec.h>
#include <crypto_hal.h>
#include <crypto_alg_config.h>
#include <crypto_manager.h>
#include "tee_obj_attr.h"

typedef TEE_Result (*attr_mem_func)(uint32_t api_level, TEE_ObjectHandle *object, uint32_t attrc);
struct attr_mem_alloc_t {
    uint32_t obj_type;
    attr_mem_func fn;
};

#define MAX_KEY_SIZE 0x000001000
#define DES_BLOCK 8
#define TEE_ATTR_ANAY 0
#define RSA_CRT_PARAM 2
#define RSA_EXPONENT 65537
#define HEX_VALUE 16
#define DH_PARAM_COUNT 3
#define DH_MIN_KEY_SIZE_IN_BIT  256
#define DH_MAX_KEY_SIZE_IN_BIT  2048
#define ECKEY_FIX_ATTRI_LEN 4
#define KEY_25519_FIX_ATTR_LEN 2
#define ECC_192_KEY_SIZE     192U
#define ECC_224_KEY_SIZE     224U
#define ECC_256_KEY_SIZE     256U
#define ECC_384_KEY_SIZE     384U
#define ECC_521_KEY_SIZE     521U
#define ECC_DEFAULT_KEY_SIZE 0U
#define DH_MIN_L             2048

struct object_max_key_size_s {
    uint32_t object_type;
    uint32_t attribute_id;
    uint32_t max_key_size_1_0;
    uint32_t max_key_size_1_2;
};

static const struct object_max_key_size_s g_max_key_size[] = {
    {TEE_TYPE_AES, TEE_ATTR_SECRET_VALUE, OBJ_MAX_SIZE_AES, OBJ_MAX_SIZE_AES},
    {TEE_TYPE_DES, TEE_ATTR_SECRET_VALUE, OBJ_SIZE_DES, OBJ_SIZE_DES},
    {TEE_TYPE_DES3, TEE_ATTR_SECRET_VALUE, OBJ_SIZE_DES3, OBJ_SIZE_DES3},
    {TEE_TYPE_SM4, TEE_ATTR_SECRET_VALUE, OBJ_MAX_SIZE_SM4, OBJ_SIZE_SM4},
    {TEE_TYPE_HMAC_SM3, TEE_ATTR_SECRET_VALUE, OBJ_MAX_SIZE_HMAC_SM3, OBJ_MAX_SIZE_HMAC_SM3},
    {TEE_TYPE_HMAC_MD5, TEE_ATTR_SECRET_VALUE, OBJ_MAX_SIZE_HMAC, OBJ_MAX_SIZE_HMAC},
    {TEE_TYPE_HMAC_SHA1, TEE_ATTR_SECRET_VALUE, OBJ_MAX_SIZE_HMAC, OBJ_MAX_SIZE_HMAC},
    {TEE_TYPE_HMAC_SHA224, TEE_ATTR_SECRET_VALUE, OBJ_MAX_SIZE_HMAC, OBJ_MAX_SIZE_HMAC},
    {TEE_TYPE_HMAC_SHA256, TEE_ATTR_SECRET_VALUE, OBJ_MAX_SIZE_HMAC, OBJ_MAX_SIZE_HMAC},
    {TEE_TYPE_HMAC_SHA384, TEE_ATTR_SECRET_VALUE, OBJ_MAX_SIZE_HMAC, OBJ_MAX_SIZE_HMAC},
    {TEE_TYPE_HMAC_SHA512, TEE_ATTR_SECRET_VALUE, OBJ_MAX_SIZE_HMAC, OBJ_MAX_SIZE_HMAC},
    {TEE_TYPE_PBKDF2_HMAC, TEE_ATTR_SECRET_VALUE, OBJ_MAX_SIZE_PBKDF2, OBJ_MAX_SIZE_PBKDF2},
    {TEE_TYPE_SIP_HASH, TEE_ATTR_SECRET_VALUE, OBJ_SIZE_SIP_HASH, OBJ_SIZE_SIP_HASH},
    {TEE_TYPE_RSA_PUBLIC_KEY, TEE_ATTR_RSA_PUBLIC_EXPONENT, OBJ_SIZE_RSA_PUB_EXPONENT, OBJ_SIZE_RSA_PUB_EXPONENT},
    {TEE_TYPE_RSA_PUBLIC_KEY, TEE_ATTR_RSA_MODULUS, OBJ_MAX_SIZE_RSA_PUB_KEY, OBJ_MAX_SIZE_RSA_PUB_KEY},
    {TEE_TYPE_RSA_KEYPAIR, TEE_ATTR_RSA_MODULUS, OBJ_MAX_SIZE_RSA_KEY_PAIR, OBJ_MAX_SIZE_RSA_KEY_PAIR},
    {TEE_TYPE_RSA_KEYPAIR, TEE_ATTR_RSA_PRIVATE_EXPONENT, OBJ_MAX_SIZE_RSA_KEY_PAIR, OBJ_MAX_SIZE_RSA_KEY_PAIR},
    {TEE_TYPE_RSA_KEYPAIR, TEE_ATTR_RSA_PUBLIC_EXPONENT, OBJ_SIZE_RSA_PUB_EXPONENT, OBJ_SIZE_RSA_PUB_EXPONENT},
    {TEE_TYPE_RSA_KEYPAIR, TEE_ATTR_RSA_PRIME1, OBJ_MAX_SIZE_RSA_CRT_ATTR, OBJ_MAX_SIZE_RSA_CRT_ATTR},
    {TEE_TYPE_RSA_KEYPAIR, TEE_ATTR_RSA_PRIME2, OBJ_MAX_SIZE_RSA_CRT_ATTR, OBJ_MAX_SIZE_RSA_CRT_ATTR},
    {TEE_TYPE_RSA_KEYPAIR, TEE_ATTR_RSA_EXPONENT1, OBJ_MAX_SIZE_RSA_CRT_ATTR, OBJ_MAX_SIZE_RSA_CRT_ATTR},
    {TEE_TYPE_RSA_KEYPAIR, TEE_ATTR_RSA_EXPONENT2, OBJ_MAX_SIZE_RSA_CRT_ATTR, OBJ_MAX_SIZE_RSA_CRT_ATTR},
    {TEE_TYPE_RSA_KEYPAIR, TEE_ATTR_RSA_COEFFICIENT, OBJ_MAX_SIZE_RSA_CRT_ATTR, OBJ_MAX_SIZE_RSA_CRT_ATTR},
    {TEE_TYPE_DSA_PUBLIC_KEY, TEE_ATTR_ANAY, OBJ_MAX_SIZE_DSA_PUB_KEY, OBJ_MAX_SIZE_DSA_PUB_KEY},
    {TEE_TYPE_DSA_KEYPAIR, TEE_ATTR_ANAY, OBJ_MAX_SIZE_DSA_KEY_PAIR, OBJ_MAX_SIZE_DSA_KEY_PAIR},
    {TEE_TYPE_DH_KEYPAIR, TEE_ATTR_ANAY, OBJ_MAX_SIZE_DH_KEY_PAIR, OBJ_MAX_SIZE_DH_KEY_PAIR},
    {TEE_TYPE_GENERIC_SECRET, TEE_ATTR_ANAY, OBJ_MAX_SIZE_GENERIC_SECRET, OBJ_MAX_SIZE_GENERIC_SECRET},
    {TEE_TYPE_ECDSA_PUBLIC_KEY, TEE_ATTR_ANAY, OBJ_MAX_SIZE_ECDSA_PUB_KEY, OBJ_MAX_SIZE_ECDSA_PUB_KEY},
    {TEE_TYPE_ECDSA_KEYPAIR, TEE_ATTR_ANAY, OBJ_MAX_SIZE_ECDSA_KEY_PAIR, OBJ_MAX_SIZE_ECDSA_KEY_PAIR},
    {TEE_TYPE_ECDH_PUBLIC_KEY, TEE_ATTR_ANAY, OBJ_MAX_SIZE_ECDH_PUB_KEY, OBJ_MAX_SIZE_ECDH_PUB_KEY},
    {TEE_TYPE_ECDH_KEYPAIR, TEE_ATTR_ANAY, OBJ_MAX_SIZE_ECDH_KEY_PAIR, OBJ_MAX_SIZE_ECDH_KEY_PAIR},
    {TEE_TYPE_X25519_KEYPAIR, TEE_ATTR_ANAY, OBJ_SIZE_X25519_PUB_KEY, OBJ_SIZE_X25519_PUB_KEY},
    {TEE_TYPE_X25519_PUBLIC_KEY, TEE_ATTR_ANAY, OBJ_SIZE_X25519_KEY_PAIR, OBJ_SIZE_X25519_KEY_PAIR},
    {TEE_TYPE_ED25519_KEYPAIR, TEE_ATTR_ANAY, OBJ_MAX_SIZE_ED25519_KEY_PAIR, OBJ_MAX_SIZE_ED25519_KEY_PAIR},
    {TEE_TYPE_ED25519_PUBLIC_KEY, TEE_ATTR_ANAY, OBJ_MAX_SIZE_ED25519_PUB_KEY, OBJ_SIZE_ED25519_PUB_KEY},
    {TEE_TYPE_SM2_DSA_PUBLIC_KEY, TEE_ATTR_ANAY, OBJ_MAX_SIZE_SM2, OBJ_SIZE_SM2},
    {TEE_TYPE_SM2_DSA_KEYPAIR, TEE_ATTR_ANAY, OBJ_MAX_SIZE_SM2, OBJ_SIZE_SM2},
    {TEE_TYPE_SM2_KEP_PUBLIC_KEY, TEE_ATTR_ANAY, OBJ_MAX_SIZE_SM2, OBJ_SIZE_SM2},
    {TEE_TYPE_SM2_KEP_KEYPAIR, TEE_ATTR_ANAY, OBJ_MAX_SIZE_SM2, OBJ_SIZE_SM2},
    {TEE_TYPE_SM2_PKE_PUBLIC_KEY, TEE_ATTR_ANAY, OBJ_MAX_SIZE_SM2, OBJ_SIZE_SM2},
    {TEE_TYPE_SM2_PKE_KEYPAIR, TEE_ATTR_ANAY, OBJ_MAX_SIZE_SM2, OBJ_SIZE_SM2},
};

static uint32_t object_max_size_of_object_type(uint32_t object_type, uint32_t attribute_id)
{
    uint32_t api_level = tee_get_ta_api_level();
    bool check = false;

    for (uint32_t index = 0; index < ELEM_NUM(g_max_key_size); index++) {
        check = (g_max_key_size[index].object_type == object_type) &&
            ((g_max_key_size[index].attribute_id == TEE_ATTR_ANAY) ||
             (g_max_key_size[index].attribute_id == attribute_id));
        if (check) {
            if (api_level > API_LEVEL1_0)
                return g_max_key_size[index].max_key_size_1_2;
            else
                return g_max_key_size[index].max_key_size_1_0;
        }
    }
    return 0;
}

/* check if the real max_key_size is biger than object_max_key_size */
static uint32_t get_attribute_length(uint32_t api_level, uint32_t object_type, uint32_t para, uint32_t max_key_size)
{
    uint32_t object_max_size = object_max_size_of_object_type(object_type, para);

    if (api_level == API_LEVEL1_0)
        return object_max_size;

    switch (object_type) {
    case TEE_TYPE_RSA_PUBLIC_KEY:
        if (para == TEE_ATTR_RSA_PUBLIC_EXPONENT)
            max_key_size = OBJ_SIZE_RSA_PUB_EXPONENT;
        break;
    case TEE_TYPE_RSA_KEYPAIR:
        if (para == TEE_ATTR_RSA_PUBLIC_EXPONENT) {
            max_key_size = OBJ_SIZE_RSA_PUB_EXPONENT;
            break;
        }
        if (para != TEE_ATTR_RSA_MODULUS && para != TEE_ATTR_RSA_PRIVATE_EXPONENT) {
            max_key_size = max_key_size / RSA_CRT_PARAM;
            break;
        }
        break;
    case TEE_TYPE_ED25519_KEYPAIR:
        if (para == TEE_ATTR_ED25519_PRIVATE_VALUE)
            max_key_size = OBJ_MAX_SIZE_ED25519_KEY_PAIR;
        /* fall-through */
    default:
        break;
    }

    if (max_key_size > object_max_size) {
        tloge("max_key_size %u is larger than the max key size %u", max_key_size, object_max_size);
        return 0;
    }

    return max_key_size;
}

/* check if the real key_size is small than object_min_key_size */
static TEE_Result check_object_min_size(uint32_t object_type, uint32_t para, uint32_t key_size)
{
    bool check = (((object_type == TEE_TYPE_RSA_PUBLIC_KEY) || (object_type == TEE_TYPE_RSA_KEYPAIR)) &&
        (para != TEE_ATTR_RSA_MODULUS));
    if (check)
        return TEE_SUCCESS;

    uint32_t object_min_size = get_object_size(object_type);
    if (key_size < object_min_size) {
        tloge("keysize %u is smaller than the min_object key size %u", key_size, object_min_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static void get_max_key_size(uint32_t *max_key_size, const TEE_ObjectHandle *object, uint32_t api_level)
{
    if (api_level > API_LEVEL1_0) {
#ifndef GP_SUPPORT
        *max_key_size = (*object)->ObjectInfo->maxObjectSize;
#else
        *max_key_size = (*object)->ObjectInfo->maxKeySize;
#endif
    }
}

static TEE_Result allocate_attribute(uint32_t api_level, TEE_ObjectHandle *object, uint32_t count, ...)
{
    uint32_t i = 0;
    va_list argp = {0};
    uint32_t para;
    uint32_t max_key_size = 0;

    /* eID use SM2_PKE algo but use SM2_KEP key,so SM2_KEP key should be supported at API_LEVEL1_0 */
    bool check = ((api_level > API_LEVEL1_0) && (((*object)->ObjectInfo->objectType == TEE_TYPE_SM2_KEP_PUBLIC_KEY) ||
            ((*object)->ObjectInfo->objectType == TEE_TYPE_SM2_KEP_KEYPAIR)));
    if (check) {
        tloge("the object type is not supported! objectType = %u\n", (*object)->ObjectInfo->objectType);
        return TEE_ERROR_NOT_SUPPORTED;
    }
    (*object)->Attribute = (TEE_Attribute *)TEE_Malloc(count * sizeof(TEE_Attribute), 0);
    if (((*object)->Attribute) == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    (void)va_start(argp, count);

    get_max_key_size(&max_key_size, object, api_level);

    while (i < count) {
        para = (uint32_t)va_arg(argp, uint32_t);
        (*object)->Attribute[i].attributeID = para;

        if (TEE_ATTR_IS_BUFFER((*object)->Attribute[i].attributeID)) {
            (*object)->Attribute[i].content.ref.length = get_attribute_length(api_level,
                (*object)->ObjectInfo->objectType, para, max_key_size);

            (*object)->Attribute[i].content.ref.buffer =
                TEE_Malloc((*object)->Attribute[i].content.ref.length, 0);
            if ((*object)->Attribute[i].content.ref.buffer == NULL)
                goto malloc_buf_error;
        } else {
            (*object)->Attribute[i].content.value.a = 0;
            (*object)->Attribute[i].content.value.b = 0;
        }
        i++;
    }
    va_end(argp);
    (*object)->attributesLen = count;
    return TEE_SUCCESS;

malloc_buf_error:
    va_end(argp);
    tloge("Failed to allocate memory for object attribute:ref buffer.\n");
    while (i > 0) {
        i--;
        if (TEE_ATTR_IS_BUFFER((*object)->Attribute[i].attributeID)) {
            TEE_Free((*object)->Attribute[i].content.ref.buffer);
            (*object)->Attribute[i].content.ref.buffer = NULL;
        }
    }
    TEE_Free((*object)->Attribute);
    (*object)->Attribute = NULL;

    return TEE_ERROR_OUT_OF_MEMORY;
}

static void free_attribute(TEE_ObjectHandle object, uint32_t attrc)
{
    if (object->Attribute == NULL) {
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    tlogd("Need to free attribute!\n");
    uint32_t i = 0;
    int32_t rc;
    uint32_t max_key_size = 0;
    uint32_t malloc_size;
    uint32_t api_level = tee_get_ta_api_level();
    if (api_level > API_LEVEL1_0) {
#ifndef GP_SUPPORT
        max_key_size = object->ObjectInfo->maxObjectSize;
#else
        max_key_size = object->ObjectInfo->maxKeySize;
#endif
    }

    while (i < attrc) {
        if (TEE_ATTR_IS_BUFFER(object->Attribute[i].attributeID) &&
            object->Attribute[i].content.ref.buffer != NULL) {
            if (api_level > API_LEVEL1_0) {
                malloc_size = get_attribute_length(api_level, object->ObjectInfo->objectType,
                    object->Attribute[i].attributeID, max_key_size);
            } else {
                max_key_size = object->Attribute[i].content.ref.length;
                malloc_size = max_key_size;
            }
            rc = memset_s(object->Attribute[i].content.ref.buffer, malloc_size, 0x0,
                object->Attribute[i].content.ref.length);
            if (rc != 0)
                /* Ignore the failure and continue the traversal */
                tlogw("memset_s failed!\n");
            TEE_Free(object->Attribute[i].content.ref.buffer);
            object->Attribute[i].content.ref.buffer = NULL;
        }
        i++;
    }
    TEE_Free((void *)object->Attribute);
    object->Attribute = NULL;
    return;
}

/*
 * Set transient object to unintialized state.
 * Called by TEE_AllocateTransientObject.
 * object->Attribute[i].attributeID and  object->attributesLen not changed.
 * object->Attribute[i].content.ref.length not changed
 */
static void transient_object_uninitialized_state(
    TEE_ObjectHandle object,
    uint32_t object_type,
    uint32_t max_object_size)
{
    uint32_t i;
    errno_t rc;

    object->dataPtr = NULL;
    object->dataLen = 0;
    rc = memset_s(object->dataName, sizeof(object->dataName), 0, sizeof(object->dataName));
    if (rc != EOK) {
        tloge("memset failed\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    object->ObjectInfo->objectType = object_type;
    /* Set to 0 for an uninitialized object */
#ifndef GP_SUPPORT
    object->ObjectInfo->objectSize = 0;
    object->ObjectInfo->maxObjectSize = max_object_size;
#else
    object->ObjectInfo->keySize = 0;
    object->ObjectInfo->maxKeySize = max_object_size;
#endif
    object->ObjectInfo->objectUsage = (uint32_t)TEE_USAGE_DEFAULT;
    /* For a transient object, always set to 0 */
    object->ObjectInfo->dataSize = 0;
    /* For a transient object, set to 0 */
    object->ObjectInfo->dataPosition = 0;
    /* For a transient object, TEE_HANDLE_FLAG_INITIALIZED initially cleared,
     * then set when the object becomes initialized */
    object->ObjectInfo->handleFlags = 0;

    if (object->Attribute == NULL)
        return;
    for (i = 0; i < (object->attributesLen); i++) {
        if (TEE_ATTR_IS_BUFFER(object->Attribute[i].attributeID)) {
            if (object->Attribute[i].content.ref.buffer != NULL)
                rc = memset_s(object->Attribute[i].content.ref.buffer,
                              object->Attribute[i].content.ref.length,
                              0, object->Attribute[i].content.ref.length);
            if (rc != EOK) {
                tloge("memset failed\n");
                TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
            }
        } else {
            object->Attribute[i].content.value.a = 0;
            object->Attribute[i].content.value.b = 0;
        }
    }
    return;
}

static uint32_t g_aes_key_size[] = {128, 192, 256};
static TEE_Result check_valid_key_size_for_aes(uint32_t max_key_size)
{
    /* aes key can only be 128/192/256 bit */
    for (uint32_t i = 0; i < sizeof(g_aes_key_size) / sizeof(g_aes_key_size[0]); i++) {
        if (max_key_size == g_aes_key_size[i])
            return TEE_SUCCESS;
    }

    return TEE_ERROR_NOT_SUPPORTED;
}

static TEE_Result check_valid_key_size_for_rsa(uint32_t max_key_size)
{
    if (max_key_size >= RSA_KEY_MIN && max_key_size <= RSA_KEY_MAX &&
        max_key_size % RSA_KEY_BLOCK == 0)
        return TEE_SUCCESS;
    return TEE_ERROR_NOT_SUPPORTED;
}

static uint32_t g_ec_key_size[] = {224, 256, 384, 521};
static TEE_Result check_valid_key_size_for_ec(uint32_t max_key_size)
{
    /* ec key can only be 224/256/384/521 bit */
    for (uint32_t i = 0; i < sizeof(g_ec_key_size) / sizeof(g_ec_key_size[0]); i++) {
        if (max_key_size == g_ec_key_size[i])
            return TEE_SUCCESS;
    }

    return TEE_ERROR_NOT_SUPPORTED;
}

static TEE_Result check_valid_key_size_for_pbkdf2(uint32_t max_key_size)
{
    if (max_key_size >= PBKDF2_MIN_KEY_SIZE * BIT_TO_BYTE && max_key_size <= PBKDF2_MAX_KEY_SIZE * BIT_TO_BYTE)
        return TEE_SUCCESS;
    return TEE_ERROR_NOT_SUPPORTED;
}

static TEE_Result check_valid_key_size_for_dh(uint32_t max_key_size)
{
    if (max_key_size >= DH_MIN_KEY_SIZE_IN_BIT && max_key_size <= DH_MAX_KEY_SIZE_IN_BIT &&
        max_key_size % DH_BLOCK_SIZE == 0)
        return TEE_SUCCESS;
    return TEE_ERROR_NOT_SUPPORTED;
}

typedef TEE_Result (*obj_key_size_check)(uint32_t max_key_size);

struct object_key_size_s {
    uint32_t type;
    obj_key_size_check check_key_size_func;
};

static const struct object_key_size_s g_object_key_size[] = {
    { TEE_TYPE_AES, check_valid_key_size_for_aes },
    { TEE_TYPE_RSA_PUBLIC_KEY, check_valid_key_size_for_rsa },
    { TEE_TYPE_RSA_KEYPAIR, check_valid_key_size_for_rsa },
    { TEE_TYPE_ECDSA_PUBLIC_KEY, check_valid_key_size_for_ec },
    { TEE_TYPE_ECDSA_KEYPAIR, check_valid_key_size_for_ec },
    { TEE_TYPE_DH_KEYPAIR, check_valid_key_size_for_dh },
    { TEE_TYPE_ECDH_PUBLIC_KEY, check_valid_key_size_for_ec },
    { TEE_TYPE_ECDH_KEYPAIR, check_valid_key_size_for_ec },
    { TEE_TYPE_PBKDF2_HMAC, check_valid_key_size_for_pbkdf2 },
};

static TEE_Result check_max_object_size(uint32_t object_type, uint32_t max_object_size)
{
    for (uint32_t i = 0; i < ELEM_NUM(g_object_key_size); i++) {
        if (object_type == g_object_key_size[i].type)
            return g_object_key_size[i].check_key_size_func(max_object_size);
    }

    if ((max_object_size % BIT_TO_BYTE) != 0) {
        tloge("maxObjectSize is invalid! maxObjectSize = %u", max_object_size);
        return TEE_ERROR_NOT_SUPPORTED;
    }

    if (object_type == TEE_TYPE_ED25519_KEYPAIR && (max_object_size / BIT_TO_BYTE) != OBJ_SIZE_ED25519_KEY_PAIR) {
        tloge("ED25519 maxObjectSize is invalid! maxObjectSize = %u", max_object_size);
        return TEE_ERROR_NOT_SUPPORTED;
    }

    if (object_type == TEE_TYPE_SIP_HASH && (max_object_size / BIT_TO_BYTE) != OBJ_SIZE_SIP_HASH) {
        tloge("sip hash maxObjectSize is invalid! maxObjectSize = %u", max_object_size);
        return TEE_ERROR_NOT_SUPPORTED;
    }

    return TEE_SUCCESS;
}

static TEE_Result check_param_allocatetransientobject(uint32_t type, uint32_t *object_size,
    const TEE_ObjectHandle *object, uint32_t *api_level)
{
    TEE_Result ret = TEE_SUCCESS;
    if (object == NULL) {
        tloge("TEE_AllocateTransientObject:bad object parameter!\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (type == TEE_TYPE_DATA)
        return TEE_SUCCESS;

    *api_level = tee_get_ta_api_level();
    if (*api_level > API_LEVEL1_0) {
        ret = check_max_object_size(type, *object_size);
        if (ret != TEE_SUCCESS) {
            tloge("maxObjectsize is Invalid\n");
            return ret;
        }
        /* maxObjectSize is byte now */
        *object_size = (*object_size + BIT_NUMBER_SEVEN) >> BIT_TO_BYTE_MOVE_THREE;
    }

    uint32_t min_object_size = get_object_size(type);
    if (*object_size < min_object_size) {
        tloge("maxObjectsize is too small\n");
        return TEE_ERROR_NOT_SUPPORTED;
    }

    if (*object_size > MAX_KEY_SIZE) {
        tloge("maxObjectsize is too big\n");
        return TEE_ERROR_NOT_SUPPORTED;
    }

    return ret;
}

static TEE_Result ae_attribute_alloc(uint32_t api_level, TEE_ObjectHandle *object, uint32_t attrc)
{
    return allocate_attribute(api_level, object, attrc, TEE_ATTR_SECRET_VALUE);
}

static TEE_Result rsa_pub_key_alloc(uint32_t api_level, TEE_ObjectHandle *object, uint32_t attrc)
{
    return allocate_attribute(api_level, object, attrc, TEE_ATTR_RSA_MODULUS, TEE_ATTR_RSA_PUBLIC_EXPONENT);
}

static TEE_Result rsa_keypair_alloc(uint32_t api_level, TEE_ObjectHandle *object, uint32_t attrc)
{
    return allocate_attribute(api_level, object, attrc,
                              TEE_ATTR_RSA_MODULUS,
                              TEE_ATTR_RSA_PUBLIC_EXPONENT,
                              TEE_ATTR_RSA_PRIVATE_EXPONENT,
                              TEE_ATTR_RSA_PRIME1,
                              TEE_ATTR_RSA_PRIME2,
                              TEE_ATTR_RSA_EXPONENT1,
                              TEE_ATTR_RSA_EXPONENT2,
                              TEE_ATTR_RSA_COEFFICIENT);
}

static TEE_Result dh_keypair_alloc(uint32_t api_level, TEE_ObjectHandle *object, uint32_t attrc)
{
    return allocate_attribute(api_level, object, attrc,
                              TEE_ATTR_DH_PRIME,
                              TEE_ATTR_DH_BASE,
                              TEE_ATTR_DH_PUBLIC_VALUE,
                              TEE_ATTR_DH_PRIVATE_VALUE,
                              TEE_ATTR_DH_SUBPRIME,
                              TEE_ATTR_DH_X_BITS);
}

static TEE_Result dsa_attribute_alloc(uint32_t api_level, TEE_ObjectHandle *object, uint32_t attrc)
{
    (void)api_level;
    (void)object;
    (void)attrc;
    tloge("Allocate memory for DSA.Not supported\n");
    return TEE_ERROR_NOT_SUPPORTED;
}

static TEE_Result ec_pub_key_alloc(uint32_t api_level, TEE_ObjectHandle *object, uint32_t attrc)
{
    return allocate_attribute(api_level, object, attrc,
                              TEE_ATTR_ECC_PUBLIC_VALUE_X,
                              TEE_ATTR_ECC_PUBLIC_VALUE_Y,
                              TEE_ATTR_ECC_CURVE);
}

static TEE_Result ec_keypair_alloc(uint32_t api_level, TEE_ObjectHandle *object, uint32_t attrc)
{
    return allocate_attribute(api_level, object, attrc,
                              TEE_ATTR_ECC_PUBLIC_VALUE_X,
                              TEE_ATTR_ECC_PUBLIC_VALUE_Y,
                              TEE_ATTR_ECC_PRIVATE_VALUE,
                              TEE_ATTR_ECC_CURVE);
}

static TEE_Result ed25519_keypair_alloc(uint32_t api_level, TEE_ObjectHandle *object, uint32_t attrc)
{
    return allocate_attribute(api_level, object, attrc,
                              TEE_ATTR_ED25519_PUBLIC_VALUE,
                              TEE_ATTR_ED25519_PRIVATE_VALUE);
}

static TEE_Result ed25519_pub_key_alloc(uint32_t api_level, TEE_ObjectHandle *object, uint32_t attrc)
{
    return allocate_attribute(api_level, object, attrc, TEE_ATTR_ED25519_PUBLIC_VALUE);
}

static TEE_Result x25519_keypair_alloc(uint32_t api_level, TEE_ObjectHandle *object, uint32_t attrc)
{
    return allocate_attribute(api_level, object, attrc,
                              TEE_ATTR_X25519_PUBLIC_VALUE,
                              TEE_ATTR_X25519_PRIVATE_VALUE);
}

static TEE_Result x25519_pub_key_alloc(uint32_t api_level, TEE_ObjectHandle *object, uint32_t attrc)
{
    return allocate_attribute(api_level, object, attrc, TEE_ATTR_X25519_PUBLIC_VALUE);
}

static TEE_Result sm2_pub_key_alloc(uint32_t api_level, TEE_ObjectHandle *object, uint32_t attrc)
{
    return allocate_attribute(api_level, object, attrc,
                              TEE_ATTR_ECC_PUBLIC_VALUE_X,
                              TEE_ATTR_ECC_PUBLIC_VALUE_Y,
                              TEE_ATTR_ECC_CURVE);
}

static TEE_Result sm2_keypair_alloc(uint32_t api_level, TEE_ObjectHandle *object, uint32_t attrc)
{
    return allocate_attribute(api_level, object, attrc,
                              TEE_ATTR_ECC_PUBLIC_VALUE_X,
                              TEE_ATTR_ECC_PUBLIC_VALUE_Y,
                              TEE_ATTR_ECC_PRIVATE_VALUE,
                              TEE_ATTR_ECC_CURVE);
}

static TEE_Result data_attribute_alloc(uint32_t api_level, TEE_ObjectHandle *object, uint32_t attrc)
{
    (void)api_level;
    (void)object;
    (void)attrc;
    tlogd("Object type %u need no key.\n", (*object)->ObjectInfo->objectType);
    return TEE_SUCCESS;
}

static const struct attr_mem_alloc_t g_attr_mem_tal[] = {
    { TEE_TYPE_AES,                ae_attribute_alloc },
    { TEE_TYPE_DES,                ae_attribute_alloc },
    { TEE_TYPE_DES3,               ae_attribute_alloc },
    { TEE_TYPE_SM4,                ae_attribute_alloc },
    { TEE_TYPE_HMAC_SM3,           ae_attribute_alloc },
    { TEE_TYPE_HMAC_MD5,           ae_attribute_alloc },
    { TEE_TYPE_HMAC_SHA1,          ae_attribute_alloc },
    { TEE_TYPE_HMAC_SHA224,        ae_attribute_alloc },
    { TEE_TYPE_HMAC_SHA256,        ae_attribute_alloc },
    { TEE_TYPE_HMAC_SHA384,        ae_attribute_alloc },
    { TEE_TYPE_HMAC_SHA512,        ae_attribute_alloc },
    { TEE_TYPE_GENERIC_SECRET,     ae_attribute_alloc },
    { TEE_TYPE_PBKDF2_HMAC,        ae_attribute_alloc },
    { TEE_TYPE_SIP_HASH,           ae_attribute_alloc },
    { TEE_TYPE_RSA_PUBLIC_KEY,     rsa_pub_key_alloc },
    { TEE_TYPE_RSA_KEYPAIR,        rsa_keypair_alloc },
    { TEE_TYPE_DH_KEYPAIR,         dh_keypair_alloc },
    { TEE_TYPE_DSA_PUBLIC_KEY,     dsa_attribute_alloc },
    { TEE_TYPE_DSA_KEYPAIR,        dsa_attribute_alloc },
    { TEE_TYPE_ECDSA_PUBLIC_KEY,   ec_pub_key_alloc },
    { TEE_TYPE_ECDH_PUBLIC_KEY,    ec_pub_key_alloc },
    { TEE_TYPE_ECDSA_KEYPAIR,      ec_keypair_alloc },
    { TEE_TYPE_ECDH_KEYPAIR,       ec_keypair_alloc },
    { TEE_TYPE_ED25519_KEYPAIR,    ed25519_keypair_alloc },
    { TEE_TYPE_ED25519_PUBLIC_KEY, ed25519_pub_key_alloc },
    { TEE_TYPE_X25519_KEYPAIR,     x25519_keypair_alloc },
    { TEE_TYPE_X25519_PUBLIC_KEY,  x25519_pub_key_alloc },
    { TEE_TYPE_SM2_DSA_PUBLIC_KEY, sm2_pub_key_alloc },
    { TEE_TYPE_SM2_PKE_PUBLIC_KEY, sm2_pub_key_alloc },
    { TEE_TYPE_SM2_KEP_PUBLIC_KEY, sm2_pub_key_alloc },
    { TEE_TYPE_SM2_DSA_KEYPAIR,    sm2_keypair_alloc },
    { TEE_TYPE_SM2_PKE_KEYPAIR,    sm2_keypair_alloc },
    { TEE_TYPE_SM2_KEP_KEYPAIR,    sm2_keypair_alloc },
    { TEE_TYPE_DATA,               data_attribute_alloc },
    { TEE_TYPE_DATA_GP1_1,         data_attribute_alloc },
};

static TEE_Result alloc_attr_mem(uint32_t object_type, TEE_ObjectHandle *object,
                                 uint32_t attrc, uint32_t api_level)
{
    TEE_Result ret;
    uint32_t num = sizeof(g_attr_mem_tal) / sizeof(g_attr_mem_tal[0]);
    for (uint32_t i = 0; i < num; i++) {
        if (object_type == g_attr_mem_tal[i].obj_type) {
            ret = g_attr_mem_tal[i].fn(api_level, object, attrc);
            if (ret != TEE_SUCCESS) {
                tloge("Failed to allocate transient object, ret 0x%x\n", ret);
                (void)tee_obj_free(object);
            }
            return ret;
        }
    }

    tloge("Object type unsupported %u.\n", object_type);
    (void)tee_obj_free(object);
    TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
    return TEE_ERROR_NOT_SUPPORTED;
}

static TEE_Result check_alg_compliance(uint32_t obj_type, uint32_t key_size)
{
    uint32_t api_level = tee_get_ta_api_level();
    if (api_level == API_LEVEL1_0)
        key_size *= BIT_TO_BYTE;

    if (check_if_unsafe_type(obj_type, key_size) != TEE_SUCCESS) {
        tloge("object type 0x%x is unsafe and not support\n", obj_type);
        return TEE_ERROR_NOT_SUPPORTED;
    }

    return TEE_SUCCESS;
}

TEE_Result TEE_AllocateTransientObject(
    uint32_t objectType,
    uint32_t maxObjectSize,     /* here should be maxKeySize */
    TEE_ObjectHandle *object)
{
    uint32_t attrc;
    TEE_Result ret;
    uint32_t api_level;

    bool check = crypto_object_type_supported(objectType);
    if (!check) {
        tloge("object type 0x%x is not supported!", objectType);
        return TEE_ERROR_NOT_SUPPORTED;
    }

    if (check_alg_compliance(objectType, maxObjectSize) != TEE_SUCCESS)
        return TEE_ERROR_NOT_SUPPORTED;

    ret = check_param_allocatetransientobject(objectType, &maxObjectSize, object, &api_level);
    if (ret != TEE_SUCCESS) {
        tloge("bad object parameter!\n");
        return ret;
    }

    if (tee_obj_new(object) != TEE_SUCCESS) {
        tloge("not available to allocate the object handle\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    attrc = get_attr_count_for_object_type(objectType);
#ifndef GP_SUPPORT
    (*object)->ObjectInfo->maxObjectSize = maxObjectSize;
#else
    (*object)->ObjectInfo->maxKeySize = maxObjectSize;
#endif
    (*object)->ObjectInfo->objectType = objectType;

    /* allocate memory for TEE_Attribute */
    ret = alloc_attr_mem(objectType, object, attrc, api_level);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to allocate transient object, ret 0x%x\n", ret);
        return ret;
    }
    /* an uninitialized transient object */
    transient_object_uninitialized_state(*object, objectType, maxObjectSize);

    ret = add_object(*object);
    if (ret != TEE_SUCCESS) {
        tloge("insert new object to list failed\n");
        free_attribute(*object, attrc);
        (void)tee_obj_free(object);
        TEE_Panic(TEE_ERROR_GENERIC);
        return TEE_ERROR_GENERIC;
    }
    (*object)->generate_flag = crypto_get_default_generate_key_engine(objectType);

    return TEE_SUCCESS;
}

static void tee_free_attribute(TEE_ObjectHandle object, uint32_t attrc)
{
    switch (object->ObjectInfo->objectType) {
    case (uint32_t)TEE_TYPE_DATA:
    case (uint32_t)TEE_TYPE_DATA_GP1_1:
        tlogd("TEE_FreeTransientObject:data object type!\n");
        break;
    case (uint32_t)TEE_TYPE_AES:
    case (uint32_t)TEE_TYPE_DES:
    case (uint32_t)TEE_TYPE_DES3:
    case (uint32_t)TEE_TYPE_HMAC_MD5:
    case (uint32_t)TEE_TYPE_HMAC_SHA1:
    case (uint32_t)TEE_TYPE_HMAC_SHA224:
    case (uint32_t)TEE_TYPE_HMAC_SHA256:
    case (uint32_t)TEE_TYPE_HMAC_SHA384:
    case (uint32_t)TEE_TYPE_HMAC_SHA512:
    case (uint32_t)TEE_TYPE_GENERIC_SECRET:
    case (uint32_t)TEE_TYPE_DH_KEYPAIR:
    case (uint32_t)TEE_TYPE_RSA_PUBLIC_KEY:
    case (uint32_t)TEE_TYPE_RSA_KEYPAIR:
    case (uint32_t)TEE_TYPE_ECDSA_PUBLIC_KEY:
    case (uint32_t)TEE_TYPE_ECDSA_KEYPAIR:
    case (uint32_t)TEE_TYPE_ECDH_PUBLIC_KEY:
    case (uint32_t)TEE_TYPE_ECDH_KEYPAIR:
    case (uint32_t)TEE_TYPE_ED25519_PUBLIC_KEY:
    case (uint32_t)TEE_TYPE_ED25519_KEYPAIR:
    case (uint32_t)TEE_TYPE_X25519_PUBLIC_KEY:
    case (uint32_t)TEE_TYPE_X25519_KEYPAIR:
    case (uint32_t)TEE_TYPE_SM4:
    case (uint32_t)TEE_TYPE_HMAC_SM3:
    case (uint32_t)TEE_TYPE_SM2_DSA_PUBLIC_KEY:
    case (uint32_t)TEE_TYPE_SM2_KEP_PUBLIC_KEY:
    case (uint32_t)TEE_TYPE_SM2_PKE_PUBLIC_KEY:
    case (uint32_t)TEE_TYPE_SM2_DSA_KEYPAIR:
    case (uint32_t)TEE_TYPE_SM2_KEP_KEYPAIR:
    case (uint32_t)TEE_TYPE_SM2_PKE_KEYPAIR:
    case (uint32_t)TEE_TYPE_SIP_HASH:
    case (uint32_t)TEE_TYPE_PBKDF2_HMAC:
    /* free DSA attributes */
    case (uint32_t)TEE_TYPE_DSA_PUBLIC_KEY:
    case (uint32_t)TEE_TYPE_DSA_KEYPAIR:
        free_attribute(object, attrc);
        break;
    default:
        tloge("TEE_FreeTransientObject:not supported object type , 0x%x\n", object->ObjectInfo->objectType);
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        break;
    }
}

void TEE_FreeTransientObject(TEE_ObjectHandle object)
{
    uint32_t attrc;

    /* Make sure the object is not persistent object */
    if (object == NULL)
        return;

    if (check_object(object) != TEE_SUCCESS) {
        tloge("object is invalid\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }
    if (object->ObjectInfo == NULL) {
        tloge("objectInfo in obj is invalid\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }
    if (TEE_HANDLE_FLAG_PERSISTENT ==
        (object->ObjectInfo->handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
        tloge("obj is persistent\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    attrc = get_attr_count_for_object_type(object->ObjectInfo->objectType);

    /* free TEE_Attribute */
    tee_free_attribute(object, attrc);

    tlogd("we will remove the obj in list\n");
    if (delete_object(object)) {
        tloge("TEE_FreeTransientObject: delete_object failed.\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
    }

    /* free TEE_ObjectInfo */
    if (tee_obj_free(&object)) {
        tloge("TEE_FreeTransientObject: tee_obj_free failed.\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
    }

#ifdef OPENSSL_ENABLE
    tee_crypto_free_openssl_drbg();
#endif
    tlogd("TEE_FreeTransientObject end!\n");
    return;
}

void TEE_ResetTransientObject(TEE_ObjectHandle object)
{
    tlogd("TEE_ResetTransientObject start!\n");

    /* Check the validation of input param */
    /* Make sure the object is not persistent object */
    if (object == NULL)
        return;

    if (check_object(object) != TEE_SUCCESS) {
        tloge("object is invalid\n");
        return;
    }
    if (object->ObjectInfo == NULL) {
        tloge("objectInfo in obj is invalid\n");
        return;
    }
    if (TEE_HANDLE_FLAG_PERSISTENT ==
        (object->ObjectInfo->handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
        tloge("obj is persistent\n");
        return;
    }

    if (object->Attribute != NULL) {
        tlogd("reset transient object\n");

    uint32_t api_level = tee_get_ta_api_level();
    if (api_level > API_LEVEL1_0) {
#ifndef GP_SUPPORT
        object->Attribute->content.ref.length = object->ObjectInfo->maxObjectSize;
#else
        object->Attribute->content.ref.length = object->ObjectInfo->maxKeySize;
#endif
    } else {
        object->Attribute->content.ref.length = object_max_size_of_object_type(
            object->ObjectInfo->objectType, (uint32_t)TEE_ATTR_SECRET_VALUE);
    }

        transient_object_uninitialized_state(
            object,
            object->ObjectInfo->objectType,
#ifndef GP_SUPPORT
            object->ObjectInfo->maxObjectSize);
#else
            object->ObjectInfo->maxKeySize);
#endif
    }
}

static TEE_Result check_attr_id_exist(const TEE_Attribute *attrs, uint32_t attr_count, uint32_t attr_id)
{
    uint32_t index;

    for (index = 0; index < attr_count; index++) {
        if (attrs[index].attributeID == attr_id)
            return TEE_SUCCESS;
    }

    return TEE_ERROR_BAD_PARAMETERS;
}

static TEE_Result check_attr(const TEE_ObjectHandle object, const TEE_Attribute *attrs, uint32_t attr_count,
    uint32_t api_level)
{
    const struct obj_attr_conf_s *config = NULL;
    uint32_t index;
    TEE_Result ret;

    if (object == NULL || object->ObjectInfo == NULL || attrs == NULL || attr_count == 0) {
        tloge("invalid input");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    config = get_object_attr_conf(object);

    for (index = 0; (config != NULL) && (index < config->min_attr_count); index++) {
        if (api_level > API_LEVEL1_0) {
            bool check = ((object->ObjectInfo->objectType == TEE_TYPE_RSA_KEYPAIR) &&
                (attr_count != config->max_attr_count) && (attr_count != config->min_attr_count));
            if (check) {
                tloge("RSA key pair need 3 or 8 attrs!");
                return TEE_ERROR_BAD_PARAMETERS;
            }
        }
        ret = check_attr_id_exist(attrs, attr_count, config->min_attr_array[index]);
        if (ret != TEE_SUCCESS) {
            tloge("Specified attribute ID: 0x%x doesn't exist\n", config->min_attr_array[index]);
            return ret;
        }
    }

    return TEE_SUCCESS;
}

static TEE_Result check_3des_key(const TEE_Attribute *attrs)
{
    char *key1 = attrs->content.ref.buffer;
    char *key2 = key1 + DES_BLOCK;
    char *key3 = key2 + DES_BLOCK;
    int32_t rc = TEE_MemCompare(key1, key2, DES_BLOCK);
    if (rc == 0) {
        tloge("des key1 is equal to key2!");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    rc = TEE_MemCompare(key2, key3, DES_BLOCK);
    if (rc == 0) {
        tloge("des key2 is equal to key3!");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    rc = TEE_MemCompare(key1, key3, DES_BLOCK);
    if (rc == 0) {
        tloge("des key1 is equal to key3!");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result check_populate_object_size(uint32_t api_level, uint32_t object_type,
    uint32_t attr, uint32_t object_size)
{
    TEE_Result ret;
    if (api_level <= API_LEVEL1_0)
        return TEE_SUCCESS;

    switch (object_type) {
    case TEE_TYPE_ECDSA_PUBLIC_KEY:
    case TEE_TYPE_ECDSA_KEYPAIR:
    case TEE_TYPE_ECDH_PUBLIC_KEY:
    case TEE_TYPE_ECDH_KEYPAIR:
        if (object_size == OBJ_MAX_SIZE_ECDSA_PUB_KEY)
            return TEE_SUCCESS;
        break;
    case TEE_TYPE_RSA_PUBLIC_KEY:
    case TEE_TYPE_RSA_KEYPAIR:
        if ((attr != TEE_ATTR_RSA_MODULUS))
            return TEE_SUCCESS;
        break;
    default:
        break;
    }

    if (object_size > (UINT32_MAX / BIT_TO_BYTE)) {
        tloge("object_size is too large!");
        return TEE_ERROR_NOT_SUPPORTED;
    }

    uint32_t temp_size = object_size * BIT_TO_BYTE;
    for (uint32_t i = 0; i < ELEM_NUM(g_object_key_size); i++) {
        if (object_type != g_object_key_size[i].type)
            continue;
        ret = g_object_key_size[i].check_key_size_func(temp_size);
        if (ret != TEE_SUCCESS)
            return ret;
    }

    bool check = ((object_size > object_max_size_of_object_type(object_type, attr)) ||
                  (check_object_min_size(object_type, attr, object_size) != TEE_SUCCESS));
    if (check) {
        tloge("attrs.content.ref.length is too small\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

static TEE_Result populate_trasient_object(TEE_ObjectHandle object, uint32_t count,
    const TEE_Attribute *attrs, uint32_t attr_count, bool function)
{
    bool attribute_flag = false;
    uint32_t api_level = tee_get_ta_api_level();

    TEE_Result ret = check_attr(object, attrs, attr_count, api_level);
    if (ret != TEE_SUCCESS)
        return ret;

    /* Populate the attrs to object */
    for (uint32_t j = 0; j < attr_count; j++) { /* attrs */
        attribute_flag = false;
        for (uint32_t i = 0; i < count; i++) { /* object */
            if (object->Attribute[i].attributeID != attrs[j].attributeID)
                continue;

            attribute_flag = true;
            if (!TEE_ATTR_IS_BUFFER(object->Attribute[i].attributeID)) {
                /* value attribute */
                object->Attribute[i].content.value.a = attrs[j].content.value.a;
                object->Attribute[i].content.value.b = attrs[j].content.value.b;
                break;
            }
            if (attrs[j].content.ref.buffer == NULL)
                return TEE_ERROR_BAD_PARAMETERS;

            ret = check_populate_object_size(api_level, object->ObjectInfo->objectType, attrs[j].attributeID,
                attrs[j].content.ref.length);
            if (ret != TEE_SUCCESS)
                return ret;

            if (memmove_s(object->Attribute[i].content.ref.buffer, object->Attribute[i].content.ref.length,
                          attrs[j].content.ref.buffer, attrs[j].content.ref.length) != EOK)
                return TEE_ERROR_SECURITY;
            object->Attribute[i].content.ref.length = attrs[j].content.ref.length;
            break;
        }

        /*
         * function true  means populate, function false means copy
         * populate should ret error and
         * copy can return success
         */
        if ((api_level > API_LEVEL1_0)) {
            if ((!attribute_flag) && (function)) {
                tloge("attrs[%u].attributeID %u is invalid !", j, attrs[j].attributeID);
                return TEE_ERROR_BAD_PARAMETERS;
            }
        }
    }

    /* object is initialized */
    object->attributesLen = attr_count <= count ? attr_count : count;
    object->ObjectInfo->handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;
    return TEE_SUCCESS;
}

static TEE_Result populate_param_check(TEE_ObjectHandle object, const TEE_Attribute *attrs)
{
    bool check = (attrs == NULL || object == NULL);
    if (check) {
        tloge("invalid input param\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (check_object(object) != TEE_SUCCESS) {
        tloge("object is invalid\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    check = (object->ObjectInfo == NULL || object->Attribute == NULL);
    if (check) {
        tloge("invalid ObjectInfo or Attribute\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Make sure the object is not a persistent object */
    if ((object->ObjectInfo->handleFlags & TEE_HANDLE_FLAG_PERSISTENT) ==
        TEE_HANDLE_FLAG_PERSISTENT) {
        tloge("this is a Persistent Object, so not supported to Free\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return  TEE_ERROR_BAD_PARAMETERS;
    }
    if ((object->ObjectInfo->handleFlags & TEE_HANDLE_FLAG_INITIALIZED) ==
        TEE_HANDLE_FLAG_INITIALIZED) {
        tloge("object is not a uninitialized object, so should panic!\n ");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

TEE_Result TEE_PopulateTransientObject(TEE_ObjectHandle object, TEE_Attribute *attrs, uint32_t attrCount)
{
    TEE_Result ret;

    ret = populate_param_check(object, attrs);
    if (ret != TEE_SUCCESS)
        return ret;

    uint32_t count = get_attr_count_for_object_type(object->ObjectInfo->objectType);
    if (attrCount > count || attrCount == 0) {
        tloge("attrCount is wrong\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t api_level = tee_get_ta_api_level();
    bool check = (api_level > API_LEVEL1_0) && (object->ObjectInfo->objectType == TEE_TYPE_DES3);
    if (check) {
        if (attrs->content.ref.length != OBJ_SIZE_DES3) {
            tloge("3des key length is invalid!\n");
            return TEE_ERROR_BAD_PARAMETERS;
        }

        ret = check_3des_key(attrs);
        if (ret != TEE_SUCCESS) {
            tloge("attrs is not valid!\n");
            return ret;
        }
    }

    ret = populate_trasient_object(object, count, attrs, attrCount, true);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to populate trasient object.\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return ret;
    }

    return TEE_SUCCESS;
}

void TEE_InitRefAttribute(TEE_Attribute *attr, uint32_t attributeID, void *buffer, size_t length)
{
    if (buffer == NULL || attr == NULL || TEE_ATTR_IS_VALUE(attributeID)) {
        tloge("Invalid buffer and attr and attributeID\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }
    attr->attributeID = attributeID;
    attr->content.ref.length = length;
    attr->content.ref.buffer = buffer;
}

void TEE_InitValueAttribute(TEE_Attribute *attr, uint32_t attributeID, uint32_t a, uint32_t b)
{
    if (attr == NULL || TEE_ATTR_IS_BUFFER(attributeID)) {
        tloge("Invalid buffer and attr and attributeID\n");
        return;
    }

    attr->attributeID = attributeID;
    attr->content.value.a = a;
    attr->content.value.b = b;
}

static TEE_Result check_object_valid_panic(TEE_ObjectHandle object)
{
    if (object == TEE_HANDLE_NULL) {
        tloge("Bad Parameter:ObjectHandle is NULL!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (check_object(object) != TEE_SUCCESS) {
        tloge("Object is invalid\n");
#ifdef SUPPORT_GP_PANIC
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
#endif
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (object->ObjectInfo == NULL) {
        tloge("Object is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result copy_obj_attr1_check(TEE_ObjectHandle dest_object, TEE_ObjectHandle src_object)
{
    if (check_object_valid_panic(dest_object) != TEE_SUCCESS) {
        tloge("dest object is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (check_object_valid_panic(src_object) != TEE_SUCCESS) {
        tloge("src object is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    bool attribute_invalid = (dest_object->Attribute == NULL || src_object->Attribute == NULL);
    if (attribute_invalid) {
        tloge("Invalid dest Object Attribute or src Object Attribute\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* The source and destination objects must have compatible types */
    bool object_type_valid = (src_object->ObjectInfo->objectType == dest_object->ObjectInfo->objectType
                              || (src_object->ObjectInfo->objectType == (uint32_t)TEE_TYPE_RSA_KEYPAIR &&
                                  dest_object->ObjectInfo->objectType == (uint32_t)TEE_TYPE_RSA_PUBLIC_KEY)
                              || (src_object->ObjectInfo->objectType == (uint32_t)TEE_TYPE_DSA_KEYPAIR &&
                                  dest_object->ObjectInfo->objectType == (uint32_t)TEE_TYPE_DSA_PUBLIC_KEY)
                              || (src_object->ObjectInfo->objectType == (uint32_t)TEE_TYPE_ECDSA_KEYPAIR &&
                                  dest_object->ObjectInfo->objectType == (uint32_t)TEE_TYPE_ECDSA_PUBLIC_KEY)
                              || (src_object->ObjectInfo->objectType == (uint32_t)TEE_TYPE_ECDH_KEYPAIR &&
                                  dest_object->ObjectInfo->objectType == (uint32_t)TEE_TYPE_ECDH_PUBLIC_KEY)
                              || (src_object->ObjectInfo->objectType == (uint32_t)TEE_TYPE_ED25519_KEYPAIR &&
                                  dest_object->ObjectInfo->objectType == (uint32_t)TEE_TYPE_ED25519_PUBLIC_KEY)
                              || (src_object->ObjectInfo->objectType == (uint32_t)TEE_TYPE_X25519_KEYPAIR &&
                                  dest_object->ObjectInfo->objectType == (uint32_t)TEE_TYPE_X25519_PUBLIC_KEY)
                              || (src_object->ObjectInfo->objectType == (uint32_t)TEE_TYPE_SM2_DSA_KEYPAIR &&
                                  dest_object->ObjectInfo->objectType == (uint32_t)TEE_TYPE_SM2_DSA_PUBLIC_KEY)
                              || (src_object->ObjectInfo->objectType == (uint32_t)TEE_TYPE_SM2_KEP_KEYPAIR &&
                                  dest_object->ObjectInfo->objectType == (uint32_t)TEE_TYPE_SM2_KEP_PUBLIC_KEY)
                              || (src_object->ObjectInfo->objectType == (uint32_t)TEE_TYPE_SM2_PKE_KEYPAIR &&
                                  dest_object->ObjectInfo->objectType == (uint32_t)TEE_TYPE_SM2_PKE_PUBLIC_KEY));
    if (object_type_valid) {
        tlogd("The type of dest Object is a subtype of src Object.\n");
    } else {
        tloge("Invalid input param:The type of dest Object is a subtype of src Object.\n");
#ifdef SUPPORT_GP_PANIC
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
#endif
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

TEE_Result TEE_CopyObjectAttributes1(TEE_ObjectHandle destObject, TEE_ObjectHandle srcObject)
{
    TEE_Result ret = copy_obj_attr1_check(destObject, srcObject);
    if (ret != TEE_SUCCESS)
        return ret;

    /* Make sure destObject is uninitialized transient object and srdObject is initialized */
    if ((destObject->ObjectInfo->handleFlags & TEE_HANDLE_FLAG_INITIALIZED) == TEE_HANDLE_FLAG_INITIALIZED ||
        (destObject->ObjectInfo->handleFlags & TEE_HANDLE_FLAG_PERSISTENT) == TEE_HANDLE_FLAG_PERSISTENT ||
        (srcObject->ObjectInfo->handleFlags & TEE_HANDLE_FLAG_INITIALIZED) != TEE_HANDLE_FLAG_INITIALIZED) {
        tloge("destObject is an initialized object or src is an uninitialized object.\n");
#ifdef SUPPORT_GP_PANIC
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
#endif
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* The effect of this function on destObject
     * is identical to the function TEE_PopulateTransientObject
     * except that the attributes are taken from srcObject instead of from parameters. */
    TEE_Attribute *attrs = srcObject->Attribute;
    uint32_t attr_count = get_attr_count_for_object_type(srcObject->ObjectInfo->objectType);
    uint32_t dest_count = get_attr_count_for_object_type(destObject->ObjectInfo->objectType);
    if (dest_count == 0)
        return TEE_ERROR_BAD_PARAMETERS;

    ret = populate_trasient_object(destObject, dest_count, attrs, attr_count, false);
    if (ret != TEE_SUCCESS) {
        tloge("TEE_CopyObjectAttributes:Failed to TEE_PopulateTransientObject.\n");
        return ret;
    }

    destObject->CRTMode = srcObject->CRTMode;
    destObject->ObjectInfo->objectUsage &= srcObject->ObjectInfo->objectUsage;
    return TEE_SUCCESS;
}

static bool is_params_attribute_id_valid(uint32_t attribute_id, uint32_t params_index)
{
    uint32_t i                  = 0;
    uint32_t attribute_id_set[] = {
        TEE_ATTR_RSA_MODULUS,
        TEE_ATTR_RSA_PUBLIC_EXPONENT,
        TEE_ATTR_RSA_PRIVATE_EXPONENT,
        TEE_ATTR_RSA_PRIME1,
        TEE_ATTR_RSA_PRIME2,
        TEE_ATTR_RSA_EXPONENT1,
        TEE_ATTR_RSA_EXPONENT2,
        TEE_ATTR_RSA_COEFFICIENT,
    };
    uint32_t total_array_num = sizeof(attribute_id_set) / sizeof(uint32_t);
    for (; i < total_array_num; i++) {
        if (attribute_id_set[i] == attribute_id && i == params_index)
            return true;
    }

    return false;
}

TEE_Result check_rsa_key_params_valid(const TEE_Attribute *params, uint32_t attribute_count)
{
    if (params == NULL) {
        tloge("The params is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (attribute_count > RSA_KEY_PAIR_ATTRIBUTE_COUNT) {
        tloge("The attributes count is invalid, attributes_count=0x%x\n", attribute_count);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t i = (attribute_count == RSA_CRT_KEY_ATTRIBUTE_COUNT) ? RSA_CRT_KEY_BASE_INDEX : 0;
    for (; i < attribute_count; i++) {
        if (params[i].content.ref.buffer == NULL || !(is_params_attribute_id_valid(params[i].attributeID, i))) {
            tloge("Attribute param is not valid, attribute_type=0x%x\n", params[i].attributeID);
            return TEE_ERROR_BAD_PARAMETERS;
        }
    }

    return TEE_SUCCESS;
}

static TEE_Result builed_dh_generator(struct dh_key_t *dh_generate_key_data, const TEE_Attribute *params,
    uint32_t param_count)
{
    int32_t index = get_attr_index_by_id(TEE_ATTR_DH_PRIME, params, param_count);
    int32_t index_2 = get_attr_index_by_id(TEE_ATTR_DH_BASE, params, param_count);
    if (index < 0 || index_2 < 0) {
        tloge("dh param is invalid");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    dh_generate_key_data->prime = (uint64_t)(uintptr_t)params[index].content.ref.buffer;
    dh_generate_key_data->prime_size = params[index].content.ref.length;
    dh_generate_key_data->generator = (uint64_t)(uintptr_t)params[index_2].content.ref.buffer;
    dh_generate_key_data->generator_size = params[index_2].content.ref.length;

    index = get_attr_index_by_id(TEE_ATTR_DH_SUBPRIME, params, param_count);
    if (index >= 0) {
        dh_generate_key_data->dh_param.generate_key_t.q =  (uint64_t)(uintptr_t)params[index].content.ref.buffer;
        dh_generate_key_data->dh_param.generate_key_t.q_size =  params[index].content.ref.length;
    }

    index = get_attr_index_by_id(TEE_ATTR_DH_X_BITS, params, param_count);
    if (index < 0) {
        tloge("dh param is invalid");
        return TEE_ERROR_BAD_PARAMETERS;
    } else if (params[index].content.value.a < DH_MIN_L) {
        tloge("the parameter L should >= %d\n", DH_MIN_L);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    dh_generate_key_data->dh_param.generate_key_t.l = params[index].content.value.a;
    dh_generate_key_data->dh_param.generate_key_t.dh_mode = DH_PKCS3_MODE;
    return TEE_SUCCESS;
}

static TEE_Result copy_single_key_to_object(TEE_ObjectHandle object, uint32_t id, const uint8_t *key, uint32_t key_len)
{
    int32_t index = get_attr_index_by_id(id, object->Attribute, object->attributesLen);
    if (index < 0 || object->Attribute[index].content.ref.length < key_len) {
        tloge("object is invalid");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    errno_t res = memcpy_s(object->Attribute[index].content.ref.buffer, object->Attribute[index].content.ref.length,
        key, key_len);
    if (res != EOK) {
        tloge("memcpy failed");
        return TEE_ERROR_SECURITY;
    }
    object->Attribute[index].content.ref.length = key_len;
    return TEE_SUCCESS;
}

static TEE_Result convert_dh_keypair_to_object(TEE_ObjectHandle object, const struct memref_t *pub_key,
    const struct memref_t *priv_key, const TEE_Attribute *params, uint32_t param_count)
{
    int32_t index = get_attr_index_by_id(TEE_ATTR_DH_X_BITS, params, param_count);
    if (index < 0)
        return TEE_ERROR_BAD_PARAMETERS;

    int32_t index_2 = get_attr_index_by_id(TEE_ATTR_DH_X_BITS, object->Attribute, object->attributesLen);
    if (index_2 < 0)
        return TEE_ERROR_BAD_PARAMETERS;

    object->Attribute[index_2].content.value.a = params[index].content.value.a;

    index = get_attr_index_by_id(TEE_ATTR_DH_PRIME, params, param_count);
    if (index < 0)
        return TEE_ERROR_BAD_PARAMETERS;

    TEE_Result ret = copy_single_key_to_object(object, TEE_ATTR_DH_PRIME,
        (const uint8_t *)params[index].content.ref.buffer,  params[index].content.ref.length);
    if (ret != TEE_SUCCESS) {
        tloge("copy dh prime failed");
        return ret;
    }

    index = get_attr_index_by_id(TEE_ATTR_DH_BASE, params, param_count);
    if (index < 0)
        return TEE_ERROR_BAD_PARAMETERS;

    ret = copy_single_key_to_object(object, TEE_ATTR_DH_BASE,
        (const uint8_t *)params[index].content.ref.buffer,  params[index].content.ref.length);
    if (ret != TEE_SUCCESS) {
        tloge("copy dh base failed");
        return ret;
    }

    ret = copy_single_key_to_object(object, TEE_ATTR_DH_PUBLIC_VALUE,
        (const uint8_t *)(uintptr_t)(pub_key->buffer), pub_key->size);
    if (ret != TEE_SUCCESS) {
        tloge("copy dh public failed");
        return ret;
    }

    ret = copy_single_key_to_object(object, TEE_ATTR_DH_PRIVATE_VALUE,
        (const uint8_t *)(uintptr_t)(priv_key->buffer), priv_key->size);
    if (ret != TEE_SUCCESS) {
        tloge("copy dh private failed");
        return ret;
    }

    return TEE_SUCCESS;
}

static TEE_Result generate_dh_keypair_hal(TEE_ObjectHandle object, const TEE_Attribute *params, uint32_t param_count)
{
    if (param_count < DH_PARAM_COUNT)
        return TEE_ERROR_BAD_PARAMETERS;

    struct dh_key_t dh_generate_key_data = {0};
    struct memref_t pub_key = {0};
    struct memref_t priv_key = {0};

    pub_key.buffer = (uint64_t)(uintptr_t)TEE_Malloc(DH_MAX_KEY_SIZE, 0);
    if (pub_key.buffer == 0) {
        tloge("malloc dh key failed");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    priv_key.buffer = (uint64_t)(uintptr_t)TEE_Malloc(DH_MAX_KEY_SIZE, 0);
    if (priv_key.buffer == 0) {
        tloge("malloc dh key failed");
        TEE_Free((void *)(uintptr_t)(pub_key.buffer));
        pub_key.buffer = 0;
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    pub_key.size = DH_MAX_KEY_SIZE;
    priv_key.size = DH_MAX_KEY_SIZE;
    TEE_Result ret = builed_dh_generator(&dh_generate_key_data, params, param_count);
    if (ret != TEE_SUCCESS) {
        tloge("builed dh generator failed");
        goto free_key;
    }

    int32_t rc = tee_crypto_dh_generate_key(&dh_generate_key_data, &pub_key, &priv_key, object->generate_flag);
    if (rc != TEE_SUCCESS) {
        tloge("generate dh keypair failed");
        ret = change_hal_ret_to_gp(rc);
        goto free_key;
    }

    ret = convert_dh_keypair_to_object(object, &pub_key, &priv_key, params, param_count);

free_key:
    TEE_Free((void *)(uintptr_t)pub_key.buffer);
    pub_key.buffer = 0;

    (void)memset_s((void *)(uintptr_t)priv_key.buffer, DH_MAX_KEY_SIZE, 0x0, DH_MAX_KEY_SIZE);
    TEE_Free((void *)(uintptr_t)priv_key.buffer);
    priv_key.buffer = 0;
    return ret;
}

static TEE_Result copy_public_key_to_object(TEE_ObjectHandle object, const struct rsa_priv_key_t *keypair)
{
    TEE_Result ret;

    /* copy rsa modulus */
    ret = copy_single_key_to_object(object, TEE_ATTR_RSA_MODULUS, keypair->n, keypair->n_len);
    if (ret != TEE_SUCCESS)
        return ret;

    /* copy rsa public exponent */
    ret = copy_single_key_to_object(object, TEE_ATTR_RSA_PUBLIC_EXPONENT, keypair->e, keypair->e_len);
    if (ret != TEE_SUCCESS)
        return ret;

    return TEE_SUCCESS;
}

static TEE_Result copy_private_key_to_object(TEE_ObjectHandle object, const struct rsa_priv_key_t *keypair)
{
    return copy_single_key_to_object(object, TEE_ATTR_RSA_PRIVATE_EXPONENT, keypair->d, keypair->d_len);
}

static TEE_Result copy_private_key_to_object_crt(TEE_ObjectHandle object, const struct rsa_priv_key_t *keypair)
{
    TEE_Result ret;

    ret = copy_single_key_to_object(object, TEE_ATTR_RSA_PRIME1, keypair->p, keypair->p_len);
    if (ret != TEE_SUCCESS)
        return ret;

    ret = copy_single_key_to_object(object, TEE_ATTR_RSA_PRIME2, keypair->q, keypair->q_len);
    if (ret != TEE_SUCCESS)
        return ret;

    ret = copy_single_key_to_object(object, TEE_ATTR_RSA_EXPONENT1, keypair->dp, keypair->dp_len);
    if (ret != TEE_SUCCESS)
        return ret;

    ret = copy_single_key_to_object(object, TEE_ATTR_RSA_EXPONENT2, keypair->dq, keypair->dq_len);
    if (ret != TEE_SUCCESS)
        return ret;

    ret = copy_single_key_to_object(object, TEE_ATTR_RSA_COEFFICIENT, keypair->qinv, keypair->qinv_len);
    if (ret != TEE_SUCCESS)
        return ret;

    return TEE_SUCCESS;
}

static TEE_Result generate_rsa_keypair_hal(TEE_ObjectHandle object, uint32_t key_size,
                                           const uint8_t *key_e, uint32_t e_size)
{
    struct memref_t e_data = {0};
    e_data.buffer = (uint64_t)(uintptr_t)key_e;
    e_data.size = e_size;
    struct rsa_priv_key_t keypair = {0};

    TEE_Result ret = check_rsa_key_params_valid(object->Attribute, RSA_KEY_PAIR_ATTRIBUTE_COUNT);
    if (ret != TEE_SUCCESS) {
        tloge("Check object params failed, ret=0x%x\n", ret);
        return ret;
    }

    int32_t rc = tee_crypto_rsa_generate_keypair(key_size, &e_data, object->CRTMode, &keypair, object->generate_flag);
    if (rc != TEE_SUCCESS) {
        tloge("generate rsa keypair failed");
        return change_hal_ret_to_gp(rc);
    }

    ret = copy_public_key_to_object(object, &keypair);
    if (ret != TEE_SUCCESS) {
        tloge("convert rsa key failed, ret = 0x%x", ret);
        (void)memset_s(&keypair, sizeof(keypair), 0x0, sizeof(keypair));
        return ret;
    }

    ret = copy_private_key_to_object(object, &keypair);
    if (ret != TEE_SUCCESS) {
        tloge("convert rsa key failed, ret = 0x%x", ret);
        (void)memset_s(&keypair, sizeof(keypair), 0x0, sizeof(keypair));
        return ret;
    }
    if (object->CRTMode)
        ret = copy_private_key_to_object_crt(object, &keypair);

    (void)memset_s(&keypair, sizeof(keypair), 0x0, sizeof(keypair));
    object->ObjectInfo->objectSize = key_size;
    return ret;
}

static TEE_Result tee_gen_rsa_key_pair_2(TEE_ObjectHandle object, uint32_t key_size, const TEE_Attribute *params,
    uint32_t param_count)
{
    int32_t index = get_attr_index_by_id(TEE_ATTR_RSA_PUBLIC_EXPONENT, params, param_count);
    if (index < 0) {
        tloge("get rsa exponent failed");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint8_t *key_e = params[index].content.ref.buffer;
    uint32_t e_size = params[index].content.ref.length;
    return generate_rsa_keypair_hal(object, key_size, key_e, e_size);
}

static TEE_Result tee_gen_rsa_key_pair(TEE_ObjectHandle object, uint32_t key_size, const TEE_Attribute *params,
    uint32_t param_count, uint32_t api_level)
{
    uint8_t key_e[] = { 0x01, 0x00, 0x01 }; /* default rsa exponent */
    uint32_t e_size = sizeof(key_e);

    if (api_level > API_LEVEL1_0) {
        key_size = (key_size + BIT_NUMBER_SEVEN) >> BIT_TO_BYTE_MOVE_THREE;
        if (params != NULL && param_count != 0)
            return tee_gen_rsa_key_pair_2(object, key_size, params, param_count);
    }

    return generate_rsa_keypair_hal(object, key_size, key_e, e_size);
}

static TEE_Result copy_ed25519_key_to_object(TEE_ObjectHandle object, const struct ecc_pub_key_t *public_key,
    const struct ecc_priv_key_t *private_key)
{
    TEE_Result ret;

    ret = copy_single_key_to_object(object, TEE_ATTR_ED25519_PUBLIC_VALUE, public_key->x, public_key->x_len);
    if (ret != TEE_SUCCESS)
        return ret;

    ret = copy_single_key_to_object(object, TEE_ATTR_ED25519_PRIVATE_VALUE, private_key->r, private_key->r_len);
    if (ret != TEE_SUCCESS)
        return ret;

    return TEE_SUCCESS;
}

static TEE_Result copy_x25519_key_to_object(TEE_ObjectHandle object, const struct ecc_pub_key_t *public_key,
    const struct ecc_priv_key_t *private_key)
{
    TEE_Result ret;

    ret = copy_single_key_to_object(object, TEE_ATTR_X25519_PUBLIC_VALUE, public_key->x, public_key->x_len);
    if (ret != TEE_SUCCESS)
        return ret;

    ret = copy_single_key_to_object(object, TEE_ATTR_X25519_PRIVATE_VALUE, private_key->r, private_key->r_len);
    if (ret != TEE_SUCCESS)
        return ret;

    return TEE_SUCCESS;
}

static TEE_Result copy_ecc_key_to_object(TEE_ObjectHandle object, const struct ecc_pub_key_t *public_key,
    const struct ecc_priv_key_t *private_key)
{
    TEE_Result ret;

    ret = copy_single_key_to_object(object, TEE_ATTR_ECC_PUBLIC_VALUE_X, public_key->x, public_key->x_len);
    if (ret != TEE_SUCCESS)
        return ret;

    ret = copy_single_key_to_object(object, TEE_ATTR_ECC_PUBLIC_VALUE_Y, public_key->y, public_key->y_len);
    if (ret != TEE_SUCCESS)
        return ret;

    ret = copy_single_key_to_object(object, TEE_ATTR_ECC_PRIVATE_VALUE, private_key->r, private_key->r_len);
    if (ret != TEE_SUCCESS)
        return ret;

    return TEE_SUCCESS;
}

static bool is_sm2_key_type(uint32_t key_type)
{
    bool check = (
        key_type == TEE_TYPE_SM2_DSA_KEYPAIR ||
        key_type == TEE_TYPE_SM2_DSA_PUBLIC_KEY ||
        key_type == TEE_TYPE_SM2_KEP_KEYPAIR ||
        key_type == TEE_TYPE_SM2_KEP_PUBLIC_KEY ||
        key_type == TEE_TYPE_SM2_PKE_KEYPAIR ||
        key_type == TEE_TYPE_SM2_PKE_PUBLIC_KEY);
    if (check)
        return true;
    return false;
}

static uint32_t get_curve_from_keysize(uint32_t object_type, uint32_t key_size)
{
    if (is_sm2_key_type(object_type))
        return ECC_CURVE_SM2;
    switch (key_size) {
    case ECC_192_KEY_SIZE:
        return TEE_ECC_CURVE_NIST_P192;
    case ECC_224_KEY_SIZE:
        return TEE_ECC_CURVE_NIST_P224;
    case ECC_256_KEY_SIZE:
    case ECC_DEFAULT_KEY_SIZE:
        return TEE_ECC_CURVE_NIST_P256;
    case ECC_384_KEY_SIZE:
        return TEE_ECC_CURVE_NIST_P384;
    case ECC_521_KEY_SIZE:
        return TEE_ECC_CURVE_NIST_P521;
    default:
        return 0;
    }
}

static TEE_Result generate_ec_keypair_hal(TEE_ObjectHandle object, uint32_t key_size, uint32_t ecc_curve)
{
    bool check = (object->Attribute == NULL || object->ObjectInfo == NULL ||
        (ecc_curve == TEE_ECC_CURVE_25519 && object->attributesLen != KEY_25519_FIX_ATTR_LEN) ||
        (ecc_curve != TEE_ECC_CURVE_25519 && object->attributesLen != ECKEY_FIX_ATTRI_LEN));
    if (check) {
        tloge("input error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (ecc_curve == 0)
        ecc_curve = get_curve_from_keysize(object->ObjectInfo->objectType, key_size);

    struct ecc_pub_key_t public_key = {0};
    struct ecc_priv_key_t private_key = {0};
    uint32_t curve;
    if (object->ObjectInfo->objectType == TEE_TYPE_ED25519_KEYPAIR)
        curve = ECC_CURVE_ED25519;
    else if (object->ObjectInfo->objectType == TEE_TYPE_X25519_KEYPAIR)
        curve = ECC_CURVE_X25519;
    else if (is_sm2_key_type(object->ObjectInfo->objectType))
        curve = get_sm2_domain(ecc_curve);
    else
        curve = get_ecc_domain(ecc_curve);

    int32_t rc = tee_crypto_ecc_generate_keypair(key_size, curve, &public_key,
        &private_key, object->generate_flag);
    if (rc != TEE_SUCCESS) {
        tloge("generate ecc keypair failed");
        return change_hal_ret_to_gp(rc);
    }

    TEE_Result ret;
    if (object->ObjectInfo->objectType == TEE_TYPE_ED25519_KEYPAIR) {
        ret = copy_ed25519_key_to_object(object, &public_key, &private_key);
    } else if (object->ObjectInfo->objectType == TEE_TYPE_X25519_KEYPAIR) {
        ret = copy_x25519_key_to_object(object, &public_key, &private_key);
    } else {
        ret = copy_ecc_key_to_object(object, &public_key, &private_key);
        (void)memset_s(&private_key, sizeof(private_key), 0x0, sizeof(private_key));

        int32_t index = get_attr_index_by_id(TEE_ATTR_ECC_CURVE, object->Attribute, object->attributesLen);
        if (index >= 0)
            object->Attribute[index].content.value.a = ecc_curve;
        else
            return TEE_ERROR_BAD_PARAMETERS;
    }
    object->ObjectInfo->objectSize = key_size;
    return ret;
}

static TEE_Result tee_gen_ecdsa_keypair_2(uint32_t key_size, const TEE_Attribute *params,
    uint32_t param_count, uint32_t *ecc_curve, uint32_t api_level)
{
    if (api_level <= API_LEVEL1_0)
        return TEE_SUCCESS;

    if (params == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    int32_t index = get_attr_index_by_id(TEE_ATTR_ECC_CURVE, params, param_count);
    if (index >= 0)
        *ecc_curve = params[index].content.value.a;

    if (index < 0) {
        tloge("get ecc curve failed");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* only support four CURVE */
    crypto_uint2uint keysize_to_curve[] = {
        { 224, TEE_ECC_CURVE_NIST_P224 },
        { 256, TEE_ECC_CURVE_NIST_P256 },
        { 384, TEE_ECC_CURVE_NIST_P384 },
        { 521, TEE_ECC_CURVE_NIST_P521 },
    };

    for (uint32_t i = 0; i < sizeof(keysize_to_curve) / sizeof(keysize_to_curve[0]); i++) {
        if (key_size == keysize_to_curve[i].src) {
            if (*ecc_curve != keysize_to_curve[i].dest)
                return TEE_ERROR_NOT_SUPPORTED;
            else
                return TEE_SUCCESS;
        }
    }
    return TEE_ERROR_NOT_SUPPORTED;
}

static TEE_Result tee_gen_ecdsa_keypair(TEE_ObjectHandle object, uint32_t key_size, const TEE_Attribute *params,
    uint32_t param_count, uint32_t api_level)
{
    uint32_t ecc_curve = 0;
    TEE_Result ret = tee_gen_ecdsa_keypair_2(key_size, params, param_count, &ecc_curve, api_level);
    if (ret != TEE_SUCCESS) {
        tloge("key size and curve is not match");
        return ret;
    }

    return generate_ec_keypair_hal(object, key_size, ecc_curve);
}

static TEE_Result generate_sm2_keypair(TEE_ObjectHandle object, uint32_t key_size,
    uint32_t param_count, uint32_t api_level)
{
    if (api_level == API_LEVEL1_0)
        return generate_ec_keypair_hal(object, key_size, param_count);
    else
        return generate_ec_keypair_hal(object, key_size, TEE_ECC_CURVE_SM2);
}

static TEE_Result tee_generate_3des_key(TEE_ObjectHandle object, uint32_t key_size, uint32_t api_level)
{
    TEE_Result ret;
    if (api_level > API_LEVEL1_0)
        key_size = key_size >> BIT_TO_BYTE_MOVE_THREE;

    bool check = (object->Attribute == NULL) || (object->Attribute->content.ref.length != OBJ_SIZE_DES3) ||
        (key_size != OBJ_SIZE_DES3);
    if (check) {
        tloge("ref length or key_size is not valid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    int i = 0;
    do {
        i++;
        TEE_GenerateRandom(object->Attribute->content.ref.buffer,
            object->Attribute->content.ref.length);
        ret = check_3des_key(object->Attribute);
    } while ((ret != TEE_SUCCESS) && (i <= 5)); /* at most loop 5 times */
    return ret;
}

static TEE_Result get_pbkdf2_buffer_attribute(const TEE_Attribute *params, uint32_t param_count,
    struct memref_t *password, struct memref_t *salt)
{
    int32_t index;

    index = get_attr_index_by_id(TEE_ATTR_PBKDF2_HMAC_PASSWORD, params, param_count);
    if (index < 0) {
        tloge("get attribute PBKDF2_HMAC_PASSWORD failed!");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    password->buffer = (uint64_t)(uintptr_t)params[index].content.ref.buffer;
    password->size = params[index].content.ref.length;

    index = get_attr_index_by_id(TEE_ATTR_PBKDF2_HMAC_SALT, params, param_count);
    if (index < 0) {
        tloge("get attribute PBKDF2_HMAC_SALT failed!");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    salt->buffer = (uint64_t)(uintptr_t)params[index].content.ref.buffer;
    salt->size = params[index].content.ref.length;

    return TEE_SUCCESS;
}

static TEE_Result check_pbkdf2_digest_type(uint32_t digest_type)
{
    switch (digest_type) {
    case CRYPTO_TYPE_DIGEST_SHA1:
    case CRYPTO_TYPE_DIGEST_SHA224:
    case CRYPTO_TYPE_DIGEST_SHA256:
    case CRYPTO_TYPE_DIGEST_SHA384:
    case CRYPTO_TYPE_DIGEST_SHA512:
        return TEE_SUCCESS;
    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }
}

static TEE_Result get_pbkdf2_value_attribute(const TEE_Attribute *params, uint32_t param_count,
    uint32_t *iterations, uint32_t *digest_type)
{
    int32_t index;

    index = get_attr_index_by_id(TEE_ATTR_PBKDF2_HMAC_DIGEST, params, param_count);
    if (index < 0) {
        tloge("get attribute PBKDF2_HMAC_DIGEST failed!");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    *iterations = params[index].content.value.a;
    if (*iterations == 0) {
        tloge("The number of iterations cannot be 0!");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t digest = params[index].content.value.b;
    TEE_Result ret = check_pbkdf2_digest_type(digest);
    if (ret != TEE_SUCCESS) {
        tloge("pbkdf2 digest type invalid! digest_type = 0x%x", digest);
        return ret;
    }

    *digest_type = digest;
    return ret;
}

static TEE_Result tee_generate_pbkdf2_key_hal(TEE_ObjectHandle object, uint32_t key_size,
    const TEE_Attribute *params, uint32_t param_count)
{
    struct memref_t password = {0};
    struct memref_t salt = {0};
    uint32_t iterations = 0;
    uint32_t digest_type = 0;

    TEE_Result ret = get_pbkdf2_buffer_attribute(params, param_count, &password, &salt);
    if (ret != TEE_SUCCESS) {
        tloge("get pbkdf2 password or salt failed!");
        return ret;
    }

    ret = get_pbkdf2_value_attribute(params, param_count, &iterations, &digest_type);
    if (ret != TEE_SUCCESS) {
        tloge("get pbkdf2 iterations or digest_type failed!");
        return ret;
    }

    struct memref_t secret = {0};
    secret.buffer = (uint64_t)(uintptr_t)object->Attribute->content.ref.buffer;
    secret.size = key_size;

    int32_t res = tee_crypto_pbkdf2_derive_key(&password, &salt, iterations, digest_type, &secret,
        object->generate_flag);
    ret = change_hal_ret_to_gp(res);
    if (ret != TEE_SUCCESS) {
        tloge("pbkdf2 generate key failed! ret = 0x%x", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

static TEE_Result tee_generate_pbkdf2_key(TEE_ObjectHandle object, uint32_t key_size,
    const TEE_Attribute *params, uint32_t param_count, uint32_t api_level)
{
    bool check = (object == NULL || object->Attribute == NULL || param_count == 0 ||
        param_count > PBKDF2_ATTRIBUTE_TOTAL || params == NULL);
    if (check) {
        tloge("Attribute of object or params is null or params count error, params_count = %u\n", param_count);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t max_pbkdf2_key_size = (uint32_t)object->Attribute->content.ref.length;
    uint32_t key_size_byte;
    if (api_level <= API_LEVEL1_0)
        key_size_byte = key_size;
    else
        key_size_byte = (key_size + BIT_NUMBER_SEVEN) >> BIT_TO_BYTE_MOVE_THREE;
    if (key_size_byte > max_pbkdf2_key_size) {
        tloge("key size is too large! key_size = %u, max_key_size = %u\n", key_size_byte, max_pbkdf2_key_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result ret = tee_generate_pbkdf2_key_hal(object, key_size_byte, params, param_count);
    if (ret != TEE_SUCCESS)
        tloge("generate pbkdf2 key failed! ret = %x\n", ret);
    return ret;
}

struct algo_key_size_low_s {
    uint32_t type;
    uint32_t min_key_size;
};

#define ECDH_MIN_KEY_SIZE_IN_BIT  224
#define ECDSA_MIN_KEY_SIZE_IN_BIT 224
static const struct algo_key_size_low_s g_algo_low_lev_key_size_config[] = {
    { TEE_TYPE_RSA_PUBLIC_KEY, RSA_MIN_KEY_SIZE },
    { TEE_TYPE_RSA_KEYPAIR, RSA_MIN_KEY_SIZE },
    { TEE_TYPE_ECDSA_PUBLIC_KEY, ECDSA_MIN_KEY_SIZE_IN_BIT },
    { TEE_TYPE_ECDSA_KEYPAIR, ECDSA_MIN_KEY_SIZE_IN_BIT  },
    { TEE_TYPE_DH_KEYPAIR, DH_MIN_KEY_SIZE_IN_BIT },
    { TEE_TYPE_ECDH_PUBLIC_KEY, ECDH_MIN_KEY_SIZE_IN_BIT },
    { TEE_TYPE_ECDH_KEYPAIR, ECDH_MIN_KEY_SIZE_IN_BIT },
    { TEE_TYPE_PBKDF2_HMAC, PBKDF2_MIN_KEY_SIZE },
};

static TEE_Result check_low_lev_key_size_for_alg(uint32_t type, uint32_t key_size)
{
    for (size_t index = 0; index < ELEM_NUM(g_algo_low_lev_key_size_config); index++) {
        if (type == g_algo_low_lev_key_size_config[index].type) {
            if (key_size >= g_algo_low_lev_key_size_config[index].min_key_size) {
                return TEE_SUCCESS;
            } else {
                tloge("the key size is invalid\n");
                return TEE_ERROR_NOT_SUPPORTED;
            }
        }
    }
    if (type == TEE_TYPE_SIP_HASH && key_size != OBJ_SIZE_SIP_HASH) {
        tloge("sip hash key_size is invalid! key_size = %u\n", key_size);
        return TEE_ERROR_NOT_SUPPORTED;
    }
    return TEE_SUCCESS;
}

static TEE_Result tee_generate_key_check(TEE_ObjectHandle object,
    uint32_t key_size, uint32_t *api_level)
{
    if (check_object_valid(object) != TEE_SUCCESS) {
        tloge("object is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    *api_level = tee_get_ta_api_level();
    if (*api_level <= API_LEVEL1_0)
        return check_low_lev_key_size_for_alg(object->ObjectInfo->objectType, key_size);

    TEE_ObjectInfo *object_info = object->ObjectInfo;
    if ((object_info->handleFlags & TEE_HANDLE_FLAG_PERSISTENT) == TEE_HANDLE_FLAG_PERSISTENT) {
        tloge("this is a Persistent Object, so not supported to Generate Key\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return  TEE_ERROR_BAD_PARAMETERS;
    }

    if ((object_info->handleFlags & TEE_HANDLE_FLAG_INITIALIZED) == TEE_HANDLE_FLAG_INITIALIZED) {
        tloge("object is not a uninitialized object, so should panic!\n ");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result ret = check_max_object_size(object_info->objectType, key_size);
    if (ret != TEE_SUCCESS) {
        tloge("keysize is Invalid!keysize = %u\n", key_size);
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return ret;
    }
    uint32_t object_size = get_object_size(object_info->objectType);
    uint32_t max_key_size;
#ifndef GP_SUPPORT
    max_key_size = object_info->maxObjectSize;
#else
    max_key_size = object_info->maxKeySize;
#endif
    uint32_t key_size_byte = (key_size + BIT_NUMBER_SEVEN) >> BIT_TO_BYTE_MOVE_THREE;
    bool check = (key_size_byte > max_key_size || key_size_byte < object_size);
    if (check) {
        tloge("GenerateKey:Invalid keySize, key_size_byte = %u\n", key_size_byte);
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

TEE_Result tee_generate_symmetric_key(TEE_ObjectHandle object, uint32_t key_size, uint32_t api_level)
{
    bool check = (object->Attribute == NULL || object->Attribute->content.ref.buffer == NULL);
    if (check) {
        tloge("object is null");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (api_level == API_LEVEL1_0)
        key_size = object->Attribute->content.ref.length;
    else
        key_size = key_size >> BIT_TO_BYTE_MOVE_THREE;

    tlogd("Use hardware CC IP to get random.\n");
    TEE_GenerateRandom(object->Attribute->content.ref.buffer, key_size);
    if (api_level > API_LEVEL1_0)
        object->Attribute->content.ref.length = key_size;
    object->Attribute->attributeID = (uint32_t)TEE_ATTR_SECRET_VALUE;

    return TEE_SUCCESS;
}

#define ECDH_DCDSA_KEY_MIN 224
static TEE_Result tee_generate_key(TEE_ObjectHandle object, uint32_t key_size,
    TEE_Attribute *params, uint32_t param_count, uint32_t api_level)
{
    switch (object->ObjectInfo->objectType) {
    case (uint32_t)TEE_TYPE_AES:
    case (uint32_t)TEE_TYPE_DES:
    case (uint32_t)TEE_TYPE_SM4:
    case (uint32_t)TEE_TYPE_HMAC_SM3:
    case (uint32_t)TEE_TYPE_HMAC_MD5:
    case (uint32_t)TEE_TYPE_HMAC_SHA1:
    case (uint32_t)TEE_TYPE_HMAC_SHA224:
    case (uint32_t)TEE_TYPE_HMAC_SHA256:
    case (uint32_t)TEE_TYPE_HMAC_SHA384:
    case (uint32_t)TEE_TYPE_HMAC_SHA512:
    case (uint32_t)TEE_TYPE_GENERIC_SECRET:
    case (uint32_t)TEE_TYPE_SIP_HASH:
        return tee_generate_symmetric_key(object, key_size, api_level);
    case (uint32_t)TEE_TYPE_DES3:
        return tee_generate_3des_key(object, key_size, api_level);
    case (uint32_t)TEE_TYPE_RSA_KEYPAIR:
        return tee_gen_rsa_key_pair(object, key_size, params, param_count, api_level);
    case (uint32_t)TEE_TYPE_DH_KEYPAIR:
        return generate_dh_keypair_hal(object, params, param_count);
    case (uint32_t)TEE_TYPE_DSA_KEYPAIR:
        return TEE_ERROR_NOT_SUPPORTED;
    case (uint32_t)TEE_TYPE_ECDSA_KEYPAIR:
    case (uint32_t)TEE_TYPE_ECDH_KEYPAIR:
        if (key_size < ECDH_DCDSA_KEY_MIN)
            return TEE_ERROR_NOT_SUPPORTED;
        return tee_gen_ecdsa_keypair(object, key_size, params, param_count, api_level);
    case (uint32_t)TEE_TYPE_ED25519_KEYPAIR:
    case (uint32_t)TEE_TYPE_X25519_KEYPAIR:
        return generate_ec_keypair_hal(object, key_size, TEE_ECC_CURVE_25519);
    case (uint32_t)TEE_TYPE_SM2_DSA_KEYPAIR:
    case (uint32_t)TEE_TYPE_SM2_KEP_KEYPAIR:
    case (uint32_t)TEE_TYPE_SM2_PKE_KEYPAIR:
        return generate_sm2_keypair(object, key_size, param_count, api_level);
    case (uint32_t)TEE_TYPE_PBKDF2_HMAC:
        return tee_generate_pbkdf2_key(object, key_size, params, param_count, api_level);
    default:
        tlogd("object type is not correct\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
}

TEE_Result TEE_GenerateKey(TEE_ObjectHandle object, uint32_t keySize,
    TEE_Attribute *params, uint32_t paramCount)
{
    uint32_t api_level = 0;

    TEE_Result ret = tee_generate_key_check(object, keySize, &api_level);
    if (ret != TEE_SUCCESS) {
        tloge("Invalid keySize");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    object->ObjectInfo->handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;

    ret = tee_generate_key(object, keySize, params, paramCount, api_level);
    if (ret == TEE_ERROR_NOT_SUPPORTED) {
        tloge("the parameter is invalid!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (ret != TEE_SUCCESS) {
        tloge("TEE_GenerateKey failed!ret = %x\n", ret);
        TEE_Panic(ret);
    }
    return ret;
}

TEE_Result TEE_InfoObjectData(TEE_ObjectHandle object, uint32_t *pos, uint32_t *len)
{
    if (object == NULL || pos == NULL || len == NULL) {
        tloge("bad parameter!\n");
        return  TEE_ERROR_BAD_PARAMETERS;
    }

    if (check_object(object) != TEE_SUCCESS) {
        tloge("object is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return ss_agent_get_object_info(object, pos, len);
}
