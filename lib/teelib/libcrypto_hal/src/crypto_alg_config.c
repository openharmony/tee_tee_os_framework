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
#include "crypto_alg_config.h"
#include <tee_crypto_api.h>
#include <crypto/siphash.h>
#include "crypto_inner_defines.h"
#include "tee_log.h"

#define TEE_OPERATION_INVALID 0xFFFFFFFF
#define TEE_TYPE_INVALID      0xFFFFFFFF
#define ELEM_NUMS(array)      (sizeof(array) / sizeof((array)[0]))

#define RSA_SAFE_KEY_SIZE_MIN   2048
#define DH_SAFE_KEY_SIZE_MIN    256
#define ECDSA_SAFE_KEY_SIZE_MIN 224
#define ECDH_SAFE_KEY_SIZE_MIN  224

typedef TEE_Result (*op_keysize_check)(uint32_t max_key_size);

struct alg_config_t {
    uint32_t alg;
    uint32_t mode;
    uint32_t class;
    op_keysize_check check_keysize;
    uint32_t keytype;
    uint32_t element;
};

static TEE_Result check_keysize_for_aes(uint32_t max_key_size)
{
    if (max_key_size != AES_KEY_SIZE_128 * BIT_TO_BYTE && max_key_size != AES_KEY_SIZE_192 * BIT_TO_BYTE &&
        max_key_size != AES_KEY_SIZE_256 * BIT_TO_BYTE)
        return TEE_ERROR_BAD_PARAMETERS;

    return TEE_SUCCESS;
}

static TEE_Result check_keysize_for_rsa(uint32_t max_key_size)
{
    if (max_key_size >= RSA_KEY_MIN && max_key_size <= RSA_KEY_MAX &&
        max_key_size % RSA_KEY_BLOCK == 0)
        return TEE_SUCCESS;
    return TEE_ERROR_BAD_PARAMETERS;
}

static TEE_Result check_keysize_for_dh_derive(uint32_t max_key_size)
{
    if (max_key_size < DH_MIN_KEY_SIZE * BIT_TO_BYTE || max_key_size > DH_MAX_KEY_SIZE * BIT_TO_BYTE ||
        max_key_size % BIT_TO_BYTE != 0)
        return TEE_ERROR_BAD_PARAMETERS;

    return TEE_SUCCESS;
}

static TEE_Result check_keysize_for_hmac(uint32_t max_key_size)
{
    if (max_key_size < HMAC_MIN_KEY || max_key_size > HMAC_MAX_KEY ||
        max_key_size % BIT_TO_BYTE != 0)
        return TEE_ERROR_BAD_PARAMETERS;

    return TEE_SUCCESS;
}
static TEE_Result check_keysize_for_hmac_sm3(uint32_t max_key_size)
{
    if (max_key_size < HMAC_SM3_MIN_KEY || max_key_size > HMAC_SM3_MAX_KEY ||
        max_key_size % BIT_TO_BYTE != 0)
        return TEE_ERROR_BAD_PARAMETERS;

    return TEE_SUCCESS;
}

static TEE_Result check_keysize_for_sip_hash(uint32_t max_key_size)
{
    if (max_key_size != SIPHASH_KEY_SIZE * BIT_TO_BYTE)
        return TEE_ERROR_BAD_PARAMETERS;

    return TEE_SUCCESS;
}

static TEE_Result check_keysize_for_ecdsa_sha_x(uint32_t max_key_size)
{
    if (
        max_key_size != ECDSA_KEY_224 &&
        max_key_size != ECDSA_KEY_256 && max_key_size != ECDSA_KEY_320 &&
        max_key_size != ECDSA_KEY_384 && max_key_size != ECDSA_KEY_521)
        return TEE_ERROR_BAD_PARAMETERS;
    return TEE_SUCCESS;
}

static TEE_Result check_keysize_for_ecdh_p224(uint32_t max_key_size)
{
    if (max_key_size != ECDSA_KEY_224)
        return TEE_ERROR_BAD_PARAMETERS;

    return TEE_SUCCESS;
}
static TEE_Result check_keysize_for_ecdh_p256(uint32_t max_key_size)
{
    if (max_key_size != ECDSA_KEY_256)
        return TEE_ERROR_BAD_PARAMETERS;

    return TEE_SUCCESS;
}
static TEE_Result check_keysize_for_ecdh_p384(uint32_t max_key_size)
{
    if (max_key_size != ECDSA_KEY_384)
        return TEE_ERROR_BAD_PARAMETERS;

    return TEE_SUCCESS;
}
static TEE_Result check_keysize_for_ecdh_p521(uint32_t max_key_size)
{
    if (max_key_size != ECDSA_KEY_521)
        return TEE_ERROR_BAD_PARAMETERS;

    return TEE_SUCCESS;
}
#ifdef CRYPTO_SSL_SUPPORT_EC25519
static TEE_Result check_keysize_for_25519(uint32_t max_key_size)
{
    if (max_key_size != ECDSA_KEY_256)
        return TEE_ERROR_BAD_PARAMETERS;

    return TEE_SUCCESS;
}
#endif
static TEE_Result check_keysize_for_sm2(uint32_t max_key_size)
{
    if (max_key_size != ECDSA_KEY_256)
        return TEE_ERROR_BAD_PARAMETERS;

    return TEE_SUCCESS;
}
static TEE_Result check_keysize_for_sm4(uint32_t max_key_size)
{
    if (max_key_size != SM4_KEY_SIZE)
        return TEE_ERROR_BAD_PARAMETERS;

    return TEE_SUCCESS;
}
static TEE_Result check_keysize_for_others(uint32_t max_key_size)
{
    if (max_key_size % BIT_TO_BYTE != 0)
        return TEE_ERROR_BAD_PARAMETERS;

    return TEE_SUCCESS;
}

static const struct alg_config_t g_alg_config[] = {
    {
        TEE_ALG_AES_ECB_NOPAD, TEE_MODE_ENCRYPT, TEE_OPERATION_CIPHER,
        check_keysize_for_aes, TEE_TYPE_AES, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_AES_CBC_NOPAD, TEE_MODE_ENCRYPT, TEE_OPERATION_CIPHER,
        check_keysize_for_aes, TEE_TYPE_AES, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_AES_CTR, TEE_MODE_ENCRYPT, TEE_OPERATION_CIPHER,
        check_keysize_for_aes, TEE_TYPE_AES, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_AES_CTS, TEE_MODE_ENCRYPT, TEE_OPERATION_CIPHER,
        check_keysize_for_aes, TEE_TYPE_AES, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_AES_XTS, TEE_MODE_ENCRYPT, TEE_OPERATION_CIPHER,
        check_keysize_for_aes, TEE_TYPE_AES, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_AES_CBC_MAC_NOPAD, TEE_MODE_MAC, TEE_OPERATION_MAC,
        check_keysize_for_aes, TEE_TYPE_AES, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_AES_CMAC, TEE_MODE_MAC, TEE_OPERATION_MAC,
        check_keysize_for_aes, TEE_TYPE_AES, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_AES_CCM, TEE_MODE_ENCRYPT, TEE_OPERATION_AE,
        check_keysize_for_aes, TEE_TYPE_AES, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_AES_GCM, TEE_MODE_ENCRYPT, TEE_OPERATION_AE,
        check_keysize_for_aes, TEE_TYPE_AES, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_AES_ECB_PKCS5, TEE_MODE_ENCRYPT, TEE_OPERATION_CIPHER,
        check_keysize_for_aes, TEE_TYPE_AES, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_AES_CBC_PKCS5, TEE_MODE_ENCRYPT, TEE_OPERATION_CIPHER,
        check_keysize_for_aes, TEE_TYPE_AES, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_RSASSA_PKCS1_V1_5_SHA256, TEE_MODE_SIGN, TEE_OPERATION_ASYMMETRIC_SIGNATURE,
        check_keysize_for_rsa, TEE_TYPE_RSA_PUBLIC_KEY, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_RSASSA_PKCS1_V1_5_SHA384, TEE_MODE_SIGN, TEE_OPERATION_ASYMMETRIC_SIGNATURE,
        check_keysize_for_rsa, TEE_TYPE_RSA_PUBLIC_KEY, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_RSASSA_PKCS1_V1_5_SHA512, TEE_MODE_SIGN, TEE_OPERATION_ASYMMETRIC_SIGNATURE,
        check_keysize_for_rsa, TEE_TYPE_RSA_PUBLIC_KEY, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1, TEE_MODE_SIGN, TEE_OPERATION_ASYMMETRIC_SIGNATURE,
        check_keysize_for_rsa, TEE_TYPE_RSA_PUBLIC_KEY, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256, TEE_MODE_SIGN, TEE_OPERATION_ASYMMETRIC_SIGNATURE,
        check_keysize_for_rsa, TEE_TYPE_RSA_PUBLIC_KEY, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384, TEE_MODE_SIGN, TEE_OPERATION_ASYMMETRIC_SIGNATURE,
        check_keysize_for_rsa, TEE_TYPE_RSA_PUBLIC_KEY, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512, TEE_MODE_SIGN, TEE_OPERATION_ASYMMETRIC_SIGNATURE,
        check_keysize_for_rsa, TEE_TYPE_RSA_PUBLIC_KEY, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_ENCRYPT, TEE_OPERATION_ASYMMETRIC_CIPHER,
        check_keysize_for_rsa, TEE_TYPE_RSA_PUBLIC_KEY, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1, TEE_MODE_ENCRYPT, TEE_OPERATION_ASYMMETRIC_CIPHER,
        check_keysize_for_rsa, TEE_TYPE_RSA_PUBLIC_KEY, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256, TEE_MODE_ENCRYPT, TEE_OPERATION_ASYMMETRIC_CIPHER,
        check_keysize_for_rsa, TEE_TYPE_RSA_PUBLIC_KEY, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384, TEE_MODE_ENCRYPT, TEE_OPERATION_ASYMMETRIC_CIPHER,
        check_keysize_for_rsa, TEE_TYPE_RSA_PUBLIC_KEY, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512, TEE_MODE_ENCRYPT, TEE_OPERATION_ASYMMETRIC_CIPHER,
        check_keysize_for_rsa, TEE_TYPE_RSA_PUBLIC_KEY, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_RSA_NOPAD, TEE_MODE_ENCRYPT, TEE_OPERATION_ASYMMETRIC_CIPHER,
        check_keysize_for_rsa, TEE_TYPE_RSA_PUBLIC_KEY, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_DH_DERIVE_SHARED_SECRET, TEE_MODE_DERIVE, TEE_OPERATION_KEY_DERIVATION,
        check_keysize_for_dh_derive, TEE_TYPE_DH_KEYPAIR, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_HMAC_SHA1, TEE_MODE_MAC, TEE_OPERATION_MAC,
        check_keysize_for_hmac, TEE_TYPE_HMAC_SHA1, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_HMAC_SHA256, TEE_MODE_MAC, TEE_OPERATION_MAC,
        check_keysize_for_hmac, TEE_TYPE_HMAC_SHA256, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_HMAC_SHA384, TEE_MODE_MAC, TEE_OPERATION_MAC,
        check_keysize_for_hmac, TEE_TYPE_HMAC_SHA384, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_HMAC_SHA512, TEE_MODE_MAC, TEE_OPERATION_MAC,
        check_keysize_for_hmac, TEE_TYPE_HMAC_SHA512, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_HMAC_SM3, TEE_MODE_MAC, TEE_OPERATION_MAC,
        check_keysize_for_hmac_sm3, TEE_TYPE_HMAC_SM3, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_SIP_HASH, TEE_MODE_MAC, TEE_OPERATION_MAC,
        check_keysize_for_sip_hash, TEE_TYPE_SIP_HASH, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_ECDSA_SHA256, TEE_MODE_SIGN, TEE_OPERATION_ASYMMETRIC_SIGNATURE,
        check_keysize_for_ecdsa_sha_x, TEE_TYPE_ECDSA_PUBLIC_KEY, TEE_ECC_CURVE_NIST_P256
    },
    {
        TEE_ALG_ECDSA_SHA384, TEE_MODE_SIGN, TEE_OPERATION_ASYMMETRIC_SIGNATURE,
        check_keysize_for_ecdsa_sha_x, TEE_TYPE_ECDSA_PUBLIC_KEY, TEE_ECC_CURVE_NIST_P384
    },
    {
        TEE_ALG_ECDSA_SHA512, TEE_MODE_SIGN, TEE_OPERATION_ASYMMETRIC_SIGNATURE,
        check_keysize_for_ecdsa_sha_x, TEE_TYPE_ECDSA_PUBLIC_KEY, TEE_ECC_CURVE_NIST_P521
    },
    {
        TEE_ALG_ECDH_DERIVE_SHARED_SECRET, TEE_MODE_DERIVE, TEE_OPERATION_KEY_DERIVATION,
        check_keysize_for_ecdsa_sha_x, TEE_TYPE_ECDH_PUBLIC_KEY, TEE_ECC_CURVE_NIST_P521
    },
    {
        TEE_ALG_ECDH_P224, TEE_MODE_DERIVE, TEE_OPERATION_KEY_DERIVATION,
        check_keysize_for_ecdh_p224, TEE_TYPE_ECDH_PUBLIC_KEY, TEE_ECC_CURVE_NIST_P224
    },
    {
        TEE_ALG_ECDH_P256, TEE_MODE_DERIVE, TEE_OPERATION_KEY_DERIVATION,
        check_keysize_for_ecdh_p256, TEE_TYPE_ECDH_PUBLIC_KEY, TEE_ECC_CURVE_NIST_P256
    },
    {
        TEE_ALG_ECDH_P384, TEE_MODE_DERIVE, TEE_OPERATION_KEY_DERIVATION,
        check_keysize_for_ecdh_p384, TEE_TYPE_ECDH_PUBLIC_KEY, TEE_ECC_CURVE_NIST_P384
    },
    {
        TEE_ALG_ECDH_P521, TEE_MODE_DERIVE, TEE_OPERATION_KEY_DERIVATION,
        check_keysize_for_ecdh_p521, TEE_TYPE_ECDH_PUBLIC_KEY, TEE_ECC_CURVE_NIST_P521
    },
    {
        TEE_ALG_SM2_DSA_SM3, TEE_MODE_SIGN, TEE_OPERATION_ASYMMETRIC_SIGNATURE,
        check_keysize_for_sm2, TEE_TYPE_SM2_DSA_PUBLIC_KEY, TEE_ECC_CURVE_SM2
    },
    {
        TEE_ALG_SM2_PKE, TEE_MODE_ENCRYPT, TEE_OPERATION_ASYMMETRIC_CIPHER,
        check_keysize_for_sm2, TEE_TYPE_SM2_PKE_PUBLIC_KEY, TEE_ECC_CURVE_SM2
    },
    {
        TEE_ALG_SM4_ECB_NOPAD, TEE_MODE_ENCRYPT, TEE_OPERATION_CIPHER,
        check_keysize_for_sm4, TEE_TYPE_SM4, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_SM4_CBC_NOPAD, TEE_MODE_ENCRYPT, TEE_OPERATION_CIPHER,
        check_keysize_for_sm4, TEE_TYPE_SM4, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_SM4_CBC_PKCS7, TEE_MODE_ENCRYPT, TEE_OPERATION_CIPHER,
        check_keysize_for_sm4, TEE_TYPE_SM4, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_SM4_CTR, TEE_MODE_ENCRYPT, TEE_OPERATION_CIPHER,
        check_keysize_for_sm4, TEE_TYPE_SM4, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_SM4_GCM, TEE_MODE_ENCRYPT, TEE_OPERATION_AE,
        check_keysize_for_sm4, TEE_TYPE_SM4, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_SM4_CFB128, TEE_MODE_ENCRYPT, TEE_OPERATION_CIPHER,
        check_keysize_for_sm4, TEE_TYPE_SM4, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_SM4_GCM, TEE_MODE_ENCRYPT, TEE_OPERATION_AE,
        check_keysize_for_sm4, TEE_TYPE_SM4, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_SM3, TEE_MODE_DIGEST, TEE_OPERATION_DIGEST,
        check_keysize_for_others, TEE_TYPE_INVALID, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_SHA256, TEE_MODE_DIGEST, TEE_OPERATION_DIGEST,
        check_keysize_for_others, TEE_TYPE_INVALID, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_SHA384, TEE_MODE_DIGEST, TEE_OPERATION_DIGEST,
        check_keysize_for_others, TEE_TYPE_INVALID, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_SHA512, TEE_MODE_DIGEST, TEE_OPERATION_DIGEST,
        check_keysize_for_others, TEE_TYPE_INVALID, TEE_OPTIONAL_ELEMENT_NONE
    },
#ifdef CRYPTO_SSL_SUPPORT_EC25519
    {
        TEE_ALG_ED25519, TEE_MODE_SIGN, TEE_OPERATION_ASYMMETRIC_SIGNATURE,
        check_keysize_for_25519, TEE_TYPE_ED25519_PUBLIC_KEY, TEE_OPTIONAL_ELEMENT_NONE
    },
    {
        TEE_ALG_X25519, TEE_MODE_DERIVE, TEE_OPERATION_KEY_DERIVATION,
        check_keysize_for_25519, TEE_TYPE_X25519_PUBLIC_KEY, TEE_OPTIONAL_ELEMENT_NONE
    },
#endif
};

bool crypto_check_alg_valid(uint32_t alg, uint32_t mode)
{
    size_t index;

    for (index = 0; index < ELEM_NUMS(g_alg_config); index++) {
        if ((alg == g_alg_config[index].alg) && (mode == g_alg_config[index].mode))
            return true;
    }

    return false;
}

uint32_t crypto_get_op_class(uint32_t alg)
{
    size_t index;

    for (index = 0; index < ELEM_NUMS(g_alg_config); index++) {
        if (alg == g_alg_config[index].alg)
            return g_alg_config[index].class;
    }

    return TEE_OPERATION_INVALID;
}

TEE_Result crypto_check_keysize(uint32_t algorithm, uint32_t max_key_size)
{
    size_t index;

    for (index = 0; index < ELEM_NUMS(g_alg_config); index++) {
        if (algorithm == g_alg_config[index].alg)
            return g_alg_config[index].check_keysize(max_key_size);
    }

    return TEE_ERROR_NOT_SUPPORTED;
}

#define TEE_TYPE_KEYPAIR_OFFSET 0x1000000
/* Check if key object type is compatible with operation algorithm */
bool crypto_check_keytype_valid(uint32_t alg, uint32_t type)
{
    size_t index;

    for (index = 0; index < ELEM_NUMS(g_alg_config); index++) {
        if (alg == g_alg_config[index].alg)
            break;
    }
    if (index == ELEM_NUMS(g_alg_config))
        return false;

    if (type == g_alg_config[index].keytype)
        return true;

    switch (g_alg_config[index].keytype) {
    case TEE_TYPE_RSA_PUBLIC_KEY:
    case TEE_TYPE_DSA_PUBLIC_KEY:
    case TEE_TYPE_ECDSA_PUBLIC_KEY:
    case TEE_TYPE_ECDH_PUBLIC_KEY:
    case TEE_TYPE_ED25519_PUBLIC_KEY:
    case TEE_TYPE_X25519_PUBLIC_KEY:
    case TEE_TYPE_SM2_DSA_PUBLIC_KEY:
    case TEE_TYPE_SM2_KEP_PUBLIC_KEY:
    case TEE_TYPE_SM2_PKE_PUBLIC_KEY:
        if (type == (g_alg_config[index].keytype + TEE_TYPE_KEYPAIR_OFFSET))
            return true;
        break;
    default:
        return false;
    }
    return false;
}

bool crypto_check_alg_supported(uint32_t alg, uint32_t element)
{
    size_t index;

    if (alg == TEE_ALG_ECDH_DERIVE_SHARED_SECRET) {
        if ((element == TEE_ECC_CURVE_NIST_P192) || (element == TEE_ECC_CURVE_NIST_P224) ||
            (element == TEE_ECC_CURVE_NIST_P256) || (element == TEE_ECC_CURVE_NIST_P384) ||
            (element == TEE_ECC_CURVE_NIST_P521))
            return true;
    }
    for (index = 0; index < ELEM_NUMS(g_alg_config); index++) {
        if ((alg == g_alg_config[index].alg) && (element == g_alg_config[index].element))
            return true;
    }

    return false;
}

static const uint32_t g_supported_object_type[] = {
    TEE_TYPE_AES,
    TEE_TYPE_SM4,
    TEE_TYPE_HMAC_SM3,
    TEE_TYPE_HMAC_SHA1,
    TEE_TYPE_HMAC_SHA224,
    TEE_TYPE_HMAC_SHA256,
    TEE_TYPE_HMAC_SHA384,
    TEE_TYPE_HMAC_SHA512,
    TEE_TYPE_GENERIC_SECRET,
    TEE_TYPE_RSA_PUBLIC_KEY,
    TEE_TYPE_RSA_KEYPAIR,
    TEE_TYPE_DSA_PUBLIC_KEY,
    TEE_TYPE_DSA_KEYPAIR,
    TEE_TYPE_DH_KEYPAIR,
    TEE_TYPE_ECDSA_PUBLIC_KEY,
    TEE_TYPE_ECDH_PUBLIC_KEY,
    TEE_TYPE_ECDSA_KEYPAIR,
    TEE_TYPE_ECDH_KEYPAIR,
    TEE_TYPE_SM2_DSA_PUBLIC_KEY,
    TEE_TYPE_SM2_KEP_PUBLIC_KEY,
    TEE_TYPE_SM2_PKE_PUBLIC_KEY,
    TEE_TYPE_SM2_DSA_KEYPAIR,
    TEE_TYPE_SM2_KEP_KEYPAIR,
    TEE_TYPE_SM2_PKE_KEYPAIR,
    TEE_TYPE_SIP_HASH,
#ifdef CRYPTO_SSL_SUPPORT_EC25519
    TEE_TYPE_ED25519_PUBLIC_KEY,
    TEE_TYPE_ED25519_KEYPAIR,
    TEE_TYPE_X25519_PUBLIC_KEY,
    TEE_TYPE_X25519_KEYPAIR,
#endif
    TEE_TYPE_DATA,
    TEE_TYPE_DATA_GP1_1,
    TEE_TYPE_PBKDF2_HMAC,
};
bool crypto_object_type_supported(uint32_t object_type)
{
    size_t index;

    for (index = 0; index < ELEM_NUMS(g_supported_object_type); index++) {
        if (object_type == g_supported_object_type[index])
            return true;
    }

    return false;
}

#define ARRAY_END         0
struct safe_alg_and_key_size_t {
    uint32_t alg_or_type;
    uint32_t min_safe_key_size;
};

static const struct safe_alg_and_key_size_t g_unsafe_alg_with_key[] = {
    { TEE_ALG_RSASSA_PKCS1_V1_5_MD5, RSA_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, RSA_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_RSASSA_PKCS1_V1_5_SHA224, RSA_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_RSASSA_PKCS1_V1_5_SHA256, RSA_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_RSASSA_PKCS1_V1_5_SHA384, RSA_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_RSASSA_PKCS1_V1_5_SHA512, RSA_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_RSASSA_PKCS1_PSS_MGF1_MD5, RSA_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1, RSA_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224, RSA_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256, RSA_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384, RSA_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512, RSA_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_RSAES_PKCS1_V1_5, RSA_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1, RSA_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224, RSA_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256, RSA_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384, RSA_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512, RSA_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_RSA_NOPAD, RSA_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_DH_DERIVE_SHARED_SECRET, DH_SAFE_KEY_SIZE_MIN },
    { TEE_ALG_ECDSA_SHA1, ECDSA_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_ECDSA_SHA224, ECDSA_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_ECDSA_SHA256, ECDSA_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_ECDSA_SHA384, ECDSA_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_ECDSA_SHA512, ECDSA_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_ECDH_DERIVE_SHARED_SECRET, ECDH_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_ECDH_P224, ECDH_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_ECDH_P256, ECDH_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_ECDH_P384, ECDH_SAFE_KEY_SIZE_MIN},
    { TEE_ALG_ECDH_P521, ECDH_SAFE_KEY_SIZE_MIN},
    { ARRAY_END, ARRAY_END },
};

static const struct safe_alg_and_key_size_t g_unsafe_type_with_key[] = {
    { TEE_TYPE_RSA_PUBLIC_KEY, RSA_SAFE_KEY_SIZE_MIN},
    { TEE_TYPE_RSA_KEYPAIR, RSA_SAFE_KEY_SIZE_MIN},
    { TEE_TYPE_DH_KEYPAIR, DH_SAFE_KEY_SIZE_MIN },
    { TEE_TYPE_ECDSA_PUBLIC_KEY, ECDSA_SAFE_KEY_SIZE_MIN},
    { TEE_TYPE_ECDSA_KEYPAIR, ECDSA_SAFE_KEY_SIZE_MIN},
    { TEE_TYPE_ECDH_PUBLIC_KEY, ECDH_SAFE_KEY_SIZE_MIN},
    { TEE_TYPE_ECDH_KEYPAIR, ECDH_SAFE_KEY_SIZE_MIN},
    { ARRAY_END, ARRAY_END },
};

TEE_Result check_if_unsafe_alg(uint32_t alg, uint32_t key_size)
{
    for (size_t index = 0; index < ELEM_NUM(g_unsafe_alg_with_key); index++) {
        if (alg == g_unsafe_alg_with_key[index].alg_or_type) {
            if (key_size < g_unsafe_alg_with_key[index].min_safe_key_size) {
                tloge("the algorithm 0x%x with key size %u is unsafe and not support\n", alg, key_size);
                return TEE_ERROR_NOT_SUPPORTED;
            }
        }
    }
    return TEE_SUCCESS;
}

TEE_Result check_if_unsafe_type(uint32_t obj_type, uint32_t key_size)
{
    for (size_t index = 0; index < ELEM_NUM(g_unsafe_type_with_key); index++) {
        if (obj_type == g_unsafe_type_with_key[index].alg_or_type) {
            if (key_size < g_unsafe_type_with_key[index].min_safe_key_size) {
                tloge("the algorithm 0x%x with key size %u is unsafe and not support\n", obj_type, key_size);
                return TEE_ERROR_NOT_SUPPORTED;
            }
        }
    }
    return TEE_SUCCESS;
}
