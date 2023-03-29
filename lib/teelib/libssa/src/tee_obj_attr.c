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
#include "tee_obj_attr.h"
#include "tee_log.h"
#include "tee_obj.h"
#include "tee_object_api.h"

static const struct obj_attr_conf_s g_obj_attr_conf[] = {
    { TEE_TYPE_AES,                1, 1, OBJ_MIN_SIZE_AES, {TEE_ATTR_SECRET_VALUE}},
    { TEE_TYPE_DES,                1, 1, OBJ_SIZE_DES, {TEE_ATTR_SECRET_VALUE}},
    { TEE_TYPE_DES3,               1, 1, OBJ_SIZE_DES3, {TEE_ATTR_SECRET_VALUE}},
    { TEE_TYPE_SM4,                1, 1, OBJ_SIZE_SM4, {TEE_ATTR_SECRET_VALUE}},
    { TEE_TYPE_HMAC_SM3,           1, 1, OBJ_MIN_SIZE_HMAC_SM3, {TEE_ATTR_SECRET_VALUE}},
    { TEE_TYPE_HMAC_MD5,           1, 1, OBJ_MIN_SIZE_HMAC, {TEE_ATTR_SECRET_VALUE}},
    { TEE_TYPE_HMAC_SHA1,          1, 1, OBJ_MIN_SIZE_HMAC, {TEE_ATTR_SECRET_VALUE}},
    { TEE_TYPE_HMAC_SHA224,        1, 1, OBJ_MIN_SIZE_HMAC, {TEE_ATTR_SECRET_VALUE}},
    { TEE_TYPE_HMAC_SHA256,        1, 1, OBJ_MIN_SIZE_HMAC, {TEE_ATTR_SECRET_VALUE}},
    { TEE_TYPE_HMAC_SHA384,        1, 1, OBJ_MIN_SIZE_HMAC, {TEE_ATTR_SECRET_VALUE}},
    { TEE_TYPE_HMAC_SHA512,        1, 1, OBJ_MIN_SIZE_HMAC, {TEE_ATTR_SECRET_VALUE}},
    { TEE_TYPE_SIP_HASH,           1, 1, OBJ_MIN_SIZE_HMAC, {TEE_ATTR_SECRET_VALUE}},
    { TEE_TYPE_GENERIC_SECRET,     1, 1, OBJ_MIN_SIZE_GENERIC_SECRET, {TEE_ATTR_SECRET_VALUE}},
    { TEE_TYPE_PBKDF2_HMAC,        1, 1, OBJ_MIN_SIZE_PBKDF2, {TEE_ATTR_SECRET_VALUE}},
    {
        TEE_TYPE_RSA_PUBLIC_KEY,     2, 2, OBJ_MIN_SIZE_RSA_PUB_KEY, {
            TEE_ATTR_RSA_MODULUS,
            TEE_ATTR_RSA_PUBLIC_EXPONENT
        }
    },
    {
        TEE_TYPE_RSA_KEYPAIR,        3, 8, OBJ_MIN_SIZE_RSA_KEY_PAIR, {
            TEE_ATTR_RSA_MODULUS,
            TEE_ATTR_RSA_PUBLIC_EXPONENT,
            TEE_ATTR_RSA_PRIVATE_EXPONENT
        }
    },
    {
        TEE_TYPE_DSA_PUBLIC_KEY,     4, 4, OBJ_MIN_SIZE_DSA_PUB_KEY, {
            TEE_ATTR_DSA_PRIME,
            TEE_ATTR_DSA_SUBPRIME,
            TEE_ATTR_DSA_BASE,
            TEE_ATTR_DSA_PUBLIC_VALUE
        }
    },
    {
        TEE_TYPE_DSA_KEYPAIR,        5, 5, OBJ_MIN_SIZE_DSA_KEY_PAIR, {
            TEE_ATTR_DSA_PRIME,
            TEE_ATTR_DSA_SUBPRIME,
            TEE_ATTR_DSA_BASE,
            TEE_ATTR_DSA_PUBLIC_VALUE,
            TEE_ATTR_DSA_PRIVATE_VALUE
        }
    },
    {
        TEE_TYPE_DH_KEYPAIR,         4, 6, OBJ_MIN_SIZE_DH_KEY_PAIR, {
            TEE_ATTR_DH_PRIME,
            TEE_ATTR_DH_BASE,
            TEE_ATTR_DH_PUBLIC_VALUE,
            TEE_ATTR_DH_PRIVATE_VALUE
        }
    },
    {
        TEE_TYPE_ECDSA_PUBLIC_KEY,   3, 3, OBJ_MIN_SIZE_ECDSA_PUB_KEY, {
            TEE_ATTR_ECC_PUBLIC_VALUE_X,
            TEE_ATTR_ECC_PUBLIC_VALUE_Y,
            TEE_ATTR_ECC_CURVE
        }
    },
    {
        TEE_TYPE_ECDH_PUBLIC_KEY,    3, 3, OBJ_MIN_SIZE_ECDH_PUB_KEY, {
            TEE_ATTR_ECC_PUBLIC_VALUE_X,
            TEE_ATTR_ECC_PUBLIC_VALUE_Y,
            TEE_ATTR_ECC_CURVE
        }
    },
    {
        TEE_TYPE_ECDSA_KEYPAIR,      4, 4, OBJ_MIN_SIZE_ECDSA_KEY_PAIR, {
            TEE_ATTR_ECC_PUBLIC_VALUE_X,
            TEE_ATTR_ECC_PUBLIC_VALUE_Y,
            TEE_ATTR_ECC_CURVE,
            TEE_ATTR_ECC_PRIVATE_VALUE
        }
    },
    {
        TEE_TYPE_ECDH_KEYPAIR,       4, 4, OBJ_MIN_SIZE_ECDH_KEY_PAIR, {
            TEE_ATTR_ECC_PUBLIC_VALUE_X,
            TEE_ATTR_ECC_PUBLIC_VALUE_Y,
            TEE_ATTR_ECC_CURVE,
            TEE_ATTR_ECC_PRIVATE_VALUE
        }
    },
    {
        TEE_TYPE_SM2_DSA_PUBLIC_KEY, 2, 3, OBJ_SIZE_SM2, {
            TEE_ATTR_ECC_PUBLIC_VALUE_X,
            TEE_ATTR_ECC_PUBLIC_VALUE_Y,
        }
    },
    {
        TEE_TYPE_SM2_KEP_PUBLIC_KEY, 2, 3, OBJ_SIZE_SM2, {
            TEE_ATTR_ECC_PUBLIC_VALUE_X,
            TEE_ATTR_ECC_PUBLIC_VALUE_Y,
        }
    },
    {
        TEE_TYPE_SM2_PKE_PUBLIC_KEY, 2, 3, OBJ_SIZE_SM2, {
            TEE_ATTR_ECC_PUBLIC_VALUE_X,
            TEE_ATTR_ECC_PUBLIC_VALUE_Y,
        }
    },
    {
        TEE_TYPE_SM2_DSA_KEYPAIR,    3, 4, OBJ_SIZE_SM2, {
            TEE_ATTR_ECC_PUBLIC_VALUE_X,
            TEE_ATTR_ECC_PUBLIC_VALUE_Y,
            TEE_ATTR_ECC_PRIVATE_VALUE
        }
    },
    {
        TEE_TYPE_SM2_KEP_KEYPAIR,    3, 4, OBJ_SIZE_SM2, {
            TEE_ATTR_ECC_PUBLIC_VALUE_X,
            TEE_ATTR_ECC_PUBLIC_VALUE_Y,
            TEE_ATTR_ECC_PRIVATE_VALUE
        }
    },
    {
        TEE_TYPE_SM2_PKE_KEYPAIR,    3, 4, OBJ_SIZE_SM2, {
            TEE_ATTR_ECC_PUBLIC_VALUE_X,
            TEE_ATTR_ECC_PUBLIC_VALUE_Y,
            TEE_ATTR_ECC_PRIVATE_VALUE
        }
    },
    {
        TEE_TYPE_ED25519_PUBLIC_KEY, 1, 1, OBJ_SIZE_ED25519_PUB_KEY, {
            TEE_ATTR_ED25519_PUBLIC_VALUE
        }
    },
    {
        TEE_TYPE_ED25519_KEYPAIR,    2, 2, OBJ_SIZE_ED25519_KEY_PAIR, {
            TEE_ATTR_ED25519_PUBLIC_VALUE,
            TEE_ATTR_ED25519_PRIVATE_VALUE
        }
    },
    {
        TEE_TYPE_X25519_PUBLIC_KEY,  1, 1, OBJ_SIZE_X25519_PUB_KEY, {
            TEE_ATTR_X25519_PUBLIC_VALUE
        }
    },
    {
        TEE_TYPE_X25519_KEYPAIR,     2, 2, OBJ_SIZE_X25519_PUB_KEY, {
            TEE_ATTR_X25519_PUBLIC_VALUE,
            TEE_ATTR_X25519_PRIVATE_VALUE
        }
    },
    { TEE_TYPE_DATA,               0, 0, 0, {0}},
    { TEE_TYPE_DATA_GP1_1,         0, 0, 0, {0}},
};

uint32_t get_attr_count_for_object_type(uint32_t object_type)
{
    uint32_t index;

    for (index = 0; index < ELEM_NUM(g_obj_attr_conf); index++) {
        if (object_type == g_obj_attr_conf[index].type)
            return g_obj_attr_conf[index].max_attr_count;
    }

    return 0;
}

uint32_t get_object_size(uint32_t object_type)
{
    uint32_t index;

    for (index = 0; index < ELEM_NUM(g_obj_attr_conf); index++) {
        if (object_type == g_obj_attr_conf[index].type)
            return g_obj_attr_conf[index].min_obj_size;
    }

    return 0;
}

const struct obj_attr_conf_s *get_object_attr_conf(const TEE_ObjectHandle object)
{
    const struct obj_attr_conf_s *config = NULL;
    uint32_t index;

    if (object == NULL || object->ObjectInfo == NULL) {
        tloge("invalid input");
        return NULL;
    }

    for (index = 0; index < ELEM_NUM(g_obj_attr_conf); index++) {
        if (object->ObjectInfo->objectType == g_obj_attr_conf[index].type)
            config = &g_obj_attr_conf[index];
    }
    return config;
}

TEE_Result check_object_valid(TEE_ObjectHandle object)
{
    if (object == TEE_HANDLE_NULL) {
        tloge("Bad Parameter:ObjectHandle is NULL!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (check_object(object) != TEE_SUCCESS) {
        tloge("Object is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (object->ObjectInfo == NULL) {
        tloge("Object is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}
