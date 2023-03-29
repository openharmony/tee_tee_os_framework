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
#include <stdint.h>
#include <openssl/err.h>
#include <tee_crypto_err.h>
#include <tee_err.h>
#include <tee_log.h>

struct crypto_err_lib_t {
    int32_t opensource_err_lib;
    int32_t crypt_err_lib;
};

static struct crypto_err_lib_t g_crypto_err_lib[] = {
    { ERR_LIB_BN,     BN_LIB_ERR_ID     },
    { ERR_LIB_RSA,    RSA_LIB_ERR_ID    },
    { ERR_LIB_EVP,    EVP_LIB_ERR_ID    },
    { ERR_LIB_PEM,    PEM_LIB_ERR_ID    },
    { ERR_LIB_X509,   X509_LIB_ERR_ID   },
    { ERR_LIB_ASN1,   ASN1_LIB_ERR_ID   },
    { ERR_LIB_CRYPTO, CRYPTO_LIB_ERR_ID },
    { ERR_LIB_EC,     EC_LIB_ERR_ID     },
    { ERR_LIB_PKCS7,  PKCS7_LIB_ERR_ID  },
};

int32_t get_soft_crypto_error(int32_t tee_error)
{
    uint32_t err_status = (uint32_t)ERR_peek_last_error();
    int32_t engine_error = ERR_GET_REASON(err_status);
    if (engine_error == 0)
        return tee_error;

    int32_t lib_error_id = ERR_GET_LIB(err_status);

    /* clear opensource lib err state */
    ERR_clear_error();

    /* for common err(<100), opensource err lib was merged into COMM_LIB_ERR_ID */
    if (engine_error <= MAX_COMMON_CRYPTO_ENGINE_ERR)
        return TEE_EXT_ERROR_BASE | CRYPTO_MODULE_ERR_ID | COMM_LIB_ERR_ID | (uint32_t)engine_error;

    for (size_t i = 0; i < sizeof(g_crypto_err_lib) / sizeof(g_crypto_err_lib[0]); i++) {
        if (lib_error_id == g_crypto_err_lib[i].opensource_err_lib)
            return TEE_EXT_ERROR_BASE | CRYPTO_MODULE_ERR_ID |
                   (uint32_t)g_crypto_err_lib[i].crypt_err_lib | (uint32_t)engine_error;
    }

    return TEE_EXT_ERROR_BASE | CRYPTO_MODULE_ERR_ID | OTHER_LIB_ERR_ID | (uint32_t)engine_error;
}
