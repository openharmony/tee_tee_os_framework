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
#ifndef CRYPTO_MGR_SYSCALL_H
#define CRYPTO_MGR_SYSCALL_H

#include <stdint.h>
#include <stdbool.h>
#include "tee_driver_module.h"

#define AES_MAC_LEN          16
#define CIPHER_CACHE_LEN     16
#define CACHED_RANDOM_SIZE   4096
#define ONE_BLOCK_SIZE       16
#define TOTAL_RANDOM_BLOCK   (CACHED_RANDOM_SIZE / ONE_BLOCK_SIZE)

#define CRYPTO_SECRET_OFFSET_0      0
#define CRYPTO_SIGNATURE_OFFSET_0   0
#define CRYPTO_DATA_OUT_OFFSET_0    0
#define CRYPTO_DATA_OUT_OFFSET_1    1
#define CRYPTO_E_VALUE_OFFSET_1     1
#define CRYPTO_TAG_OUT_OFFSET_1     1
#define CRYPTO_TAG_OUT_OFFSET_2     2
#define CRYPTO_IV_OFFSET_1          1
#define CRYPTO_IV_OFFSET_2          2
#define CRYPTO_IV_OFFSET_3          3
#define CRYPTO_PARAM_COUNT_1        1
#define CRYPTO_PARAM_COUNT_2        2
#define CRYPTO_PARAM_COUNT_3        3
#define CRYPTO_PARAM_COUNT_4        4
#define CRYPTO_PARAM_COUNT_5        5
#define CRYPTO_PARAM_COUNT_MAX      5
#define SHARE_MEMORY_MAX_SIZE       (10 * 1024 * 1024) /* shared mem max size 10M */
#define INVALID_MEMORY_SIZE         0xFFFFFFFF
#define MAX_CRYPTO_CTX_SIZE   (1024 * 1024)
#define DATA_SIZE_MAX         512

struct crypto_ioctl {
    uint64_t buf;
    uint32_t buf_len;
    uint32_t total_nums;
    uint8_t data_1[DATA_SIZE_MAX];
    uint8_t data_2[DATA_SIZE_MAX];
    uint32_t data_size_1;
    uint32_t data_size_2;
    uint32_t arg1;
    uint32_t arg2;
    uint32_t arg3;
    uint32_t arg4;
    uint32_t arg5;
    uint32_t arg6;
    uint32_t arg7;
    uint32_t arg8;
};

/* CRYPTO HAL */
enum crypto_hal {
    IOCTRL_CRYPTO_BASE =                 0xc700,
    IOCTRL_CRYPTO_GET_CTX_SIZE =         0xc701,
    IOCTRL_CRYPTO_CTX_COPY =             0xc702,
    IOCTRL_CRYPTO_HASH_INIT =            0xc703,
    IOCTRL_CRYPTO_HASH_UPDATE =          0xc704,
    IOCTRL_CRYPTO_HASH_DOFINAL =         0xc705,
    IOCTRL_CRYPTO_HASH =                 0xc706,
    IOCTRL_CRYPTO_HMAC_INIT =            0xc707,
    IOCTRL_CRYPTO_HMAC_UPDATE =          0xc708,
    IOCTRL_CRYPTO_HMAC_DOFINAL =         0xc709,
    IOCTRL_CRYPTO_HMAC =                 0xc70a,
    IOCTRL_CRYPTO_CIPHER_INIT =          0xc70b,
    IOCTRL_CRYPTO_CIPHER_UPDATE =        0xc70c,
    IOCTRL_CRYPTO_CIPHER_DOFINAL =       0xc70d,
    IOCTRL_CRYPTO_CIPHER =               0xc70e,
    IOCTRL_CRYPTO_AE_INIT =              0xc70f,
    IOCTRL_CRYPTO_AE_UPDATE_AAD =        0xc710,
    IOCTRL_CRYPTO_AE_UPDATE =            0xc711,
    IOCTRL_CRYPTO_AE_ENC_FINAL =         0xc712,
    IOCTRL_CRYPTO_AE_DEC_FINAL =         0xc713,
    IOCTRL_CRYPTO_RSA_GENERATE_KEYPAIR = 0xc714,
    IOCTRL_CRYPTO_RSA_ENCRYPT =          0xc715,
    IOCTRL_CRYPTO_RSA_DECRYPT =          0xc716,
    IOCTRL_CRYPTO_RSA_SIGN_DIGEST =      0xc717,
    IOCTRL_CRYPTO_RSA_VERIFY_DIGEST =    0xc718,
    IOCTRL_CRYPTO_ECC_GENERATE_KEYPAIR = 0xc719,
    IOCTRL_CRYPTO_ECC_ENCRYPT =          0xc71a,
    IOCTRL_CRYPTO_ECC_DECRYPT =          0xc71b,
    IOCTRL_CRYPTO_ECC_SIGN_DIGEST =      0xc71c,
    IOCTRL_CRYPTO_ECC_VERIFY_DIGEST =    0xc71d,
    IOCTRL_CRYPTO_ECDH_DERIVE_KEY =      0xc71e,
    IOCTRL_CRYPTO_DH_GENERATE_KEY =      0xc71f,
    IOCTRL_CRYPTO_DH_DERIVE_KEY =        0xc720,
    IOCTRL_CRYPTO_GENERATE_RANDOM =      0xc721,
    IOCTRL_CRYPTO_DERIVE_ROOT_KEY =      0xc722,
    IOCTRL_CRYPTO_PBKDF2 =               0xc723,
    IOCTRL_CRYPTO_GET_DRV_ABILITY =      0xc724,
    IOCTRL_CRYPTO_GET_ENTROPY =          0xc725,
    IOCTRL_CRYPTO_LOAD_DRV    =          0xc726,
    IOCTRL_CRYPTO_CHECK_ALG_SUPPORT  =   0xc727,
    IOCTRL_CRYPTO_GET_OEMKEY         =   0xc728,
    IOCTRL_CRYPTO_MAX =                  0xc729
};

int32_t crypto_ioctl_func(const struct drv_data *drv, uint32_t cmd, unsigned long args, uint32_t args_len);
uint8_t *get_ctx_ctx_buf(void);
int32_t crypto_ioctl_suspend(void);
int32_t crypto_ioctl_resume(void);

#endif
