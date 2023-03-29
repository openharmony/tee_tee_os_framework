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

#ifndef __CRYPTO_INNER_DEFINES_H_
#define __CRYPTO_INNER_DEFINES_H_

#include <tee_crypto_api.h>
#define SIP_HASH_OUTPUT_LEN                 8
#define MD5_OUTPUT_LEN                      16
#define SHA1_OUTPUT_LEN                     20
#define SHA224_OUTPUT_LEN                   28
#define SHA256_OUTPUT_LEN                   32
#define SHA384_OUTPUT_LEN                   48
#define SHA512_OUTPUT_LEN                   64
#define DIGEST_NO_ALLOC_CTX                 0
#define DIGEST_ALLOC_CTX                    1
#define PKCS5_PADDING_LEN                   16
#define LISENCE_KEY                         0
#define SESSION_KEY                         1
#define MAX_MALLOC_LEN                      (500 * 1024 + 1)
#define MAX_DX_ASYMMETRIC_KEY_SIZE          3072
#define BIT_TO_BYTE                         8
#define AES_IV_LEN                          16
#define DES_IV_LEN                          8
#define DES_BLOCK_SIZE                      8
#define ECC_MAX_KEY_IN_BYTE                 66
#define ECC_SPECIAL_KEY_LEN_IN_BYTE         66
#define ECC_SPECIAL_KEY_LEN_IN_BITS         521
#define BYTE_TO_WORD                        4
#define AES_KEY_SIZE_128                    16
#define AES_KEY_SIZE_192                    24
#define AES_KEY_SIZE_256                    32
#define AES_KEY_SIZE_512                    64
#define DES_KEY_64                          8
#define DES_KEY_128                         16
#define DES_KEY_192                         24
#define AES_MAC_LEN                         16
#define DES_CMAC_LEN                        8
#define RSA_V1_5_PADDING                    11
#define DH_ATTRIBUTE_TOTAL                  6
#define PBKDF2_ATTRIBUTE_TOTAL              3
#define CTX_OFF_SET                         256
#define RSA_KEY_MIN                         2048
#define RSA_KEY_MAX                         4096
#define RSA_KEY_BLOCK                       128
#define ECDSA_KEY_224                       224
#define ECDSA_KEY_256                       256
#define ECDSA_KEY_320                       320
#define ECDSA_KEY_384                       384
#define ECDSA_KEY_521                       521
#define MALLOC_MAX_KEY_SIZE                 1024
#define DH_MIN_KEY_SIZE                     32
#define DH_MAX_KEY_SIZE                     256
#define MAX_IV_LEN                          32
#define RSA_MIN_KEY_SIZE                    256
#define ECDH_MIN_KEY_SIZE                   28
#define ECDSA_MIN_KEY_SIZE                  28
#define PBKDF2_MIN_KEY_SIZE                 14
#define PBKDF2_MAX_KEY_SIZE                 1024
#define HMAC_MIN_KEY                        64
#define HMAC_MAX_KEY                        (1024 * 8)
#define HMAC_SM3_MIN_KEY                    80
#define HMAC_SM3_MAX_KEY                    1024
#define SM4_KEY_SIZE                        128
#define AES_BLOCK_SIZE                      16
#define DH_BLOCK_SIZE                       8
#define MAX_HMAC_LEN                        64
#define RSA_PKCS1_PADDING_LEN               2
#define RSA_KEY_PAIR_ATTRIBUTE_COUNT        8
#define RSA_PRIV_KEY_ATTRIBUTE_COUNT        3
#define RSA_KEY_PAIR_ATTRIBUTE_COUNT_NO_CRT 3
#define BIT_NUMBER_SEVEN                    7
#define BIT_TO_BYTE_MOVE_THREE              3
#define EC_KEY_FIX_BUFFER_LEN               66
#define RSA_PUB_KEY_ATTRIBUTE_COUNT         2
#define RSA_CRT_KEY_ATTRIBUTE_COUNT         5
#define RSA_CRT_KEY_BASE_INDEX              3
#define UINT32_SIZE                         4
#define DH_MAX_KEY_SIZE                     256
#define SM2_GROUP_NOSTANDARD                0x12
#define SM2_GROUP_NOSTANDARD_USER           2
#define MAX_EXTRA_PARAM_COUNT               10
#define MAX_KDF_PARAM_COUNT                 9
#define UINT32_SHIFT_MAX                    4
#define MAX_ATTR_LEN                        8
#define AES_GCM_AAD_LEN                     16
#define RSA_FACTOR_P_INDEX                  0
#define RSA_FACTOR_Q_INDEX                  1
#define RSA_CRT_DMP1                        2
#define RSA_CRT_DMQ1                        3
#define RSA_CRT_IQMP                        4
#define MAX_MODE_NUM                        2
#define ELEM_NUM(array)                     (sizeof(array) / sizeof((array)[0]))

struct min_size_of_algorithm {
    uint32_t algorithm;
    size_t output_lower_limit;
};

const static struct min_size_of_algorithm g_output_lower_limit[] = {
    { TEE_ALG_MD5,                MD5_OUTPUT_LEN },
    { TEE_ALG_SHA1,               SHA1_OUTPUT_LEN },
    { TEE_ALG_SHA224,             SHA224_OUTPUT_LEN },
    { TEE_ALG_SHA256,             SHA256_OUTPUT_LEN },
    { TEE_ALG_SHA384,             SHA384_OUTPUT_LEN },
    { TEE_ALG_SHA512,             SHA512_OUTPUT_LEN },
    { TEE_ALG_SM3,                SHA256_OUTPUT_LEN },
    { TEE_ALG_HMAC_MD5,           MD5_OUTPUT_LEN },
    { TEE_ALG_HMAC_SHA1,          SHA1_OUTPUT_LEN },
    { TEE_ALG_HMAC_SHA224,        SHA224_OUTPUT_LEN },
    { TEE_ALG_HMAC_SHA256,        SHA256_OUTPUT_LEN },
    { TEE_ALG_HMAC_SHA384,        SHA384_OUTPUT_LEN },
    { TEE_ALG_HMAC_SHA512,        SHA512_OUTPUT_LEN },
    { TEE_ALG_HMAC_SM3,           SHA256_OUTPUT_LEN },
    { TEE_ALG_AES_CMAC,           AES_MAC_LEN },
    { TEE_ALG_AES_CBC_MAC_NOPAD,  AES_MAC_LEN },
    { TEE_ALG_DES_CBC_MAC_NOPAD,  DES_CMAC_LEN },
    { TEE_ALG_DES3_CBC_MAC_NOPAD, DES_CMAC_LEN },
    { TEE_ALG_SIP_HASH,           SIP_HASH_OUTPUT_LEN },
};

typedef struct {
    uint32_t crypto_flag;
    uint32_t digestalloc_flag;
    uint32_t cipher_update_len;
} crypto_hal_info;

TEE_Result change_hal_ret_to_gp(int32_t error);
uint32_t get_ecc_domain(uint32_t curve);
uint32_t get_sm2_domain(uint32_t curve);
TEE_Result get_tee_curve_by_keysize(uint32_t keySize, uint32_t *curve);
int32_t get_attr_index_by_id(uint32_t id, const TEE_Attribute *attrs, uint32_t attrCount);
TEE_Result crypto_lock_operation(TEE_OperationHandle operation);
void crypto_unlock_operation(TEE_OperationHandle operation);
TEE_Result crypto_lock_two_operation(TEE_OperationHandle op1, TEE_OperationHandle op2);
void crypyo_unlock_two_operation(TEE_OperationHandle op1, TEE_OperationHandle op2);
void free_operation_ctx(TEE_OperationHandle operation);
void fill_src_dest_param(operation_src_dest *src_dest_param, void *src_data_value, size_t src_len_value,
    void *dest_data_value, size_t *dest_len_value);
#endif
