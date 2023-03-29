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
#ifndef CRYPTO_SYSCALL_TYPES_H
#define CRYPTO_SYSCALL_TYPES_H

#include <stdint.h>

#define AES_KEY_BYTES_16     16
#define AES_KEY_BYTES_24     24
#define AES_KEY_BYTES_32     32
#define AES_KEY_BYTES_64     64

struct rsa_private_key_size_ptr {
    uint32_t p_size_low;
    uint32_t p_size_high;
    uint32_t q_size_low;
    uint32_t q_size_high;
    uint32_t dp_size_low;
    uint32_t dp_size_high;
    uint32_t dq_size_low;
    uint32_t dq_size_high;
    uint32_t qinv_size_low;
    uint32_t qinv_size_high;
};
struct dh_key_t {
    uint32_t client_privatekey_ptr_low;
    uint32_t client_privatekey_ptr_high;
    uint32_t client_privatekey_size_ptr_low;
    uint32_t client_privatekey_size_ptr_high;
    uint32_t client_pub1_ptr_low;
    uint32_t client_pub1_ptr_high;
    uint32_t client_pub_size_ptr_low;
    uint32_t client_pub_size_ptr_high;
};
struct ccm_size_t {
    uint32_t keysize_id;
    uint8_t size_of_n;
    uint32_t aad_size;
    uint32_t data_in_size;
    uint8_t size_of_tag;
};
struct sm4_param_t {
    uint32_t pkey_low;
    uint32_t pkey_high;
    uint32_t pkey_len;
    uint32_t iv_low;
    uint32_t iv_high;
    uint32_t iv_len;
    uint32_t input_buffer_low;
    uint32_t input_buffer_high;
    uint32_t input_len;
    uint32_t output_buffer_low;
    uint32_t output_buffer_high;
    uint32_t output_len_low;
    uint32_t output_len_high;
    uint32_t context_low;
    uint32_t context_high;
    uint32_t alg;
};

struct decrypt_wraper_t {
    uint32_t hash_func;
    uint32_t l_len;
    uint32_t mgf;
    uint32_t data_in_size;
    uint32_t pkcs1_ver;
};

struct private_key_crt_size_t {
    uint32_t p_size;
    uint32_t q_size;
    uint32_t dp_size;
    uint32_t dq_size;
    uint32_t q_inv_size;
};

struct cdrm_trans_params {
    uint64_t pkey;
    uint64_t iv;
    uint64_t input_buffer;
    uint64_t output_buffer;
    uint64_t output_len;
    uint64_t context;
    uint32_t pkey_len;
    uint32_t iv_len;
    uint32_t input_len;
    uint32_t alg;
};
#endif
