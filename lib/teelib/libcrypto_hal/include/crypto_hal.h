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
#ifndef CRYPTO_HAL_H
#define CRYPTO_HAL_H

#include <stdbool.h>
#include <tee_mem_mgmt_api.h>
#include <crypto_driver_adaptor.h>

#define CRYPTO_PADDING_LEN    16
#define MAX_CRYPTO_DATA_LEN   (500 * 1024)
#define MAX_RANDOM_SIZE       0x100000

#define MAX_CRYPTO_RANDOM_LEN (500 * 1024)
#define MAX_CRYPTO_CTX_SIZE   (1024 * 1024)
#define TYPE_DRV_OPEN          2


struct crypto_cache_t {
    void *buffer;
    uint32_t total_len;
    uint32_t effective_len;
};

struct ctx_handle_t *alloc_ctx_handle(uint32_t alg_type, uint32_t engine);
int32_t tee_crypto_ctx_copy(const struct ctx_handle_t *src_ctx, struct ctx_handle_t *dest_ctx);
void tee_crypto_ctx_free(struct ctx_handle_t *ctx);
void tee_crypto_free_sharemem(struct ctx_handle_t *ctx);
int32_t tee_crypto_generate_random(void *buffer, uint32_t size, bool is_hw_rand);
int32_t tee_crypto_check_alg_support(uint32_t alg_type);
struct ctx_handle_t *driver_alloc_ctx_handle(uint32_t alg_type, uint32_t engine, struct ctx_handle_t *ctx);
int64_t get_ctx_fd_handle(uint32_t alg_type, bool is_copy_ctx);
int32_t driver_ctx_buffer_prepare(const struct ctx_handle_t *src_ctx, struct ctx_handle_t *dest_ctx);
#ifdef OPENSSL_ENABLE
void tee_crypto_free_openssl_drbg(void);
#endif
#endif
