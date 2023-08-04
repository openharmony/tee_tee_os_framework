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

#include <stdio.h>
#include "crypto/rand_pool.h"
#include "openssl/crypto.h"
#include "openssl/types.h"

#ifdef OPENSSL_RAND_SEED_ENTROPY_CUSTOMER
size_t rand_acquire_entropy_from_customer(RAND_POOL *pool)
{
    size_t bytes_needed;
    unsigned char *buffer;
    int ret;

    bytes_needed = ossl_rand_pool_bytes_needed(pool, 1);
    if (bytes_needed > 0) {
        buffer = ossl_rand_pool_add_begin(pool, bytes_needed);
        if (buffer != NULL){
            ret = (int)OPENSSL_RAND_SEED_ENTROPY_CUSTOMER(buffer, (uint32_t)bytes_needed);
            if (ret == 0)
                ossl_rand_pool_add_end(pool, bytes_needed, 8 * bytes_needed);
        }
    }
    return ossl_rand_pool_entropy_available(pool);
}

size_t ossl_pool_acquire_entropy(RAND_POOL *pool)
{
    size_t entropy_available;
    entropy_available = rand_acquire_entropy_from_customer(pool);
    if (entropy_available > 0)
        return entropy_available;
    return 0;
}
#endif

int ossl_pool_add_nonce_data(RAND_POOL *pool)
{
    struct data_t {
        pid_t pid;
        CRYPTO_THREAD_ID tid;
        uint64_t time;
    };
    struct data_t *data = malloc(sizeof(struct data_t));
    if (data == NULL)
        return 0;
    (void)memset(data, 0, sizeof(struct data_t));
    return ossl_rand_pool_add(pool, (unsigned char *)&data, sizeof(struct data_t), 0);
}
