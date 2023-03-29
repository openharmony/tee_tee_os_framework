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
#include "crypto_hal_hmac.h"
#include <tee_log.h>
#include <tee_crypto_hal.h>
#include "crypto_manager.h"
#include "crypto_hal.h"
#include "soft_hmac.h"

struct ctx_handle_t *tee_crypto_hmac_init(uint32_t alg_type, const struct symmerit_key_t *key, uint32_t engine)
{
    if (key == NULL) {
        tloge("Invalid key\n");
        return NULL;
    }

    struct ctx_handle_t *ctx = alloc_ctx_handle(alg_type, engine);
    if (ctx == NULL) {
        tloge("Malloc ctx handle failed\n");
        return NULL;
    }

    int32_t ret;
    if (engine == SOFT_CRYPTO)
        ret = soft_crypto_hmac_init(ctx, key);
    else
        ret = crypto_driver_hmac_init(ctx, key);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Hmac init failed, ret=%d\n", ret);
        tee_crypto_ctx_free(ctx);
        return NULL;
    }

    return ctx;
}

int32_t tee_crypto_hmac_update(struct ctx_handle_t *ctx, const struct memref_t *data_in)
{
    bool check = ((ctx == NULL) || (data_in == NULL));
    if (check) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (ctx->engine == SOFT_CRYPTO)
        return soft_crypto_hmac_update(ctx, data_in);

    return crypto_driver_hmac_update(ctx, data_in);
}

int32_t tee_crypto_hmac_dofinal(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    bool check = ((ctx == NULL) || (data_out == NULL));
    if (check) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    int32_t rc = CRYPTO_SUCCESS;
    check = (data_in != NULL && data_in->buffer != 0 && data_in->size != 0);
    if (check)
        rc = tee_crypto_hmac_update(ctx, data_in);

    if (rc != CRYPTO_SUCCESS) {
        tloge("hmac update failed, rc = %d", rc);
        return rc;
    }

    if (ctx->engine == SOFT_CRYPTO)
        return soft_crypto_hmac_dofinal(ctx, data_out);

    return crypto_driver_hmac_dofinal(ctx, NULL, data_out);
}

int32_t tee_crypto_hmac(uint32_t alg_type, const struct symmerit_key_t *key,
    const struct memref_t *data_in, struct memref_t *data_out, uint32_t engine)
{
    bool check = ((data_in == NULL) || (data_out == NULL));
    if (check) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    if (engine == SOFT_CRYPTO)
        return soft_crypto_hmac(alg_type, key, data_in, data_out);

    return crypto_driver_hmac(alg_type, key, data_in, data_out, engine);
}

