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
#include <dlfcn.h>
#include <securec.h>
#include <tee_log.h>
#include <tee_crypto_hal.h>
#include <crypto_hal_hmac.h>
#include <crypto_hal_hash.h>
#include <oemkey.h>
#include "crypto_inner_interface.h"

static int32_t get_derived_key(uint8_t *tmp_key,  uint8_t *priv, uint32_t priv_len)
{
    struct memref_t data_in = {0};
    struct memref_t data_out = {0};
    uint8_t derived_key[SHA256_LEN] = {0};
    data_in.buffer = (uint64_t)(uintptr_t)tmp_key;
    data_in.size = OEM_KEY_LEN;
    data_out.buffer = (uint64_t)(uintptr_t)derived_key;
    data_out.size = SHA256_LEN;
    (void)tee_crypto_hash(CRYPTO_TYPE_DIGEST_SHA256, &data_in, &data_out, SOFT_CRYPTO);

    errno_t ret_s = memcpy_s(priv, priv_len, derived_key, SHA256_LEN);
    (void)memset_s(derived_key, SHA256_LEN, 0, SHA256_LEN);
    if (ret_s != EOK)
        return -1;

    return 0;
}

int32_t get_class_ecc_key(uint8_t *priv, uint32_t priv_len)
{
    uint32_t ret;
    uint8_t tmp_key[OEM_KEY_LEN] = {0};
    bool check = (priv == NULL || priv_len != SHA256_LEN);
    if (check) {
        tloge("invalid parameters\n");
        return -1;
    }

    ret = tee_hal_get_provision_key(tmp_key, OEM_KEY_LEN);
    if (ret) {
        tloge("get provision data failed\n");
        return -1;
    }

    ret = (uint32_t)get_derived_key(tmp_key, priv, priv_len);
    (void)memset_s(tmp_key, OEM_KEY_LEN, 0, OEM_KEY_LEN);
    return (int32_t)ret;
}
