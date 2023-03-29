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
#ifndef EC_WRAPPER_H
#define EC_WRAPPER_H
struct ecc_derive_public_key_t {
    BIGNUM *priv_bn;
    EC_POINT *pub_pt;
    EC_GROUP *group;
    BIGNUM *x_bn;
    BIGNUM *y_bn;
    BN_CTX *ctx;
};

struct derive_ecc_private_key_from_huk_t {
    BIGNUM *x;
    BIGNUM *ord;
    BN_CTX *ctx;
};
#endif

