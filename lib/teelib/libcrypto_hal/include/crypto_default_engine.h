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
#ifndef CRYPTO_DEFAULT_ENGINE_H
#define CRYPTO_DEFAULT_ENGINE_H

#include <crypto_driver_adaptor.h>

#define DX_CRYPTO   0
#define EPS_CRYPTO  1
#define SOFT_CRYPTO 2
#define SEC_CRYPTO  3

struct algorithm_engine_t {
    uint32_t             algorithm;
    uint32_t             engine;
};

const struct algorithm_engine_t g_algorithm_engine[] = {
    { 0,       SOFT_CRYPTO },
};
const struct algorithm_engine_t g_generate_key_engine[] = {
    { 0,       SOFT_CRYPTO },
};

#endif
