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

#ifndef TEE_ERROR_H
#define TEE_ERROR_H

#include <tee_crypto_err.h>

/*
 * notes: all extension tee error rule is TEE_EXT_ERROR_BASE | xx_MODULE_ERR_ID | base_error_value,
 * For example, the crypto module extension error codes are prefixed with 0x8002.
 */
#define TEE_EXT_ERROR_BASE 0x80000000

enum ext_error_module {
    SSA_MODULE_ERR_ID    = 0x010000,
    CRYPTO_MODULE_ERR_ID = 0x020000,
};

#endif
