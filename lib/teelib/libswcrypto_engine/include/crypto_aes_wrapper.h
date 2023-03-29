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
#ifndef __CRYPTO_AES_WRAPPER_H__
#define __CRYPTO_AES_WRAPPER_H__

#include <stdint.h>
#include <tee_defines.h>
#include <chinadrm.h>

TEE_Result aes_key_wrap(struct cdrm_params *params);
TEE_Result aes_key_unwrap(struct cdrm_params *params);
#endif
