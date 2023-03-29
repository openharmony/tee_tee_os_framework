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
#ifndef __CRYPTO_INNER_WRAPPER_H__
#define __CRYPTO_INNER_WRAPPER_H__

#include <stdint.h>
#include <tee_defines.h>

/*
 * Get common name from certificate.
 *
 * @param name      [OUT]    The common name buffer
 * @param name_size [IN/OUT] The length of common name buffer
 * @param cert      [IN]     The certificate buffer
 * @param cert_len  [IN]     The length of certificate buffer
 *
 * @return -1: Get common name failed
 * @return  others: Get common name success
 */
int32_t get_subject_CN(uint8_t *name, uint32_t name_size, const uint8_t *cert, uint32_t cert_len);

/*
 * Get organization name from certificate.
 *
 * @param name      [OUT]    The organization name buffer
 * @param name_size [IN/OUT] The length of organization name buffer
 * @param cert      [IN]     The certificate buffer
 * @param cert_len  [IN]     The length of certificate buffer
 *
 * @return -1: Get organization name failed
 * @return  others: Get organization name success
 */
int32_t get_subject_OU(uint8_t *name, uint32_t name_size, const uint8_t *cert, uint32_t cert_len);

#endif
