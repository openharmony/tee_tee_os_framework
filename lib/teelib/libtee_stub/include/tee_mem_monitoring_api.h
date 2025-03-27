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

#ifndef TEE_MEM_MONITORING_API_H
#define TEE_MEM_MONITORING_API_H

/**
 * @addtogroup TeeTrusted
 * @{
 *
 * @brief TEE(Trusted Excution Environment) API.
 * Provides security capability APIs such as trusted storage, encryption and decryption,
 * and trusted time for trusted application development.
 *
 * @since 12
 */

/**
 * @file tee_mem_monitoring_api.h
 *
 * @brief Provides APIs for memory monitoring.
 *
 * @library NA
 * @kit TEE Kit
 * @syscap SystemCapability.Tee.TeeClient
 * @since 12
 * @version 1.0
 */

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Obtains the heap usage of this trusted application (TA).
 *
 * @param show Indicates whether to print the result in the log file.
 *
 * @return Returns the heap usage in percentage.
 *
 * @since 12
 * @version 1.0
 */
uint32_t get_heap_usage(bool show);

#ifdef __cplusplus
}
#endif
/** @} */
#endif
