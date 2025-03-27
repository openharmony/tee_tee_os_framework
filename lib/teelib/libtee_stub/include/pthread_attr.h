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
#ifndef PTHREAD_ATTR_H
#define PTHREAD_ATTR_H

#include <pthread.h>

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
 * @file pthread_attr.h
 *
 * @brief Provides the attr about TA multi-thread.
 *
 * @library NA
 * @kit TEEKit
 * @syscap SystemCapability.Tee.TeeClient
 * @since 12
 * @version 1.0
 */

#define TEESMP_THREAD_ATTR_CA_WILDCARD 0

#define TEESMP_THREAD_ATTR_CA_INHERIT (-1U)

#define TEESMP_THREAD_ATTR_TASK_ID_INHERIT (-1U)

#define TEESMP_THREAD_ATTR_HAS_SHADOW 0x1

#define TEESMP_THREAD_ATTR_NO_SHADOW 0x0

int pthread_attr_settee(pthread_attr_t *, int ca, int task_id, int shadow);
/** @} */
#endif
