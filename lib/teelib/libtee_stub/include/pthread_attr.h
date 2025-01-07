/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
