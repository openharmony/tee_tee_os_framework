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

#ifndef __TEE_RTC_TIME_API_H
#define __TEE_RTC_TIME_API_H

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
 * @file tee_rtc_time_api.h
 *
 * @brief Provides APIs about rtc timer.
 *
 * @library NA
 * @kit TEE Kit
 * @syscap SystemCapability.Tee.TeeClient
 * @since 12
 * @version 1.0
 */

#include <tee_defines.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create a secure timer.
 *
 * @param time_seconds Indicates the security duration.
 * @param timer_property Indicates the property of the timer, where only need to specify the timer type.
 *
 * @return Returns <b>TEE_SUCCESS</b> if the operation is successful.
 * @return Returns other values if the operation fails.
 *
 * @since 12
 * @version 1.0
 */
TEE_Result tee_ext_create_timer(uint32_t time_seconds, TEE_timer_property *timer_property);

/**
 * @brief Destory a secure timer.
 *
 * @param timer_property Indicates the property of the timer, where only need to specify the timer type.
 *
 * @return Returns <b>TEE_SUCCESS</b> if the operation is successful.
 * @return Returns other values if the operation fails.
 *
 * @since 12
 * @version 1.0
 */
TEE_Result tee_ext_destory_timer(TEE_timer_property *timer_property);

/**
 * @brief Obtain the set timing duration.
 *
 * @param timer_property Indicates the property of the timer, where only need to specify the timer type.
 * @param time_seconds Indicates the timing duration.
 *
 * @return Returns <b>TEE_SUCCESS</b> if the operation is successful.
 * @return Returns other values if the operation fails.
 *
 * @since 12
 * @version 1.0
 */
TEE_Result tee_ext_get_timer_expire(TEE_timer_property *timer_property, uint32_t *time_seconds);

/**
 * @brief Obtain the remain timing duration.
 *
 * @param timer_property Indicates the property of the timer, where only need to specify the timer type.
 * @param time_seconds Indicates the remain timing duration.
 *
 * @return Returns <b>TEE_SUCCESS</b> if the operation is successful.
 * @return Returns other values if the operation fails.
 *
 * @since 12
 * @version 1.0
 */
TEE_Result tee_ext_get_timer_remain(TEE_timer_property *timer_property, uint32_t *time_seconds);

/**
 * @brief Obtain the current timing of the RTC clock.
 * @attention The obtained time is in seconds and cannot be converted to universal time.
 *
 * @return The RTC clock count(in seconds).
 *
 * @since 12
 * @version 1.0
 */
unsigned int tee_get_secure_rtc_time(void);
#ifdef __cplusplus
}
#endif
/** @} */
#endif