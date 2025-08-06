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

#ifndef TEE_HW_EXT_API_H
#define TEE_HW_EXT_API_H

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
 * @file tee_hw_ext_api.h
 *
 * @brief Provides extended interfaces.
 *
 * @library NA
 * @kit TEE Kit
 * @syscap SystemCapability.Tee.TeeClient
 * @since 12
 * @version 1.0
 */

#include "tee_defines.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Obtains the unique device ID from the TEE.
 *
 * @param device_unique_id Indicates the pointer to the buffer for storing the device ID.
 * @param length Indicates the pointer to the buffer length.
 *
 * @return Returns <b>TEE_SUCCESS</b> if the operation is successful.
 * @return Returns other information otherwise.
 *
 * @since 20
 */
TEE_Result tee_ext_get_device_unique_id(uint8_t *device_unique_id, uint32_t *length);

/**
 * @brief Defines the memory information.
 *
 * @since 20
 */
struct meminfo_t {
    /** Pointer to the memory buffer. */
    uint64_t buffer;
    /** The size of the memory. */
    uint32_t size;
};

/**
 * @brief Derive key from device rootkey and UUID of the current task for iteration.
 *
 * @param salt [IN] Indicates the data for salt.
 * @param key [OUT] Indicates the pointer where key is saved.
 * @param outer_iter_num [IN] Indicates the iteration times in huk service.
 * @param inner_iter_num [IN] Indicates the iteration times in platform driver.
 *
 * @return Returns {@code TEE_SUCCESS} if the operation is successful.
 *         Returns {@code TEE_ERROR_BAD_PARAMETERS} if input parameter is incorrect.
 *         Returns {@code TEE_ERROR_GENERIC} if the processing failed.
 *
 * @since 20
 */
TEE_Result tee_ext_derive_key_iter(const struct meminfo_t *salt, struct meminfo_t *key,
    uint32_t outer_iter_num, uint32_t inner_iter_num);

/**
 * @brief Derive key from device rootkey and UUID of the current task for iteration by huk2 encryption.
 *
 * @param salt [IN] Indicates the data for salt.
 * @param key [OUT] Indicates the pointer where key is saved.
 * @param outer_iter_num [IN] Indicates the iteration times in huk service.
 * @param inner_iter_num [IN] Indicates the iteration times in platform driver.
 *
 * @return Returns {@code TEE_SUCCESS} if the operation is successful.
 *         Returns {@code TEE_ERROR_BAD_PARAMETERS} if input parameter is incorrect.
 *         Returns {@code TEE_ERROR_GENERIC} if the processing failed.
 *
 * @since 20
 */
TEE_Result tee_ext_derive_key_iter_by_huk2(const struct meminfo_t *salt, struct meminfo_t *key,
    uint32_t outer_iter_num, uint32_t inner_iter_num);

/**
 * @brief Derive key from device root key by HUK2.
 * @attention If the device does not support HUK2, the key is derived by HUK.
 *
 * @param salt [IN] Indicates the data for salt.
 * @param size [IN] Indicates the length of salt.
 * @param key [OUT] Indicates the pointer where key is saved.
 * @param key_size [IN] Indicates the size of the key, which must be integer times of 16.
 *
 * @return Returns {@code TEE_SUCCESS} if the operation is successful.
 *         Returns {@code TEE_ERROR_BAD_PARAMETERS} if input parameter is incorrect.
 *         Returns {@code TEE_ERROR_GENERIC} if the processing failed.
 *
 * @since 20
 * @version 1.0
 */
TEE_Result tee_ext_derive_ta_root_key_by_huk2(const uint8_t *salt, uint32_t size, uint8_t *key, uint32_t key_size);

/**
 * @brief derive key from device rootkey and UUID of the current task for iteration using huk2 enhance
 *
 * @param salt [IN] data for salt
 * @param key [OUT] pointer where key is saved
 * @param outer_iter_num [IN] iteration times in huk service
 * @param inner_iter_num  [IN] iteration times in platdrv
 *
 * @return Returns {@code TEE_SUCCESS} if the operation is successful.
 *         Returns {@code TEE_ERROR_BAD_PARAMETERS} if input parameter is illegal.
 *         Returns {@code TEE_ERROR_GENERIC} if the processing failed.
 *
 * @since 20
 * @version 1.0
 */
TEE_Result tee_ext_derive_key_iter_by_huk2_enhance(const struct meminfo_t *salt, struct meminfo_t *key,
    uint32_t outer_iter_num, uint32_t inner_iter_num);

#ifdef __cplusplus
}
#endif
/** @} */
#endif