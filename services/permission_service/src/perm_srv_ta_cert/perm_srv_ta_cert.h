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
#ifndef PERM_SRV_TA_CERT_H
#define PERM_SRV_TA_CERT_H

#include <tee_defines.h>
#include <crypto_wrapper.h>
#include <ta_config_builder.h>

#define MAX_CERT_LEN 2048
#define MAX_PUBKEY_LEN 1024

TEE_Result perm_srv_export_cert_from_storage(uint8_t *dst, uint32_t *dst_len, uint32_t limit);
TEE_Result perm_srv_import_cert_to_storage(const uint8_t *src, size_t len);
TEE_Result perm_srv_remove_cert_from_storage(void);

void perm_srv_cert_expiration_alarm(const TEE_Date_Time *time1, const TEE_Date_Time *time2);
TEE_Result perm_srv_get_imported_cert_pubkey(uint8_t *dst, uint32_t *len);
TEE_Result perm_srv_check_cert_import_enable(const struct config_info *config, uint32_t cmd,
                                             bool *is_cert_import_enable);

TEE_Result perm_srv_cert_expiration_date_check(const validity_period_t *valid_date);
TEE_Result perm_srv_cert_expiration_check(const uint8_t *cert, uint32_t cert_size);
TEE_Result perm_srv_cert_validation_check(const uint8_t *cert, uint32_t cert_size,
                                          const uint8_t *parent_key, uint32_t parent_key_len);
#endif
