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
#include "perm_srv_ta_cert.h"
#include <securec.h>
#include <tee_log.h>
#include "perm_srv_ta_crl.h"
#include "tee_elf_verify.h"

static TEE_Result perm_srv_cert_params_check(const uint8_t *cert, const uint8_t *parent_key)
{
    bool is_invalid = (cert == NULL || parent_key == NULL);
    if (is_invalid) {
        tloge("cert or parent is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

TEE_Result perm_srv_cert_expiration_check(const uint8_t *cert, uint32_t cert_size)
{
    int32_t ret;
    validity_period_t valid_date = { { 0 }, { 0 } };

    if (cert == NULL) {
        tloge("cert is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Get validate date from the certificate */
    ret = get_validity_from_cert(&valid_date, (uint8_t *)(uintptr_t)cert, cert_size);
    if (ret < 0) {
        tloge("Failed to get valid date from certificate, errno: %d!\n", ret);
        return TEE_ERROR_GENERIC;
    }

    return perm_srv_cert_expiration_date_check(&valid_date);
}

TEE_Result perm_srv_cert_validation_check(const uint8_t *cert, uint32_t cert_size,
                                          const uint8_t *parent_key, uint32_t parent_key_len)
{
    int32_t ret;
    uint8_t sn[SN_MAX_SIZE] = { 0 };
    uint8_t issuer[ISSUER_MAX_SIZE] = { 0 };
    int32_t sn_size;
    int32_t issuer_size;
    bool revoked = false;
    TEE_Result result;

    result = perm_srv_cert_params_check(cert, parent_key);
    if (result != TEE_SUCCESS)
        return result;

    /* Verify the certificate is signed by our CA center */
    ret = x509_cert_validate((uint8_t *)(uintptr_t)cert, cert_size, (uint8_t *)(uintptr_t)parent_key, parent_key_len);
    if (ret <= 0) {
        tloge("Failed to validate certificate, errno: %d\n", ret);
        return TEE_ERROR_GENERIC;
    }

    result = perm_srv_cert_expiration_check(cert, cert_size);
    if (result != TEE_SUCCESS) {
        tloge("cert is expired\n");
        return result;
    }

    /* Get issuer of the certificate */
    issuer_size = get_issuer_from_cert(issuer, sizeof(issuer), (uint8_t *)(uintptr_t)cert, cert_size);
    if (issuer_size < 0) {
        tloge("Failed to get issuer from certificate: %d\n", issuer_size);
        return TEE_ERROR_GENERIC;
    }

    /* Get serial number of the certificate */
    sn_size = get_serial_number_from_cert(sn, sizeof(sn), (uint8_t *)(uintptr_t)cert, cert_size);
    if (sn_size < 0) {
        tloge("Failed to get serial number from certificate: %d\n", sn_size);
        return TEE_ERROR_GENERIC;
    }
    /* Check whether the certificate is revoked */
    result = perm_srv_check_cert_revoked(sn, (uint32_t)sn_size, issuer, (uint32_t)issuer_size, &revoked);
    if (result != TEE_SUCCESS || revoked == true) {
        tloge("Failed to pass cert crl check\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}
