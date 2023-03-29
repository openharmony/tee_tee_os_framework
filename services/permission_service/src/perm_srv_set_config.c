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
#include "perm_srv_set_config.h"
#include <string.h>
#include <securec.h>
#include <tee_log.h>
#include <tee_ext_api.h>
#include <crypto_wrapper.h>
#include <openssl/rsa.h>
#include <openssl/obj_mac.h>
#include <tee_internal_task_pub.h>
#include "tee_crypto_hal.h"
#include "tee_elf_verify.h"
#include "tee_elf_verify_inner.h"
#include "target_type.h"
#include "perm_srv_ta_cert.h"
#include "perm_srv_ta_config.h"
#include "perm_srv_ta_crl.h"
#include "perm_srv_ta_ctrl.h"
#include "perm_srv_common.h"

#define CERT_ARRAY_SIZE   1024
#define ECC_SIGNATURE_LEN 72

static uint32_t g_ca_type;

static conf_cert_t g_conf_cert_type;

uint8_t *g_ta_cert;

uint8_t* get_g_ta_cert(void)
{
    return g_ta_cert;
}

static TEE_Result get_cert_subjects(const uint8_t *cert, uint32_t cert_len, struct cert_subjects *subjects)
{
    int32_t len;

    /* Get cn from the certificate */
    len = get_subject_CN(subjects->cn, subjects->cn_size, cert, cert_len);
    if (len < 0) {
        tloge("Failed to get CN from certificate: %d\n", len);
        return TEE_ERROR_GENERIC;
    }
    subjects->cn_size = (uint32_t)len;

    /* Get OU from the certificate */
    len = get_subject_OU(subjects->ou, subjects->ou_size, cert, cert_len);
    if (len < 0) {
        tloge("Failed to validate certificate, length: %d\n", len);
        return TEE_ERROR_GENERIC;
    }
    subjects->ou_size = (uint32_t)len;

    return TEE_SUCCESS;
}

static TEE_Result conf_cert_cn_check(const uint8_t *cn, size_t cn_size)
{
    const char *config_cn = get_config_cert_cn();
    bool check = (cn == NULL || cn_size > SN_MAX_SIZE);

    if (check)
        return TEE_ERROR_BAD_PARAMETERS;

    check = (config_cn != NULL && strstr((const char *)cn, config_cn) != NULL);
    if (check)
        return TEE_SUCCESS;

    return TEE_ERROR_GENERIC;
}

static TEE_Result conf_cert_ou_check(const uint8_t *ou, size_t ou_size, conf_cert_t *cert_type)
{
    const char *config_ou_prod = get_config_cert_ou_prod();
    const char *config_ou_dev = get_config_cert_ou_dev();

    bool is_invalid = (ou == NULL || cert_type == NULL || ou_size > SN_MAX_SIZE);
    if (is_invalid)
        return TEE_ERROR_BAD_PARAMETERS;

    is_invalid = (config_ou_prod != NULL && strstr((const char *)ou, config_ou_prod) != NULL);
    if (is_invalid) {
        tlogd("TA certificate type: %s\n", "Production");
        *cert_type = CONF_RELEASE_CERT;
        return TEE_SUCCESS;
    }

    is_invalid = (config_ou_dev != NULL && strstr((const char *)ou, config_ou_dev) != NULL);
    if (is_invalid) {
        tlogd("TA certificate type: %s\n", "Development");
        *cert_type = CONF_DEBUG_CERT;
        return TEE_SUCCESS;
    }

    tloge("size: 0x%x, %s\n", ou_size, ou);
    return TEE_ERROR_GENERIC;
}

static TEE_Result ta_cert_ou_check(const uint8_t *ou, size_t ou_size, ta_cert_t *cert_type)
{
    const char *config_ou_prod = get_config_cert_ou_prod();
    const char *config_ou_dev = get_config_cert_ou_dev();

    bool is_invalid = (ou == NULL || cert_type == NULL || ou_size > SN_MAX_SIZE);
    if (is_invalid)
        return TEE_ERROR_BAD_PARAMETERS;

    is_invalid = (config_ou_prod != NULL && strstr((const char *)ou, config_ou_prod) != NULL &&
                  g_conf_cert_type == CONF_RELEASE_CERT);
    if (is_invalid) {
        tlogd("TA certificate type: %s\n", "Production");
        *cert_type = TA_RELEASE_CERT;
        return TEE_SUCCESS;
    }

    is_invalid = (config_ou_dev != NULL && strstr((const char *)ou, config_ou_dev) != NULL &&
                  g_conf_cert_type == CONF_DEBUG_CERT);
    if (is_invalid) {
        tlogd("TA certificate type: %s\n", "Development");
        *cert_type = TA_DEBUG_CERT;
        return TEE_SUCCESS;
    }

    tloge("size: 0x%x, %s\n", ou_size, ou);
    return TEE_ERROR_GENERIC;
}

static TEE_Result tee_secure_img_ta_cn_check(const uint8_t *cn_buff, uint32_t cn_size, const TEE_UUID *uuid,
                                             const uint8_t *service_name, uint32_t service_name_len)
{
    uint8_t buff[TA_CERT_MAX_CN_INFO_LEN] = { 0 };
    errno_t ret;

    bool is_invalid = (cn_buff == NULL || uuid == NULL || service_name == NULL || (cn_size > TA_CERT_MAX_CN_INFO_LEN) ||
                       (service_name_len > TA_CERT_MAX_CN_INFO_LEN - (UUID_STR_LEN + TA_CERT_CN_UNDERLINE_SIZE)));
    if (is_invalid)
        return TEE_ERROR_BAD_PARAMETERS;

    if (cn_size != service_name_len + UUID_STR_LEN + TA_CERT_CN_UNDERLINE_SIZE) {
        tloge("invalid CN size 0x%x in TA cert, expected 0x%x\n",
              cn_size, service_name_len + UUID_STR_LEN + TA_CERT_CN_UNDERLINE_SIZE);
        return TEE_ERROR_GENERIC;
    }

    if (perm_srv_convert_uuid_to_str(uuid, (char *)buff, sizeof(buff)) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    buff[UUID_STR_LEN] = '_';
    ret = memcpy_s(&buff[UUID_STR_LEN + TA_CERT_CN_UNDERLINE_SIZE],
                   sizeof(buff) - UUID_STR_LEN - TA_CERT_CN_UNDERLINE_SIZE, service_name, service_name_len);
    if (ret != EOK)
        return TEE_ERROR_GENERIC;

    if (TEE_MemCompare(buff, cn_buff, cn_size) != 0) {
        tloge("CN content is mismatch with uuid or service name in manifest\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result config_cert_cn_ou_check(const struct cert_subjects *subjects, bool is_sys_ta)
{
    TEE_Result ret;

    ret = conf_cert_cn_check(subjects->cn, subjects->cn_size);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to pass ta developer alliance certificate CN check\n");
        return TEE_ERROR_GENERIC;
    }

#ifdef DYN_IMPORT_CERT
    if (!is_sys_ta)
        return TEE_SUCCESS;
#else
    (void)is_sys_ta;
#endif

    ret = conf_cert_ou_check(subjects->ou, subjects->ou_size, &g_conf_cert_type);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to pass ta developer alliance certificate OU check\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result get_config_header(const struct ta_package *package,
                                    struct config_header *header)
{
    uint32_t magic;
    errno_t rc;

    bool is_invalid = (package->package_size <= sizeof(*header) - sizeof(header->version));
    if (is_invalid)
        return TEE_ERROR_BAD_PARAMETERS;

    magic = *(uint32_t *)(uintptr_t)package->config_package;
    if (magic != TA_CONFIG_SEGMENT_MAGIC) {
        tloge("invliad config segment header data\n");
        return TEE_ERROR_GENERIC;
    }

    header->version = *(uint16_t *)(uintptr_t)(package->config_package + sizeof(magic));
    if (header->version == CONFIG_HEADER_V1) {
        rc = memcpy_s(&header->header.v1, sizeof(header->header.v1),
            package->config_package, sizeof(header->header.v1));
    } else if (header->version == CONFIG_HEADER_V2) {
        rc = memcpy_s(&header->header.v2, sizeof(header->header.v2),
            package->config_package, sizeof(header->header.v2));
    } else {
        tloge("Unsupported header version %u\n", header->version);
        return TEE_ERROR_NOT_SUPPORTED;
    }
    if (rc != EOK)
        return TEE_ERROR_SECURITY;

    return TEE_SUCCESS;
}

#define OFFSET_MAX_VAL  0xFFFFFFFF
static TEE_Result check_and_get_off_val(uint32_t *offset, uint32_t off_len, uint32_t allow_len)
{
    if (*offset > OFFSET_MAX_VAL - off_len) {
        tloge("off len is too long\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    *offset += off_len;
    if (*offset > allow_len) {
        tloge("off set is too long\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result ta_cert_cn_ou_check(const struct cert_subjects *subjects, const struct ta_identity *identity,
    cert_param_t *cert_param)
{
    TEE_Result ret;

    ret = tee_secure_img_ta_cn_check(subjects->cn, subjects->cn_size,
        &identity->uuid, identity->service_name, identity->service_name_len);
    if (ret != TEE_SUCCESS)
        return ret;
#ifdef DYN_IMPORT_CERT
    if (!cert_param->sys_verify_ta)
        return TEE_SUCCESS;
#endif
    ret = ta_cert_ou_check(subjects->ou, subjects->ou_size, &cert_param->cert_type);
    if (ret != TEE_SUCCESS)
        return ret;

    return TEE_SUCCESS;
}

static TEE_Result check_ta_cert_subjects(struct ta_config_info *config,
    const struct ta_identity *identity, struct perm_config *perm_config, cert_param_t *cert_param)
{
    TEE_Result ret;
    const uint8_t *cert = config->ta_cert.cert;
    uint32_t cert_len = config->ta_cert.cert_len;
    struct cert_subjects subjects = { { 0 }, 0, { 0 }, 0 };
    subjects.cn_size = (uint32_t)sizeof(subjects.cn);
    subjects.ou_size = (uint32_t)sizeof(subjects.ou);

    ret = get_cert_subjects(cert, cert_len, &subjects);
    if (ret != TEE_SUCCESS)
        return ret;

    errno_t rc = memcpy_s(perm_config->cn, sizeof(perm_config->cn), subjects.cn, subjects.cn_size);
    if (rc != EOK)
        return TEE_ERROR_SECURITY;

    perm_config->cn_size = subjects.cn_size;
    g_ta_cert = config->ta_cert.cert;

    ret = ta_cert_cn_ou_check(&subjects, identity, cert_param);
    if (ret != TEE_SUCCESS)
        return ret;

    perm_config->cert_type = cert_param->cert_type;

    return TEE_SUCCESS;
}

static void get_ta_pubkey_from_diff_plat(const struct ta_config_info *config, cert_param_t *cert_param,
                                         uint8_t **ca_public_key, uint32_t *ca_public_key_len)
{
    bool is_oh = false;
    uint32_t sign_sec_alg;
    if (config->header.version == CONFIG_HEADER_V1) {
        sign_sec_alg = config->header.header.v1.signature_len >> SIGN_CONFIG_ALG_BITS;
        is_oh = ((config->header.header.v1.policy_version & PRODUCT_BIT_MAP) == CONFIG_POLICY_OH) ? true : false;
    }

    if (is_oh) {
        cert_param->cert_product_type = OH_CA_TYPE;
        if (g_ca_type == CA_PUBLIC) {
            *ca_public_key = (uint8_t *)(uintptr_t)get_pub_ca_key(sign_sec_alg);
            *ca_public_key_len = get_pub_ca_key_size(sign_sec_alg);
        } else {
            *ca_public_key = (uint8_t *)(uintptr_t)get_priv_ca_key(sign_sec_alg);
            *ca_public_key_len = get_priv_ca_key_size(sign_sec_alg);
        }
    } else {
        cert_param->cert_product_type = TEE_CA_TYPE;
        *ca_public_key = (uint8_t *)(uintptr_t)get_ca_pubkey();
        *ca_public_key_len = get_ca_pubkey_size();
    }
}

static void check_crl_cert_ctl_list(void)
{
    load_img_info *img_info = get_img_info();
    if (img_info == NULL)
        return;

    /* The revocation list is not required for loading the drynamic cypto driver */
    if (img_info->manifest.ext.target_type == DRV_TARGET_TYPE &&
        img_info->manifest.ext.hardware_type == HARDWARE_ENGINE_CRYPTO)
        return;

    TEE_Result ret;
    ret = perm_srv_global_ta_crl_list_loading(true);
    if (ret != TEE_SUCCESS)
        tloge("CRL list loading fail, ret is 0x%x\n", ret);
    ret = perm_srv_global_ta_ctrl_list_loading(true);
    if (ret != TEE_SUCCESS)
        tloge("TA control list loading fail, ret is 0x%x\n", ret);
}

static TEE_Result ta_cert_verify(struct ta_config_info *config, cert_param_t *cert_param,
    const struct ta_identity *identity, struct perm_config *perm_config)
{
    TEE_Result ret;
    const uint8_t *cert = config->ta_cert.cert;
    uint32_t cert_len = config->ta_cert.cert_len;
    uint8_t buff[CERT_ARRAY_SIZE] = {0};
    uint32_t buff_len = (uint32_t)sizeof(buff);
    uint8_t *ca_public_key = NULL;
    uint32_t ca_public_key_len = 0;

    get_ta_pubkey_from_diff_plat(config, cert_param, &ca_public_key, &ca_public_key_len);

    if (!cert_param->sys_verify_ta) {
        uint8_t tmp_pubkey_buff[MAX_CERT_LEN] = { 0 };
        uint32_t tmp_pubkey_key_len = 0;
        if (perm_srv_get_imported_cert_pubkey(tmp_pubkey_buff, &tmp_pubkey_key_len) == TEE_SUCCESS) {
            if (tmp_pubkey_key_len != 0) {
                cert_param->cert_product_type = IMPORT_CA_TYPE;
                ca_public_key = tmp_pubkey_buff;
                ca_public_key_len = tmp_pubkey_key_len;
            }
        }
    }

    if (ca_public_key == NULL || ca_public_key_len == 0) {
        tloge("failed to get ca public key to verify ta cert\n");
        return TEE_ERROR_GENERIC;
    }

    /* update crl list before check ta cert, when use TYPE_PUB_KEY */
    check_crl_cert_ctl_list();

    /* 1.validate ta cert with preload CA's public key, and check revoke status */
    ret = perm_srv_cert_validation_check(cert, cert_len, ca_public_key, ca_public_key_len);
    if (ret != TEE_SUCCESS)
        return ret;

    /* 2.check cert subjects cn and ou */
    ret = check_ta_cert_subjects(config, identity, perm_config, cert_param);
    if (ret != TEE_SUCCESS)
        return ret;

    /* 3.get the public key */
    if (get_subject_public_key_new(buff, sizeof(buff), cert, cert_len) < 0) {
        tloge("Failed to get subject public key from cert\n");
        return TEE_ERROR_GENERIC;
    }

    if (import_pub_from_sp(cert_param->public_key, buff, buff_len) < 0) {
        tloge("Failed to get public key from subject public key\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result ta_cert_verify_v5(struct ta_config_info *config, cert_param_t *cert_param,
    const struct ta_identity *identity, struct perm_config *perm_config)
{
    bool revoked = false;
    uint8_t issuer[ISSUER_MAX_SIZE] = { 0 };
    int32_t issuer_len;
    TEE_Result result;
    uint8_t sn_buf[SN_MAX_SIZE] = { 0 };
    int32_t sn_size;

    cert_param->cert_product_type = TEE_CA_TYPE;
    check_crl_cert_ctl_list();
    result = perm_srv_cert_expiration_check(config->ta_cert.cert, config->ta_cert.cert_len);
    if (result != TEE_SUCCESS) {
        tloge("cert is expired\n");
        return result;
    }

    result = check_ta_cert_subjects(config, identity, perm_config, cert_param);
    if (result != TEE_SUCCESS)
        return result;

    issuer_len = get_issuer_from_cert(issuer, sizeof(issuer), config->ta_cert.cert, config->ta_cert.cert_len);
    if (issuer_len < 0) {
        tloge("Failed to get issuer from certificate: %d\n", issuer_len);
        return TEE_ERROR_GENERIC;
    }

    sn_size = get_serial_number_from_cert(sn_buf, sizeof(sn_buf), config->ta_cert.cert, config->ta_cert.cert_len);
    if (sn_size < 0) {
        tloge("Failed to get serial number from certificate: %d\n", sn_size);
        return TEE_ERROR_GENERIC;
    }

    result = perm_srv_check_cert_revoked(sn_buf, (uint32_t)sn_size, issuer, (uint32_t)issuer_len, &revoked);
    if (result != TEE_SUCCESS || revoked == true) {
        tloge("Failed to pass cert crl check\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result ta_cert_info_verify(struct ta_config_info *config, cert_param_t *cert_param,
    const struct ta_identity *identity, struct perm_config *perm_config)
{
    if (config->verify_data.type == TYPE_CERT_CHAIN) {
        return ta_cert_verify_v5(config, cert_param, identity, perm_config);
    } else {
        return ta_cert_verify(config, cert_param, identity, perm_config);
    }

    tloge("Unsupported ta cert type %u\n", config->ta_cert.type);
    return TEE_ERROR_GENERIC;
}

static TEE_Result get_config_info_v1(const struct ta_package *package, struct ta_config_info *config)
{
    uint32_t offset = 0;
    uint32_t index;
    TEE_Result ret;

    config->ta_cert.type = TYPE_CERT;
    ret = check_and_get_off_val(&offset, sizeof(config->header.header.v1), package->package_size);
    if (ret != TEE_SUCCESS)
        return ret;

    index = offset;
    ret = check_and_get_off_val(&offset, config->header.header.v1.ta_cert_len, package->package_size);
    if (ret != TEE_SUCCESS)
        return ret;

    config->ta_cert.cert = (uint8_t *)(uintptr_t)package->config_package + index;
    config->ta_cert.cert_len = config->header.header.v1.ta_cert_len;
    index = offset;

    ret = check_and_get_off_val(&offset, config->header.header.v1.config_len, package->package_size);
    if (ret != TEE_SUCCESS)
        return ret;

    config->tlv_config.data = (uint8_t *)(uintptr_t)(package->config_package) + index;
    config->tlv_config.len = config->header.header.v1.config_len;
    index = offset;

    uint32_t real_sig_len = config->header.header.v1.signature_len & CONFIG_SIGNATURE_LEN_MASK;
    /* 1: rsa_pkcsv15 2: rsa_pss 3: ecdsa */
    uint32_t algorithm = config->header.header.v1.signature_len >> SIGN_CONFIG_ALG_BITS;
    ret = check_and_get_off_val(&offset, real_sig_len, package->package_size);
    if (ret != TEE_SUCCESS)
        return ret;

    config->verify_data.signature = (uint8_t *)(uintptr_t)package->config_package + index;
    config->verify_data.signature_len = real_sig_len;
    index = offset;

    ret = check_and_get_off_val(&offset, config->header.header.v1.config_cert_len, package->package_size);
    if (ret != TEE_SUCCESS)
        return ret;

    config->verify_data.type = TYPE_CERT;
    if (config->verify_data.signature_len == ECC_SIGNATURE_LEN) {
        config->verify_data.sign_alg = SIGN_TYPE_ECDSA_SHA256;
    } else {
        config->verify_data.sign_alg = SIGN_TYPE_RSA_SHA256_PKCS1;
        if (algorithm == CONFIG_SIGN_ALG_RSA_PSS)
            config->verify_data.sign_alg = SIGN_TYPE_RSA_SHA256_PSS;
    }
    config->verify_data.cert = (uint8_t *)(uintptr_t)package->config_package + index;
    config->verify_data.cert_len = config->header.header.v1.config_cert_len;

    return TEE_SUCCESS;
}

static TEE_Result get_ta_cert(const uint8_t *data, uint32_t len, struct ta_cert_info *ta_cert)
{
    uint32_t offset = 0;
    TEE_Result ret;

    ret = check_and_get_off_val(&offset, sizeof(ta_cert->type), len);
    if (ret != TEE_SUCCESS) {
        tloge("parser ta cert info failed\n");
        return ret;
    }

    ta_cert->type = *((uint32_t *)(uintptr_t)data);

    ta_cert->cert_len = len - offset;
    ta_cert->cert = (uint8_t *)(uintptr_t)data + offset;

    return TEE_SUCCESS;
}

/*
 * signature verify segment struct as below:
 * +---------+
 * |-4 bytes-| type (0:public key; 1:cert; 2:cert chain;)
 * |-4 bytes-| sign algrithom
 * |-4 bytes-| cert len
 * |-n bytes-| cert content; n denpend on "cert len"
 * |-n bytes-| signature; n denpend on "sign algrithom"
 * +---------+
 */
static TEE_Result get_sign_verify_data(const uint8_t *data, uint32_t len, struct sign_verify_data *verify_data)
{
    uint32_t offset = 0;
    uint32_t index;
    TEE_Result ret;

    ret = check_and_get_off_val(&offset, sizeof(verify_data->type), len);
    if (ret != TEE_SUCCESS)
        return ret;

    verify_data->type = *((uint32_t *)(uintptr_t)data);
    index = offset;

    ret = check_and_get_off_val(&offset, sizeof(verify_data->sign_alg), len);
    if (ret != TEE_SUCCESS)
        return ret;

    verify_data->sign_alg = *((uint32_t *)(uintptr_t)(data + index));
    index = offset;

    ret = check_and_get_off_val(&offset, sizeof(verify_data->cert_len), len);
    if (ret != TEE_SUCCESS)
        return ret;

    verify_data->cert_len = *((uint32_t *)(uintptr_t)(data + index));
    index = offset;

    ret = check_and_get_off_val(&offset, verify_data->cert_len, len);
    if (ret != TEE_SUCCESS)
        return ret;

    verify_data->cert = (uint8_t *)(uintptr_t)data + index;
    index = offset;

    verify_data->signature = (uint8_t *)(uintptr_t)data + index;
    verify_data->signature_len = len - index;

    return TEE_SUCCESS;
}

/*
 * config segment sturct info as below:
 * +----------+
 * |-44 bytes-| header
 * |- n bytes-| ta cert info; n depends on value in header
 * |- n bytes-| tlv config data; n depends on value in header
 * |- n bytes-| signature verify data; n depends on value in header
 * +----------+
 */
static TEE_Result get_config_info_v2(const struct ta_package *package, struct ta_config_info *config)
{
    TEE_Result ret;
    uint32_t offset = 0;
    uint32_t index;

    ret = check_and_get_off_val(&offset, sizeof(config->header.header.v2), package->package_size);
    if (ret != TEE_SUCCESS)
        return ret;

    index = offset;

    ret = check_and_get_off_val(&offset, config->header.header.v2.ta_cert_len, package->package_size);
    if (ret != TEE_SUCCESS)
        return ret;

    ret = get_ta_cert(package->config_package + index, config->header.header.v2.ta_cert_len, &config->ta_cert);
    if (ret != TEE_SUCCESS)
        return ret;

    index = offset;
    ret = check_and_get_off_val(&offset, config->header.header.v2.config_len, package->package_size);
    if (ret != TEE_SUCCESS)
        return ret;

    config->tlv_config.data = (uint8_t *)(uintptr_t)package->config_package + index;
    config->tlv_config.len = config->header.header.v2.config_len;

    index = offset;
    ret = check_and_get_off_val(&offset, config->header.header.v2.config_verify_len, package->package_size);
    if (ret != TEE_SUCCESS)
        return ret;

    ret = get_sign_verify_data(package->config_package + index,
        config->header.header.v2.config_verify_len, &config->verify_data);
    if (ret != TEE_SUCCESS) {
        tloge("parser sign verify data failed\n");
        return ret;
    }

    return TEE_SUCCESS;
}

static TEE_Result get_config_info(const struct ta_package *package, struct ta_config_info *config)
{
    if (config->header.version == CONFIG_HEADER_V1)
        return get_config_info_v1(package, config);
    else if (config->header.version == CONFIG_HEADER_V2)
        return get_config_info_v2(package, config);

    tloge("Unsupported header version: %u\n", config->header.version);
    return TEE_ERROR_BAD_PARAMETERS;
}

static TEE_Result check_config_cert_subjects(const uint8_t *cert, uint32_t cert_len,
                                             const cert_param_t *cert_param)
{
    TEE_Result ret;
    struct cert_subjects subjects = { { 0 }, 0, { 0 }, 0 };
    subjects.cn_size = (uint32_t)sizeof(subjects.cn);
    subjects.ou_size = (uint32_t)sizeof(subjects.ou);

    ret = get_cert_subjects(cert, cert_len, &subjects);
    if (ret != TEE_SUCCESS)
        return ret;

    return config_cert_cn_ou_check(&subjects, cert_param->sys_verify_ta);
}

uint32_t get_ca_type(void)
{
    return g_ca_type;
}

static TEE_Result check_oh_cert_validation(const struct ta_config_info *config,
        const uint8_t *cert, uint32_t cert_len)
{
    TEE_Result ret;
    uint32_t alg = config->header.header.v1.signature_len >> SIGN_CONFIG_ALG_BITS;
    uint8_t *pub_ca_key = (uint8_t *)(uintptr_t)get_pub_ca_key(alg);
    uint32_t pub_ca_key_size = get_pub_ca_key_size(alg);
    if (pub_ca_key == NULL || pub_ca_key_size == 0) {
        tloge("failed to get public ca key to verify config cert\n");
        return TEE_ERROR_GENERIC;
    }

    uint8_t *priv_ca_key = (uint8_t *)(uintptr_t)get_priv_ca_key(alg);
    uint32_t priv_ca_key_size = get_priv_ca_key_size(alg);
    if (priv_ca_key == NULL || priv_ca_key_size == 0) {
        tloge("failed to get private ca key to verify config cert\n");
        return TEE_ERROR_GENERIC;
    }

    /* 1.verify cert with parent key, and check cert revoked status */
    ret = perm_srv_cert_validation_check(cert, cert_len, pub_ca_key, pub_ca_key_size);
    if (ret != TEE_SUCCESS) {
        tlogd("config cert is not signed by public CA\n");
    } else {
        g_ca_type = CA_PUBLIC;
        return TEE_SUCCESS;
    }

    ret = perm_srv_cert_validation_check(cert, cert_len, priv_ca_key, priv_ca_key_size);
    if (ret != TEE_SUCCESS) {
        tloge("check cert validation failed\n");
        return ret;
    } else {
        g_ca_type = CA_PRIVATE;
        return TEE_SUCCESS;
    }
}

static TEE_Result check_config_cert_validation(const struct ta_config_info *config, const uint8_t *cert,
                                               uint32_t cert_len, uint8_t *key, const cert_param_t *cert_param)
{
    TEE_Result ret;
    uint8_t buff[CERT_ARRAY_SIZE] = { 0 };
    int32_t buff_len;
    bool is_oh = false;
    if (config->header.version == CONFIG_HEADER_V1)
        is_oh = ((config->header.header.v1.policy_version & PRODUCT_BIT_MAP) == CONFIG_POLICY_OH) ? true : false;

    if (is_oh) {
        ret = check_oh_cert_validation(config, cert, cert_len);
    } else {
        uint8_t *ca_key = (uint8_t *)(uintptr_t)get_ca_pubkey();
        uint32_t ca_key_size = get_ca_pubkey_size();
        uint8_t tmp_pubkey_buff[MAX_CERT_LEN] = {0};
        uint32_t tmp_pubkey_key_len = 0;
        if (!cert_param->sys_verify_ta) {
            ret = perm_srv_get_imported_cert_pubkey(tmp_pubkey_buff, &tmp_pubkey_key_len);
            bool pubkey_valid = (ret == TEE_SUCCESS) && (tmp_pubkey_key_len != 0);
            if (pubkey_valid) {
                ca_key = tmp_pubkey_buff;
                ca_key_size = tmp_pubkey_key_len;
            }
        }
   
        if (ca_key == NULL || ca_key_size == 0) {
            tloge("failed to get ca public key to verify config cert\n");
            return TEE_ERROR_GENERIC;
        }
        check_crl_cert_ctl_list();
        /* 1.verify cert with parent key, and check cert revoked status */
        ret = perm_srv_cert_validation_check(cert, cert_len, ca_key, ca_key_size);
    }
    if (ret != TEE_SUCCESS) {
        tloge("failed to verify config cert\n");
        return ret;
    }

    /* 2.check cn and ou subjects */
    ret = check_config_cert_subjects(cert, cert_len, cert_param);
    if (ret != TEE_SUCCESS)
        return ret;

    /* 3.get the public key */
    buff_len = get_subject_public_key_new(buff, sizeof(buff), cert, cert_len);
    if (buff_len < 0) {
        tloge("Failed to get subject public key from cert\n");
        return TEE_ERROR_GENERIC;
    }

    if (import_pub_from_sp(key, buff, (uint32_t)buff_len) < 0) {
        tloge("Failed to get public key from subject public key\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result validate_sign_verify_data(const struct ta_config_info *config, const struct sign_verify_data *data,
                                            uint8_t *key, size_t key_size, const cert_param_t *cert_param)
{
    if (data->type == TYPE_PUB_KEY) {
        rsa_pub_key_t *temp = (rsa_pub_key_t *)(uintptr_t)get_config_pub_key();
        if (temp == NULL) {
            tloge("cannot get public key to verify config signature\n");
            return TEE_ERROR_GENERIC;
        }
        errno_t ret;
        ret = memcpy_s(key, key_size, temp, sizeof(*temp));
        if (ret != EOK)
            return TEE_ERROR_GENERIC;
        return TEE_SUCCESS;
    } else if (data->type == TYPE_CERT) {
        return check_config_cert_validation(config, data->cert, data->cert_len, key, cert_param);
    }

    tloge("Unsupported sign verify data type %u\n", data->type);

    return TEE_ERROR_GENERIC;
}

static TEE_Result get_data_hash_for_sign(const uint8_t *package, uint32_t package_len,
    const struct config_header *header,
    uint8_t *hash, uint32_t hash_len)
{
    (void)package_len;
    uint32_t len;

    /*
     * values in header already checked in parsering ta_config_info,
     * don't need to check reversal risk when calculating len
     */
    if (header->version == CONFIG_HEADER_V1)
        len = (uint32_t)sizeof(header->header.v1) + header->header.v1.ta_cert_len + header->header.v1.config_len;
    else if (header->version == CONFIG_HEADER_V2)
        /* v2head + ta cert type + cert len + config len */
        len = (uint32_t)sizeof(header->header.v2) + header->header.v2.ta_cert_len + header->header.v2.config_len;
    else
        return TEE_ERROR_GENERIC;

    return perm_srv_calc_hash(package, len, hash, hash_len, TEE_ALG_SHA256);
}

static TEE_Result config_signature_verify_rsa(const struct ta_package *package,
                                              const struct ta_config_info *config,
                                              const cert_param_t *cert_param)
{
    TEE_Result ret;
    rsa_pub_key_t key = { { 0 }, 0, { 0 }, 0 };
    uint8_t hash[SHA256_LEN] = {0};
    uint32_t hash_len = (uint32_t)sizeof(hash);

    /* 1.check validation of config cert/ cert chain, and get public key to verify signature */
    ret = validate_sign_verify_data(config, &config->verify_data, (uint8_t *)&key, sizeof(key), cert_param);
    if (ret != TEE_SUCCESS) {
        tloge("check config cert rsa failed\n");
        return ret;
    }

    /* 2.get hash value of data to be signed */
    ret = get_data_hash_for_sign(package->config_package, package->package_size, &config->header, hash, hash_len);
    if (ret != TEE_SUCCESS) {
        tloge("get hash failed\n");
        return ret;
    }

    /* 3.check signature validation */
    uint32_t padding;
    if (config->verify_data.sign_alg == SIGN_TYPE_RSA_SHA256_PSS)
        padding = RSA_PKCS1_PSS_PADDING;
    else
        padding = RSA_PKCS1_PADDING;

    if (rsa_verify_digest(config->verify_data.signature, config->verify_data.signature_len,
                          hash, hash_len, &key, hash_len, NID_sha256, (int32_t)padding) != 0) {
        tloge("rsa signature VerifyDigest failed\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result config_signature_verify_ecc(const struct ta_package *package,
                                              const struct ta_config_info *config,
                                              const cert_param_t *cert_param)
{
    TEE_Result ret;
    ecc_pub_key_t key = { 0, { 0 }, 0, { 0 }, 0 };
    uint8_t hash[SHA256_LEN] = {0};
    uint32_t hash_len = (uint32_t)sizeof(hash);

    /* 1.check validation of config cert/ cert chain, and get public key to verify signature */
    ret = validate_sign_verify_data(config, &config->verify_data, (uint8_t *)&key, sizeof(key), cert_param);
    if (ret != TEE_SUCCESS) {
        tloge("check config cert ecc failed\n");
        return ret;
    }

    /* 2.get hash value of data to be signed */
    ret = get_data_hash_for_sign(package->config_package, package->package_size, &config->header, hash, hash_len);
    if (ret != TEE_SUCCESS) {
        tloge("get hash failed\n");
        return ret;
    }

    uint32_t i = 0;
    for (; i < config->verify_data.signature_len; i++) {
        if (config->verify_data.signature[i] == 0x00)
            continue;
        break;
    }

    /* 3.check signature validation */
    if (ecc_verify_digest(config->verify_data.signature + i, config->verify_data.signature_len - i,
                          hash, hash_len, &key) != 1) {
        tloge("ecc signature VerifyDigest failed\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result config_signature_verify(const struct ta_package *package,
                                          const struct ta_config_info *config,
                                          const cert_param_t *cert_param)
{
    if (config->verify_data.sign_alg == SIGN_TYPE_ECDSA_SHA256)
        return config_signature_verify_ecc(package, config, cert_param);
    else
        return config_signature_verify_rsa(package, config, cert_param);
}

static uint32_t get_policy_version(const struct config_header *header)
{
    if (header->version == CONFIG_HEADER_V1)
        return (uint32_t)header->header.v1.policy_version;
    else if (header->version == CONFIG_HEADER_V2)
        return (uint32_t)header->header.v2.policy_version;

    return 0;
}

static TEE_Result ta_config_package_process(const TEE_UUID *uuid,
    const struct ta_package *package, cert_param_t *cert_param)
{
    TEE_Result ret;
    struct ta_config_info config;
    struct perm_config perm_config = {0};
    struct ta_identity ta_identity = { { 0 }, NULL, 0 };

    (void)memset_s(&config, sizeof(config), 0, sizeof(config));
    bool is_invalid = (uuid == NULL || package == NULL || package->config_package == NULL ||
                       cert_param == NULL || package->name == NULL);
    if (is_invalid)
        return TEE_ERROR_BAD_PARAMETERS;

    /* 1.get header info of config segment */
    ret = get_config_header(package, &config.header);
    if (ret != TEE_SUCCESS) {
        tloge("parser config header failed\n");
        return ret;
    }

    /* 2.parser config segment to config info structure */
    ret = get_config_info(package, &config);
    if (ret != TEE_SUCCESS) {
        tloge("parser config info failed\n");
        return ret;
    }

    /* 3.verify the signature of config segment */
    ret = config_signature_verify(package, &config, cert_param);
    if (ret != TEE_SUCCESS)
        return ret;

    ta_identity.uuid = *uuid;
    ta_identity.service_name = (uint8_t *)(uintptr_t)package->name;
    ta_identity.service_name_len = package->name_len;
    /*
     * 4.check validation of ta cert:
     *  a)verify cert with CA's public key and revoked status
     *  b)check cert subjects with ta identity (uuid and service name)
     *  c)get cn content and cert type to check with config tlv content
     *  d)and get public key to verify elf segment in later process
     */
    ret = ta_cert_info_verify(&config, cert_param, &ta_identity, &perm_config);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to pass certificate validation check 0x%x\n", ret);
        return TEE_ERROR_GENERIC;
    }

    perm_config.tlv_buf = config.tlv_config.data;
    perm_config.tlv_len = config.tlv_config.len;
    perm_config.policy_version = get_policy_version(&config.header);

    /* 5.parser permissions in config tlv data segment */
    ret = perm_srv_parse_config_body(uuid, &perm_config);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to parse configure body\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

TEE_Result tee_ext_set_config(const uint8_t *conf, uint32_t conf_len, const TEE_UUID *uuid,
    const uint8_t *service_name, uint32_t service_name_len, void *cert_param)
{
    struct ta_package package;

    if (conf == NULL || cert_param == NULL || uuid == NULL || service_name == NULL) {
        tloge("tee ext set config recv bad parameter!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (conf_len == 0 || service_name_len == 0 || service_name_len > TA_CERT_MAX_SERVICE_NAME_LEN) {
        tloge("tee ext set config recv bad parameter, size error!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    package.config_package = conf;
    package.package_size = conf_len;
    package.name = service_name;
    package.name_len = service_name_len;
    return ta_config_package_process(uuid, &package, (cert_param_t *)cert_param);
}
