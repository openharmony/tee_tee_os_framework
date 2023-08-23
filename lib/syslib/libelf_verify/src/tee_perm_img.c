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
#include "tee_perm_img.h"
#include "perm_srv_set_config.h"
#include "tee_log.h"
#include "securec.h"
#include "ta_lib_img_unpack.h"
#include "ta_verify_key.h"
#include "tee_elf_verify.h"
#include "tee_elf_verify_inner.h"
#include "permission_service.h"

TEE_Result get_config_cert_param(cert_param_t *cert_param, struct sign_config_t *config)
{
    if (cert_param == NULL || config == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    ta_payload_layer_t *ta_payload = get_ta_payload();
    if (ta_payload->payload_hdr.ta_conf_size == 0)
        return TEE_SUCCESS;

    load_img_info *img_info = get_img_info();
    if (img_info == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    cert_param->sys_verify_ta = img_info->manifest.ext.sys_verify_ta;
    TEE_Result ret = tee_ext_set_config(ta_payload->ta_conf, ta_payload->payload_hdr.ta_conf_size,
        &img_info->manifest.srv_uuid, (uint8_t *)img_info->manifest.service_name,
        img_info->manifest.mani_info.service_name_len, cert_param);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to set configuration\n");
        return ret;
    }
    config->is_oh = (cert_param->cert_product_type == OH_CA_TYPE) ? true : false;
    ta_payload->conf_registed = true;
    return TEE_SUCCESS;
}
