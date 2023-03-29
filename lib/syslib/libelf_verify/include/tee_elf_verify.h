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
#ifndef TEE_ELF_VERIFY_H
#define TEE_ELF_VERIFY_H

#include <ta_lib_img_unpack.h>
#include "tee_defines.h"
#include "ta_framework.h"

#define SN_MAX_SIZE 64
#define ISSUER_MAX_SIZE   256

typedef struct {
    uint32_t version;
    uint32_t img_size;
    char tmp_file[MAX_TAFS_NAME_LEN];
} __attribute__((__packed__)) elf_verify_req;

typedef struct {
    char service_name[SERVICE_NAME_MAX_IN_MANIFEST];
    uint32_t service_name_len;
    TEE_UUID srv_uuid;
    manifest_extension_t mani_ext;
    ta_property_t ta_property;
    ta_payload_hdr_t payload_hdr;
    int32_t off_manifest_buf;
    int32_t off_ta_elf;
    TEE_Result verify_result;
    bool conf_registed;
    bool dyn_conf_registed;
} elf_verify_reply;

typedef struct {
    uint8_t *elf_hash;
    uint32_t hash_size;
} elf_hash_data;
#define MAX_IMAGE_HASH_SIZE 64

struct cert_subjects {
    uint8_t cn[SN_MAX_SIZE];
    uint32_t cn_size;
    uint8_t ou[SN_MAX_SIZE];
    uint32_t ou_size;
};

TEE_Result secure_elf_verify(const elf_verify_req *req, elf_verify_reply *rep);

TEE_Result tee_secure_img_parse_manifest_v3(const uint8_t *manifest_ext, uint32_t *ext_size,
                                            bool control, const uint32_t config_target_type);

#endif
