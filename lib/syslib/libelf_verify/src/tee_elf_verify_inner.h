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
#ifndef TEE_ELF_VERIFY_INNER_H
#define TEE_ELF_VERIFY_INNER_H

#include <ta_lib_img_unpack.h>
#include "tee_defines.h"
#include "ta_framework.h"
#include "tee_elf_verify.h"
#include "dyn_conf_dispatch_inf.h"

ta_property_t *get_ta_property_ptr(void);
load_img_info *get_img_info(void);
teec_image_head *get_image_hd(void);
ta_payload_layer_t *get_ta_payload(void);
uint32_t get_img_size(void);
bool overflow_check(uint32_t a, uint32_t b);
void copy_hash_data(elf_hash_data *hash_data, uint8_t *hash_src, uint32_t hash_src_size);
TEE_Result tee_secure_img_manifest_extention_process(const uint8_t *extension, uint32_t extension_size,
    manifest_extension_t *mani_ext, struct dyn_conf_t *dyn_conf);
bool boundary_check(uint32_t max_size, uint32_t input_size);
TEE_Result tee_secure_img_duplicate_buff(const uint8_t *src, uint32_t src_size, uint8_t **dst);

struct process_version {
    uint32_t version;
    void (*tee_free_func)(void);
    TEE_Result (*img_copy_rsp)(elf_verify_reply *rep);
    TEE_Result (*tee_secure_img_unpack)(uint32_t rsa_algo_len, uint32_t ta_hd_len, uint8_t *img_buf,
        uint32_t img_size, elf_hash_data *hash_data);
    uint32_t rsa_algo_len;
    uint32_t ta_hd_len;
};

#endif

