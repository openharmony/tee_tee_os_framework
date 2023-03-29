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
#include "load_app_comm.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <securec.h>
#include <sys/mman.h>
#include "gtask_inner.h"
#include "service_manager.h"
#include "tee_log.h"
#include "target_type.h"
#include "tee_elf_verify.h"
#include "dynload.h"

#include "load_v3_app.h"

static elf_image_info g_img_info = { NULL, NULL, NULL, 0, 0, 0, -1, 0, { 0 }, false };
static elf_image_info *g_img_info_ptr = NULL;

void set_load_ta_mode_global_ptr(void)
{
    g_img_info_ptr = &g_img_info;
}

elf_image_info *get_img_info_ptr(void)
{
    return g_img_info_ptr;
}

static tee_img_type_t get_img_type_v(const elf_verify_reply *verify_reply, uint32_t img_version);
static struct image_version_info g_images_attribute[] = {
#ifdef DYN_TA_SUPPORT_V3
    {CIPHER_LAYER_VERSION, NULL, get_img_type_v, tee_secure_get_img_size_v3},
#endif
};

static inline void set_service_attr(bool buildin, bool ta_64bit,
                            tee_img_type_t img_type, struct service_attr *service_attr)
{
    service_attr->build_in     = buildin;
    service_attr->ta_64bit     = ta_64bit;
    service_attr->img_type     = img_type;
}

static TEE_Result load_secure_app_image_general(tee_img_type_t img_type,
    const elf_verify_reply *verify_reply)
{
    struct service_attr service_attr;
    bool ta_64bit = false;

    tlogi("TA: %s, UUID: %08x, ELF: %u, stack: %u, heap: %u, multi session: %s, keepalive: %s, singleInstance: %s, "\
        "heap stack size page align :%s\n", (char *)verify_reply->service_name,
        verify_reply->srv_uuid.timeLow,
        verify_reply->payload_hdr.ta_elf_size, verify_reply->ta_property.stack_size,
        verify_reply->ta_property.heap_size,
        (verify_reply->ta_property.multi_session != 0) ? "Y" : "N",
        (verify_reply->ta_property.instance_keep_alive != 0) ? "Y" : "N",
        (verify_reply->ta_property.single_instance != 0) ? "Y" : "N",
        (verify_reply->mani_ext.mem_page_align != 0) ? "Y" : "N");

    if (elf_param_check((uint32_t)(verify_reply->ta_property.stack_size),
        (uint32_t)(verify_reply->ta_property.heap_size), verify_reply->payload_hdr.mani_ext_size) != 0) {
        tloge("load_elf_param_check failed\n");
        return TEE_ERROR_GENERIC;
    }

    TEE_Result ret = varify_elf_arch((const char *)g_img_info_ptr->ptr_ta_elf,
                                     verify_reply->payload_hdr.ta_elf_size, &ta_64bit);
    if (ret != TEE_SUCCESS) {
        tloge("varify elf architecture failed %x\n", ret);
        return TEE_ERROR_GENERIC;
    }
    set_service_attr(false, ta_64bit, img_type, &service_attr);

    ret = load_elf_to_tee(&verify_reply->srv_uuid, (char *)verify_reply->service_name, false,
        verify_reply->dyn_conf_registed, &service_attr);
    if (ret != TEE_SUCCESS)
        return ret;

    init_service_property(&verify_reply->srv_uuid, (uint32_t)verify_reply->ta_property.stack_size,
        (uint32_t)verify_reply->ta_property.heap_size,
        (bool)verify_reply->ta_property.single_instance,
        (bool)verify_reply->ta_property.multi_session,
        (bool)verify_reply->ta_property.instance_keep_alive,
        (bool)verify_reply->mani_ext.ssa_enum_enable, (bool)verify_reply->mani_ext.mem_page_align,
        (char *)g_img_info_ptr->ptr_manifest_buf, verify_reply->payload_hdr.mani_ext_size);

    if (memmove_s(g_img_info_ptr->img_buf, g_img_info_ptr->aligned_img_size, (const char *)g_img_info_ptr->ptr_ta_elf,
        verify_reply->payload_hdr.ta_elf_size) != 0) {
        tloge("move elf to file head failed\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

TEE_Result load_secure_app_image(tee_img_type_t img_type,
    const elf_verify_reply *verify_reply)
{
    TEE_Result ret;
    if (verify_reply == NULL) {
        tloge("bad parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t i = 0;
    for (; i < ARRAY_SIZE(g_images_attribute); i++) {
        if (g_img_info_ptr->img_version == g_images_attribute[i].img_version) {
            ret = load_secure_app_image_general(img_type, verify_reply);
            if (ret != TEE_SUCCESS) {
                tloge("Failed to load TA image\n");
                return ret;
            }
            break;
        }
    }
    if (i == ARRAY_SIZE(g_images_attribute)) {
        tloge("Unsupported secure image version: %d\n", g_img_info_ptr->img_version);
        return TEE_ERROR_NOT_SUPPORTED;
    }
    return TEE_SUCCESS;
}


TEE_Result tee_secure_img_permission_check(uint32_t img_version, elf_verify_reply *verify_reply)
{
    TEE_Result ret;

    if (verify_reply == NULL) {
        tloge("bad parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t i = 0;
    for (; i < ARRAY_SIZE(g_images_attribute); i++) {
        if (img_version == g_images_attribute[i].img_version) {
            if (g_images_attribute[i].secure_img_permission_check == NULL)
                break;
            ret = g_images_attribute[i].secure_img_permission_check(verify_reply);
            if (ret != TEE_SUCCESS) {
                tloge("Failed to load TA image\n");
                return ret;
            }
            break;
        }
    }
    if (i == ARRAY_SIZE(g_images_attribute)) {
        tloge("Unknown image version error %u\n", img_version);
        return TEE_ERROR_NOT_SUPPORTED;
    }
        return TEE_SUCCESS;
}

static tee_img_type_t get_img_type_v(const elf_verify_reply *verify_reply, uint32_t img_version)
{
    tee_img_type_t ret = IMG_TYPE_MAX;
    switch (img_version) {
    case TA_SIGN_VERSION:
    case TA_RSA2048_VERSION:
    case CIPHER_LAYER_VERSION:
        if (verify_reply->mani_ext.target_type == DRV_TARGET_TYPE &&
            verify_reply->mani_ext.hardware_type == HARDWARE_ENGINE_CRYPTO)
            ret = IMG_TYPE_CRYPTO_DRV;
        else if (verify_reply->mani_ext.is_lib)
            ret = IMG_TYPE_LIB;
        else if (verify_reply->mani_ext.target_type == DRV_TARGET_TYPE)
            ret = IMG_TYPE_DYNAMIC_DRV;
        else if (verify_reply->mani_ext.target_type == SRV_TARGET_TYPE)
            ret = IMG_TYPE_DYNAMIC_SRV;
        else if (verify_reply->mani_ext.target_type == CLIENT_TARGET_TYPE)
            ret = IMG_TYPE_DYNAMIC_CLIENT;
        else
            ret = IMG_TYPE_APP;
        break;
    default:
        tloge("Unsupported secure image version: %d\n", img_version);
        break;
    }
    return ret;
}

tee_img_type_t tee_secure_get_img_type(const elf_verify_reply *verify_reply, uint32_t img_version)
{
    tee_img_type_t ret = IMG_TYPE_MAX;
    uint32_t i = 0;

    if (verify_reply == NULL) {
        tloge("bad parameters\n");
        return ret;
    }

    for (; i < ARRAY_SIZE(g_images_attribute); i++) {
        if (img_version == g_images_attribute[i].img_version) {
            ret = g_images_attribute[i].get_img_type(verify_reply, img_version);
            break;
        }
    }
    return ret;
}

TEE_Result tee_secure_get_img_size(uint32_t img_version, uint8_t *share_buf, uint32_t buf_len, uint32_t *img_size)
{
    TEE_Result ret;
    if (share_buf == NULL || img_size == NULL) {
        tloge("bad parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t i = 0;
    for (; i < ARRAY_SIZE(g_images_attribute); i++) {
        if (img_version == g_images_attribute[i].img_version) {
            if (g_images_attribute[i].get_img_size == NULL)
                break;
            ret = g_images_attribute[i].get_img_size(share_buf, buf_len, img_size);
            if (ret != TEE_SUCCESS) {
                tloge("Failed to load TA image\n");
                return ret;
            }
            break;
        }
    }
    if (i == ARRAY_SIZE(g_images_attribute)) {
        tloge("Unknown image version error %u\n", img_version);
        return TEE_ERROR_NOT_SUPPORTED;
    }
    return ret;
}
