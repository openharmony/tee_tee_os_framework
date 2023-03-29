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
#include "tee_load_ext_mf.h"
#include <securec.h>
#include <ta_framework.h>
#include <tee_mem_mgmt_api.h>
#include <tee_log.h>
#include <dyn_conf_dispatch_inf.h>

struct config {
    char *key;
    int type;
};

// Add all valid configurations
static const struct config g_valid_config[] = { { "gpd.ta.distribution", TA_DISTRIBUTION },
                                                { "gpd.ta.api_level", TA_API_LEVEL },
                                                { "gpd.sdk.version", SDK_VERSION },
                                                { "gpd.ta.is_lib", IS_LIB },

                                                { "gpd.ta.objectEnumEnable", SSA_ENUM_ENABLE },
                                                { "gpd.ta.dynConf", IS_DYN_CONF },
                                                { "gpd.ta.target_type", TARGET_TYPE },
                                                { "gpd.ta.sys_verify_ta", SYS_VERIFY_TA },
                                                { "gpd.elf.target_version", TARGET_VERSION },
                                                { "gpd.ta.hardWareType", HARD_WARE_TYPE},
                                                { "gpd.srv.is_need_release_ta_res", SRV_RELEASE_TA_RES},
                                                { "gpd.srv.crash_callback", SRV_CRASH_CALLBACK},
                                                { "gpd.srv.is_need_create_msg", SRV_NEED_CREATE_MSG},
                                                { "gpd.srv.is_need_release_msg", SRV_NEED_RELEASE_MSG},
                                                { NULL, UNSUPPORTED } };

static int get_conf_type(const char *key, uint32_t key_size)
{
    if (key == NULL || key_size == 0)
        return TEE_ERROR_BAD_PARAMETERS;
    for (int i = 0; g_valid_config[i].key != NULL; i++) {
        uint32_t len = strlen(g_valid_config[i].key);
        if (len == key_size) {
            int ret = TEE_MemCompare(g_valid_config[i].key, key, key_size);
            if (ret == 0)
                return g_valid_config[i].type;
        }
    }
    return UNSUPPORTED;
}

static TEE_Result str_to_bool(const char *str, size_t str_size, bool *value)
{
    if (value == NULL || str == NULL || str_size == 0)
        return TEE_ERROR_BAD_PARAMETERS;
    int ret = strcasecmp(str, "true");
    if (ret == 0)
        *value = true;
    else
        *value = false;
    return TEE_SUCCESS;
}

static TEE_Result str_to_uint16(const char *str, size_t str_size, uint16_t *value, int32_t base)
{
    if (value == NULL || str == NULL || str_size == 0)
        return TEE_ERROR_BAD_PARAMETERS;

    long val = strtol(str, NULL, base);

    bool temp_check = (val < 0 || val > 0xFFFF); // Max value of uint16_t
    if (temp_check) {
        tloge("Invalid string for type uint16_t");
        return TEE_ERROR_GENERIC;
    }
    *value = (uint16_t)val;

    return TEE_SUCCESS;
}

static bool manifest_item_params_check(char *item, size_t item_size, manifest_extension_t *mani_ext)
{
    if (item == NULL)
        return true;

    if (!((mani_ext != NULL && item_size > 0) || (item_size == 0)))
        return true;

    return false;
}

static bool is_service_type(int type)
{
    return (type == SRV_RELEASE_TA_RES || type == SRV_CRASH_CALLBACK ||
        type == SRV_NEED_CREATE_MSG || type == SRV_NEED_RELEASE_MSG || type == SYS_VERIFY_TA);
}

static TEE_Result parse_service_manifest_item(int type, char *value, uint32_t size, manifest_extension_t *mani_ext)
{
    switch (type) {
    case SRV_RELEASE_TA_RES:
        return str_to_bool(value, size, &mani_ext->is_need_release_ta_res);
    case SRV_CRASH_CALLBACK:
        return str_to_bool(value, size, &mani_ext->crash_callback);
    case SRV_NEED_CREATE_MSG:
        return str_to_bool(value, size, &mani_ext->is_need_create_msg);
    case SRV_NEED_RELEASE_MSG:
        return str_to_bool(value, size, &mani_ext->is_need_release_msg);
    case SYS_VERIFY_TA:
        return str_to_bool(value, size, &mani_ext->sys_verify_ta);
    default:
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result parse_ext_item(int type, char *value, manifest_extension_t *mani_ext)
{
    if (is_service_type(type))
        return parse_service_manifest_item(type, value, strlen(value), mani_ext);
    return TEE_SUCCESS;
}
static TEE_Result tee_secure_img_parse_manifest_item(char *item, size_t item_size, manifest_extension_t *mani_ext,
                                                     struct dyn_conf_t *dyn_conf)
{
    char *ptr = NULL;
    TEE_Result ret;

    if (manifest_item_params_check(item, item_size, mani_ext))
        return TEE_ERROR_BAD_PARAMETERS;
    // Skip the empty line of manifest extension configuration
    if (item_size == 0)
        return TEE_SUCCESS;

    // Get the key of the item
    char *name = strtok_r(item, ":", &ptr);
    // Get the value of the item
    char *value = strtok_r(NULL, ":", &ptr);

    bool temp_check = (name == NULL || value == NULL);
    if (temp_check)
        return TEE_ERROR_GENERIC;

    int type = get_conf_type(name, strlen(name));

    switch (type) {
    case TA_DISTRIBUTION:
        return str_to_uint16(value, strlen(value), &mani_ext->distribution, HEX_BASE);
    case TA_API_LEVEL:
        return str_to_uint16(value, strlen(value), &mani_ext->api_level, HEX_BASE);
    case SDK_VERSION:
        return str_to_uint16(value, strlen(value), &mani_ext->sdk_version, HEX_BASE);
    case IS_LIB:
        return str_to_bool(value, strlen(value), &mani_ext->is_lib);
    case SSA_ENUM_ENABLE:
        return str_to_bool(value, strlen(value), &mani_ext->ssa_enum_enable);
    case IS_DYN_CONF:
        /* if dyn_conf is NULL, means that is not support dyn conf */
        if (dyn_conf != NULL)
            dyn_conf->dyn_conf_size = 1;
        return TEE_SUCCESS;
    case TARGET_TYPE:
        return str_to_uint16(value, strlen(value), &mani_ext->target_type, HEX_BASE);
    case TARGET_VERSION:
        ret = str_to_uint16(value, strlen(value), &mani_ext->target_version, DECIMAL_BASE);
        temp_check = (ret == TEE_SUCCESS && mani_ext->target_version == 0);
        if (temp_check) {
            tloge("target version : 0 is not valid\n");
            ret = TEE_ERROR_BAD_PARAMETERS;
        }
        return ret;
    case MEM_PAGE_ALIGN:
        return str_to_bool(value, strlen(value), &mani_ext->mem_page_align);
    case HARD_WARE_TYPE:
        return str_to_uint16(value, strlen(value), &mani_ext->hardware_type, DECIMAL_BASE);
    default:
        return parse_ext_item(type, value, mani_ext);
    }
}

static TEE_Result set_dyn_conf(const char *start, const char *end, struct dyn_conf_t *dyn_conf)
{
    /*
     * if dyn_conf is NULL, means that is not support dyn conf
     * if dyn_conf->dyn_conf_buffer is not NULL, means dyn_conf_buffer has already been set_dyn_conf
     * if dyn_conf_size is 0, means we haven't find gpd.ta.dynConf flag yet
     */
    if (dyn_conf == NULL || dyn_conf->dyn_conf_buffer != NULL || dyn_conf->dyn_conf_size == 0)
        return TEE_SUCCESS;

    if ((uintptr_t)(end - start) <= (strlen(DYN_CONF_START) + 1) || (uintptr_t)(end - start) >= MAX_IMAGE_LEN) {
        tloge("dyn conf size is invalied\n");
        return TEE_ERROR_GENERIC;
    }

    /* end - start is dyn_conf total size, we must del 'gpd.ta.dynConf:' from it */
    dyn_conf->dyn_conf_size = (uintptr_t)(end - start) - (strlen(DYN_CONF_START) + 1);
    dyn_conf->dyn_conf_buffer = malloc(dyn_conf->dyn_conf_size);
    if (dyn_conf->dyn_conf_buffer == NULL) {
        tloge("failed to load dyn conf buffer\n");
        return TEE_ERROR_GENERIC;
    }

    /* copy the dyn conf buffer, we should ignore 'gpd.ta.dynConf:', and copy rest of it */
    errno_t rc = memcpy_s(dyn_conf->dyn_conf_buffer, dyn_conf->dyn_conf_size,
                          start + strlen(DYN_CONF_START) + 1, dyn_conf->dyn_conf_size);
    if (rc != EOK) {
        tloge("Failed to copy extension");
        free(dyn_conf->dyn_conf_buffer);
        dyn_conf->dyn_conf_buffer = NULL;
        return TEE_ERROR_SECURITY;
    }

    return TEE_SUCCESS;
}

static bool check_extention_process_params(const char *extension, uint32_t extension_size,
                                    manifest_extension_t *mani_ext)
{
    if (extension_size > MAX_IMAGE_LEN) {
        tloge("manifest extension size too large: %u", extension_size);
        return true;
    }

    if (mani_ext == NULL || extension == NULL || extension_size == 0)
        return true;

    if (extension != NULL && extension_size > 0)
        return false;

    return true;
}

#define EXTENSION_MAX 64
TEE_Result tee_secure_img_parse_manifest_extension(const char *extension, uint32_t extension_size,
                                                  manifest_extension_t *mani_ext, struct dyn_conf_t *dyn_conf)
{
    TEE_Result ret = TEE_SUCCESS;

    if (check_extention_process_params(extension, extension_size, mani_ext))
        return TEE_ERROR_BAD_PARAMETERS;

    uint32_t temp_extension_size = extension_size + 1;
    char *temp_extension = TEE_Malloc(temp_extension_size, 0);
    if (temp_extension == NULL) {
        tloge(" Failed to malloc buffer for temp extension\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (memcpy_s(temp_extension, temp_extension_size, extension, extension_size) != EOK) {
        tloge(" Failed to copy extension\n");
        ret = TEE_ERROR_SECURITY;
        goto free_buffer;
    }

    const char *start = (char *)temp_extension;
    const char *end = strchr(start, '\n');
    while (end != NULL) {
        char buff[EXTENSION_MAX] = {0};
        uint32_t size = (uint32_t)(end - start);

        if ((uint32_t)(end - temp_extension) >= temp_extension_size) {
            ret = TEE_SUCCESS;
            goto free_buffer;
        }

        if (size >= EXTENSION_MAX)
            size = EXTENSION_MAX - 1;

        if (memcpy_s(buff, EXTENSION_MAX - 1, start, size) != EOK) {
            tloge("Failed to copy extension");
            ret = TEE_ERROR_SECURITY;
            goto free_buffer;
        }

        ret = tee_secure_img_parse_manifest_item(buff, size, mani_ext, dyn_conf);
        if (ret != TEE_SUCCESS) {
            tloge("Failed to parse manifest extension item: %s", buff);
            goto free_buffer;
        }

        ret = set_dyn_conf(start, end, dyn_conf);
        if (ret != TEE_SUCCESS)
            goto free_buffer;

        start = end + 1;
        end = strchr(start, '\n');
    }
free_buffer:
    TEE_Free(temp_extension);
    return ret;
}

