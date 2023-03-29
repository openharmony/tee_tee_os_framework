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

#include "ta_config_builder.h"
#include <securec.h>
#include <tee_log.h>
#include <tee_ext_api.h>
#include <tee_mem_mgmt_api.h>

static bool check_multiply_overflow(uint32_t a, uint32_t b)
{
    uint32_t p = a * b;
    if (a != 0 && (p / a != b)) {
        tloge("the result is over flow");
        return true;
    }

    return false;
}
#define HEX_TO_STR_LEN_VALUE 2

static void hex2str(uint8_t *dest, uint32_t dest_len, const uint8_t *source, uint32_t source_len)
{
    if (check_multiply_overflow(source_len, HEX_TO_STR_LEN_VALUE))
        return;

    uint32_t len_max = source_len * HEX_TO_STR_LEN_VALUE;

    bool check = (dest == NULL || source == NULL || dest_len < len_max + 1);
    if (check)
        return;

    uint8_t ch[] = "0123456789ABCDEF";
    uint8_t *p = dest;
    uint32_t i;

    for (i = 0; i < source_len; i++) {
        *(p++) = ch[source[i] >> LEN_OFFSET_VALUE];
        *(p++) = ch[source[i] & 0xf]; /* get low bits nums */
    }
    *p = '\0';
}

/* TODO: need replace this function by new ways */
static TEE_Result tee_ext_get_device_unique_id(uint8_t *device_unique_id, uint32_t *length)
{
    (void)device_unique_id;
    (void)length;
    tloge("device id not support\n");
    return TEE_ERROR_GENERIC;
}

TEE_Result check_device_id(struct config_info *config, const uint8_t *buff, uint32_t len)
{
    bool is_invalid = (config == NULL || buff == NULL || len == 0);
    if (is_invalid)
        return TEE_ERROR_BAD_PARAMETERS;

    if (config->control_info.debug_info.valid_device)
        return TEE_SUCCESS;

    if (len != TLV_DEVICE_ID_LEN) {
        tloge("config tlv parser::device id len invalid should be: %u\n", TLV_DEVICE_ID_LEN);
        config->control_info.debug_info.valid_device = false;
        return TEE_ERROR_GENERIC;
    }

    uint8_t unique_id[DEVICE_ID_LEN] = { 0 };
    uint32_t id_len = sizeof(unique_id);
    uint8_t tlv_device_id[DEVICE_ID_LEN * 2 + 1] = { 0 }; /* 2 is double */

    if (tee_ext_get_device_unique_id(unique_id, &id_len) != TEE_SUCCESS) {
        tloge("get device id failed\n");
        config->control_info.debug_info.valid_device = false;
        return TEE_ERROR_GENERIC;
    }

    hex2str(tlv_device_id, sizeof(tlv_device_id), unique_id, sizeof(unique_id));
    if (TEE_MemCompare(tlv_device_id, buff, len) == 0)
        config->control_info.debug_info.valid_device = true;

    return TEE_SUCCESS;
}

#ifdef TEE_SUPPORT_DYN_CONF

/* build drv conf */
static int32_t handle_ta_basic_info_service_name(struct config_info *cfg_info,
                                                 uint32_t size, const char *value)
{
    if (size == 0 || size >= MAX_SERVICE_NAME_LEN) {
        tloge("param invalid while handle config info ta basic info service name\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (memcpy_s(cfg_info->service_name, MAX_SERVICE_NAME_LEN, value, size) != 0) {
        tloge("memcpy failed while handle config info ta basic info service name\n");
        return TEE_ERROR_GENERIC;
    }
    cfg_info->service_name[size] = '\0';
    cfg_info->service_name_len = size;

    return TEE_SUCCESS;
}

static int32_t build_ta_basic_info_service_name(struct dlist_node **pos, const struct conf_node_t *node,
                                                void *obj, uint32_t obj_size)
{
    (void)pos;
    struct config_info *cfg_info = NULL;
    if (obj_size != sizeof(*cfg_info)) {
        tloge("obj size is invalid while build ta basic info service name\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    cfg_info = (struct config_info *)obj;

    switch (node->tag) {
    case CONFIGINFO_TA_BASIC_INFO_SERVICE_NAME_SERVICE_NAME:
        if (handle_ta_basic_info_service_name(cfg_info, node->size, node->value) != TEE_SUCCESS) {
            tloge("handle ta basic info service name failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    default:
        break;
    }

    return TEE_SUCCESS;
}

static int32_t handle_ta_basic_info_uuid(struct config_info *cfg_info, uint32_t size, const char *value)
{
    if (size == 0 || size > MAX_UUID_SIZE) {
        tloge("param invalid while handle config info ta basic info uuid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    int32_t ret = tlv_to_uuid(value, size, &cfg_info->uuid);
    if (ret != TEE_SUCCESS) {
        tloge("param invalid while handle config info ta basic info trans uuid failed\n");
        return ret;
    }

    return TEE_SUCCESS;
}

static int32_t build_ta_basic_info_uuid(struct dlist_node **pos, const struct conf_node_t *node,
                                        void *obj, uint32_t obj_size)
{
    (void)pos;
    struct config_info *cfg_info = NULL;
    if (obj_size != sizeof(*cfg_info)) {
        tloge("obj size is invalid while build ta basic info uuid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    cfg_info = (struct config_info *)obj;

    switch (node->tag) {
    case CONFIGINFO_TA_BASIC_INFO_UUID_UUID:
        if (handle_ta_basic_info_uuid(cfg_info, node->size, node->value) != TEE_SUCCESS) {
            tloge("handle ta basic info uuid\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    default:
        break;
    }

    return TEE_SUCCESS;
}

static int32_t build_ta_basic_info(struct dlist_node **pos, const struct conf_node_t *node,
                                   void *obj, uint32_t obj_size)
{
    (void)pos;
    struct config_info *cfg_info = NULL;
    if (obj_size != sizeof(*cfg_info)) {
        tloge("obj size is invalid while build ta basic info\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    cfg_info = (struct config_info *)obj;

    switch (node->tag) {
    case CONFIGINFO_TA_BASIC_INFO_SERVICE_NAME:
        if (handle_conf_node_to_obj(pos, build_ta_basic_info_service_name,
                                    cfg_info, sizeof(*cfg_info)) != TEE_SUCCESS) {
            tloge("build ta basic info service name failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    case CONFIGINFO_TA_BASIC_INFO_UUID:
        if (handle_conf_node_to_obj(pos, build_ta_basic_info_uuid,
                                    cfg_info, sizeof(*cfg_info)) != TEE_SUCCESS) {
            tloge("build ta basic info service name failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    default:
        tlogd("skip in build ta basic info\n");
        if (handle_conf_node_to_obj(pos, NULL, cfg_info, sizeof(*cfg_info)) != TEE_SUCCESS)
            return TEE_ERROR_GENERIC;
        break;
    }

    return TEE_SUCCESS;
}

static int32_t build_ta_mani_info_instance_keep_alive(struct dlist_node **pos, const struct conf_node_t *node,
                                                      void *obj, uint32_t obj_size)
{
    (void)pos;
    struct config_info *cfg_info = NULL;
    if (obj_size != sizeof(*cfg_info)) {
        tloge("obj size is invalid while build ta manifest info instance keep alive\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    cfg_info = (struct config_info *)obj;

    switch (node->tag) {
    case CONFIGINFO_TA_MANIFEST_INFO_INSTANCE_KEEP_ALIVE_INSTANCE_KEEP_ALIVE:
        if (node->size == 1 && node->value[0] == TLV_TRUE)
            cfg_info->manifest_info.instance_keep_alive = true;
        break;
    default:
        break;
    }

    return TEE_SUCCESS;
}

static int32_t build_ta_mani_info_multi_command(struct dlist_node **pos, const struct conf_node_t *node,
                                                void *obj, uint32_t obj_size)
{
    (void)pos;
    struct config_info *cfg_info = NULL;
    if (obj_size != sizeof(*cfg_info)) {
        tloge("obj size is invalid while build ta manifest info multi command\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    cfg_info = (struct config_info *)obj;

    switch (node->tag) {
    case CONFIGINFO_TA_MANIFEST_INFO_MULTI_COMMAND_MULTI_COMMAND:
        if (node->size == 1 && node->value[0] == TLV_TRUE)
            cfg_info->manifest_info.multi_command = true;
        break;
    default:
        break;
    }

    return TEE_SUCCESS;
}

static int32_t build_ta_mani_info_multi_session(struct dlist_node **pos, const struct conf_node_t *node,
                                                void *obj, uint32_t obj_size)
{
    (void)pos;
    struct config_info *cfg_info = NULL;
    if (obj_size != sizeof(*cfg_info)) {
        tloge("obj size is invalid while build ta manifest info multi session\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    cfg_info = (struct config_info *)obj;

    switch (node->tag) {
    case CONFIGINFO_TA_MANIFEST_INFO_MULTI_SESSION_MULTI_SESSION:
        if (node->size == 1 && node->value[0] == TLV_TRUE)
            cfg_info->manifest_info.multi_session = true;
        break;
    default:
        break;
    }

    return TEE_SUCCESS;
}

static int32_t handle_ta_mani_info_stack_size(uint32_t *stack_size, uint32_t size, const char *value)
{
    uint64_t tmp_stack_size;

    if (value == NULL || size > MAX_UINT32_LEN || size == 0) {
        tloge("invalid param while handle stack size\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    char buff[MAX_UINT32_LEN + 1];
    if (memcpy_s(buff, sizeof(buff), value, size) != 0) {
        tloge("memcpy failed while handle stack size\n");
        return TEE_ERROR_GENERIC;
    }
    buff[size] = '\0';

    if (trans_str_to_int(buff, size, BASE_OF_TEN, &tmp_stack_size) != TEE_SUCCESS) {
        tloge("get stack size failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (tmp_stack_size > UINT32_MAX) {
        tloge("stack size is invalied %llx\n", (unsigned long long)tmp_stack_size);
        return TEE_ERROR_GENERIC;
    }

    *stack_size = (uint32_t)tmp_stack_size;

    return TEE_SUCCESS;
}

static int32_t build_ta_mani_info_stack_size(struct dlist_node **pos, const struct conf_node_t *node,
                                             void *obj, uint32_t obj_size)
{
    (void)pos;
    struct config_info *cfg_info = NULL;
    if (obj_size != sizeof(*cfg_info)) {
        tloge("obj size is invalid while build ta manifest info stack size\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    cfg_info = (struct config_info *)obj;

    switch (node->tag) {
    case CONFIGINFO_TA_MANIFEST_INFO_STACK_SIZE_STACK_SIZE:
        if (handle_ta_mani_info_stack_size(&cfg_info->manifest_info.stack_size,
                                           node->size, node->value) != TEE_SUCCESS) {
            tloge("build ta manifest info stack size failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    default:
        break;
    }

    return TEE_SUCCESS;
}

static int32_t handle_ta_mani_info_heap_size(uint32_t *heap_size, uint32_t size, const char *value)
{
    uint64_t tmp_heap_size;

    if (value == NULL || size > MAX_UINT32_LEN || size == 0) {
        tloge("invalid param while handle heap size\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    char buff[MAX_UINT32_LEN + 1];
    if (memcpy_s(buff, sizeof(buff), value, size) != 0) {
        tloge("memcpy failed while handle heap size\n");
        return TEE_ERROR_GENERIC;
    }
    buff[size] = '\0';

    if (trans_str_to_int(buff, size, BASE_OF_TEN, &tmp_heap_size) != TEE_SUCCESS) {
        tloge("get heap size failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (tmp_heap_size > UINT32_MAX) {
        tloge("heap size is invalied %llx\n", (unsigned long long)tmp_heap_size);
        return TEE_ERROR_GENERIC;
    }

    *heap_size = (uint32_t)tmp_heap_size;

    return TEE_SUCCESS;
}

static int32_t build_ta_mani_info_heap_size(struct dlist_node **pos, const struct conf_node_t *node,
                                            void *obj, uint32_t obj_size)
{
    (void)pos;
    struct config_info *cfg_info = NULL;
    if (obj_size != sizeof(*cfg_info)) {
        tloge("obj size is invalid while build ta manifest info heap size\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    cfg_info = (struct config_info *)obj;

    switch (node->tag) {
    case CONFIGINFO_TA_MANIFEST_INFO_HEAP_SIZE_HEAP_SIZE:
        if (handle_ta_mani_info_heap_size(&cfg_info->manifest_info.heap_size,
                                          node->size, node->value) != TEE_SUCCESS) {
            tloge("build ta manifest info heap size failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    default:
        break;
    }

    return TEE_SUCCESS;
}

static int32_t handle_ta_mani_info_target_type(uint32_t *target_type, uint32_t size, const char *value)
{
    uint64_t tmp_target_type;

    if (value == NULL || size > MAX_UINT32_LEN || size == 0) {
        tloge("invalid param while handle target type\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    char buff[MAX_UINT32_LEN + 1];
    if (memcpy_s(buff, sizeof(buff), value, size) != 0) {
        tloge("memcpy failed while handle target type\n");
        return TEE_ERROR_GENERIC;
    }
    buff[size] = '\0';

    if (trans_str_to_int(buff, size, BASE_OF_TEN, &tmp_target_type) != TEE_SUCCESS) {
        tloge("get heap size failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (tmp_target_type > UINT32_MAX) {
        tloge("target type is invalied %llx\n", (unsigned long long)tmp_target_type);
        return TEE_ERROR_GENERIC;
    }

    *target_type = (uint32_t)tmp_target_type;

    return TEE_SUCCESS;
}

static int32_t build_ta_mani_info_target_type(struct dlist_node **pos, const struct conf_node_t *node,
                                              void *obj, uint32_t obj_size)
{
    (void)pos;
    struct config_info *cfg_info = NULL;
    if (obj_size != sizeof(*cfg_info)) {
        tloge("obj size is invalid while build ta manifest info target type\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    cfg_info = (struct config_info *)obj;

    switch (node->tag) {
    case CONFIGINFO_TA_MANIFEST_INFO_TARGET_TYPE_TARGET_TYPE:
        if (handle_ta_mani_info_target_type(&cfg_info->manifest_info.target_type,
                                            node->size, node->value) != TEE_SUCCESS) {
            tloge("build ta manifest info target type failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    default:
        break;
    }

    return TEE_SUCCESS;
}

static int32_t build_ta_mani_info_single_instance(struct dlist_node **pos, const struct conf_node_t *node,
                                                  void *obj, uint32_t obj_size)
{
    (void)pos;
    struct config_info *cfg_info = NULL;
    if (obj_size != sizeof(*cfg_info)) {
        tloge("obj size is invalid while build ta manifest info single instance\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    cfg_info = (struct config_info *)obj;

    switch (node->tag) {
    case CONFIGINFO_TA_MANIFEST_INFO_SINGLE_INSTANCE_SINGLE_INSTANCE:
        if (node->size == 1 && node->value[0] == TLV_TRUE)
            cfg_info->manifest_info.single_instance = true;
        break;
    default:
        break;
    }

    return TEE_SUCCESS;
}

static struct dyn_conf_build_func ta_mani_funcs[] = {
    { CONFIGINFO_TA_MANIFEST_INFO_INSTANCE_KEEP_ALIVE, build_ta_mani_info_instance_keep_alive, NULL },
    { CONFIGINFO_TA_MANIFEST_INFO_STACK_SIZE, build_ta_mani_info_stack_size, NULL },
    { CONFIGINFO_TA_MANIFEST_INFO_HEAP_SIZE, build_ta_mani_info_heap_size, NULL },
    { CONFIGINFO_TA_MANIFEST_INFO_TARGET_TYPE, build_ta_mani_info_target_type, NULL },
    { CONFIGINFO_TA_MANIFEST_INFO_MULTI_COMMAND, build_ta_mani_info_multi_command, NULL },
    { CONFIGINFO_TA_MANIFEST_INFO_MULTI_SESSION, build_ta_mani_info_multi_session, NULL },
    { CONFIGINFO_TA_MANIFEST_INFO_SINGLE_INSTANCE, build_ta_mani_info_single_instance, NULL },
};

static int32_t build_ta_mani_info(struct dlist_node **pos, const struct conf_node_t *node,
                                  void *obj, uint32_t obj_size)
{
    (void)pos;
    struct config_info *cfg_info = NULL;
    if (obj_size != sizeof(*cfg_info)) {
        tloge("obj size is invalid while build ta manifest info\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    cfg_info = (struct config_info *)obj;

    uint32_t ta_mani_funcs_size = sizeof(ta_mani_funcs) / sizeof(ta_mani_funcs[0]);
    uint32_t i;
    for (i = 0; i < ta_mani_funcs_size; i++) {
        if (node->tag != ta_mani_funcs[i].tag)
            continue;

        if (ta_mani_funcs[i].handle != NULL &&
            handle_conf_node_to_obj(pos, ta_mani_funcs[i].handle, cfg_info, sizeof(*cfg_info)) != TEE_SUCCESS)
            return TEE_ERROR_GENERIC;

        if (ta_mani_funcs[i].checker != NULL && ta_mani_funcs[i].checker(cfg_info) != TEE_SUCCESS)
            return TEE_ERROR_GENERIC;

        break;
    }

    if (i == ta_mani_funcs_size) {
        tlogd("skip in build ta manifest info\n");
        if (handle_conf_node_to_obj(pos, NULL, cfg_info, sizeof(*cfg_info)) != TEE_SUCCESS)
            return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

#if defined(CONFIG_APP_TEE_SE)
static int32_t build_ta_control_info_se_open_session(struct dlist_node **pos, const struct conf_node_t *node,
                                                     void *obj, uint32_t obj_size)
{
    (void)pos;
    struct config_info *cfg_info = NULL;
    if (obj_size != sizeof(*cfg_info)) {
        tloge("obj size is invalid while build se open session\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    cfg_info = (struct config_info *)obj;

    switch (node->tag) {
    case CONFIGINFO_TA_CONTROL_INFO_SE_INFO_SE_OPEN_SESSION_SE_OPEN_SESSION:
        if (node->size == 1 && node->value[0] == TLV_TRUE)
            cfg_info->control_info.se_info.permissions |= SE_OPEN_SESSION_PERMISSION;
        break;
    default:
        break;
    }

    return TEE_SUCCESS;
}

static int32_t build_ta_control_info_se_info(struct dlist_node **pos, const struct conf_node_t *node,
                                             void *obj, uint32_t obj_size)
{
    (void)pos;
    struct config_info *cfg_info = NULL;
    if (obj_size != sizeof(*cfg_info)) {
        tloge("obj size is invalid while build se info\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    cfg_info = (struct config_info *)obj;

    switch (node->tag) {
    case CONFIGINFO_TA_CONTROL_INFO_SE_INFO_SE_OPEN_SESSION:
        if (handle_conf_node_to_obj(pos, build_ta_control_info_se_open_session,
                                    cfg_info, sizeof(*cfg_info)) != TEE_SUCCESS) {
            tloge("build ta control info se info se open session failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    default:
        tlogd("skip in build ta control info se info\n");
        if (handle_conf_node_to_obj(pos, NULL, cfg_info, sizeof(*cfg_info)) != TEE_SUCCESS)
            return TEE_ERROR_GENERIC;
        break;
    }

    return TEE_SUCCESS;
}
#endif

static int32_t build_ta_control_info_debug_status(struct dlist_node **pos, const struct conf_node_t *node,
                                                  void *obj, uint32_t obj_size)
{
    (void)pos;
    struct config_info *cfg_info = NULL;
    if (obj_size != sizeof(*cfg_info)) {
        tloge("obj size is invalid while build debug status\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    cfg_info = (struct config_info *)obj;

    switch (node->tag) {
    case CONFIGINFO_TA_CONTROL_INFO_DEBUG_INFO_DEBUG_STATUS_DEBUG_STATUS:
        if (node->size == 1 && node->value[0] == TLV_TRUE)
            cfg_info->control_info.debug_info.status = true;
        break;
    default:
        break;
    }

    return TEE_SUCCESS;
}

static int32_t handle_ta_control_info_debug_device_id(struct config_info *cfg_info, const struct conf_node_t *node)
{
    if (cfg_info == NULL || node == NULL || node->size != TLV_DEVICE_ID_LEN) {
        tloge("bad param\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint8_t buff[TLV_DEVICE_ID_LEN + 1] = { 0 };
    if (memcpy_s(buff, TLV_DEVICE_ID_LEN, node->value, node->size) != 0) {
        tloge("memcpy for debug device id failed\n");
        return TEE_ERROR_GENERIC;
    }
    buff[node->size] = '\0';

    if (check_device_id(cfg_info, buff, node->size) != TEE_SUCCESS) {
        tloge("check device id failed\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static int32_t build_ta_control_info_debug_device_id(struct dlist_node **pos, const struct conf_node_t *node,
                                                     void *obj, uint32_t obj_size)
{
    (void)pos;
    struct config_info *cfg_info = NULL;
    if (obj_size != sizeof(*cfg_info)) {
        tloge("obj size is invalid while build debug device id\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    cfg_info = (struct config_info *)obj;

    switch (node->tag) {
    case CONFIGINFO_TA_CONTROL_INFO_DEBUG_INFO_DEBUG_DEVICE_ID_DEBUG_DEVICE_ID:
        if (handle_ta_control_info_debug_device_id(cfg_info, node) != TEE_SUCCESS) {
            tloge("check device id failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    default:
        break;
    }

    return TEE_SUCCESS;
}

static int32_t build_ta_control_info_debug_info(struct dlist_node **pos, const struct conf_node_t *node,
                                                void *obj, uint32_t obj_size)
{
    (void)pos;
    struct config_info *cfg_info = NULL;
    if (obj_size != sizeof(*cfg_info)) {
        tloge("obj size is invalid while build debug info\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    cfg_info = (struct config_info *)obj;

    switch (node->tag) {
    case CONFIGINFO_TA_CONTROL_INFO_DEBUG_INFO_DEBUG_STATUS:
        if (handle_conf_node_to_obj(pos, build_ta_control_info_debug_status,
                                    cfg_info, sizeof(*cfg_info)) != TEE_SUCCESS) {
            tloge("build ta control info debug info debug status failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    case CONFIGINFO_TA_CONTROL_INFO_DEBUG_INFO_DEBUG_DEVICE_ID:
        if (handle_conf_node_to_obj(pos, build_ta_control_info_debug_device_id,
                                    cfg_info, sizeof(*cfg_info)) != TEE_SUCCESS) {
            tloge("build ta control info debug info debug status failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    default:
        tlogd("skip in build ta control info debug info\n");
        if (handle_conf_node_to_obj(pos, NULL, cfg_info, sizeof(*cfg_info)) != TEE_SUCCESS)
            return TEE_ERROR_GENERIC;
        break;
    }

    return TEE_SUCCESS;
}

static int32_t build_ta_control_info(struct dlist_node **pos, const struct conf_node_t *node,
                                     void *obj, uint32_t obj_size)
{
    (void)pos;
    struct config_info *cfg_info = (struct config_info *)obj;
    if (obj_size != sizeof(*cfg_info)) {
        tloge("obj size is invalid while build ta control info\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    switch (node->tag) {
#if defined(CONFIG_APP_TEE_SE)
    case CONFIGINFO_TA_CONTROL_INFO_SE_INFO:
        if (handle_conf_node_to_obj(pos, build_ta_control_info_se_info,
                                    cfg_info, sizeof(*cfg_info)) != TEE_SUCCESS) {
            tloge("build ta control info rpmb info failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
#endif
    case CONFIGINFO_TA_CONTROL_INFO_DEBUG_INFO:
        if (handle_conf_node_to_obj(pos, build_ta_control_info_debug_info,
                                    cfg_info, sizeof(*cfg_info)) != TEE_SUCCESS) {
            tloge("build ta control info rpmb info failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    default:
        tlogd("skip in build ta control info\n");
        if (handle_conf_node_to_obj(pos, NULL, cfg_info, sizeof(*cfg_info)) != TEE_SUCCESS)
            return TEE_ERROR_GENERIC;
        break;
    }

    return TEE_SUCCESS;
}

static int32_t build_ta_config(struct dlist_node **pos, const struct conf_node_t *node, void *obj, uint32_t obj_size)
{
    struct config_info *cfg_info = NULL;

    if (obj_size != sizeof(*cfg_info)) {
        tloge("obj size is invalid while build ta config\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    cfg_info = (struct config_info *)obj;

    switch (node->tag) {
    case CONFIGINFO_TA_BASIC_INFO:
        if (handle_conf_node_to_obj(pos, build_ta_basic_info,
                                    cfg_info, sizeof(*cfg_info)) != TEE_SUCCESS) {
            tloge("build ta basic info failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    case CONFIGINFO_TA_MANIFEST_INFO:
        if (handle_conf_node_to_obj(pos, build_ta_mani_info,
                                    cfg_info, sizeof(*cfg_info)) != TEE_SUCCESS) {
            tloge("build ta basic info failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    case CONFIGINFO_TA_CONTROL_INFO:
        if (handle_conf_node_to_obj(pos, build_ta_control_info,
                                    cfg_info, sizeof(*cfg_info)) != TEE_SUCCESS) {
            tloge("build ta basic info failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    default:
        tlogd("skip in build ta config\n");
        if (handle_conf_node_to_obj(pos, NULL, cfg_info, sizeof(*cfg_info)) != TEE_SUCCESS)
            return TEE_ERROR_GENERIC;
        break;
    }

    return TEE_SUCCESS;
}

int32_t install_ta_config(void *obj, uint32_t obj_size, const struct conf_queue_t *conf_queue)
{
    if (conf_queue == NULL || obj == NULL) {
        tloge("param is invalid while install ta config\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (obj_size != sizeof(struct config_info)) {
        tloge("obj size is invalied while install ta config\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    struct config_info *cfg_info = (struct config_info *)obj;

    /* init ta config info */
    if (memset_s(cfg_info, sizeof(*cfg_info), 0, sizeof(*cfg_info)) != 0) {
        tloge("memset for ta config info failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (!dlist_empty(&conf_queue->queue)) {
        struct dlist_node *pos = dlist_get_next(&conf_queue->queue);
        int32_t ret = handle_conf_node_to_obj(&pos, build_ta_config, cfg_info, sizeof(*cfg_info));
        if (ret != TEE_SUCCESS) {
            tloge("handle ta config failed\n");
            return ret;
        }
    }

    return TEE_SUCCESS;
}

#else

int32_t install_ta_config(void *obj, uint32_t obj_size, const struct conf_queue_t *conf_queue)
{
    (void)obj;
    (void)obj_size;
    (void)conf_queue;
    return TEE_SUCCESS;
}

#endif
