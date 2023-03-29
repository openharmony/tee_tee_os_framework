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

#ifndef TA_CONFIG_BUILDER_H
#define TA_CONFIG_BUILDER_H

#include <tee_defines.h>
#include "dyn_conf_dispatch_inf.h"

enum ta_config_tags {
    CONFIGINFO = 0x0,
    CONFIGINFO_TA_BASIC_INFO = 0x1,
    CONFIGINFO_TA_BASIC_INFO_SERVICE_NAME,
    CONFIGINFO_TA_BASIC_INFO_SERVICE_NAME_SERVICE_NAME,
    CONFIGINFO_TA_BASIC_INFO_UUID,
    CONFIGINFO_TA_BASIC_INFO_UUID_UUID,
    CONFIGINFO_TA_MANIFEST_INFO,
    CONFIGINFO_TA_MANIFEST_INFO_INSTANCE_KEEP_ALIVE,
    CONFIGINFO_TA_MANIFEST_INFO_INSTANCE_KEEP_ALIVE_INSTANCE_KEEP_ALIVE,
    CONFIGINFO_TA_MANIFEST_INFO_STACK_SIZE,
    CONFIGINFO_TA_MANIFEST_INFO_STACK_SIZE_STACK_SIZE,
    CONFIGINFO_TA_MANIFEST_INFO_HEAP_SIZE,
    CONFIGINFO_TA_MANIFEST_INFO_HEAP_SIZE_HEAP_SIZE,
    CONFIGINFO_TA_MANIFEST_INFO_TARGET_TYPE,
    CONFIGINFO_TA_MANIFEST_INFO_TARGET_TYPE_TARGET_TYPE,
    CONFIGINFO_TA_MANIFEST_INFO_MULTI_COMMAND,
    CONFIGINFO_TA_MANIFEST_INFO_MULTI_COMMAND_MULTI_COMMAND,
    CONFIGINFO_TA_MANIFEST_INFO_MULTI_SESSION,
    CONFIGINFO_TA_MANIFEST_INFO_MULTI_SESSION_MULTI_SESSION,
    CONFIGINFO_TA_MANIFEST_INFO_SINGLE_INSTANCE,
    CONFIGINFO_TA_MANIFEST_INFO_SINGLE_INSTANCE_SINGLE_INSTANCE,
    CONFIGINFO_TA_CONTROL_INFO,
#if defined(CONFIG_APP_TEE_SE)
    CONFIGINFO_TA_CONTROL_INFO_SE_INFO,
    CONFIGINFO_TA_CONTROL_INFO_SE_INFO_SE_OPEN_SESSION,
    CONFIGINFO_TA_CONTROL_INFO_SE_INFO_SE_OPEN_SESSION_SE_OPEN_SESSION,
#endif
    CONFIGINFO_TA_CONTROL_INFO_DEBUG_INFO,
    CONFIGINFO_TA_CONTROL_INFO_DEBUG_INFO_DEBUG_STATUS,
    CONFIGINFO_TA_CONTROL_INFO_DEBUG_INFO_DEBUG_STATUS_DEBUG_STATUS,
    CONFIGINFO_TA_CONTROL_INFO_DEBUG_INFO_DEBUG_DEVICE_ID,
    CONFIGINFO_TA_CONTROL_INFO_DEBUG_INFO_DEBUG_DEVICE_ID_DEBUG_DEVICE_ID,
    CONFIGINFO_UNUSED,
};

#define SE_OPEN_SESSION_PERMISSION   0x01U
#define CERT_GENERAL_PERMISSION      0x01U

/* CN format in TA's certificate: "uuid string" + "_" + "service name" */
#define TA_CERT_MAX_CN_INFO_LEN   64
#define TA_CERT_CN_UNDERLINE_SIZE 1
#define UUID_STR_LEN              36
#define TLV_DEVICE_ID_LEN         64U
#define POLICY_OLD_VERSION        0
#define POLICY_VERSION_ONE        1
#define MAX_CALLEE_TA_COUNT       100
#define MAX_CALLEE_COMMAND_COUNT  100
#define DEVICE_ID_LEN             32
#define LEN_OFFSET_VALUE          4U
#define MAX_SERVICE_NAME_LEN 40

struct ta_manifest_info {
    bool single_instance;
    bool multi_session;
    bool multi_command;
    bool instance_keep_alive;
    uint32_t heap_size;
    uint32_t stack_size;
    bool mem_page_align;
    uint32_t target_type;
    bool sys_verify_ta;
};

struct ta_sfs_info {
    uint64_t permissions;
};

struct ta_se_info {
    uint64_t permissions;
};

struct ta_cert_perm_info {
    uint64_t permissions;
};

struct ta_debug_info {
    bool status;
    bool valid_device;
};

struct callee_ta_info {
    struct callee_ta_info *next;
    TEE_UUID uuid;
    uint32_t command_num;
    uint32_t *command_id;
};

struct ta_control_info {
    struct ta_sfs_info sfs_info;
    struct ta_se_info se_info;
    struct ta_cert_perm_info cert_info;
    uint32_t ta_manager;
    struct callee_ta_info *callee_info;
    struct ta_debug_info debug_info;
};
struct config_info {
    struct dlist_node head;
    TEE_UUID uuid;
    char service_name[MAX_SERVICE_NAME_LEN];
    uint32_t service_name_len;
    uint32_t version;
    struct ta_manifest_info manifest_info;
    struct ta_control_info control_info;
    struct dlist_node task_config_list;
};

int32_t install_ta_config(void *obj, uint32_t obj_size, const struct conf_queue_t *conf_queue);
TEE_Result check_device_id(struct config_info *config, const uint8_t *buff, uint32_t len);

#endif
