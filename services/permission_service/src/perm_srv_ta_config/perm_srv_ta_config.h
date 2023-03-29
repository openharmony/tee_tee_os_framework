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
#ifndef PERM_SRV_TA_CONFIG_H
#define PERM_SRV_TA_CONFIG_H

#include <dlist.h>
#include <stddef.h>
#include <tee_defines.h>
#include <ta_config_builder.h>
#include "permission_service.h"
#include "tee_elf_verify.h"

#define PERMSRV_OK    0
#define PERMSRV_ERROR (-1)

struct task_config {
    uint32_t taskid;
    uint32_t userid;
    struct dlist_node head;
};

struct perm_config {
    const uint8_t *tlv_buf;
    uint32_t tlv_len;
    uint32_t policy_version;
    uint8_t cn[SN_MAX_SIZE];
    size_t cn_size;
    ta_cert_t cert_type;
};

/* define TAG values for TLV Parser */
#define TLV_TAG_CONFIG_INFO      0x00
#define TLV_TAG_TA_BASIC_INFO    0x01
#define TLV_TAG_TA_MANIFEST_INFO 0x02
#define TLV_TAG_TA_CONTROL_INFO  0x03

#define TLV_TAG_CALLEETA_INFO 0x04
#define TLV_TAG_SFS_INFO      0x32
#define TLV_TAG_SE_INFO       0x33
#define TLV_TAG_DEBUG_INFO    0x35
#define TLV_TAG_CERT_INFO     0x36

#define TLV_TAG_SFS_PERMISSION  0x72
#define TLV_TAG_CERT_PERMISSION 0x73
#define TLV_TAG_CALLEETA_UUID   0x41

#define TLV_TAG_UUID                (0x01 + 0xFF)
#define TLV_TAG_SERVICE_NAME        (0x02 + 0xFF)
#define TLV_TAG_SINGLE_INSTANCE     (0x11 + 0xFF)
#define TLV_TAG_MULTI_SESSION       (0x12 + 0xFF)
#define TLV_TAG_MULTI_COMMAND       (0x13 + 0xFF)
#define TLV_TAG_HEAP_SIZE           (0x14 + 0xFF)
#define TLV_TAG_STACK_SIZE          (0x15 + 0xFF)
#define TLV_TAG_INSTANCE_KEEP_ALIVE (0x16 + 0xFF)
#define TLV_TAG_MEM_PAGE_ALIGN      (0x17 + 0xFF)
#define TLV_TAG_TARGET_TYPE         (0x18 + 0xFF)
#define TLV_TAG_SYS_VERIFY_TA       (0x19 + 0xFF)
#define TLV_TAG_SFS_PROVISION_KEY   (0x31 + 0xFF)
#define TLV_TAG_SFS_INSE            (0x32 + 0xFF)
#define TLV_TAG_SE_OPEN_SESSION     (0x41 + 0xFF)
#define TLV_TAG_TA_MANAGER          (0x71 + 0xFF)
#define TLV_TAG_CALLEETA_COMMAND_ID (0x81 + 0xFF)
#define TLV_TAG_DEBUG_STATUS        (0x51 + 0xFF)
#define TLV_TAG_DEBUG_DEVICE_ID     (0x52 + 0xFF)

TEE_Result perm_srv_parse_config_body(const TEE_UUID *uuid, struct perm_config *perm_config);
TEE_Result perm_srv_get_config_by_uuid(const TEE_UUID *uuid, struct config_info *config);
TEE_Result perm_srv_convert_uuid_to_str(const TEE_UUID *uuid, char *buff, uint32_t len);
TEE_Result perm_srv_get_config_by_taskid(uint32_t taskid, struct config_info *config);
void perm_srv_clear_ta_permissions(const TEE_UUID *uuid);
TEE_Result perm_srv_register_ta_taskid(const TEE_UUID *uuid, uint32_t taskid, uint32_t userid);
TEE_Result perm_srv_unregister_ta_taskid(const TEE_UUID *uuid, uint32_t taskid);
#endif
