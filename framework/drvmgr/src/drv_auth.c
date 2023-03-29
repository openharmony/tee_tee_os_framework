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
#include "drv_auth.h"
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <tee_log.h>
#include <tee_drv_internal.h>
#include "drv_dyn_conf_mgr.h"
#include "drvcall_dyn_conf_mgr.h"

static int32_t get_mac_perm_by_uuid(const struct drv_conf_t *drv_conf, const struct tee_uuid *srv_uuid,
                                    uint64_t *mac_perm)
{
    uint32_t i;

    for (i = 0; i < drv_conf->mac_info_list_size; i++) {
        struct drv_mac_info_t drv_mac_info = drv_conf->mac_info_list[i];

        if (memcmp(&drv_mac_info.uuid, srv_uuid, sizeof(struct tee_uuid)) == 0) {
            if (mac_perm != NULL)
                *mac_perm = drv_mac_info.perm;
            return TEE_SUCCESS;
        }
    }
    tloge("cannot find uuid %08x-%04x-%04x in mac list\n",
          srv_uuid->timeLow, srv_uuid->timeMid, srv_uuid->timeHiAndVersion);
    return TEE_ERROR_GENERIC;
}

static int32_t get_perm_by_service_name_in_perm_apply_list(const struct task_tlv *tlv,
                                                           const char *service_name, uint32_t service_name_size,
                                                           uint64_t *perm)
{
    uint32_t i;

    for (i = 0; i < tlv->drvcall_perm_apply_list_size; i++) {
        struct drvcall_perm_apply_item_t item = tlv->drvcall_perm_apply_list[i];
        if (item.name_size != service_name_size)
            continue;

        if (strncmp(item.name, service_name, item.name_size) == 0) {
            if (perm != NULL)
                *perm = item.perm;
            return TEE_SUCCESS;
        }
    }

    tloge("cannot find service name %s in perm apply list\n", service_name);
    return TEE_ERROR_GENERIC;
}

bool caller_open_auth_check(const struct task_node *call_node, const char *drv_name, uint32_t name_len)
{
    if (call_node == NULL || drv_name == NULL || name_len == 0) {
        tloge("invalid param\n");
        return false;
    }

    /* check if TA have registed drv name in perm apply list */
    if (get_perm_by_service_name_in_perm_apply_list(&call_node->tlv, drv_name, name_len, NULL) != TEE_SUCCESS)
        return false;

    return true;
}

bool drv_mac_open_auth_check(const struct drv_conf_t *drv_conf, const struct tee_uuid *uuid)
{
    if (uuid == NULL || drv_conf == NULL) {
        tloge("invalid uuid or drv_conf\n");
        return false;
    }

    /* if drv not have mac list, all TA can open */
    if (drv_conf->mac_info_list_size == 0)
        return true;

    /* check if TA in drv's mac list */
    if (get_mac_perm_by_uuid(drv_conf, uuid, NULL) == TEE_SUCCESS)
        return true;

    return false;
}

int32_t get_drvcaller_cmd_perm(const struct task_node *call_node, const struct task_node *dnode, uint64_t *perm)
{
    if (call_node == NULL || dnode == NULL || dnode->tlv.drv_conf == NULL || perm == NULL) {
        tloge("invalid param\n");
        return -1;
    }

    int32_t ret;
    if (dnode->tlv.drv_conf->mac_info_list_size == 0) {
        tlogd("no mac perm, use drvcaller perm\n");
        ret = get_perm_by_service_name_in_perm_apply_list(&call_node->tlv,
            dnode->tlv.drv_conf->mani.service_name, dnode->tlv.drv_conf->mani.service_name_size, perm);
        return ret;
    }

    ret = get_mac_perm_by_uuid(dnode->tlv.drv_conf, &call_node->tlv.uuid, perm);
    return ret;
}
