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

#include "drvcall_dyn_conf_mgr.h"
#include <tee_log.h>
#include <libdrv_frame.h>
#include <tee_mem_mgmt_api.h>
#include <ipclib.h>
#include <ta_framework.h>
#include <dyn_conf_dispatch_inf.h>
#include <drv_thread.h>
#include "drv_fd_ops.h"
#include "drv_param_ops.h"
#include "task_mgr.h"

int32_t receive_perm_apply_list(struct drvcall_perm_apply_t *drvcall_perm_apply)
{
    if (drvcall_perm_apply == NULL) {
        tloge("invalid drvcall perm param\n");
        return -1;
    }

    if (drvcall_perm_apply->base_perm)
        return TEE_SUCCESS;

    if (drvcall_perm_apply->drvcall_perm_apply_list_size == 0 ||
        drvcall_perm_apply->drvcall_perm_apply_list_size >= MAX_IMAGE_LEN) {
        tloge("invalied params while receive perm apply list\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* drvcall_perm_apply->drvcall_perm_apply_list_size < MAX_IMAGE_LEN means tmp_size cannot larger than 0xFFFFFFFF */
    uint32_t tmp_size = drvcall_perm_apply->drvcall_perm_apply_list_size * sizeof(struct drvcall_perm_apply_item_t);
    struct drvcall_perm_apply_item_t *drvcall_perm_apply_list = malloc(tmp_size);
    if (drvcall_perm_apply_list == NULL) {
        tloge("malloc drvcall_perm_apply_list failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (copy_from_client((uint64_t)(uintptr_t)drvcall_perm_apply->drvcall_perm_apply_list, tmp_size,
                         (uintptr_t)drvcall_perm_apply_list, tmp_size) != 0) {
        tloge("copy_from_client drvcall_perm_apply_list failed\n");
        free(drvcall_perm_apply_list);
        return TEE_ERROR_GENERIC;
    }

    drvcall_perm_apply->drvcall_perm_apply_list = drvcall_perm_apply_list;

    return TEE_SUCCESS;
}
