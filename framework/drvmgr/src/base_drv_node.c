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
#include "base_drv_node.h"
#include <libdrv_frame.h>
#include "drv_dispatch.h"
#include "drv_process_mgr.h"
#include "ta_framework.h"
#include "target_type.h"
#include "tee_config.h"
#include "tee_log.h"

const struct base_driver_node g_product_base_drv[] = {
#ifdef CRYPTO_MGR_SERVER_ENABLE
    { CRYPTOMGR,
      { CRYPTOMGR, TEE_CRYPTO_DRIVER_NAME, 10, true, DEFAULT_STACK_SIZE * 10, DEFAULT_HEAP_SIZE * 50, 0 },
      { 1, false, true, 2}
    },
#endif
#ifdef CONFIG_TEE_MISC_DRIVER
    { TEE_MISC_DRIVER, { TEE_MISC_DRIVER, TEE_MISC_DRIVER_NAME, TEE_MISC_DRV_SIZE, true, DEFAULT_STACK_SIZE,
        DEFAULT_HEAP_SIZE * 50, 0 }, { 1, false, false, 2} },
#endif
};

static const uint32_t g_product_base_drv_num =
    sizeof(g_product_base_drv) / sizeof(g_product_base_drv[0]);

bool get_base_drv_flag(const char *drv_name, uint32_t drv_name_size)
{
    if (drv_name == NULL)
        return false;

    for (uint32_t i = 0; i < g_product_base_drv_num; i++) {
        if (strncmp(drv_name, g_product_base_drv[i].mani.service_name, drv_name_size + 1) == 0)
            return true;
    }

    return false;
}

static int32_t set_tlv_node(struct drv_tlv *tlv, const struct base_driver_node *drv_service_property)
{
    errno_t ret;
    ret = memcpy_s(&tlv->uuid, sizeof(tlv->uuid), &drv_service_property->uuid, sizeof(drv_service_property->uuid));
    if (ret != EOK) {
        tloge("copy uuid failed\n");
        return -1;
    }

    ret = memcpy_s(&tlv->drv_conf.mani, sizeof(tlv->drv_conf.mani),
                   &drv_service_property->mani, sizeof(drv_service_property->mani));
    if (ret != EOK) {
        tloge("copy mani failed\n");
        return -1;
    }

    ret = memcpy_s(&tlv->drv_conf.drv_basic_info, sizeof(tlv->drv_conf.drv_basic_info),
                   &(drv_service_property->drv_basic_info), sizeof(drv_service_property->drv_basic_info));
    if (ret != EOK) {
        tloge("copy drv basic info failed\n");
        return -1;
    }

    return 0;
}

static void init_base_drv_node(const struct base_driver_node *drv_service_property)
{
    struct drv_tlv *tlv = malloc(sizeof(struct drv_tlv));
    if (tlv == NULL) {
        tloge("malloc tlv node failed\n");
        return;
    }

    errno_t rc = memset_s(tlv, sizeof(*tlv), 0, sizeof(*tlv));
    if (rc != EOK) {
        tloge("memset failed\n");
        free(tlv);
        return;
    }

    int32_t ret = set_tlv_node(tlv, drv_service_property);
    if (ret != 0) {
        tloge("set tlv node value failed\n");
        free(tlv);
        return;
    }

    struct task_node *node = alloc_and_init_drv_node(tlv);
    if (node == NULL) {
        tloge("alloc node failed\n");
        free(tlv);
        return;
    }

    if (receive_task_conf(node) != 0) {
        tloge("task conf node get failed\n");
        free(tlv);
        free_task_node(node);
        return;
    }

    free(tlv);
    return;
}

int32_t register_base_drv_node(void)
{
    uint32_t drv_property_num = g_product_base_drv_num;
    const struct base_driver_node *drv_service_property = g_product_base_drv;
    if (drv_service_property == NULL)
        return 0;

    for (uint32_t i = 0; i < drv_property_num; i++)
        init_base_drv_node(&drv_service_property[i]);

    return 0;
}
