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
#include "drvcall_dyn_conf_builder.h"
#include <stdint.h>
#include <securec.h>
#include <tee_log.h>
#include <tee_defines.h>
#include <drv.h>
#include <tee_drv_internal.h>
#include <ta_framework.h>
#include <drvcall_dyn_conf_mgr.h>
#include <mem_ops.h>
#include "tee_inner_uuid.h"

#ifdef TEE_SUPPORT_DYN_CONF
void free_drvcall_perm(struct drvcall_perm_apply_t *drvcall_perm)
{
    if (drvcall_perm == NULL) {
        tloge("invalid drvcall perm\n");
        return;
    }

    if (drvcall_perm->drvcall_perm_apply_list != NULL) {
        uint32_t size = drvcall_perm->drvcall_perm_apply_list_size *
                        sizeof(struct drvcall_perm_apply_item_t);
        free_sharemem(drvcall_perm->drvcall_perm_apply_list, size);
        drvcall_perm->drvcall_perm_apply_list = NULL;
    }
}

static void free_drvcall_conf(struct drvcall_conf_t *drvcall_conf)
{
    free_drvcall_perm(&drvcall_conf->drvcall_perm_apply);
    free(drvcall_conf);
}

int32_t init_drvcall_conf(struct drvcall_perm_apply_t *drvcall_perm_apply,
                          const struct conf_queue_t *conf_queue)
{
    struct tee_uuid drv_server_uuid = DRVMGR;

    if (drvcall_perm_apply == NULL || conf_queue == NULL) {
        tloge("invalid drvcall perm or conf queue\n");
        return TEE_ERROR_GENERIC;
    }

    uint16_t num = get_num_of_tag(conf_queue, DRV_PERM_DRVCALL_PERM_APPLY_ITEM);
    /* num < 0xffff means size cannot larger than 0xFFFFFFFF */
    uint32_t size = num * sizeof(struct drvcall_perm_apply_item_t);
    if (size == 0)
        return TEE_SUCCESS;

    drvcall_perm_apply->drvcall_perm_apply_list_size = 0;
    drvcall_perm_apply->drvcall_perm_apply_list = alloc_sharemem_aux(&drv_server_uuid, size);
    if (drvcall_perm_apply->drvcall_perm_apply_list == NULL) {
        tloge("malloc share mem for drvcall perm apply list failed\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static int32_t handle_perm_apply_item_name(struct drvcall_perm_apply_item_t *drvcall_perm_apply_item,
                                           uint32_t size, const char *value)
{
    if (size == 0 || size >= DRV_NAME_MAX_LEN) {
        tloge("the drv name in drvcall's perm apply list is invalied\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (memcpy_s(drvcall_perm_apply_item->name, DRV_NAME_MAX_LEN, value, size) != 0) {
        tloge("memcpy for drvcall perm apply item failed\n");
        return TEE_ERROR_GENERIC;
    }
    drvcall_perm_apply_item->name[size] = '\0';
    drvcall_perm_apply_item->name_size = size;

    return TEE_SUCCESS;
}

int32_t combine_perms(uint64_t *perm, uint32_t size, const char *value)
{
    if (perm == NULL || value == NULL || size == 0 || size >= MAX_IMAGE_LEN) {
        tloge("invalied params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    char *buff = malloc(size + 1);
    if (buff == NULL) {
        tloge("malloc for buff failed\n");
        return TEE_ERROR_GENERIC;
    }

    int32_t ret = memcpy_s(buff, size + 1, value, size);
    if (ret != 0) {
        tloge("memcpy for buff failed\n");
        goto out;
    }
    buff[size] = '\0';

    *perm = 0;
    char *target = buff;
    char *rest = NULL;
    while (1) {
        target = strtok_r(target, "|", &rest);
        if (target == NULL)
            break;

        uint64_t target_size = strlen(target);
        if (target_size > MAX_UINT32_LEN) {
            tloge("target size cannot larger than MAX_UINT32_LEN\n");
            ret = TEE_ERROR_BAD_PARAMETERS;
            goto out;
        }

        uint64_t off = 0;
        if (trans_str_to_int(target, (uint32_t)target_size, BASE_OF_TEN, &off) != TEE_SUCCESS) {
            tloge("get perms failed while combine perms\n");
            ret = TEE_ERROR_BAD_PARAMETERS;
            goto out;
        }

        if (off == 0 || off > BIT_NUM_OF_UINT64) {
            tloge("cmd permission must in range of [1, 64]\n");
            ret = TEE_ERROR_BAD_PARAMETERS;
            goto out;
        }

        *perm = *perm | (1 << (off - 1));

        target = NULL;
    }

out:
    free(buff);
    return ret;
}

static int32_t handle_perm_apply_item_perm(uint64_t *perm, uint32_t size, const char *value)
{
    return combine_perms(perm, size, value);
}

static int32_t build_drvcall_perm_apply_item(struct dlist_node **pos, const struct conf_node_t *node,
                                             void *obj, uint32_t obj_size)
{
    struct drvcall_perm_apply_item_t *drvcall_perm_apply_item = NULL;
    (void)pos;

    if (obj_size != sizeof(*drvcall_perm_apply_item)) {
        tloge("invalied params while build drvcall perm apply item\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    drvcall_perm_apply_item = (struct drvcall_perm_apply_item_t *)obj;

    switch (node->tag) {
    case DRV_PERM_DRVCALL_PERM_APPLY_ITEM_NAME:
        if (handle_perm_apply_item_name(drvcall_perm_apply_item, node->size, node->value) != TEE_SUCCESS) {
            tloge("handle perm apply item name failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    case DRV_PERM_DRVCALL_PERM_APPLY_ITEM_PERMISSION:
        if (handle_perm_apply_item_perm(&drvcall_perm_apply_item->perm, node->size, node->value) != TEE_SUCCESS) {
            tloge("handle perm apply item perm failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    default:
        tlogd("skip in build drvcall perm apply item\n");
        if (handle_conf_node_to_obj(pos, NULL, drvcall_perm_apply_item,
                                    sizeof(*drvcall_perm_apply_item)) != TEE_SUCCESS)
            return TEE_ERROR_GENERIC;
        break;
    }

    return TEE_SUCCESS;
}

static int32_t check_perm_apply_list(struct drvcall_perm_apply_item_t drvcall_perm_apply_item)
{
    if (drvcall_perm_apply_item.name_size == 0 || drvcall_perm_apply_item.name_size >= DRV_NAME_MAX_LEN) {
        tloge("drv's name size is invalied in perm apply list\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

int32_t build_drvcall_perm_apply(struct dlist_node **pos, const struct conf_node_t *node,
                                 void *obj, uint32_t obj_size)
{
    struct drvcall_perm_apply_t *drvcall_perm_apply = NULL;

    if (pos == NULL || node == NULL || obj == NULL || obj_size != sizeof(*drvcall_perm_apply)) {
        tloge("invalied params while build drvcall perm apply\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    drvcall_perm_apply = (struct drvcall_perm_apply_t *)obj;
    uint32_t index = drvcall_perm_apply->drvcall_perm_apply_list_size;

    switch (node->tag) {
    case DRV_PERM_DRVCALL_PERM_APPLY_ITEM:
        /*
         * drvcall_perm_apply_list malloc by the num of tag DRV_PERM_DRVCALL_PERM_APPLY_ITEM
         * so index will never over the bound of drvcall_perm_apply_list
         */
        if (handle_conf_node_to_obj(pos, build_drvcall_perm_apply_item,
                                    &drvcall_perm_apply->drvcall_perm_apply_list[index],
                                    sizeof(drvcall_perm_apply->drvcall_perm_apply_list[index])) != TEE_SUCCESS) {
            tloge("build drvcall perm apply failed\n");
            return TEE_ERROR_GENERIC;
        }

        if (check_perm_apply_list(drvcall_perm_apply->drvcall_perm_apply_list[index]) != TEE_SUCCESS)
            return TEE_ERROR_GENERIC;

        drvcall_perm_apply->drvcall_perm_apply_list_size++;

        break;
    default:
        break;
    }

    return TEE_SUCCESS;
}

int32_t build_drvcall_conf(struct dlist_node **pos, const struct conf_node_t *node,
                           void *obj, uint32_t obj_size)
{
    struct drvcall_perm_apply_t *drvcall_perm = NULL;

    if (pos == NULL || node == NULL || obj == NULL || obj_size != sizeof(*drvcall_perm)) {
        tloge("invalied params while build drvcall conf\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    drvcall_perm = (struct drvcall_perm_apply_t *)obj;

    switch (node->tag) {
    case DRV_PERM_DRVCALL_PERM_APPLY:
        if (handle_conf_node_to_obj(pos, build_drvcall_perm_apply, drvcall_perm,
                                    sizeof(*drvcall_perm)) != TEE_SUCCESS) {
            tloge("build drvcall perm apply failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    default:
        tlogd("skip in build drvcall conf\n");
        if (handle_conf_node_to_obj(pos, NULL, drvcall_perm, sizeof(*drvcall_perm)) != TEE_SUCCESS)
            return TEE_ERROR_GENERIC;
        break;
    }

    return TEE_SUCCESS;
}

static int32_t send_drvcall_conf(const struct drvcall_conf_t *drvcall_conf, uint32_t drvcall_conf_size)
{
    uint64_t args[] = {
        (uintptr_t)drvcall_conf,
        drvcall_conf_size,
    };

    uint32_t lens[] = {
        drvcall_conf_size,
        0,
    };

    /* the main thread just handle register cmd */
    return drv_call_new("drvmgr", REGISTER_DRVCALL_CONF, args, lens, ARRAY_SIZE(args));
}

static int32_t send_drvcall_uuid(const struct tee_uuid *uuid, uint32_t uuid_size)
{
    uint64_t args[] = {
        (uintptr_t)uuid,
        uuid_size,
    };

    uint32_t lens[] = {
        uuid_size,
        0,
    };

    return drv_call_new("drvmgr_multi", UNREGISTER_DRVCALL_CONF, args, lens, ARRAY_SIZE(args));
}

void dump_drvcall_conf(void)
{
    uint64_t args[] = {};
    uint32_t lens[] = {};

    (void)drv_call_new("drvmgr_multi", DUMP_DRVCALL_CONF, args, lens, ARRAY_SIZE(args));
}

void uninstall_drvcall_permission(const void *obj, uint32_t obj_size)
{
    if (obj == NULL) {
        tloge("obj is NULL while uninstall drvcall permission\n");
        return;
    }

    if (obj_size != sizeof(struct tee_uuid)) {
        tloge("obj size is invalied while uninstall drvcall permission\n");
        return;
    }

    const struct tee_uuid *uuid = (const struct tee_uuid *)obj;
    if (send_drvcall_uuid(uuid, obj_size) != 0)
        tloge("uninstall drvcall permission failed\n");
}

int32_t install_drvcall_permission(void *obj, uint32_t obj_size, const struct conf_queue_t *conf_queue)
{
    /* 1. check the params */
    if (obj == NULL || conf_queue == NULL || dlist_empty(&conf_queue->queue)) {
        tloge("params is NULL while install drvcall permission\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (obj_size != sizeof(struct tee_uuid)) {
        tloge("obj size is invalied while install drvcall permission\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* 2. parse the obj to what you want */
    struct tee_uuid *uuid = (struct tee_uuid *)obj;

    /* 3.create new obj */
    struct drvcall_conf_t *drvcall_conf = (struct drvcall_conf_t *)malloc(sizeof(struct drvcall_conf_t));
    if (drvcall_conf == NULL) {
        tloge("drvcall_conf malloc failed\n");
        return TEE_ERROR_GENERIC;
    }

    /* 4.init new obj */
    (void)memset_s(drvcall_conf, sizeof(*drvcall_conf), 0, sizeof(*drvcall_conf));
    int32_t ret = -1;
    if (memcpy_s(&drvcall_conf->uuid, sizeof(drvcall_conf->uuid), uuid, sizeof(*uuid)) != 0) {
        tloge("set uuid to drv conf fail\n");
        goto out;
    }

    ret = init_drvcall_conf(&drvcall_conf->drvcall_perm_apply, conf_queue);
    if (ret != TEE_SUCCESS)
        goto out;

    /* 5.handle new obj */
    struct dlist_node *pos = dlist_get_next(&conf_queue->queue);
    ret = handle_conf_node_to_obj(&pos, build_drvcall_conf, &drvcall_conf->drvcall_perm_apply,
                                  sizeof(drvcall_conf->drvcall_perm_apply));
    if (ret != TEE_SUCCESS) {
        tloge("handle drvcall conf failed\n");
        goto out;
    }

    /* 6.do something else */
    ret = send_drvcall_conf(drvcall_conf, sizeof(*drvcall_conf));

out:
    /* 7. free obj and return */
    free_drvcall_conf(drvcall_conf);
    return ret;
}

#else

int32_t install_drvcall_permission(void *obj, uint32_t obj_size, const struct conf_queue_t *conf_queue)
{
    (void)obj;
    (void)obj_size;
    (void)conf_queue;
    return TEE_SUCCESS;
}

void uninstall_drvcall_permission(const void *obj, uint32_t obj_size)
{
    (void)obj;
    (void)obj_size;
}

void dump_drvcall_conf(void)
{
    return;
}
#endif
