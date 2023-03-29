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

#include "drv_dyn_conf_mgr.h"
#include <tee_log.h>
#include <libdrv_frame.h>
#include <ta_framework.h>
#include <dyn_conf_dispatch_inf.h>
#include <target_type.h>
#include "drv_fd_ops.h"
#include "drv_param_ops.h"
#include "drv_process_mgr.h"

void free_drv_conf_list(struct drv_conf_t *drv_conf, uint32_t receive_flag)
{
    if (drv_conf == NULL) {
        tloge("invalid drv conf\n");
        return;
    }

    if (receive_flag >= RECEIVE_IO_MAP_LIST && drv_conf->io_map_list != NULL) {
        free(drv_conf->io_map_list);
        drv_conf->io_map_list = NULL;
        drv_conf->io_map_list_size = 0;
    }

    if (receive_flag >= RECEIVE_IRQ_LIST && drv_conf->irq_list != NULL) {
        free(drv_conf->irq_list);
        drv_conf->irq_list = NULL;
        drv_conf->irq_list_size = 0;
    }

    if (receive_flag >= RECEIVE_MAP_SECURE_LIST && drv_conf->map_secure_list != NULL) {
        free(drv_conf->map_secure_list);
        drv_conf->map_secure_list = NULL;
        drv_conf->map_secure_list_size = 0;
    }

    if (receive_flag >= RECEIVE_MAP_NOSECURE_LIST && drv_conf->map_nosecure_list != NULL) {
        free(drv_conf->map_nosecure_list);
        drv_conf->map_nosecure_list = NULL;
        drv_conf->map_nosecure_list_size = 0;
    }

    if (receive_flag >= RECEIVE_MAC_INFO_LIST && drv_conf->mac_info_list != NULL) {
        free(drv_conf->mac_info_list);
        drv_conf->mac_info_list = NULL;
        drv_conf->mac_info_list_size = 0;
    }

    if (receive_flag >= RECEIVE_CMD_PERM_LIST && drv_conf->cmd_perm_list != NULL) {
        free(drv_conf->cmd_perm_list);
        drv_conf->cmd_perm_list = NULL;
        drv_conf->cmd_perm_list_size = 0;
    }
}

#ifdef TEE_SUPPORT_DYN_CONF_DEBUG
static void dump_drv_basic_info(const struct drv_basic_info_t *drv_basic_info)
{
    if (drv_basic_info->upgrade)
        tlogi("[drv dyn conf] upgrade: true\n");
    else
        tlogi("[drv dyn conf] upgrade: false\n");

    if (drv_basic_info->virt2phys)
        tlogi("[drv dyn conf] virt2phys: true\n");
    else
        tlogi("[drv dyn conf] virtphys: false\n");

    tlogi("[drv dyn conf] thread_limit: %u\n", drv_basic_info->thread_limit);

    if (drv_basic_info->exception_mode == DYN_CONF_SYSCRASH_TAG)
        tlogi("[drv dyn conf] exception_mode: syscrash\n");
    else if (drv_basic_info->exception_mode == DYN_CONF_RESTART_TAG)
        tlogi("[drv dyn conf] exception_mode: restart\n");
    else if (drv_basic_info->exception_mode == DYN_CONF_DDOS_TAG)
        tlogi("[drv dyn conf] exception_mode: ddos\n");
    else
        tlogi("[drv dyn conf] exception_mode: unknown\n");
}

static void dump_drv_mani(const struct drv_mani_t *mani)
{
    tlogi("[drv dyn conf] UUID %x\n", mani->srv_uuid.timeLow);
    tlogi("[drv dyn conf] service name %s\n", mani->service_name);

    if (mani->keep_alive)
        tlogi("[drv dyn conf] keep_alive is true\n");
    else
        tlogi("[drv dyn conf] keep_alive is false\n");

    tlogi("[drv dyn conf] data size 0x%x\n", mani->data_size);
    tlogi("[drv dyn conf] stack size 0x%x\n", mani->stack_size);
}

static void dump_drv_io_map_list(const struct drv_conf_t *drv_conf)
{
    tlogi("[drv dyn conf] io map list size %u\n", drv_conf->io_map_list_size);
    uint32_t i;
    for (i = 0; i < drv_conf->io_map_list_size; i++)
        tlogi("[drv dyn conf] iomap region size %llx\n",
              (unsigned long long)(drv_conf->io_map_list[i].end -
                                   drv_conf->io_map_list[i].start));
}

static void dump_drv_irq_list(const struct drv_conf_t *drv_conf)
{
    tlogi("[drv dyn conf] irq list size %u\n", drv_conf->irq_list_size);
    uint32_t i;
    for (i = 0; i < drv_conf->irq_list_size; i++)
        tlogi("[drv dyn conf] irq %llu\n", (unsigned long long)drv_conf->irq_list[i]);
}

static void dump_drv_map_secure_list(const struct drv_conf_t *drv_conf)
{
    tlogi("[drv dyn conf] map secure list size %u\n", drv_conf->map_secure_list_size);
    uint32_t i;
    for (i = 0; i < drv_conf->map_secure_list_size; i++) {
        struct tee_uuid uuid = drv_conf->map_secure_list[i].uuid;
        tlogi("[drv dyn conf] map_secure uuid %08x-%04x-%04x\n",
              uuid.timeLow, uuid.timeMid, uuid.timeHiAndVersion);
        tlogi("[drv dyn conf] map_secure region size %llx\n",
              (unsigned long long)(drv_conf->map_secure_list[i].region.end -
                                   drv_conf->map_secure_list[i].region.start));
    }
}

static void dump_drv_map_nosecure_list(const struct drv_conf_t *drv_conf)
{
    tlogi("[drv dyn conf] map nosecure list size %u\n", drv_conf->map_nosecure_list_size);
    uint32_t i;
    for (i = 0; i < drv_conf->map_nosecure_list_size; i++) {
        struct tee_uuid uuid = drv_conf->map_nosecure_list[i].uuid;
        tlogi("[drv dyn conf] map_nosecure uuid %08x-%04x-%04x\n",
              uuid.timeLow, uuid.timeMid, uuid.timeHiAndVersion);
    }
}

static void dump_drv_mac_info(const struct drv_conf_t *drv_conf)
{
    tlogi("[drv dyn conf] drv mac list size %u\n", drv_conf->mac_info_list_size);
    uint32_t i;
    for (i = 0; i < drv_conf->mac_info_list_size; i++) {
        struct tee_uuid uuid = drv_conf->mac_info_list[i].uuid;
        tlogi("[drv dyn conf] mac info uuid %08x-%04x-%04x perm %llx\n",
              uuid.timeLow, uuid.timeMid, uuid.timeHiAndVersion,
              (unsigned long long)drv_conf->mac_info_list[i].perm);
    }
}

static void dump_drv_cmd_perm_info(const struct drv_conf_t *drv_conf)
{
    tlogi("[drv dyn conf] drv cmd perm list size %u\n", drv_conf->cmd_perm_list_size);
    uint32_t i;
    for (i = 0; i < drv_conf->cmd_perm_list_size; i++)
        tlogi("[drv dyn conf] cmd %llx permission %llx\n",
              (unsigned long long)drv_conf->cmd_perm_list[i].cmd,
              (unsigned long long)drv_conf->cmd_perm_list[i].perm);
}

void dump_drv_conf(const struct drv_conf_t *drv_conf)
{
    if (drv_conf == NULL) {
        tloge("invalid drv conf\n");
        return;
    }

    dump_drv_mani(&drv_conf->mani);
    dump_drv_basic_info(&drv_conf->drv_basic_info);
    dump_drv_io_map_list(drv_conf);
    dump_drv_irq_list(drv_conf);
    dump_drv_map_secure_list(drv_conf);
    dump_drv_map_nosecure_list(drv_conf);
    dump_drv_mac_info(drv_conf);
    dump_drv_cmd_perm_info(drv_conf);
}
#endif

static int32_t receive_drv_conf_list(void **list, uint16_t list_size, uint32_t item_size)
{
    if (list == NULL || item_size == 0 || item_size >= MAX_IMAGE_LEN) {
        tloge("invalied params while receive drv conf list\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (*list == NULL || list_size == 0)
        return TEE_SUCCESS;

    /* list_size < 0xffff means tmp_size cannot larger than 0xFFFFFFFF */
    uint32_t tmp_size = list_size * item_size;
    if (tmp_size >= MAX_IMAGE_LEN || list_size * item_size < item_size) {
        tloge("tmp size is too large or overflow while receive drv conf list %u\n", item_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    void *tmp_list = malloc(tmp_size);
    if (tmp_list == NULL) {
        tloge("malloc tmp_list failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (copy_from_client((uint64_t)(uintptr_t)(*list), tmp_size, (uintptr_t)tmp_list, tmp_size) != TEE_SUCCESS) {
        tloge("copy_from_client tmp_list failed\n");
        free(tmp_list);
        return TEE_ERROR_GENERIC;
    }

    *list = tmp_list;

    return TEE_SUCCESS;
}

int32_t do_receive_drv_conf(struct drv_conf_t *drv_conf)
{
    uint32_t receive_flag = 0;
    if (drv_conf == NULL) {
        tloge("invalid receive param\n");
        return -1;
    }

    /* receive drv_conf iomap list */
    if (receive_drv_conf_list((void **)&drv_conf->io_map_list,
                              drv_conf->io_map_list_size, sizeof(struct addr_region_t)) != 0)
        goto err_out;
    receive_flag = RECEIVE_IO_MAP_LIST;

    /* receive irq list */
    if (receive_drv_conf_list((void **)&drv_conf->irq_list,
                              drv_conf->irq_list_size, sizeof(uint64_t)) != 0)
        goto err_out;
    receive_flag = RECEIVE_IRQ_LIST;

    /* receive map secure list */
    if (receive_drv_conf_list((void **)&drv_conf->map_secure_list,
                              drv_conf->map_secure_list_size, sizeof(struct drv_map_secure_t)) != 0)
        goto err_out;
    receive_flag = RECEIVE_MAP_SECURE_LIST;

    /* receive map nosecure list */
    if (receive_drv_conf_list((void **)&drv_conf->map_nosecure_list,
                              drv_conf->map_nosecure_list_size, sizeof(struct drv_map_nosecure_t)) != 0)
        goto err_out;
    receive_flag = RECEIVE_MAP_NOSECURE_LIST;

    /* receive mac info list */
    if (receive_drv_conf_list((void **)&drv_conf->mac_info_list,
                              drv_conf->mac_info_list_size, sizeof(struct drv_mac_info_t)) != 0)
        goto err_out;
    receive_flag = RECEIVE_MAC_INFO_LIST;

    /* receive cmd perm list */
    if (receive_drv_conf_list((void **)&drv_conf->cmd_perm_list,
                              drv_conf->cmd_perm_list_size, sizeof(struct drv_cmd_perm_info_t)) != 0)
        goto err_out;

    return 0;

err_out:
    free_drv_conf_list(drv_conf, receive_flag);
    return -1;
}

int32_t check_drv_node_state(struct task_node *node)
{
    int32_t func_ret = DRV_FAIL;

    if (node == NULL || node->tlv.drv_conf == NULL) {
        tloge("invalid node\n");
        return DRV_FAIL;
    }

    int32_t ret = drv_mutex_lock(&node->state_mtx);
    if (ret != 0) {
        tloge("get state mtx fail\n");
        return DRV_FAIL;
    }

    switch (node->state) {
    case TASK_LOAD:
        node->state = TASK_SPAWN;
        func_ret = DRV_NEED_SPAWN;
        break;
    case TASK_SPAWN:
        while (node->state == TASK_SPAWN) {
            tloge("drv:%s is spawn by other thread, just wait\n", node->tlv.drv_conf->mani.service_name);
            ret = pthread_cond_wait(&node->state_cond, &node->state_mtx);
            if (ret != 0) {
                tloge("something wrong, drv:%s cond wait fail:0x%x\n", node->tlv.drv_conf->mani.service_name, ret);
                goto unlock_mtx;
            }
        }

        if (node->state == TASK_NORMAL)
            func_ret = DRV_SUCC;
        else
            tloge("something wrong, wait spawn fail state:0x%x\n", node->state);
        break;
    case TASK_NORMAL:
        func_ret = DRV_SUCC;
        break;
    default:
        /* when drv spawn fail, just return fail */
        tloge("something wrong, drv:%s state:%d\n", node->tlv.drv_conf->mani.service_name, node->state);
    }

unlock_mtx:
    ret = pthread_mutex_unlock(&node->state_mtx);
    if (ret != 0)
        tloge("something wrong, unlock mtx in drv state fail\n");

    return func_ret;
}

void broadcast_drv_state(struct task_node *node, bool spawn_succ)
{
    if (node == NULL) {
        tloge("invalid node\n");
        return;
    }

    int32_t ret = drv_mutex_lock(&node->state_mtx);
    if (ret != 0) {
        tloge("get state mtx fail\n");
        return;
    }

    if (node->state != TASK_SPAWN)
        tloge("something wrong, node->state:%d not DRV_SPAWN\n", node->state);

    if (spawn_succ)
        node->state = TASK_NORMAL;
    else
        node->state = TASK_SPAWN_FAIL;

    pthread_cond_broadcast(&node->state_cond);

    ret = pthread_mutex_unlock(&node->state_mtx);
    if (ret != 0)
        tloge("something wrong, unlock stat mtx fail\n");
}
