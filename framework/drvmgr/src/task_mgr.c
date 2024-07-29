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

#include "task_mgr.h"
#include <tee_log.h>
#include <ipclib.h>
#include <libdrv_frame.h>
#include <dyn_conf_dispatch_inf.h>
#include <target_type.h>
#include <drv_thread.h>
#include <ta_lib_img_unpack.h>
#include "drv_fd_ops.h"
#include "drv_process_mgr.h"
#include "drv_dyn_policy_mgr.h"
#include "drv_index_mgr.h"
#include "drv_dyn_conf_mgr.h"
#include <securec.h>

static struct dlist_node g_task_list = dlist_head_init(g_task_list);
static pthread_mutex_t g_task_mtx = PTHREAD_MUTEX_INITIALIZER;

static int32_t init_drv_node(struct task_node *node)
{
    int32_t drv_index = alloc_drv_index();
    if (drv_index == -1) {
        tloge("alloc drv index fail\n");
        return -1;
    }

    node->drv_task.drv_index = drv_index;
    node->drv_task.register_policy = false;
    node->ref_cnt = 0; /* not support dynamic load */
    node->state = TASK_LOAD;
    node->target_type = DRV_TARGET_TYPE;

    return 0;
}

static int32_t init_ta_node(struct task_node *node)
{
    node->ref_cnt = 1; /* will dec when unregister ta */
    node->state = TASK_NORMAL;
    node->target_type = TA_TARGET_TYPE;

    return 0;
}

static int32_t init_task_node(struct task_node *node)
{
    dlist_init(&node->node_list);
    node->pid = INVALID_CALLER_PID;

    /* TA will not use this */
    node->drv_task.drv_index = -1;
    node->drv_task.channel = -1;
    node->tlv.drvcall_perm_apply_list = NULL;
    node->tlv.drv_conf = NULL;

    dlist_init(&node->fd_head);
    if (drv_mutex_init(&node->fd_mtx) != 0) {
        tloge("fd mtx init fail\n");
        return -1;
    }

    node->fd_count = 0;

    if (pthread_cond_init(&node->state_cond, NULL) != 0) {
        tloge("state cond init fail\n");
        return -1;
    }

    if (drv_mutex_init(&node->state_mtx) != 0) {
        tloge("state mtx init fail\n");
        return -1;
    }

    return 0;
}

static int32_t init_drvcall_perm(const struct drvcall_perm_apply_t *drvcall_in, struct task_node *node)
{
    struct drvcall_perm_apply_t drvcall_perm;
    if (memset_s(&drvcall_perm, sizeof(drvcall_perm), 0, sizeof(drvcall_perm)) != 0) {
        tloge("memset for drvcall_perm failed\n");
        return -1;
    }

    drvcall_perm.drvcall_perm_apply_list_size = drvcall_in->drvcall_perm_apply_list_size;
    drvcall_perm.drvcall_perm_apply_list = drvcall_in->drvcall_perm_apply_list;
    drvcall_perm.base_perm = drvcall_in->base_perm;

    if (receive_perm_apply_list(&drvcall_perm) != 0)
        return -1;

    node->tlv.drvcall_perm_apply_list = drvcall_perm.drvcall_perm_apply_list;
    node->tlv.drvcall_perm_apply_list_size = drvcall_perm.drvcall_perm_apply_list_size;

    return 0;
}

static int32_t init_drv_conf(const struct drv_conf_t *drv_conf, struct task_node *node)
{
    struct drv_conf_t *temp_drv_conf = malloc(sizeof(struct drv_conf_t));
    if (temp_drv_conf == NULL) {
        tloge("alloc drv conf fail\n");
        return -1;
    }

    if (memcpy_s(temp_drv_conf, sizeof(*temp_drv_conf), drv_conf, sizeof(*drv_conf)) != 0) {
        tloge("copy drv conf fail\n");
        goto free_temp;
    }

    if (do_receive_drv_conf(temp_drv_conf) != 0) {
        tloge("receive drv conf fail\n");
        goto free_temp;
    }

    node->tlv.drv_conf = temp_drv_conf;
    return 0;

free_temp:
    free(temp_drv_conf);
    return -1;
}

struct task_node *alloc_and_init_drv_node(struct drv_tlv *tlv)
{
    if (tlv == NULL) {
        tloge("invalid drv tlv\n");
        return NULL;
    }

    struct task_node *node = malloc(sizeof(*node));
    if (node == NULL) {
        tloge("alloc drv node fail\n");
        return NULL;
    }

    (void)memset_s(node, sizeof(*node), 0, sizeof(*node));
    node->tlv.uuid = tlv->uuid;

    if (init_task_node(node) != 0)
        goto free_node;

    if (init_drv_node(node) != 0)
        goto free_node;

    if (tlv->drvcall_perm_apply.drvcall_perm_apply_list_size != 0) {
        /* drv may not has drvcall perm */
        if (init_drvcall_perm(&tlv->drvcall_perm_apply, node) != 0)
            goto free_node;
    }

    if (init_drv_conf(&tlv->drv_conf, node) != 0)
        goto free_node;

    return node;

free_node:
    free_task_node(node);
    return NULL;
}

struct task_node *alloc_and_init_ta_node(const struct drvcall_conf_t *tlv)
{
    if (tlv == NULL) {
        tloge("invalid tlv\n");
        return NULL;
    }

    struct task_node *node = malloc(sizeof(*node));
    if (node == NULL) {
        tloge("alloc task node fail\n");
        return NULL;
    }

    if (memset_s(node, sizeof(*node), 0, sizeof(*node)) != 0) {
        tloge("memset_s for task node fail\n");
        free(node);
        return NULL;
    }

    node->tlv.uuid = tlv->uuid;

    if (init_task_node(node) != 0)
        goto free_node;

    if (init_ta_node(node) != 0)
        goto free_node;

    if (init_drvcall_perm(&tlv->drvcall_perm_apply, node) != 0)
        goto free_node;

    return node;

free_node:
    free_task_node(node);
    return NULL;
}

static void free_drv_node(struct task_node *node)
{
    if (node->drv_task.drv_index != -1) {
        clear_drv_index(node->drv_task.drv_index);
        node->drv_task.drv_index = -1;
    }

    release_driver(node);

    if (node->tlv.drv_conf != NULL) {
        free_drv_conf_list(node->tlv.drv_conf, RECEIVE_MAX_TAG);
        free(node->tlv.drv_conf);
        node->tlv.drv_conf = NULL;
    }
}

void free_task_node(struct task_node *node)
{
    if (node == NULL) {
        tloge("invalid task node\n");
        return;
    }

    if (node->tlv.drvcall_perm_apply_list != NULL) {
        free(node->tlv.drvcall_perm_apply_list);
        node->tlv.drvcall_perm_apply_list = NULL;
    }

    if (node->target_type == DRV_TARGET_TYPE)
        free_drv_node(node);

    free(node);
}

static int32_t inc_drv_node(struct task_node *node)
{
    if (node->ref_cnt == UINT32_MAX) {
        tloge("something wrong, ref cnt is overflow\n");
        return -1;
    }

    node->ref_cnt++;
    return 0;
}

static bool is_state_match(struct task_node *node, enum node_state except_state)
{
    bool match_flag = true;
    int32_t ret = drv_mutex_lock(&node->state_mtx);
    if (ret != 0) {
        tloge("get state mtx fail\n");
        return false;
    }

    if (node->state != except_state) {
        tlogd("node state:%d not match except state:%d\n", node->state, except_state);
        match_flag = false;
    }

    ret = pthread_mutex_unlock(&node->state_mtx);
    if (ret != 0)
        tloge("unlock state mtx fail\n");

    return match_flag;
}

static struct task_node *find_normal_node(const struct tee_uuid *uuid, uint32_t taskid)
{
    struct dlist_node *pos = NULL;
    dlist_for_each(pos, &g_task_list) {
        struct task_node *temp = dlist_entry(pos, struct task_node, node_list);
        if (memcmp(uuid, &temp->tlv.uuid, sizeof(*uuid)) == 0) {
            if (!is_state_match(temp, TASK_NORMAL))
                continue;

            tlogd("find uuid:0x%x\n", uuid->timeLow);
            /* taskid is INVALID_CALLER_PID when uninstall ta */
            if (taskid == (uint32_t)INVALID_CALLER_PID)
                return temp;

            /* temp->pid is INVALID_CALLER_PID when ta open drv in the first time */
            if (temp->pid == (uint32_t)INVALID_CALLER_PID) {
                temp->pid = taskid_to_pid(taskid);
            } else if (temp->pid != taskid_to_pid(taskid)) {
                tloge("something wrong, uuid:0x%x pid:0x%x not match taskid:0x%x\n",
                    uuid->timeLow, temp->pid, taskid);
                continue;
            }

            return temp;
        }
    }

    return NULL;
}

/* find node whose state not set TASK_EXIT */
static struct task_node *find_effective_node(const struct tee_uuid *uuid)
{
    struct dlist_node *pos = NULL;
    dlist_for_each(pos, &g_task_list) {
        struct task_node *temp = dlist_entry(pos, struct task_node, node_list);
        if (memcmp(uuid, &temp->tlv.uuid, sizeof(*uuid)) == 0) {
            if (!is_state_match(temp, TASK_EXIT)) {
                tlogd("find uuid:0x%x\n", uuid->timeLow);
                return temp;
            }
        }
    }

    return NULL;
}

static struct task_node *find_node_by_name(const char *drv_name, uint32_t len)
{
    struct dlist_node *pos = NULL;
    dlist_for_each(pos, &g_task_list) {
        struct task_node *temp = dlist_entry(pos, struct task_node, node_list);
        if (temp->target_type == DRV_TARGET_TYPE &&
            temp->tlv.drv_conf != NULL &&
            temp->tlv.drv_conf->mani.service_name_size == len &&
            strncmp(temp->tlv.drv_conf->mani.service_name, drv_name, len + 1) == 0) {
            if (is_state_match(temp, TASK_EXIT)) {
                tloge("something wrong, drv state is exit\n");
                continue;
            }

            tlogd("find drv:%s\n", drv_name);
            return temp;
        }
    }

    return NULL;
}

/*
 * called by get_valid_drv_node
 * it must be drv node
 * the state will be checked in check_drv_node_state so no need check state in find_node_by_name
 */
struct task_node *get_drv_node_by_name_with_lock(const char *drv_name, uint32_t len)
{
    if (drv_name == NULL || len == 0) {
        tloge("invalid drv name\n");
        return NULL;
    }

    if (drv_mutex_lock(&g_task_mtx) != 0) {
        tloge("something wrong, get task mtx fail\n");
        return NULL;
    }

    struct task_node *temp = find_node_by_name(drv_name, len);
    if (temp == NULL) {
        tloge("cannot find drv:%s\n", drv_name);
        goto unlock_mtx;
    }

    if (inc_drv_node(temp) != 0)
        temp = NULL;

unlock_mtx:
    if (pthread_mutex_unlock(&g_task_mtx) != 0)
        tloge("something wrong, cannot unlock task mtx\n");

    return temp;
}

static int32_t set_task_exit_state(struct task_node *node)
{
    int32_t ret = drv_mutex_lock(&node->state_mtx);
    if (ret != 0) {
        tloge("get state mtx fail\n");
        return -1;
    }

    node->state = TASK_EXIT;

    ret = pthread_mutex_unlock(&node->state_mtx);
    if (ret != 0)
        tloge("unlock state mtx fail\n");

    return 0;
}

static struct task_node *get_node_by_uuid(const struct tee_uuid *uuid, uint32_t taskid,
    bool exit_flag, int32_t target_type)
{
    struct task_node *temp = find_normal_node(uuid, taskid);
    if (temp == NULL) {
        if (!exit_flag)
            tlogd("cannot find node:0x%x\n", uuid->timeLow);
        return NULL;
    }

    /* ignore target_type of node when input is -1 */
    if (target_type != -1 && temp->target_type != target_type) {
        tloge("uuid:0x%x target_type:%u not match %u\n", uuid->timeLow, temp->target_type, target_type);
        return NULL;
    }

    if (inc_drv_node(temp) != 0)
        return NULL;

    if (exit_flag) {
        if (set_task_exit_state(temp) != 0) {
            temp->ref_cnt--;
            return NULL;
        }
    }

    return temp;
}

static struct task_node *get_node_by_uuid_handle(const struct tee_uuid *uuid, uint32_t taskid,
    bool exit_flag, int32_t target_type)
{
    if (uuid == NULL) {
        tloge("invalid uuid\n");
        return NULL;
    }

    if (drv_mutex_lock(&g_task_mtx) != 0) {
        tloge("something wrong, get task mtx fail\n");
        return NULL;
    }

    struct task_node *temp = get_node_by_uuid(uuid, taskid, exit_flag, target_type);

    if (pthread_mutex_unlock(&g_task_mtx) != 0)
        tloge("something wrong, cannot unlock task mtx\n");

    return temp;
}

/*
 * called by get_valid_drvcall_node
 * it can be ta node or drv node
 * the state must be TASK_NORMAL for both ta and drv node
 */
struct task_node *get_node_by_uuid_with_lock(const struct tee_uuid *uuid, uint32_t taskid)
{
    return get_node_by_uuid_handle(uuid, taskid, false, -1);
}

/*
 * called by drvcall_conf_unregister_handle
 * the node must be TA_TARGET_TYPE
 * the state must be TASK_NORMAL
 */
struct task_node *get_ta_node_and_set_exit(const struct tee_uuid *uuid)
{
    return get_node_by_uuid_handle(uuid, INVALID_CALLER_PID, true, TA_TARGET_TYPE);
}

int32_t get_drvcall_and_fd_node(int64_t fd, const struct tee_drv_param *params,
    struct task_node **call_node, struct fd_node **fdata)
{
    if (params == NULL || call_node == NULL || fdata == NULL) {
        tloge("invalid param\n");
        return -1;
    }

    struct fd_node *data = NULL;
    struct task_node *node = NULL;

    if (drv_mutex_lock(&g_task_mtx) != 0) {
        tloge("something wrong, get task mtx fail\n");
        return -1;
    }

    struct dlist_node *pos = NULL;
    dlist_for_each(pos, &g_task_list) {
        struct task_node *temp = dlist_entry(pos, struct task_node, node_list);
        if (memcmp(&temp->tlv.uuid, &params->uuid, sizeof(struct tee_uuid)) == 0 &&
            temp->pid == taskid_to_pid(params->caller_pid)) {
            /*
             * fd must match in case of the drvcall node exit abnormally,
             * and restart soon before the first process open has not return.
             * drvcall which uuid is uuid1:
             * 1.drvcall process start, alloc pid1 and drvcall node1
             * 2.thread 0 of pid1 call open in cpux and thread 1 of pid1 abort in cpuy at the same time
             * 3.gtask handle pid1 crash msg, and send to drvmgr, drvmgr set the node1 exit status
             * 4.uuid1 drvcall restart, it reuse the pid1 and alloc new drvcall node2
             * in this case, it will cannot find fd data if we just check whether the uuid and pid are equal,
             * since the drvcall node2 also match
             */
            data = close_get_fd_node_with_lock(node, fd);
            if (data == NULL)
                continue;

            if (node->ref_cnt == UINT32_MAX) {
                tloge("something wrong, cannot get drvcall node:0x%x task:0x%x for fd:0x%llx, just del\n",
                    params->uuid.timeLow, node->pid, fd);
                del_fd_to_drvcall_node(&data, node);
                data = NULL;
                continue;
            } else {
                node->ref_cnt++;
            }
            break;
        }
    }

    if (pthread_mutex_unlock(&g_task_mtx) != 0)
        tloge("something wrong, cannot unlock task mtx\n");

    if (data != NULL) {
        *call_node = node;
        *fdata = data;
        return 0;
    }

    return -1;
}

static void put_node(struct task_node *node, uint32_t dec_cnt)
{
    if (node->ref_cnt < dec_cnt)
        tloge("something wrong, uuid:0x%x ref_cnt:%u dec_cnt:%u invalid\n",
            node->tlv.uuid.timeLow, node->ref_cnt, dec_cnt);
    else
        node->ref_cnt = node->ref_cnt - dec_cnt;

    if (node->ref_cnt == 0) {
        /*
         * do not release drv since it not support dynamic load
         * in current time, drv can only be delete when register fail
         * which will call free_drv_conf_by_service_name
         */
        if (node->target_type == DRV_TARGET_TYPE) {
            tlogd("drv:0x%x cannot free\n", node->tlv.uuid.timeLow);
            return;
        }

        dlist_delete(&node->node_list);
        free_task_node(node);
    }
}

void put_node_with_lock(struct task_node *node, uint32_t dec_cnt)
{
    if (node == NULL) {
        tloge("invalid node\n");
        return;
    }

    if (drv_mutex_lock(&g_task_mtx) != 0) {
        tloge("something wrong, get task mtx fail\n");
        return;
    }

    put_node(node, dec_cnt);

    if (pthread_mutex_unlock(&g_task_mtx) != 0)
        tloge("something wrong, cannot unlock task mtx\n");
}

bool check_hardware_type(const struct task_node *node, uint16_t type)
{
    if (node == NULL) {
        tloge("invalid node while check hardware type");
        return false;
    }

    struct drv_conf_t *drv_conf = node->tlv.drv_conf;
    if (node->target_type == DRV_TARGET_TYPE && drv_conf != NULL && drv_conf->mani.hardware_type == type)
        return true;

    return false;
}

/*
 * since not support load drv dynamically, one drv must have only one node,
 * ignore its state
 */
static bool drv_is_exist(const struct task_tlv *tlv)
{
    struct task_node *node = find_effective_node(&tlv->uuid);
    if (node != NULL) {
        tloge("this uuid:0x%x cannot register again\n", tlv->uuid.timeLow);
        return true;
    }

    node = find_node_by_name(tlv->drv_conf->mani.service_name, tlv->drv_conf->mani.service_name_size);
    if (node != NULL) {
        tloge("this drv:%s cannot register again\n", tlv->drv_conf->mani.service_name);
        return true;
    }

    return false;
}

static bool check_drv_name_invalid(const char *drv_name, uint32_t len)
{
    if (len == 0 || len >= DRV_NAME_MAX_LEN) {
        tloge("invalid drv name len:%u\n", len);
        return true;
    }

    if (strnlen(drv_name, DRV_NAME_MAX_LEN) != len) {
        tloge("drv name not match drv len:%u\n", len);
        return true;
    }

    return false;
}

static int32_t receive_drv_conf(struct task_node *node)
{
    if (node->tlv.drv_conf == NULL) {
        tloge("invalid drv conf\n");
        return -1;
    }

    if (check_drv_name_invalid(node->tlv.drv_conf->mani.service_name, node->tlv.drv_conf->mani.service_name_size))
        return -1;

    if (drv_is_exist(&node->tlv))
        return -1;

    if (register_drv_policy(node) != 0)
        return -1;

    return 0;
}

static int32_t receive_ta_conf(struct task_node *node)
{
    /* state cannot be TASK_EXIT */
    if (find_effective_node(&node->tlv.uuid) != NULL) {
        tloge("ta uuid:0x%x cannot register again\n", node->tlv.uuid.timeLow);
        return -1;
    }

    return 0;
}

static int32_t check_drv_conf_target_is_valid(const struct drv_conf_t *dst)
{
    if (dst->io_map_list_size != 0 || dst->io_map_list != NULL) {
        tloge("drv conf target io map list is invalied\n");
        return -1;
    }

    if (dst->irq_list_size != 0 || dst->irq_list != NULL) {
        tloge("drv conf target irq list is invalied\n");
        return -1;
    }

    if (dst->map_secure_list_size != 0 || dst->map_secure_list != NULL) {
        tloge("drv conf target map secure list is invalied\n");
        return -1;
    }

    if (dst->map_nosecure_list_size != 0 || dst->map_nosecure_list != NULL) {
        tloge("drv conf target io map nosecure is invalied\n");
        return -1;
    }

    if (dst->mac_info_list_size != 0 || dst->mac_info_list != NULL) {
        tloge("drv conf target mac info list is invalied\n");
        return -1;
    }

    if (dst->cmd_perm_list_size != 0 || dst->cmd_perm_list != NULL) {
        tloge("drv conf target cmd perm list is invalied\n");
        return -1;
    }

    return 0;
}

static int32_t do_copy_drv_conf_to_target(const void *src_list, uint16_t src_list_size, void **dst_list,
                                          uint16_t *dst_list_size, uint32_t unit_size)
{
    if (src_list_size == 0)
        return 0;

    if (unit_size == 0 || src_list_size >= MAX_IMAGE_LEN / unit_size) {
        tloge("invalied src list size\n");
        return -1;
    }

    uint32_t size = src_list_size * unit_size;
    *dst_list = malloc(size);
    if (*dst_list == NULL) {
        tloge("malloc for dst list failed\n");
        return -1;
    }

    if (memcpy_s(*dst_list, size, src_list, size) != 0) {
        tloge("memcpy for dst list failed\n");
        free(*dst_list);
        *dst_list = NULL;
        return -1;
    }

    *dst_list_size = src_list_size;
    return 0;
}

static int32_t copy_drv_conf_to_target(struct drv_conf_t *src, struct drv_conf_t *dst)
{
    if (check_drv_conf_target_is_valid(dst) != 0)
        return -1;

    if (do_copy_drv_conf_to_target((void *)src->io_map_list, src->io_map_list_size,
                                   (void **)&dst->io_map_list, &dst->io_map_list_size,
                                   sizeof(struct addr_region_t)) != 0)
        goto out;

    if (do_copy_drv_conf_to_target((void *)src->irq_list, src->irq_list_size,
                                   (void **)&dst->irq_list, &dst->irq_list_size,
                                   sizeof(uint64_t)) != 0)
        goto out;

    if (do_copy_drv_conf_to_target((void *)src->map_secure_list, src->map_secure_list_size,
                                   (void **)&dst->map_secure_list, &dst->map_secure_list_size,
                                   sizeof(struct drv_map_secure_t)) != 0)
        goto out;

    if (do_copy_drv_conf_to_target((void *)src->map_nosecure_list, src->map_nosecure_list_size,
                                   (void **)&dst->map_nosecure_list, &dst->map_nosecure_list_size,
                                   sizeof(struct drv_map_nosecure_t)) != 0)
        goto out;

    if (do_copy_drv_conf_to_target((void *)src->mac_info_list, src->mac_info_list_size,
                                   (void **)&dst->mac_info_list, &dst->mac_info_list_size,
                                   sizeof(struct drv_mac_info_t)) != 0)
        goto out;

    if (do_copy_drv_conf_to_target((void *)src->cmd_perm_list, src->cmd_perm_list_size,
                                   (void **)&dst->cmd_perm_list, &dst->cmd_perm_list_size,
                                   sizeof(struct drv_cmd_perm_info_t)) != 0)
        goto out;

    dst->drv_basic_info.upgrade = src->drv_basic_info.upgrade;
    dst->drv_basic_info.virt2phys = src->drv_basic_info.virt2phys;
    dst->drv_basic_info.exception_mode = src->drv_basic_info.exception_mode;

    return 0;

out:
    free_drv_conf_list(dst, RECEIVE_MAX_TAG);
    return -1;
}

static void free_drv_perm_apply_list(struct task_tlv *dst)
{
    free((void *)dst->drvcall_perm_apply_list);
    dst->drvcall_perm_apply_list = NULL;
    dst->drvcall_perm_apply_list_size = 0;
}

static int32_t copy_drv_perm_apply_to_target(struct task_tlv *src, struct task_tlv *dst)
{
    if (dst->drvcall_perm_apply_list_size != 0 || dst->drvcall_perm_apply_list != NULL) {
        tloge("drvcall perm apply list is invalied\n");
        return -1;
    }

    uint32_t uint_size =  sizeof(struct drvcall_perm_apply_item_t);
    if (uint_size == 0 || src->drvcall_perm_apply_list_size >= MAX_IMAGE_LEN / uint_size)
        return -1;

    if (src->drvcall_perm_apply_list_size == 0)
        return 0;

    uint32_t size = src->drvcall_perm_apply_list_size * uint_size;
    dst->drvcall_perm_apply_list = malloc(size);
    if (dst->drvcall_perm_apply_list == NULL) {
        tloge("malloc for dst list failed\n");
        return -1;
    }

    if (memcpy_s((void **)dst->drvcall_perm_apply_list, size, (void **)src->drvcall_perm_apply_list, size) != 0) {
        tloge("memcpy for dst list failed\n");
        free_drv_perm_apply_list(dst);
        return -1;
    }

    dst->drvcall_perm_apply_list_size = src->drvcall_perm_apply_list_size;
    return 0;
}

static int32_t inherit_drv_node(struct task_tlv *tlv)
{
    if (tlv == NULL || tlv->drv_conf == NULL) {
        tloge("invalid node while inherit drv node\n");
        return -1;
    }

    struct dlist_node *pos = NULL;

    dlist_for_each(pos, &g_task_list) {
        struct task_node *temp = dlist_entry(pos, struct task_node, node_list);
        if (temp->tlv.drv_conf != NULL &&
            strcmp(tlv->drv_conf->mani.service_name, temp->tlv.drv_conf->mani.service_name) == 0) {
            if (copy_drv_conf_to_target(tlv->drv_conf, temp->tlv.drv_conf) != 0) {
                tloge("copy drv conf to %s failed\n", tlv->drv_conf->mani.service_name);
                return -1;
            }

            if (copy_drv_perm_apply_to_target(tlv, &temp->tlv) != 0) {
                free_drv_conf_list(temp->tlv.drv_conf, RECEIVE_MAX_TAG);
                tloge("copy drv perm to %s failed\n", tlv->drv_conf->mani.service_name);
                return -1;
            }

            if (add_dynamic_policy_to_drv(&temp->tlv) != 0) {
                free_drv_perm_apply_list(&temp->tlv);
                tloge("add dynamic policy to drv failed\n");
                free_drv_conf_list(temp->tlv.drv_conf, RECEIVE_MAX_TAG);
                return -1;
            }

            return 0;
        }
    }

    tloge("inherit drv conf %s failed\n", tlv->drv_conf->mani.service_name);
    return -1;
}

/*
 * must init all conf before add to list
 * otherwise it maybe used by another thread when it add to list before init all conf
 * something bind with uuid, such as policy, must be registered
 * after check this node is valid in g_task_mtx lock
 * because this uuid may have been registerd to this list if we not lock
 */
int32_t receive_task_conf(struct task_node *node)
{
    int32_t ret = -1;
    if (node == NULL || (node->target_type != DRV_TARGET_TYPE && node->target_type != TA_TARGET_TYPE)) {
        tloge("invalid node\n");
        return ret;
    }

    if (drv_mutex_lock(&g_task_mtx) != 0) {
        tloge("something wrong, get task mtx fail\n");
        return ret;
    }

    if (check_hardware_type(node, HARDWARE_ENGINE_CRYPTO)) {
        ret = inherit_drv_node(&node->tlv);
        goto unlock_mtx;
    }

    if (node->target_type == DRV_TARGET_TYPE)
        ret = receive_drv_conf(node);
    else
        ret = receive_ta_conf(node);

    if (ret != 0)
        goto unlock_mtx;

    dlist_insert_tail(&node->node_list, &g_task_list);

    ret = 0;

unlock_mtx:
    if (pthread_mutex_unlock(&g_task_mtx) != 0)
        tloge("something wrong, cannot unlock task mtx\n");

    return ret;
}

int32_t free_drv_conf_by_service_name(const char *drv_name, uint32_t len)
{
    int32_t ret = -1;
    bool free_flag = false;

    if (drv_name == NULL || len == 0) {
        tloge("free drv conf invalid param\n");
        return -1;
    }

    if (drv_mutex_lock(&g_task_mtx) != 0) {
        tloge("something wrong, get task mtx fail\n");
        return -1;
    }

    struct task_node *node = find_node_by_name(drv_name, len);
    if (node == NULL) {
        tloge("cannot find drv:%s node\n", drv_name);
        goto unlock_mtx;
    }

    /* ref_cnt is not zero means this drv node has been used by other, cannot free */
    if (node->ref_cnt != 0) {
        tloge("something wrong, drv:%s ref_cnt:%d cannot unregister\n", drv_name, node->ref_cnt);
        goto unlock_mtx;
    }

    /*
     * drv node not TASK_LOAD means it has been opened by other
     * add this because ref_cnt may be zero in some cases:
     * drv_node has been opened and closed in the same time
     */
    if (!is_state_match(node, TASK_LOAD)) {
        tloge("something wrong, drv:%s state not match, cannot unregister\n", drv_name);
        goto unlock_mtx;
    }

    dlist_delete(&node->node_list);
    free_flag = true;
    ret = 0;

unlock_mtx:
    if (pthread_mutex_unlock(&g_task_mtx) != 0)
        tloge("something wrong, cannot unlock task mtx\n");

    if (free_flag)
        free_task_node(node);

    return ret;
}

struct task_node *find_drv_node_by_taskid(uint32_t exit_pid)
{
    struct task_node *node = NULL;
    if (drv_mutex_lock(&g_task_mtx) != 0) {
        tloge("something wrong, get task mtx fail\n");
        return NULL;
    }

    struct dlist_node *pos = NULL;
    dlist_for_each(pos, &g_task_list) {
        struct task_node *temp = dlist_entry(pos, struct task_node, node_list);
        if (temp->target_type == DRV_TARGET_TYPE && taskid_to_pid(temp->pid) == taskid_to_pid(exit_pid)) {
            tlogd("find drv taskid:0x%x uuid:0x%x\n", exit_pid, temp->tlv.uuid.timeLow);
            node = temp;
            break;
        }
    }

    if (pthread_mutex_unlock(&g_task_mtx) != 0)
        tloge("something wrong, unlock task mtx fail\n");

    return node;
}

#ifdef TEE_SUPPORT_DYN_CONF_DEBUG
static void dump_task_state(struct task_node *node)
{
    static const char *task_state[] = {
        "TASK_LOAD",
        "TASK_SPAWN",
        "TASK_NORMAL",
        "TASK_SPAWN_FAIL",
        "TASK_EXIT",
        "UNKNOWN",
    };

    int32_t ret = drv_mutex_lock(&node->state_mtx);
    if (ret != 0) {
        tloge("get state mtx fail\n");
        return;
    }

    int32_t state = node->state;

    ret = pthread_mutex_unlock(&node->state_mtx);
    if (ret != 0)
        tloge("unlock state mtx fail\n");

    int32_t index = state - TASK_LOAD;
    if (index < 0 || index > (TASK_EXIT - TASK_LOAD))
        index = TASK_EXIT - TASK_LOAD + 1;

    tlogi("[task node] state:%s\n", task_state[index]);
}

static void dump_drv_task(const struct task_node *node)
{
    if (node->target_type != DRV_TARGET_TYPE)
        return;

    tlogi("[drv task] index:%u channel:0x%llx\n",
        node->drv_task.drv_index, node->drv_task.channel);

    if (node->tlv.drv_conf == NULL) {
        tloge("something wrong, not drv conf invalid\n");
        return;
    }

    dump_drv_conf(node->tlv.drv_conf);
}

static void dump_drvcall_perm(const struct task_tlv *tlv)
{
    if (tlv->drvcall_perm_apply_list == NULL || tlv->drvcall_perm_apply_list_size == 0) {
        tlogi("[drvcall dyn conf] has nothing\n");
        return;
    }

    uint32_t i;

    for (i = 0; i < tlv->drvcall_perm_apply_list_size; i++) {
        struct drvcall_perm_apply_item_t item = tlv->drvcall_perm_apply_list[i];
        tlogi("[drvcall dyn conf] drv_name = %s, perm 0x%llx\n", item.name, (unsigned long long)item.perm);
    }
}

void dump_task_node(void)
{
    if (drv_mutex_lock(&g_task_mtx) != 0) {
        tloge("something wrong, get task mtx fail\n");
        return;
    }

    struct dlist_node *pos = NULL;
    dlist_for_each(pos, &g_task_list) {
        struct task_node *temp = dlist_entry(pos, struct task_node, node_list);
        tlogi("[task node begin] uuid:0x%x pid:0x%x type:%s ref_cnt:%u\n", temp->tlv.uuid.timeLow, temp->pid,
            (temp->target_type == DRV_TARGET_TYPE) ? "DRV" : "TA", temp->ref_cnt);
        dump_task_state(temp);
        dump_drvcall_perm(&temp->tlv);
        dump_drv_task(temp);
        dump_drvcall_fd(temp);
    }

    if (pthread_mutex_unlock(&g_task_mtx) != 0)
        tloge("something wrong, cannot unlock task mtx\n");
}
#endif
