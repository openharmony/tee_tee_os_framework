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
#include "drv_fd_ops.h"
#include <securec.h>
#include <dlist.h>
#include <tee_log.h>
#include <tee_drv_internal.h>
#include "drv_ipc_mgr.h"
#include "task_mgr.h"

int32_t drv_mutex_lock(pthread_mutex_t *mtx)
{
    if (mtx == NULL)
        return -1;

    int32_t ret = pthread_mutex_lock(mtx);

    return ret;
}

int32_t drv_mutex_init(pthread_mutex_t *mtx)
{
    int32_t ret;

    if (mtx == NULL) {
        tloge("invalid mtx\n");
        return -1;
    }

    ret = pthread_mutex_init(mtx, NULL);
    if (ret != 0) {
        tloge("pthread mutex init failed with ret:%d\n", ret);
    }

    return ret;
}

struct fd_node *alloc_and_init_fd_node(void)
{
    struct fd_node *data = malloc(sizeof(*data));
    if (data == NULL) {
        tloge("alloc fd data fail\n");
        return NULL;
    }

    (void)memset_s(data, sizeof(*data), 0, sizeof(*data));

    dlist_init(&data->data_list);
    data->fd = -1;
    data->drv = NULL;
    data->close_flag = false;

    return data;
}

int32_t add_fd_to_drvcall_node(struct fd_node *data, struct task_node *node)
{
    if (data == NULL || node == NULL) {
        tloge("insert fd invalid param\n");
        return -1;
    }

    int32_t ret = drv_mutex_lock(&node->fd_mtx);
    if (ret != 0) {
        tloge("lock fd mtx fail\n");
        return -1;
    }

    dlist_insert_tail(&data->data_list, &node->fd_head);

    ret = pthread_mutex_unlock(&node->fd_mtx);
    if (ret != 0)
        tloge("something wrong, unlock fd mtx fail\n");

    return 0;
}

struct fd_node *close_get_fd_node_with_lock(struct task_node *node, int64_t fd)
{
    struct fd_node *data = NULL;

    if (node == NULL) {
        tloge("invalid drvcall node\n");
        return NULL;
    }

    int32_t ret = drv_mutex_lock(&node->fd_mtx);
    if (ret != 0) {
        tloge("get lock fd mtx fail\n");
        return NULL;
    }

    struct dlist_node *pos = NULL;
    struct dlist_node *next = NULL;
    struct fd_node *temp = NULL;
    dlist_for_each_safe(pos, next, &node->fd_head) {
        temp = dlist_entry(pos, struct fd_node, data_list);
        if (temp->fd == fd) {
            if (temp->close_flag) {
                tloge("this fd:0x%llx has already close\n", fd);
                break;
            }

            data = temp;
            data->close_flag = true;
        }
    }

    ret = pthread_mutex_unlock(&node->fd_mtx);
    if (ret != 0)
        tloge("something wrong, get fd unlock fd mtx fail\n");

    return data;
}

int32_t del_fd_to_drvcall_node(struct fd_node **fnode, struct task_node *node)
{
    if (fnode == NULL || node == NULL || *fnode == NULL) {
        tloge("put fd invalid param\n");
        return -1;
    }

    struct fd_node *data = *fnode;

    int32_t ret = drv_mutex_lock(&node->fd_mtx);
    if (ret != 0) {
        tloge("lock fd mtx fail\n");
        return -1;
    }

    if (node->fd_count > 0)
        node->fd_count--;
    else
        tloge("something wrong, task:0x%x fd_count is zero\n", node->pid);

    dlist_delete(&data->data_list);

    ret = pthread_mutex_unlock(&node->fd_mtx);
    if (ret != 0)
        tloge("something wrong, unlock fd mtx fail\n");

    free(data);
    *fnode = NULL;

    return 0;
}

static void dump_fd_node(const struct task_node *node)
{
    struct dlist_node *pos = NULL;
    struct dlist_node *next = NULL;
    struct fd_node *temp = NULL;

    dlist_for_each_safe(pos, next, &node->fd_head) {
        temp = dlist_entry(pos, struct fd_node, data_list);
        tlogi("\t fd:0x%llx close_flag:%d ", temp->fd, (int32_t)temp->close_flag);
        if (temp->drv != NULL && temp->drv->tlv.drv_conf != NULL)
            tlogi("\t\t drv_name:%s\n", temp->drv->tlv.drv_conf->mani.service_name);
        else
            tloge("\t\t fd no driver (something wrong)\n");
    }
}

int32_t get_fd_count(struct task_node *node)
{
    if (node == NULL) {
        tloge("get fd count invalid param\n");
        return -1;
    }

    int32_t func_ret = -1;
    int32_t ret = drv_mutex_lock(&node->fd_mtx);
    if (ret != 0) {
        tloge("get fd count lock fd mtx fail\n");
        return -1;
    }

    if (node->fd_count >= TASK_FD_COUNT_MAX) {
        tloge("task:%u fd_count:%u is overflow\n", node->pid, node->fd_count);
        dump_fd_node(node);
    } else {
        node->fd_count++;
        func_ret = 0;
    }

    ret = pthread_mutex_unlock(&node->fd_mtx);
    if (ret != 0)
        tloge("something wrong, get fd count unlock fd mtx fail\n");

    return func_ret;
}

void put_fd_count(struct task_node *node)
{
    if (node == NULL) {
        tloge("put fd count invalid param\n");
        return;
    }

    int32_t ret = drv_mutex_lock(&node->fd_mtx);
    if (ret != 0) {
        tloge("put fd count lock fd mtx fail\n");
        return;
    }

    if (node->fd_count == 0)
        tloge("something wrong, task:%u fd count cannot put\n", node->pid);
    else
        node->fd_count--;

    ret = pthread_mutex_unlock(&node->fd_mtx);
    if (ret != 0)
        tloge("something wrong, get fd count unlock fd mtx fail\n");
}

/*
 * return value means the fd number that be closed in exception_close_handle,
 * the ref_cnt of drvcall node should be subtracted the same number
 */
uint32_t exception_close_handle(struct task_node *node)
{
    uint32_t close_fd_count = 0;
    if (node == NULL) {
        tloge("invalid node\n");
        return close_fd_count;
    }

    int32_t ret = drv_mutex_lock(&node->fd_mtx);
    if (ret != 0) {
        tloge("get fd mtx lock fail\n");
        return close_fd_count;
    }

    struct dlist_node *pos = NULL;
    struct dlist_node *next = NULL;
    struct fd_node *temp = NULL;
    dlist_for_each_safe(pos, next, &node->fd_head) {
        temp = dlist_entry(pos, struct fd_node, data_list);
        if (temp->close_flag) {
            tloge("fd:0x%llx has already call by close\n", temp->fd);
            continue;
        }

        temp->close_flag = true;
        close_fd_count++;
        if (node->fd_count > 0)
            node->fd_count--;
        else
            tloge("something wrong, fd count is zero\n");

        dlist_delete(&temp->data_list);
        tlogi("close fd:0x%llx in exception handle\n", temp->fd);

        struct task_node *dnode = temp->drv;
        if (dnode == NULL) {
            tloge("something wrong, fd:0x%llx data has no drv\n", temp->fd);
        } else {
            ret = call_drv_close(node->pid, &node->tlv.uuid, temp->fd, dnode->drv_task.channel);
            /* pair with dnode ref_cnt add one in open, called in drvcall fd_mtx lock */
            put_node_with_lock(dnode, 1);
        }

        free(temp);
    }

    ret = pthread_mutex_unlock(&node->fd_mtx);
    if (ret != 0)
        tloge("something wrong, unlock mtx fd lock fail\n");

    return close_fd_count;
}

#ifdef TEE_SUPPORT_DYN_CONF_DEBUG
void dump_drvcall_fd(struct task_node *node)
{
    if (node == NULL) {
        tloge("dump invalid drvcall node\n");
        return;
    }

    int32_t ret = drv_mutex_lock(&node->fd_mtx);
    if (ret != 0) {
        tloge("put fd count lock fd mtx fail\n");
        return;
    }

    tlogi("\t[drvcall fd] fd_count:%u\n", node->fd_count);
    dump_fd_node(node);

    ret = pthread_mutex_unlock(&node->fd_mtx);
    if (ret != 0)
        tloge("something wrong, get fd count unlock fd mtx fail\n");
}
#endif
