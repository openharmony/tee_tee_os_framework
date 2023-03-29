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
#include "drv_operations.h"
#include <stdint.h>
#include <securec.h>
#include <dlist.h>
#include <ipclib.h>
#include <tee_log.h>
#include <tee_bitmap.h>
#include <drv.h>
#include <tee_drv_internal.h>
#include <spawn_ext.h>
#include "tee_driver_module.h"
#include "tee_drv_entry.h"
#include "drv_param_ops.h"

struct drv_cmd_perm {
    struct drv_cmd_perm_info_t *base_vaddr;
    uint32_t cmd_num;
};

static struct drv_cmd_perm g_cmd_perm = {
    .base_vaddr = NULL,
    .cmd_num = 0,
};
static struct dlist_node g_drv_node = dlist_head_init(g_drv_node);
static pthread_mutex_t g_drv_mtx = PTHREAD_MUTEX_INITIALIZER;

static uint8_t g_fd_bitmap[(FD_COUNT_MAX) >> MOVE_BIT];
static pthread_mutex_t g_fd_mtx = PTHREAD_MUTEX_INITIALIZER;
static void task_dump_fd(const struct drv_task *task);

/*
 * used when get_drv_task in driver_open
 * will put one once operation are succeeded, and put another one in driver_close
 */
#define DRV_TASK_OPEN_REF_CNT_STEP 2U

int32_t drv_mutex_lock(pthread_mutex_t *mtx)
{
    if (mtx == NULL)
        return -1;

    int32_t ret = pthread_mutex_lock(mtx);

    return ret;
}

static int32_t drv_mutex_init(pthread_mutex_t *mtx)
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

/*
 * this function is locked by g_drv_mtx
 * so it can add to g_drv_node directly when alloc succ
 */
static struct drv_task *alloc_and_add_drv_task(uint32_t pid)
{
    struct drv_task *new_task = malloc(sizeof(*new_task));
    if (new_task == NULL) {
        tloge("alloc new task failed\n");
        return NULL;
    }

    (void)memset_s(new_task, sizeof(*new_task), 0, sizeof(*new_task));

    dlist_init(&new_task->task_list);
    new_task->task_pid = pid;
    new_task->task_count = 0;
    new_task->ref_cnt = DRV_TASK_OPEN_REF_CNT_STEP;
    dlist_init(&new_task->data_head);

    int32_t ret = drv_mutex_init(&new_task->task_mtx);
    if (ret != 0) {
        free(new_task);
        tloge("init task_mtx failed\n");
        return NULL;
    }

    dlist_insert_tail(&new_task->task_list, &g_drv_node);

    return new_task;
}

static int32_t update_drv_task_ref_cnt(struct drv_task *task, bool open)
{
    if (open) {
        if (task->ref_cnt >= (UINT32_MAX - DRV_TASK_OPEN_REF_CNT_STEP)) {
            tloge("something wrong, pid:%u drv task ref_cnt:%u is overflow\n",
                task->task_pid, task->ref_cnt);
            return -1;
        }

        task->ref_cnt += DRV_TASK_OPEN_REF_CNT_STEP;
        return 0;
    }

    if (task->ref_cnt == UINT32_MAX) {
        tloge("something wrong, pid:%u drv task ref_cnt is overflow\n", task->task_pid);
        return -1;
    }

    task->ref_cnt++;
    return 0;
}

static struct drv_task *find_and_get_drv_task_locked(uint32_t pid, bool open)
{
    struct drv_task *task = NULL;
    bool find_flag = false;

    int32_t ret = drv_mutex_lock(&g_drv_mtx);
    if (ret != 0) {
        tloge("lock drv mtx failed\n");
        return task;
    }

    struct dlist_node *pos = NULL;
    struct dlist_node *next = NULL;
    struct drv_task *temp = NULL;

    dlist_for_each_safe(pos, next, &g_drv_node) {
        temp = dlist_entry(pos, struct drv_task, task_list);
        if (temp->task_pid == pid) {
            find_flag = true;
            tlogd("find pid:%u\n", pid);
            ret = update_drv_task_ref_cnt(temp, open);
            if (ret != 0) {
                tloge("update drv task ref_cnt failed, pid:%u\n", pid);
                break;
            }
            task = temp;
            break;
        }
    }

    /*
     * when cannot find drv task in driver_open
     * should create it
     */
    if (!find_flag && open) {
        tlogd("cannot find task:%u in open, create it\n", pid);
        task = alloc_and_add_drv_task(pid);
    }

    ret = pthread_mutex_unlock(&g_drv_mtx);
    if (ret != 0)
        tloge("unlock drv mtx failed\n");

    return task;
}

static void free_drv_task(struct drv_task *task)
{
    free(task);
}

static void put_drv_task_locked(struct drv_task *task, uint32_t put_cnt)
{
    bool free_flag = false;

    int32_t ret = drv_mutex_lock(&g_drv_mtx);
    if (ret != 0) {
        tloge("lock drv mtx failed\n");
        return;
    }

    if (task->ref_cnt < put_cnt)
        tloge("something wrong, pid:%u task ref_cnt:%u small than put_cnt:%u\n",
            task->task_pid, task->ref_cnt, put_cnt);
    else
        task->ref_cnt = task->ref_cnt - put_cnt;

    if (task->ref_cnt == 0) {
        dlist_delete(&task->task_list);
        free_flag = true;
    }

    ret = pthread_mutex_unlock(&g_drv_mtx);
    if (ret != 0)
        tloge("unlock drv mtx failed\n");

    if (free_flag)
        free_drv_task(task);
}

static int32_t inc_fd_ref_locked(struct fd_data *data)
{
    int32_t func_ret = -1;
    int32_t ret = drv_mutex_lock(&data->ref_mtx);
    if (ret != 0) {
        tloge("get ref mtx fail\n");
        return -1;
    }

    if (data->ref_cnt == UINT32_MAX) {
        tloge("something wrong, fd:%d ref cnt is overflow\n", data->drv.fd);
    } else {
        data->ref_cnt++;
        func_ret = 0;
    }

    ret = pthread_mutex_unlock(&data->ref_mtx);
    if (ret != 0)
        tloge("something wrong, unlock ref mtx fail\n");

    return func_ret;
}

static void dec_fd_ref_locked(struct fd_data *data)
{
    int32_t ret = drv_mutex_lock(&data->ref_mtx);
    if (ret != 0) {
        tloge("dec fd ref get mtx fail\n");
        return;
    }

    if (data->ref_cnt == 0) {
        tloge("something wrong, fd:%d ref cnt is 0, cannot put\n", data->drv.fd);
    } else {
        data->ref_cnt--;
        tlogd("fd:%d ref_cnt:%u after dec\n", data->drv.fd, data->ref_cnt);
    }

    if (data->ref_cnt == 0) {
        tloge("fd:%d is closed before ioctl, signal other thread\n", data->drv.fd);
        ret = pthread_cond_signal(&data->ref_cond);
        if (ret != 0)
            tloge("fd:%d signal to other thread fail:0x%x\n", data->drv.fd, ret);
    }

    ret = pthread_mutex_unlock(&data->ref_mtx);
    if (ret != 0)
        tloge("something wrong, dec fd unlock ref mtx fail\n");
}

static struct fd_data *find_fd_data(int32_t fd, const struct tee_uuid *uuid, const struct drv_task *task)
{
    struct fd_data *data = NULL;

    struct dlist_node *pos = NULL;
    struct dlist_node *next = NULL;
    struct fd_data *temp = NULL;

    dlist_for_each_safe(pos, next, &task->data_head) {
        temp = dlist_entry(pos, struct fd_data, data_list);
        if (temp->drv.fd == fd) {
            /*
             * compare uuid to avoid this case:
             * when task(pid1) crash, driver_close_fd_by_pid will call by gtask in cpux,
             * and in cpuy, it may just receive pid1 drv_open cmd,
             * when cpux handle the cmd before cpuy, although cpuy will call driver_close_fd
             * after ipc_msg_reply fail, the fd1 opened by cpuy can be get from pid1
             * since it will be added to pid1 task_drv in driver_open_fd.
             * If the pid1 is reused by another ta, and this ta call drv_ioctl(fd1) maliciously,
             * it cannot auth in driver. So, compare uuid after fd is matched, it can limit only
             * the same ta used this fd. In this case, it has no effect for driver.
             * And at the same time, it reduces the probability of reuse pid significantly
             * since the same pid used by the same uuid.
             */
            if (memcmp(uuid, &temp->drv.uuid, sizeof(*uuid)) == 0) {
                tlogd("find fd:%d\n", fd);
                data = temp;
                break;
            }

            tloge("find fd:%d which owner uuid:0x%x not match caller 0x%x",
                fd, temp->drv.uuid.timeLow, uuid->timeLow);
            break;
        }
    }

    return data;
}

static struct fd_data *find_and_get_fd_data_locked(int32_t fd,
    const struct tee_uuid *uuid, struct drv_task *task)
{
    struct fd_data *data = NULL;

    int32_t ret = drv_mutex_lock(&task->task_mtx);
    if (ret != 0) {
        tloge("lock task mtx failed\n");
        return NULL;
    }

    data = find_fd_data(fd, uuid, task);
    if (data == NULL) {
        tloge("cannot find fd:%d\n", fd);
        goto unlock_task_mtx;
    }

    if (inc_fd_ref_locked(data) != 0) {
        tloge("something wrong, task:%u cannot inc fd ref\n", task->task_pid);
        data = NULL;
    }

unlock_task_mtx:
    ret = pthread_mutex_unlock(&task->task_mtx);
    if (ret != 0)
        tloge("unlock task mtx failed\n");

    return data;
}

static void dec_task_count(struct drv_task *task)
{
    if (task->task_count == 0)
        tloge("something wrong, task:%u task_count is zero, cannot put\n", task->task_count);
    else
        task->task_count--;
}

static struct fd_data *find_and_del_fd_data_locked(int32_t fd,
    const struct tee_uuid *uuid, struct drv_task *task)
{
    struct fd_data *data = NULL;

    int32_t ret = drv_mutex_lock(&task->task_mtx);
    if (ret != 0) {
        tloge("del lock task mtx failed\n");
        return NULL;
    }

    data = find_fd_data(fd, uuid, task);
    if (data == NULL) {
        tloge("del cannot find fd:%d\n", fd);
        goto unlock_task_mtx;
    }

    dec_task_count(task);
    dlist_delete(&data->data_list);

unlock_task_mtx:
    ret = pthread_mutex_unlock(&task->task_mtx);
    if (ret != 0)
        tloge("del unlock task mtx failed\n");

    return data;
}

static void free_fd_data(struct fd_data *data)
{
    int32_t fd = data->drv.fd;

    free(data);
    data = NULL;

    int32_t ret = drv_mutex_lock(&g_fd_mtx);
    if (ret != 0) {
        tloge("lock fd mtx failed, cannot clear fd:%d\n", fd);
        return;
    }

    clear_bitmap(g_fd_bitmap, FD_COUNT_MAX, (fd - 1));

    ret = pthread_mutex_unlock(&g_fd_mtx);
    if (ret != 0)
        tloge("unlock fd mtx failed\n");
}

static void close_and_free_fd_data(struct fd_data *data)
{
    const struct tee_driver_module *drv_func = get_drv_func();

    if (drv_func == NULL || drv_func->close == NULL) {
        tloge("something wrong, fd:%d has invalid drv func\n", data->drv.fd);
    } else {
        /*
         * do not dlclose so since drv not support load so dynamically,
         * once it support, should dlclose after call so close function,
         * and in this case, should add ref_cnt in so structure,
         * when ref_cnt is zero, should delete so from so list and dlclose it
         */
        int64_t ret = drv_func->close(&data->drv);
        if (ret != 0)
            tloge("drv close fd:%d failed ret:0x%llx\n", data->drv.fd, ret);
    }

    free_fd_data(data);
}

static void close_fd_data_locked(struct fd_data *data)
{
    bool free_flag = true;
    int32_t ret = drv_mutex_lock(&data->ref_mtx);
    if (ret != 0) {
        tloge("something wrong, close fd get ref mtx fail\n");
        return;
    }

    if (data->ref_cnt == 0) {
        tloge("something wrong, fd:%d ref cnt is zero\n", data->drv.fd);
    } else {
        data->ref_cnt--;
        while (data->ref_cnt != 0) {
            tloge("fd:%d is used by other, cannot close, just wait\n", data->drv.fd);
            ret = pthread_cond_wait(&data->ref_cond, &data->ref_mtx);
            if (ret != 0) {
                tloge("something wrong, fd:%d cond wait fail:0x%x\n", data->drv.fd, ret);
                free_flag = false;
                goto unlock_ref_mtx;
            }
        }
    }

unlock_ref_mtx:
    ret = pthread_mutex_unlock(&data->ref_mtx);
    if (ret != 0)
        tloge("something wrong, unlock ref fail\n");

    if (free_flag)
        close_and_free_fd_data(data);
}

static int32_t alloc_fd(void)
{
    int32_t ret = drv_mutex_lock(&g_fd_mtx);
    if (ret != 0) {
        tloge("get mtx failed\n");
        return -1;
    }

    int32_t fd = get_valid_bit(g_fd_bitmap, FD_COUNT_MAX);
    if (fd == -1) {
        tloge("cannot get fd bit, and dump in fd mtx\n");
        driver_dump();
        ret = pthread_mutex_unlock(&g_fd_mtx);
        if (ret != 0)
            tloge("unlock fd failed ret:%d\n", ret);
        return -1;
    }

    set_bitmap(g_fd_bitmap, FD_COUNT_MAX, fd);

    ret = pthread_mutex_unlock(&g_fd_mtx);
    if (ret != 0)
        tloge("unlock fd failed ret:%d\n", ret);

    return (fd + 1); /* cannot start from 0 */
}

static int32_t get_caller_uuid(const struct tee_drv_param *params, struct tee_uuid *caller_uuid)
{
    uint64_t *args = (uint64_t *)(uintptr_t)(params->args);
    uint64_t uuid_time = args[DRV_UUID_TIME_INDEX];
    uint64_t uuid_clock = args[DRV_UUID_CLOCK_INDEX];

    struct tee_uuid uuid;
    (void)memset_s(&uuid, sizeof(uuid), 0, sizeof(uuid));
    uuid.timeLow = (uuid_time >> UUID_TIME_LOW_OFFSET) & UUID_TIME_LOW_MASK;
    uuid.timeMid = (uuid_time >> UUID_TIME_MID_OFFSET) & UUID_TIME_MASK;
    uuid.timeHiAndVersion = uuid_time & UUID_TIME_MASK;

    uint32_t i;
    for (i = 0; i < NODE_LEN; i++) {
        uuid.clockSeqAndNode[NODE_LEN - i - 1] =  uuid_clock & UUID_TIME_CLOCK_MASK;
        uuid_clock >>= BITS_NUM_PER_BYTE;
    }

    if (memcpy_s(caller_uuid, sizeof(*caller_uuid), &uuid, sizeof(uuid)) != 0) {
        tloge("copy uuid:0x%x fail\n", uuid.timeLow);
        return -1;
    }

    return 0;
}

static struct fd_data *alloc_fd_data(uint32_t caller_taskid, const struct tee_drv_param *params, int32_t *fd_out)
{
    struct fd_data *data = malloc(sizeof(*data));
    if (data == NULL) {
        tloge("alloc data failed\n");
        return NULL;
    }

    (void)memset_s(data, sizeof(*data), 0, sizeof(*data));
    int32_t ret = get_caller_uuid(params, &(data->drv.uuid));
    if (ret != 0) {
        tloge("copy pid:%u uuid to fd failed\n", params->caller_pid);
        goto free_data;
    }

    if (pthread_cond_init(&data->ref_cond, NULL) != 0) {
        tloge("ref cond init fail\n");
        goto free_data;
    }

    if (drv_mutex_init(&data->ref_mtx) != 0) {
        tloge("ref mtx init fail\n");
        goto free_data;
    }

    int32_t fd = alloc_fd();
    if (fd <= 0)
        goto free_data;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    *fd_out = fd;
    dlist_init(&data->data_list);
    data->drv.fd = fd;
    data->drv.taskid = caller_taskid;
    data->drv.private_data = NULL;
    data->ref_cnt = 1;
    data->cmd_perm = args[DRV_PERM_INDEX];

    return data;

free_data:
    free(data);
    return NULL;
}

static int64_t add_fd_data_locked(struct fd_data *data, struct drv_task *task)
{
    int32_t ret = drv_mutex_lock(&task->task_mtx);
    if (ret != 0) {
        tloge("get task mtx failed\n");
        return -1;
    }

    dlist_insert_tail(&data->data_list, &task->data_head);

    ret = pthread_mutex_unlock(&task->task_mtx);
    if (ret != 0)
        tloge("unlock task mtx failed\n");

    return 0;
}

static int32_t get_task_count(struct drv_task *task)
{
    int32_t func_ret = -1;

    int32_t ret = drv_mutex_lock(&task->task_mtx);
    if (ret != 0) {
        tloge("check task count get drv mtx failed\n");
        return -1;
    }

    if (task->task_count >= TASK_FD_COUNT_MAX) {
        tloge("task:%u task_count:%u is overflow, max:%u\n",
            task->task_pid, task->task_count, TASK_FD_COUNT_MAX);
        task_dump_fd(task);
    } else {
        /*
         * add one to task_count when find drv_task in driver_open
         * in order to reduce the probability of failure
         * when add fd_data to drv_task after call dirver module open function
         */
        task->task_count++;
        func_ret = 0;
    }

    ret = pthread_mutex_unlock(&task->task_mtx);
    if (ret != 0)
        tloge("check task count unlock drv mtx failed\n");

    return func_ret;
}

static void put_task_count(struct drv_task *task)
{
    int32_t ret = drv_mutex_lock(&task->task_mtx);
    if (ret != 0) {
        tloge("check task count get drv mtx failed\n");
        return;
    }

    dec_task_count(task);

    ret = pthread_mutex_unlock(&task->task_mtx);
    if (ret != 0)
        tloge("check task count unlock drv mtx failed\n");
}

static int32_t open_param_check(const struct tee_drv_param *params, const struct tee_driver_module *drv_func)
{
    if (params == NULL || params->args == 0) {
        tloge("open invalid param\n");
        return -1;
    }

    if (drv_func == NULL) {
        tloge("invalid drv func\n");
        return -1;
    }

    if (drv_func->open == NULL) {
        tloge("no open func\n");
        return -1;
    }

    if (drv_func->close == NULL) { /* called in exception branch */
        tloge("no close func\n");
        return -1;
    }

    return 0;
}

static int32_t get_drv_param(const struct tee_drv_param *params, uint64_t **args_base, uint32_t *args_len)
{
    uint64_t *args = (uint64_t *)(uintptr_t)(params->args);
    char *indata = (char *)(uintptr_t)params->data;
    uint64_t param_len = args[DRV_PARAM_LEN_INDEX];
    uint64_t param_offset = args[DRV_PARAM_INDEX];

    /* it may have no param */
    if (param_len == 0) {
        tlogd("input NULL param\n");
        *args_base = NULL;
        *args_len = 0;
        return 0;
    }

    if (param_len > (SYSCAL_MSG_BUFFER_SIZE - sizeof(struct drv_req_msg_t))) {
        tloge("param_len:0x%llx is invalid\n", param_len);
        return -1;
    }

    if (param_offset != 0) {
        tloge("invalid param_offset:0x%llx\n", param_offset);
        return -1;
    }

    if (indata == NULL) {
        tloge("invalid param_indata\n");
        return -1;
    }

    uint64_t *param_buffer = malloc(param_len);
    if (param_buffer == 0) {
        tloge("malloc for param_buffer:0x%llx failed\n", param_len);
        return -1;
    }

    if (memcpy_s(param_buffer, param_len, indata, param_len) != EOK) {
        tloge("copy param_buffer failed\n");
        free(param_buffer);
        return -1;
    }

    *args_base = param_buffer;
    *args_len = param_len;
    return 0;
}

static void free_drv_args(uint64_t *args)
{
    if (args != NULL)
        free(args);
}

static int32_t get_open_param(const struct tee_drv_param *params, const struct tee_driver_module *drv_func,
    uint64_t **arg, uint32_t *arg_len)
{
    if (open_param_check(params, drv_func) != 0)
        return -1;

    if (get_drv_param(params, arg, arg_len) != 0) {
        tloge("open get param failed\n");
        return -1;
    }

    return 0;
}

static int32_t get_drv_open_task(uint32_t pid, struct drv_task **open_task)
{
    struct drv_task *task = find_and_get_drv_task_locked(pid, true);
    if (task == NULL) {
        tloge("pid:%u cannot open this driver\n", pid);
        return -1;
    }

    int32_t ret = get_task_count(task);
    if (ret != 0) {
        tloge("task open fd is overflow, cannot open");
        put_drv_task_locked(task, DRV_TASK_OPEN_REF_CNT_STEP);
        return -1;
    }

    *open_task = task;

    return 0;
}

int64_t driver_open(const struct tee_drv_param *params, const struct tee_driver_module *drv_func)
{
    uint64_t *input_args = NULL;
    uint32_t input_args_len = 0;

    if (get_open_param(params, drv_func, &input_args, &input_args_len) != 0)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    uint32_t pid = taskid_to_pid(args[CALLER_TASKID_INDEX]);
    struct drv_task *task = NULL;
    if (get_drv_open_task(pid, &task) != 0) {
        free_drv_args(input_args);
        return -1;
    }

    int32_t fd = -1;
    struct fd_data *data = alloc_fd_data(args[CALLER_TASKID_INDEX], params, &fd);
    if (data == NULL)
        goto alloc_fd_failed;

    int64_t ret = drv_func->open(&data->drv, (unsigned long)(uintptr_t)input_args, input_args_len);
    if (ret != 0) {
        tloge("open fd ret:0x%llx\n", ret);
        goto open_fd_failed;
    }

    /*
     * add to list after open can limit ioctl/close cannot get fd_data
     * before call open in concurrent scene
     */
    ret = add_fd_data_locked(data, task);
    if (ret != 0)
        goto add_fd_failed;

    put_drv_task_locked(task, 1);

    tlogd("caller taskid:0x%x alloc new fd:%d\n", pid, fd);
    free_drv_args(input_args);

    /*
     * cannot return fd from data->drv.fd in case of use after free of data.
     * cpux call driver_open_fd, cpuy receive task exit signal from gtask,
     * when cpux alloc fd and add to drv_task, cpuy will free all fd data in this drv_task
     * and in this case, cpux may return fd after cpuy free all fd data,
     * since it not atomic between add fd data to drv_task and return fd to caller.
     * use local variable fd as return value after cpuy free all fd data,
     * cpux will ipc_msg_reply fail to ta since this ta has been killed by gtask
     */
    return (int64_t)fd;

add_fd_failed:
    ret = drv_func->close(&data->drv);
    if (ret != 0)
        tloge("caller pid:0x%x close fd:%d failed ret:0x%llx\n", pid, data->drv.fd, ret);

open_fd_failed:
    free_fd_data(data);

alloc_fd_failed:
    /*
     * pair with get_task_count after get drv_task
     * should call before put_drv_task_locked
     */
    put_task_count(task);
    put_drv_task_locked(task, DRV_TASK_OPEN_REF_CNT_STEP);
    free_drv_args(input_args);

    return -1;
}

static bool check_fd_invalid(uint64_t fd)
{
    uint32_t drv_index = (uint32_t)((fd >> DRV_INDEX_OFFSET) & DRV_INDEX_MASK);
    uint32_t orig_index = get_drv_index();
    if (drv_index != orig_index) {
        tloge("invalid fd drv_index:0x%x orig_index:0x%x\n", drv_index, orig_index);
        return true;
    }

    fd = fd & DRV_FD_MASK;
    if (fd == 0 || fd > FD_COUNT_MAX) {
        tloge("invalid fd:0x%llx\n", fd);
        return true;
    }

    return false;
}

static int32_t ioctl_param_check(uint64_t fd, const struct tee_drv_param *params, const int64_t *fn_ret)
{
    if (params == NULL || params->args == 0 || fn_ret == NULL) {
        tloge("ioctl invalid params\n");
        return -1;
    }

    if (check_fd_invalid(fd))
        return -1;

    return 0;
}

static int32_t get_ioctl_param(uint64_t fd, struct tee_drv_param *params,
    const int64_t *fn_ret, uint64_t **arg, uint32_t *arg_len)
{
    if (ioctl_param_check(fd, params, fn_ret) != 0)
        return -1;

    spawn_uuid_t uuid;
    uint32_t pid = taskid_to_pid(params->caller_pid);
    int32_t ret = getuuid(pid, &uuid);
    if (ret != 0) {
        tloge("get pid:%u uuid failed\n", pid);
        return -1;
    }

    ret = memcpy_s(&(params->uuid), sizeof(params->uuid), &uuid.uuid, sizeof(uuid.uuid));
    if (ret != 0) {
        tloge("copy pid:%u uuid to params failed\n", pid);
        return -1;
    }

    if (get_drv_param(params, arg, arg_len) != 0) {
        tloge("ioctl get param failed\n");
        return -1;
    }

    return 0;
}

static bool ioctl_auth_check(uint32_t cmd, const struct fd_data *data)
{
    uint32_t i;
    uint64_t cmd_perm = 0;

    for (i = 0; i < g_cmd_perm.cmd_num; i++) {
        struct drv_cmd_perm_info_t item = g_cmd_perm.base_vaddr[i];
        if (item.cmd == cmd) {
            cmd_perm = item.perm;
            break;
        }
    }

    if (i == g_cmd_perm.cmd_num) {
        tlogd("cmd has no perm\n");
        return true;
    }

    tlogd("cmd:0x%x need perm:0x%llx, fd cmd 0x%llx\n", cmd, cmd_perm, data->cmd_perm);

    if ((cmd_perm & data->cmd_perm) != 0)
        return true;

    tloge("cmd:0x%x need perm:0x%llx not 0x%llx\n", cmd, cmd_perm, data->cmd_perm);
    return false;
}

int64_t driver_ioctl(uint64_t fd, struct tee_drv_param *params,
    const struct tee_driver_module *drv_func, int64_t *fn_ret)
{
    if (drv_func == NULL || drv_func->ioctl == NULL) {
        tloge("invalid ioctl func\n");
        return -1;
    }

    uint64_t *input_args = NULL;
    uint32_t input_args_len = 0;
    int64_t ret;

    if (get_ioctl_param(fd, params, fn_ret, &input_args, &input_args_len) != 0)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    uint32_t pid = taskid_to_pid(params->caller_pid);
    struct drv_task *task = find_and_get_drv_task_locked(pid, false);
    if (task == NULL) {
        tloge("task:%u has not open this driver, cannot ioctl\n", pid);
        free_drv_args(input_args);
        return -1;
    }

    struct fd_data *data = find_and_get_fd_data_locked((int32_t)(fd & DRV_FD_MASK), &(params->uuid), task);
    if (data == NULL) {
        put_drv_task_locked(task, 1);
        tloge("task:%u has not open fd:%d, cannot ioctl\n", pid, (int32_t)(fd & DRV_FD_MASK));
        free_drv_args(input_args);
        return -1;
    }

    tlogd("task:%u taskid:0x%x ioctl fd:%d\n", pid, params->caller_pid, data->drv.fd);

    if (!ioctl_auth_check((uint32_t)args[DRV_CMD_ID_INDEX], data)) {
        ret = -1;
        goto err_put;
    }

    ret = drv_func->ioctl(&data->drv,
        (uint32_t)args[DRV_CMD_ID_INDEX], (unsigned long)(uintptr_t)input_args, input_args_len);

    *fn_ret = ret;
    ret = 0;

err_put:
    dec_fd_ref_locked(data);
    put_drv_task_locked(task, 1);
    free_drv_args(input_args);

    return ret;
}

static int32_t close_param_check(uint64_t fd, const struct tee_drv_param *params)
{
    if (params == NULL || params->args == 0) {
        tloge("invalid params\n");
        return -1;
    }

    if (check_fd_invalid(fd))
        return -1;

    return 0;
}

int64_t driver_close(uint64_t fd, const struct tee_drv_param *params)
{
    if (close_param_check(fd, params) != 0)
        return -1;

    struct tee_uuid uuid;
    if (get_caller_uuid(params, &uuid) != 0)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    uint32_t pid = taskid_to_pid(args[CALLER_TASKID_INDEX]);
    struct drv_task *task = find_and_get_drv_task_locked(pid, false);
    if (task == NULL) {
        tloge("task:%u has not open this driver, cannot close\n", pid);
        return -1;
    }

    /*
     * In order to discard whether the driver ioctl function is stucked,
     * the close function registerd by driver must be called during the close execution flow.
     * So in close entry, the flow is below:
     * 1. find and delete the fd_data from task node
     * 2. wait fd_data's ref_cnt to 0 (if ioctl flow has not be exited, the ref_cnt cannot be 0)
     * 3. call close func registerd by driver and release fd resource
     * And in ioctl entry, the flow is below:
     * 1. find and get the fd_data
     * 2. call ioctl func registerd by driver
     * 3. put fd_data, and signal to other thread if the fd_data's ref_cnt is 0
     */
    struct fd_data *data = find_and_del_fd_data_locked((int32_t)(fd & DRV_FD_MASK), &uuid, task);
    if (data == NULL) {
        put_drv_task_locked(task, 1);
        tloge("task:%u has not open fd:%d, cannot close\n", pid, (int32_t)(fd & DRV_FD_MASK));
        return -1;
    }

    tlogd("task:%u close fd:%d\n", pid, data->drv.fd);

    close_fd_data_locked(data);
    put_drv_task_locked(task, DRV_TASK_OPEN_REF_CNT_STEP); /* pair with alloc_drv_task ref_cnt init with 1 */

    return 0;
}

static void task_dump_fd(const struct drv_task *task)
{
    struct dlist_node *pos = NULL;
    struct dlist_node *next = NULL;
    struct fd_data *temp = NULL;

    dlist_for_each_safe(pos, next, &task->data_head) {
        temp = dlist_entry(pos, struct fd_data, data_list);
        tloge("\t fd:%d ref_cnt:%u", temp->drv.fd, temp->ref_cnt);
    }
}

static void task_dump_fd_locked(struct drv_task *task)
{
    int32_t ret = drv_mutex_lock(&task->task_mtx);
    if (ret != 0) {
        tloge("lock task mtx failed\n");
        return;
    }

    task_dump_fd(task);

    ret = pthread_mutex_unlock(&task->task_mtx);
    if (ret != 0)
        tloge("unlock task mtx failed\n");
}

void driver_dump(void)
{
    struct dlist_node *pos = NULL;
    struct dlist_node *next = NULL;
    struct drv_task *temp = NULL;

    tloge("***** driver dump fd begin *****\n");
    int32_t ret = drv_mutex_lock(&g_drv_mtx);
    if (ret != 0) {
        tloge("lock drv mtx failed\n");
        return;
    }

    dlist_for_each_safe(pos, next, &g_drv_node) {
        temp = dlist_entry(pos, struct drv_task, task_list);
        tloge("task_pid:%u task_count:%u ref_cnt:%u\n", temp->task_pid, temp->task_count, temp->ref_cnt);
        task_dump_fd_locked(temp);
    }

    ret = pthread_mutex_unlock(&g_drv_mtx);
    if (ret != 0)
        tloge("unlock drv mtx failed\n");

    tloge("***** driver dump fd end *****\n");
}

#ifdef TEE_SUPPORT_CMD_DUMP
static void dump_cmd_perm(void)
{
    tloge("====== dump cmd perm begin ======\n");

    uint32_t i;
    for (i = 0; i < g_cmd_perm.cmd_num; i++)
        tloge("cmd, perm [%u, 0x%llx]\n", g_cmd_perm.base_vaddr[i].cmd,
            (unsigned long long)g_cmd_perm.base_vaddr[i].perm);

    tloge("====== dump cmd perm end ======\n");
}
#endif

int32_t driver_register_cmd_perm(const struct tee_drv_param *params, int64_t *ret_val)
{
    if (params == NULL || params->args == 0 || ret_val == NULL)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    uint64_t vaddr = args[DRV_REGISTER_CMD_ADDR_INDEX];
    uint64_t size = args[DRV_REGISTER_CMD_SIZE_INDEX];
    if (size >= UINT32_MAX || size == 0 || size % sizeof(struct drv_cmd_perm_info_t) != 0 || vaddr == 0) {
        tloge("invalid size:0x%llx or vaddr\n", size);
        return -1;
    }

    taskid_t drv_mgr_pid = get_drv_mgr_pid();
    if (taskid_to_pid(drv_mgr_pid) != (taskid_to_pid(params->caller_pid))) {
        tloge("caller pid:0x%x cannot register drv cmd perm\n", params->caller_pid);
        return -1;
    }

    if (g_cmd_perm.base_vaddr != NULL) {
        tloge("something wrong, cmd perm has registered\n");
        return -1;
    }

    void *cmd_perm = malloc(size);
    if (cmd_perm == NULL) {
        tloge("alloc for cmd perm fail\n");
        return -1;
    }

    if (copy_from_client(vaddr, size, (uintptr_t)cmd_perm, size) != 0) {
        tloge("copy cmd perm fail\n");
        free(cmd_perm);
        return -1;
    }

    g_cmd_perm.base_vaddr = cmd_perm;
    g_cmd_perm.cmd_num = size / sizeof(struct drv_cmd_perm_info_t);

#ifdef TEE_SUPPORT_CMD_DUMP
    dump_cmd_perm();
#endif

    *ret_val = 0;

    return 0;
}
