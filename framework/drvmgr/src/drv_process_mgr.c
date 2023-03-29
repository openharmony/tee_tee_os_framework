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
#include "drv_process_mgr.h"
#include <stdint.h>
#include <securec.h>
#include <dlfcn.h>
#include <pthread.h>
#include <ipclib.h>
#include <spawn_ext.h>
#include <sys/wait.h>
#include <signal.h>
#include <fileio.h>
#include <priorities.h>
#include <tee_log.h>
#include <drv_thread.h>
#include <spawn_init.h>
#include <get_elf_info.h>
#include <target_type.h>
#include <tee_drv_internal.h>
#include <mem_ops.h>
#include <mem_page_ops.h>
#include "drv_fd_ops.h"
#include "drv_dyn_policy_mgr.h"
#include "task_mgr.h"
#include "base_drv_node.h"
#include <ipclib_hal.h>

static const char *g_drv_loader = "/tarunner.elf";
static const char *g_drv_a32_loader = "/tarunner_a32.elf";

/*
 * channel and msghdl used for send/receive ipc msg
 * between drvmgr and drv process, locked by g_drv_spawn_mtx
 */
static cref_t g_drv_spawn_sync_channel;
static cref_t g_drv_spawn_sync_msghdl;

int32_t create_spawn_sync_msg_info(void)
{
    int32_t ret = ipc_create_channel_native(DRV_SPAWN_SYNC_NAME, &g_drv_spawn_sync_channel);
    if (ret != 0) {
        /* called by drvmgr main, use tloge instead of tloge */
        tloge("create spawn sync channel fail\n");
        return -1;
    }

    g_drv_spawn_sync_msghdl = ipc_msg_create_hdl();
    if (!check_ref_valid(g_drv_spawn_sync_msghdl)) {
        tloge("create spawn sync hdl fail\n");
        return -1;
    }

    return 0;
}

/*
 * process argv and env which will be passed to driver loader by kernel,
 * all this buffer should be in drvmgr map pages, otherwise will cannot
 * find map_page in find_map_page called by vspace_stream_sync.
 * Now, only the stack of main thread or the  global value added to map pages,
 * so in order to spawn in other thread, we use global value as the spawn buffer.
 */
static char g_spawn_buffer[sizeof(struct spawn_drv_buffer) * 2];
static char *g_argv[ARGV_MAX] = { 0 };
static char *g_env[ENV_MAX] = { 0 };
static pthread_mutex_t g_drv_spawn_mtx = PTHREAD_MUTEX_INITIALIZER;

static int32_t spawn_driver(const struct drv_spawn_param *param, int32_t loader_type,
    char *argv[], char *env[], uint32_t *taskid)
{
    pid_t pid;
    tid_t tid;
    posix_spawnattr_t spawnattr;

    int32_t ret = spawnattr_init(&spawnattr);
    if (ret != 0) {
        tloge("spawnattr init failed\n");
        return -1;
    }

    ret = spawnattr_setstack(&spawnattr, param->stack_size);
    if (ret != 0) {
        tloge("set stack size:0x%x failed\n", param->stack_size);
        return -1;
    }

    ret = spawnattr_setheap(&spawnattr, param->heap_size);
    if (ret != 0) {
        tloge("set heap size:0x%x failed\n", param->heap_size);
        return -1;
    }

    spawn_uuid_t uuid;
    uuid.uuid_valid = 0; /* drvloader in ramfs, not tafs */
    if (memcpy_s(&uuid.uuid, sizeof(uuid.uuid), &param->uuid, sizeof(param->uuid)) != 0) {
        tloge("set uuid failed\n");
        return -1;
    }
    spawnattr_setuuid(&spawnattr, &uuid);

    spawnattr.ptid = 0;

    const char *drv_loader = g_drv_loader;
    if (loader_type == ELF_TARUNNER_A32)
        drv_loader = g_drv_a32_loader;

    ret = posix_spawn_ex(&pid, drv_loader, NULL, &spawnattr, argv, env, &tid);
    if (ret != 0) {
        tloge("spawn driver failed ret:0x%x\n", ret);
        return -1;
    }

    *taskid = pid_to_taskid((uint32_t)tid, (uint32_t)pid);

    return 0;
}

static int32_t drv_name_to_path(const struct drv_spawn_param *drv_param, char *drv_path, int32_t path_len)
{
    bool base_drv_flag = get_base_drv_flag(drv_param->drv_name, strlen(drv_param->drv_name));
    if (base_drv_flag) {
        int32_t ret = snprintf_s(drv_path, path_len, (path_len - 1), "/%s%s", drv_param->drv_name, ".elf");
        if (ret < 0) {
            tloge("get drv path failed\n");
            return -1;
        }
    } else {
        int32_t ret = snprintf_s(drv_path, path_len, (path_len - 1), "%s/%s%s",
                                 TAFS_MOUNTPOINT, drv_param->drv_name, ".elf");
        if (ret < 0) {
            tloge("get drv path failed\n");
            return -1;
        }
    }

    tlogd("get drv path is %s\n", drv_path);

    return 0;
}

static int32_t init_spawn_argv(const char *drv_name, uint32_t drv_name_len,
    const char *path_name, uint32_t path_len, struct argv_base_buffer *argv)
{
    /* uncommit default is true */
    if (strncpy_s(argv->task_name, sizeof(argv->task_name), drv_name, drv_name_len) != 0) {
        tloge("set loader path failed\n");
        return -1;
    }

    if (strncpy_s(argv->task_path, sizeof(argv->task_path), path_name, path_len) != 0) {
        tloge("set task path name failed\n");
        return -1;
    }

    return 0;
}

static void init_spawn_buffer(struct spawn_drv_buffer *buffer)
{
    g_argv[ARGV_TASK_NAME_INDEX] = buffer->argv.task_name;
    g_argv[ARGV_TASK_PATH_INDEX] = buffer->argv.task_path;
    g_argv[ARGV_UNCOMMIT_INDEX] = buffer->argv.uncommit;

    g_env[ENV_PRIORITY_INDEX] = buffer->env.priority;
    g_env[ENV_UID_INDEX] = buffer->env.uid;
    g_env[ENV_TARGET_TYPE_INDEX] = buffer->env.target_type;
    g_env[ENV_DRV_INDEX_INDEX] = buffer->env_drv.drv_index;
    g_env[ENV_THREAD_LIMIT_INDEX] = buffer->env_drv.thread_limit;
    g_env[ENV_STACK_SIZE_INDEX] = buffer->env_drv.stack_size;
}

static int32_t init_spawn_env(const struct drv_spawn_param *drv_param, struct spawn_drv_buffer *buffer)
{
    struct env_param eparam = { 0 };
    eparam.priority = HM_PRIO_TEE_DRV;
    eparam.target_type = DRV_TARGET_TYPE;
    eparam.drv_index = drv_param->drv_index;
    eparam.thread_limit = drv_param->thread_limit;
    eparam.stack_size = drv_param->stack_size;

    int32_t ret = set_env_for_task(&eparam, &(drv_param->uuid), &(buffer->env));
    if (ret != 0)
        return -1;

    ret = set_drv_env_for_task(&eparam, &(buffer->env_drv));
    if (ret != 0)
        return -1;

    return 0;
}

static int32_t get_drv_loader(const char *name)
{
    char ehdr[EH_SIZE];
    int32_t loader = ELF_NOT_SUPPORT;

    int32_t fd = open(name, O_RDONLY);
    if (fd < 0) {
        tloge("cannot open file %d\n", fd);
        return loader;
    }

    if (read(fd, ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        tloge("read file failed, name=%s\n", name);
        goto close_fd;
    }

    int32_t elf_class = get_elf_class(ehdr, sizeof(ehdr));
    int32_t elf_type  = get_elf_type(ehdr, sizeof(ehdr), elf_class);
    if (elf_type != ET_DYN) {
        tloge("not support elf_type:0x%x\n", elf_type);
        goto close_fd;
    }

    if (elf_class == ELFCLASS64)
        loader = ELF_TARUNNER;
    else
        loader = ELF_TARUNNER_A32;

close_fd:
    close(fd);

    return loader;
}

#define MAX_WAIT_RETRY_COUNT 16
static int32_t wait_drv_spawn_msg(uint32_t taskid)
{
    struct src_msginfo info = { 0 }; /* store sender msg info */
    struct spawn_sync_msg msg = { 0 };

    int32_t ret;
    uint32_t retry_count = 0;

wait_retry:
    /*
     * To prevent other process send invalid msg, drvmgr should retry when the sender pid
     * not match the spawn process pid.
     * And in order to prevent other process send msg all the time, drvmgr will return fail
     * when retry MAX_WAIT_RETRY_COUNT.
     */
    if (retry_count >= MAX_WAIT_RETRY_COUNT) {
        tloge("wait drv msg retry_count:%u, should retry fail\n", retry_count);
        return -1;
    }

    retry_count++;
    ret = ipc_msg_receive(g_drv_spawn_sync_channel, &msg, sizeof(msg), g_drv_spawn_sync_msghdl, 
                          &info, WAIT_DRV_MSG_MAX_TIME);
    if (ret == E_EX_TIMER_TIMEOUT) {
        tloge("wait drv:0x%x spawn msg timeout:%u\n", taskid, WAIT_DRV_MSG_MAX_TIME);
        return -1;
    }

    if (ret != 0) {
        tloge("get drv:0x%x msg receiver fail ret:0x%x\n", taskid, ret);
        return -1;
    }

    if (info.src_pid != taskid_to_pid(taskid)) {
        tloge("sender:0x%x is not spawn process:0x%x, just wait again\n",
            info.src_pid, taskid);
        goto wait_retry;
    }

    if (msg.msg_id != PROCESS_INIT_SUCC) {
        tloge("spawn task:0x%x init fail\n", taskid);
        return -1;
    }

    tlogd("get drv:0x%x spawn msg succ\n", taskid);

    return 0;
}

#define DRV_KILL_WAIT_MAX_COUNT 5
void drv_kill_task(uint32_t taskid)
{
    if (kill((pid_t)taskid_to_pid(taskid), 0) == 0) {
        int32_t i;
        int32_t status;
        for (i = 0; i < DRV_KILL_WAIT_MAX_COUNT; i++) {
            if (wait(&status) == (pid_t)taskid_to_pid(taskid)) {
                tloge("wait drv:0x%x exit succ\n", taskid);
                break;
            }
        }

        if (i == DRV_KILL_WAIT_MAX_COUNT)
            tloge("wait drv:0x%x exit failed\n", taskid);
    } else {
        tloge("kill drv:0x%x failed\n", taskid);
    }
}

static int32_t prepare_spawn_params(const struct drv_spawn_param *drv_param, uint32_t *taskid)
{
    int32_t func_ret = -1;
    int32_t ret = drv_mutex_lock(&g_drv_spawn_mtx);
    if (ret != 0) {
        tloge("get drv spawn mtx failed\n");
        return -1;
    }

    /* make spawn_buffer in one page */
    struct spawn_drv_buffer *spawn_buffer = (struct spawn_drv_buffer *)g_spawn_buffer;
    (void)memset_s(g_spawn_buffer, sizeof(g_spawn_buffer), 0, sizeof(g_spawn_buffer));
    if (((uintptr_t)g_spawn_buffer & (PAGE_SIZE - 1)) + sizeof(struct spawn_drv_buffer) > PAGE_SIZE)
        spawn_buffer = (struct spawn_drv_buffer *)(g_spawn_buffer + sizeof(struct spawn_drv_buffer));

    init_spawn_buffer(spawn_buffer);

    if (init_spawn_env(drv_param, spawn_buffer) != 0)
        goto unlock_spawn_mtx;

    char drv_path[ARGV_SIZE] = { 0 };
    ret = drv_name_to_path(drv_param, drv_path, sizeof(drv_path));
    if (ret != 0)
        goto unlock_spawn_mtx;

    ret = init_spawn_argv(drv_param->drv_name, (strlen(drv_param->drv_name) + 1),
        drv_path, (strlen(drv_path) + 1), &(spawn_buffer->argv));
    if (ret != 0)
        goto unlock_spawn_mtx;

    int32_t loader_type = get_drv_loader(drv_path);
    if (loader_type == ELF_NOT_SUPPORT) {
        tloge("get drv loader ret:0x%x fail\n", loader_type);
        goto unlock_spawn_mtx;
    }

    ret = spawn_driver(drv_param, loader_type, g_argv, g_env, taskid);
    if (ret != 0)
        goto unlock_spawn_mtx;

    ret = wait_drv_spawn_msg(*taskid);
    if (ret != 0) {
        tloge("wait drv spawn msg fail\n");
        drv_kill_task(*taskid);
        goto unlock_spawn_mtx;
    }

    func_ret = 0;

unlock_spawn_mtx:
    ret = pthread_mutex_unlock(&g_drv_spawn_mtx);
    if (ret != 0)
        tloge("something wrong, unlock mtx in drv spawn fail:0x%x\n", ret);

    return func_ret;
}

static int32_t set_drv_name_and_uuid(const struct task_node *node, struct drv_spawn_param *param)
{
    if (memcpy_s(&param->drv_name, (sizeof(param->drv_name) - 1),
        node->tlv.drv_conf->mani.service_name, node->tlv.drv_conf->mani.service_name_size) != 0) {
        tloge("copy name:%s fail\n", node->tlv.drv_conf->mani.service_name);
        return -1;
    }

    param->drv_name[node->tlv.drv_conf->mani.service_name_size] = '\0';

    if (memcpy_s(&param->uuid, sizeof(param->uuid),
        &node->tlv.uuid, sizeof(node->tlv.uuid)) != 0) {
        tloge("copy uuid:0x%x fail\n", node->tlv.uuid.timeLow);
        return -1;
    }

    return 0;
}

static void set_drv_thread_limit(const struct task_node *node, struct drv_spawn_param *param)
{
    param->thread_limit = node->tlv.drv_conf->drv_basic_info.thread_limit;
    tlogd("thread limit:%u\n", param->thread_limit);
}

static int32_t set_drv_stack_size(const struct task_node *node, struct drv_spawn_param *param)
{
    uint32_t stack_size = node->tlv.drv_conf->mani.stack_size;
    uint32_t stack_size_align = PAGE_ALIGN_UP(stack_size);
    if (stack_size_align < stack_size) {
        tloge("invalid stack_size:0x%x\n", stack_size);
        return -1;
    }

    if (stack_size_align < DRV_DEFAULT_STACK_SIZE) {
        tloge("stack_size:0x%x use default:0x%x", stack_size_align, DRV_DEFAULT_STACK_SIZE);
        stack_size_align = DRV_DEFAULT_STACK_SIZE;
    }

    param->stack_size = stack_size_align;

    return 0;
}

static int32_t set_drv_heap_size(const struct task_node *node, struct drv_spawn_param *param)
{
    uint32_t heap_size = node->tlv.drv_conf->mani.data_size;
    uint32_t heap_size_align = PAGE_ALIGN_UP(heap_size);
    if (heap_size_align < heap_size) {
        tloge("invalid heap_size:0x%x\n", heap_size);
        return -1;
    }

    uint32_t stack_size = param->stack_size;
    uint32_t thread_limit = param->thread_limit;
    uint32_t extra_stack_size = stack_size * thread_limit;
    if (extra_stack_size < stack_size) {
        tloge("stack_size:0x%x and thread_limit:%u is overflow\n", stack_size, thread_limit);
        return -1;
    }

    if (heap_size_align + extra_stack_size < heap_size_align) {
        tloge("heap_size:0x%x and extra_stack_size:0x%x is overflow\n", heap_size_align, extra_stack_size);
        return -1;
    }

    heap_size_align += extra_stack_size;
    param->heap_size = heap_size_align;

    return 0;
}

static int32_t get_drv_channel(const char *drv_name, cref_t *ch)
{
    cref_t channel;
    int32_t ret = ipc_get_ch_from_path(drv_name, &channel);
    if (ret != 0) {
        tloge("get drv:%s channel fail:0x%x\n", drv_name, ret);
        return -1;
    }

    tlogd("get drv:%s channel:0x%llx succ\n", drv_name, channel);

    *ch = channel;

    return 0;
}

static int32_t send_cmd_perm_msg(uint64_t drv_vaddr, uint32_t drv_size, cref_t channel)
{
    char buf[SYSCAL_MSG_BUFFER_SIZE] = { 0 };
    struct drv_req_msg_t *msg = (struct drv_req_msg_t *)buf;
    struct drv_reply_msg_t *rmsg = (struct drv_reply_msg_t *)buf;

    msg->args[DRV_REGISTER_CMD_ADDR_INDEX] = drv_vaddr;
    msg->args[DRV_REGISTER_CMD_SIZE_INDEX] = drv_size;

    msg->header.send.msg_id = REGISTER_DRV_CMD_PERM;
    msg->header.send.msg_size = sizeof(struct drv_req_msg_t);

    int32_t ret = ipc_msg_call(channel, msg, msg->header.send.msg_size, rmsg, SYSCAL_MSG_BUFFER_SIZE, -1);
    if (ret != 0) {
        tloge("msg call:0x%x fail ret:0x%x\n", REGISTER_DRV_CMD_PERM, ret);
        return -1;
    }

    return rmsg->header.reply.ret_val;
}

static int32_t send_cmd_perm_to_drv(const struct task_node *node)
{
    int32_t ret = -1;
    uint32_t self_pid = get_self_taskid();
    if (self_pid == SRE_PID_ERR) {
        tloge("get self pid fail\n");
        return ret;
    }

    if (node->tlv.drv_conf->cmd_perm_list_size == 0) {
        tlogd("no cmd perm, just return\n");
        return 0;
    }

    uint32_t tmp_size = node->tlv.drv_conf->cmd_perm_list_size * sizeof(struct drv_cmd_perm_info_t);
    void *tmp_addr = alloc_sharemem_aux(&node->tlv.uuid, tmp_size);
    if (tmp_addr == NULL) {
        tloge("alloc share mem:0x%x fail\n", tmp_size);
        return ret;
    }

    if (memcpy_s(tmp_addr, tmp_size, node->tlv.drv_conf->cmd_perm_list, tmp_size) != 0) {
        tloge("copy cmd perm to share mem fail\n");
        goto free_addr;
    }

    ret = send_cmd_perm_msg((uint64_t)(uintptr_t)tmp_addr, tmp_size, node->drv_task.channel);

free_addr:
    if (free_sharemem(tmp_addr, tmp_size) != 0)
        tloge("free share mem fail\n");

    return ret;
}

int32_t spawn_driver_handle(struct task_node *node)
{
    if (node == NULL || node->tlv.drv_conf == NULL || node->drv_task.drv_index < 0) {
        tloge("spawn invalid node\n");
        return -1;
    }

    struct drv_spawn_param param;
    (void)memset_s(&param, sizeof(param), 0, sizeof(param));
    param.drv_index = (uint32_t)node->drv_task.drv_index;

    if (set_drv_name_and_uuid(node, &param) != 0)
        return -1;

    set_drv_thread_limit(node, &param);

    if (set_drv_stack_size(node, &param) != 0)
        return -1;

    /* set heap size must call after set_drv_stack_size and set thread_limit */
    if (set_drv_heap_size(node, &param) != 0)
        return -1;

    uint32_t taskid;
    int32_t ret = prepare_spawn_params(&param, &taskid);
    if (ret != 0) {
        tloge("spawn drv:%s fail\n", param.drv_name);
        return -1;
    }

    ret = get_drv_channel(param.drv_name, &node->drv_task.channel);
    if (ret != 0)
        goto kill_task;

    ret = send_cmd_perm_to_drv(node);
    if (ret != 0)
        goto release_channel;

    node->pid = taskid_to_pid(taskid);

    return 0;

release_channel:
    if (ipc_release_from_path(node->tlv.drv_conf->mani.service_name, node->drv_task.channel) != 0)
        tloge("release drv:%s channel:0x%llx failed\n", node->tlv.drv_conf->mani.service_name, node->drv_task.channel);
    node->drv_task.channel = -1;

kill_task:
    drv_kill_task(taskid);

    return -1;
}

void release_driver(struct task_node *node)
{
    if (node == NULL || node->target_type != DRV_TARGET_TYPE || node->tlv.drv_conf == NULL) {
        tloge("invalid node\n");
        return;
    }

    if (node->drv_task.register_policy) {
        del_dynamic_policy_to_drv(&node->tlv.uuid);
        node->drv_task.register_policy = false;
    }

    if (check_ref_valid(node->drv_task.channel)) {
        if (ipc_release_from_path(node->tlv.drv_conf->mani.service_name, node->drv_task.channel) != 0)
            tloge("release drv:%s channel:0x%llx failed\n",
                node->tlv.drv_conf->mani.service_name, node->drv_task.channel);
        node->drv_task.channel = -1;
    }

    if (node->pid != (uint32_t)INVALID_CALLER_PID) {
        drv_kill_task(node->pid);
        node->pid = (uint32_t)INVALID_CALLER_PID;
    }
}
