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

#include "tee_task.h"
#include "spawn_ext.h"
#include <sys/wait.h>
#include <signal.h>
#include <inttypes.h>

#include <stdio.h>
#include <elf.h>
#include <fileio.h>
#include <priorities.h>
#include <drv.h>
#include <spawn_init.h>
#include <get_elf_info.h>
#include <target_type.h>

#include "ta_framework.h"
#include "tee_log.h"
#include "tee_config.h"
#include "gtask_config_hal.h"

#include <string.h>
#include "ipclib.h"
#include "securec.h"
#include "uuid2path.h"
#include "timer.h"

#include "gtask_core.h" /* for session_struct */
#include "session_manager.h"

#include "task_adaptor_pub.h"
#include "init.h"
#include "dynload.h"
#include <ipclib_hal.h>

#define MAX_PATH_NAME_LEN 64
#define PAGES_FOR_STACK   2

#define CREATE_THREAD_FAIL  0xFFFFFFFFU
#if defined(CONFIG_OFF_DRV_TIMER) && defined(CONFIG_ARCH_AARCH64)
#define TASK_TIMEOUT 2000
#else
#define TASK_TIMEOUT 0xFFFFFFFFU
#endif
static TEE_Result ta_name_to_path(const struct service_struct *service,
                                  char *path_name, size_t len, int *p_priority)
{
    uint32_t i;
    uint32_t builtin_task_num = get_builtin_task_nums();

    if (service == NULL || len > MAX_PATH_NAME_LEN)
        return TEE_ERROR_BAD_PARAMETERS;

    /* search builtin tasks first */
    for (i = 0; i < builtin_task_num; i++) {
        const struct task_info_st *builtin_task_info = get_builtin_task_info_by_index(i);
        if (builtin_task_info == NULL)
            break;

        if (strncmp(service->name, builtin_task_info->name, strlen(builtin_task_info->name) + 1) == 0) {
            if (strncpy_s(path_name, len, builtin_task_info->path, strlen(builtin_task_info->path)) == EOK) {
                /* set priority for buitlin task */
                *p_priority = builtin_task_info->priority;
                return TEE_SUCCESS;
            }
            return TEE_ERROR_GENERIC;
        }
    }

    /* set default priority for normal dynload task */
    *p_priority = PRIO_TEE_TA;

    /* for dynload task, use uuid as path */
    if (uuid_to_fname(&service->property.uuid, path_name, (int)len) == 0)
        return TEE_SUCCESS;

    tloge("%s uuid_to_fname error!\n", service->name);

    return TEE_ERROR_ITEM_NOT_FOUND;
}

#define WAIT_MAX 5
void gt_wait_process(uint32_t task_id)
{
    int i;
    int wstatus;

    (void)ipc_release_from_taskid(task_id, 0);
    for (i = 0; i < WAIT_MAX; i++) {
        if (wait(&wstatus) == (pid_t)taskid_to_pid(task_id)) {
            tlogd("wait %" PRIu32 " exit succeeded\n", task_id);
            break;
        }
    }
    if (i == WAIT_MAX)
        tloge("wait %" PRIu32 " exit failed\n", task_id);
}

static timer_event *start_timeout(void)
{
#if (!defined CONFIG_OFF_TIMER) && (!defined CONFIG_OFF_DRV_TIMER)
    struct timer_private_data_kernel dummy = { 0 };
    timeval_t val;

    dummy.dev_id = 1;
    dummy.type   = TIMER_CALLBACK_TIMEOUT;

    timer_event *event = tee_time_event_create(NULL, TIMER_GENERIC, (void *)(&dummy));
    if (event == NULL) {
        tloge("create timer failed\n");
        return NULL;
    }

    /* wait for 2 seconds */
    val.tval.sec  = 2;
    val.tval.nsec = 0;
    if (tee_time_event_start(event, &val) != 0)
        tloge("start timer failed\n");
    return event;
#else
    return NULL;
#endif
}

static void stop_timeout(timer_event *event)
{
    if (event == NULL)
        return;

#if (!defined CONFIG_OFF_TIMER) && (!defined CONFIG_OFF_DRV_TIMER)
    if (tee_time_event_stop(event) != 0)
        tloge("stop timer failed\n");

    if (tee_time_event_destroy(event) != 0)
        tloge("destroy timer failed\n");
#endif
}

static int gt_create_thread(pid_t *pid)
{
    struct global_to_service_thread_msg entry_msg = { { { 0 } } };
    uint32_t msg_id;
    taskid_t sender_pid;
    uint32_t rc;
    uint64_t stack_size;

    if (get_cur_service() == NULL || get_cur_service()->service_thread == 0)
        return NORMAL_FAIL_RET;

    stack_size = get_cur_service()->property.stack_size;
    if (stack_size > MAX_STACK_SIZE) {
        tloge("Stack is too large 0x%" PRIx32 "\n", stack_size);
        return NORMAL_FAIL_RET;
    }

    entry_msg.create_msg.stack_size = stack_size + PAGE_SIZE;
    if (entry_msg.create_msg.stack_size <= stack_size) {
        tloge("stack size overflow\n");
        return NORMAL_FAIL_RET;
    }

    rc = ipc_msg_snd(CALL_TA_CREATE_THREAD, get_cur_service()->service_thread, &entry_msg, sizeof(entry_msg));
    if (rc != 0) {
        tloge("CALL_TA_CRTEATE_THREAD msg send failed:0x%" PRIx32 "\n", rc);
        return NORMAL_FAIL_RET;
    }
    /*
     * wait at Q#1 for ACK message from "worker_thread" created by service thread,
     * drop messages from other sources.
     */
    timer_event *event = start_timeout();
    do {
        if (ipc_msg_q_recv(&msg_id, &sender_pid, 1, TASK_TIMEOUT) != 0) {
            stop_timeout(event);
            tloge("CALL_TA_CRTEATE_THREAD msg QRecv failed\n");
            return NORMAL_FAIL_RET;
        }
        if (taskid_to_pid(sender_pid) == get_timer_pid() && msg_id == TIMER_CALLBACK_TIMEOUT) {
            stop_timeout(event);
            tloge("CALL_TA_CREATE_THREAD timeout\n");
            return TIMEOUT_FAIL_RET;
        }
    } while (taskid_to_pid(sender_pid) != taskid_to_pid(get_cur_service()->service_thread));
    stop_timeout(event);
    tlogd("gtask get tid 0x%" PRIx32 " from pid 0x%" PRIx32 "\n", msg_id, sender_pid);

    if (msg_id == CREATE_THREAD_FAIL) {
        tloge("gtask create TA create failed\n");
        return NORMAL_FAIL_RET;
    }

    *pid = (int)sender_pid;

    return SUCC_RET;
}

static int gt_recycle_thread(uint32_t task_id, uint32_t session_id)
{
    struct global_to_service_thread_msg entry_msg = { { { 0 } } };
    uint32_t msg_id;
    taskid_t pid = 0;
    uint32_t rc;

    if (get_cur_service() == NULL || get_cur_service()->service_thread == 0)
        return NORMAL_FAIL_RET;

    msg_id = CALL_TA_REMOVE_THREAD;
    tlogd("Recycle thread %s task_id %" PRIx32 " msgid = 0x%" PRIx32 "\n", get_cur_service()->name, task_id, msg_id);

    entry_msg.remove_msg.tid = taskid_to_tid(task_id);
    entry_msg.remove_msg.session_id = session_id;
    rc = ipc_msg_snd(msg_id, get_cur_service()->service_thread, &entry_msg, sizeof(entry_msg));
    if (rc != 0) {
        tloge("recycle msg 0x%" PRIx32 " send failed:0x%" PRIx32 "\n", msg_id, rc);
        return NORMAL_FAIL_RET;
    }

    /*
     * wait at Q#1 for ACK message from get_cur_service()->service_thread,
     * drop messages from other sources.
     */
    timer_event *event = start_timeout();
    do {
        if (ipc_msg_q_recv(&msg_id, &pid, 1, TASK_TIMEOUT) != 0) {
            stop_timeout(event);
            tloge("recycle msg QRecv failed\n");
            return NORMAL_FAIL_RET;
        }
        if (taskid_to_pid(pid) == get_timer_pid() && msg_id == TIMER_CALLBACK_TIMEOUT) {
            stop_timeout(event);
            tloge("CALL_TA_REMOVE_THREAD timeout\n");
            return TIMEOUT_FAIL_RET;
        }
    } while (pid != get_cur_service()->service_thread);
    stop_timeout(event);

    /* "invalid tid" is the the only case for this */
    if (msg_id != 0) {
        tloge("recycle failed, ret=%" PRIu32 "\n", msg_id);
        return NORMAL_FAIL_RET;
    }

    return SUCC_RET;
}

static int32_t decide_executer(const char *ehdr, uint32_t ehdr_size, int32_t fd)
{
    (void)fd;
    int32_t elf_class = get_elf_class(ehdr, ehdr_size);
    int32_t elf_type  = get_elf_type(ehdr, ehdr_size, elf_class);

    tlogd("elf_class: %d, elf type: %d\n", elf_class, elf_type);

    if (elf_type == ET_REL)
        return ELF_NOT_SUPPORT;

    if (elf_type == ET_DYN)
        return ELF_TARUNNER;

    tloge("unsupported elf type\n");
    return ELF_NOT_SUPPORT;
}

#define EH_SIZE sizeof(Elf64_Ehdr)

static int check_binary_type(const char *name)
{
    int ldr = ELF_NOT_SUPPORT;
    char ehdr[EH_SIZE];

    int fd = open(name, O_RDONLY);
    if (fd < 0) {
        tloge("cannot open file %d\n", fd);
        return ldr;
    }

    if (read(fd, ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        tloge("read file failed, name=%s\n", name);
        goto close_fd;
    }

    ldr = decide_executer(ehdr, sizeof(ehdr), fd);

close_fd:
    close(fd);
    return ldr;
}

static int32_t set_stack_size(posix_spawnattr_t *spawnattr)
{
    uint64_t total_size;
    uint64_t stack_size = (get_cur_service()->property).stack_size;

    if (stack_size > MAX_STACK_SIZE) {
        tloge("Stack is too large 0x%" PRIx32 "\n", get_cur_service()->property.stack_size);
        return -1;
    }

    /* rdr log buffer and msg_recv buffer need more stack */
    total_size = stack_size + PAGE_SIZE;
    if (total_size <= stack_size) {
        tloge("stack size overflow!\n");
        return -1;
    }

    if (total_size < PAGE_SIZE * PAGES_FOR_STACK)
        total_size = PAGE_SIZE * PAGES_FOR_STACK;

    return spawnattr_setstack(spawnattr, total_size);
}

static int32_t get_mem_total_size(uint64_t *size)
{
    uint64_t heap_size;
    uint64_t stack_size;
    uint64_t total_size;
    uint64_t tmp_size;

    heap_size = (get_cur_service()->property).heap_size;
    stack_size = get_cur_service()->property.stack_size;

    if ((get_cur_service()->property).multi_session == true) {
        tmp_size = stack_size * TA_STACK_MAX;
        if (tmp_size <= stack_size) {
            tloge("size overflow!\n");
            return -1;
        }
        total_size = heap_size + tmp_size;
    } else {
        tmp_size = stack_size;
        total_size = heap_size + tmp_size;
    }

    if (total_size <= heap_size || total_size <= tmp_size) {
        tloge("size overflow!\n");
        return -1;
    }
    *size = total_size;
    return 0;
}

static int tee_spawn_with_attr(int *ptask_id, const char *elf_path, char *argv[], char *env[],
                              const spawn_uuid_t *uuid)
{
    pid_t pid;
    tid_t tid;
    posix_spawnattr_t spawnattr;
    uint64_t heap_size;

    if (spawnattr_init(&spawnattr) != 0)
        return -1;

    if (get_cur_service() == NULL)
        return -1;

    if (set_stack_size(&spawnattr) != 0) {
        tloge("set stack size failed\n");
        return -1;
    }

    spawnattr_setuuid(&spawnattr, uuid);

    if (get_mem_total_size(&heap_size) != 0)
        return -1;

    if (spawnattr_setheap(&spawnattr, heap_size) != 0)
        return -1;

    if (posix_spawn_ex(&pid, elf_path, NULL, &spawnattr, argv, env, &tid) != 0)
        return -1;

    /* build task_id by pid and tid */
    if (ptask_id != NULL)
        *ptask_id = pid_to_taskid((uint32_t)tid, (uint32_t)pid);

    return 0;
}

static int32_t get_elf_path(int32_t bin_type, char *loader_path, uint32_t loader_path_size)
{
    if (get_cur_service()->ta_64bit == true) {
        if (memcpy_s(loader_path, loader_path_size, "/tarunner.elf", sizeof("/tarunner.elf")) != EOK) {
            tloge("set loader tarunner fail\n");
            return -1;
        }
    } else if (bin_type == ELF_TARUNNER) {
        if (memcpy_s(loader_path, loader_path_size, "/tarunner_a32.elf", sizeof("/tarunner_a32.elf")) != EOK) {
            tloge("set loader tarunner a32 fail\n");
            return -1;
        }
    } else {
        tloge("unsupported elf type\n");
        return -1;
    }

    return 0;
}

static void wait_srvc_thread_message(struct msg_recv_param *msg_recv_p, uint32_t *task_id, taskid_t service_thread)
{
    /*
     * wait at Q#1 for ACK message from "worker_thread" created by
     * service thread, drop messages from other sources.
     */
    timer_event *event = start_timeout();
    do {
        if (ipc_msg_q_recv(&(msg_recv_p->msg_id), task_id, 1, TASK_TIMEOUT) != 0)
            tloge("gtask get tid failed\n");
        if (taskid_to_pid(*task_id) == get_timer_pid() && msg_recv_p->msg_id == TIMER_CALLBACK_TIMEOUT) {
            tloge("spawn multi-session TA timeout\n");
            msg_recv_p->msg_id = CREATE_THREAD_FAIL;
            break;
        }
    } while (taskid_to_pid(*task_id) != taskid_to_pid(service_thread));
    stop_timeout(event);
    tlogd("gtask get tid 0x%" PRIx32 " from pid 0x%" PRIx32 "\n", msg_recv_p->msg_id, task_id);
}

static int32_t create_service_thread(const char *elf_path, char **argv, char **env,
                                     const spawn_uuid_t *uuid, uint32_t *puw_pid)
{
    taskid_t service_thread = 0;
    uint32_t task_id         = 0;
    struct msg_recv_param msg_recv_p;
    int32_t ret;

    ret = tee_spawn_with_attr((int *)&service_thread, elf_path, argv, env, uuid);
    if (ret != 0)
        return -1;

    wait_srvc_thread_message(&msg_recv_p, &task_id, service_thread);
    /* create thread fail, kill service thread and return error */
    if (msg_recv_p.msg_id == CREATE_THREAD_FAIL) {
        if (kill((int)taskid_to_pid(service_thread), 0) == 0)
            gt_wait_process(service_thread);
        else
            tloge("kill BAD service thread failed\n");
        return -1;
    }
    // record service_thread to current service
    get_cur_service()->service_thread = service_thread;
    *puw_pid                          = task_id;
    /* send msg to internal service */
    task_adapt_ta_create(taskid_to_pid(service_thread), &((get_cur_service()->property).uuid));
    return 0;
}

static int set_argv_for_tsk(struct argv_base_buffer *argv, char *loader_path, uint32_t loader_path_size,
    const char *path_name, uint32_t path_name_size)
{
    int bin_type = check_binary_type(path_name);
    if (bin_type < ELF_NATIVE)
        return -EINVAL;

    if (ta_no_uncommit(&((get_cur_service()->property).uuid))) {
        argv->uncommit[0] = 'n';
        argv->uncommit[1] = 'o';
        argv->uncommit[2] = '_';
        argv->uncommit[3] = 'u';
        argv->uncommit[4] = 'c';
    }

    if (bin_type != ELF_NATIVE) {
        if (get_elf_path(bin_type, loader_path, loader_path_size) != 0)
            return -EINVAL;

        if (memcpy_s(argv->elf_path, sizeof(argv->elf_path), loader_path, loader_path_size) != EOK)
            return -EINVAL;

        /* tasks load by  taloader and tarunner */
        if (strncpy_s(argv->task_name, sizeof(argv->task_name), get_cur_service()->name,
                      sizeof(get_cur_service()->name) - 1) != EOK)
            return -EINVAL;
        if (strncpy_s(argv->task_path, sizeof(argv->task_path), path_name, path_name_size - 1) != EOK)
            return -EINVAL;

        /*
         * During parameter transfer, '/0' is used to determine the parameter length.
         * Multiple strings are transferred here, so replace '/0' with '#'
         */
        (void)memset_s(argv->client_name, sizeof(argv->client_name), '#', sizeof(argv->client_name));
        argv->client_name[sizeof(argv->client_name) - 1] = '\0';
        if (get_dyn_client_name(get_cur_service()->ta_64bit, argv->client_name,
            sizeof(argv->client_name)) != 0)
            tlogd("no dyn client exists\n");
    } else {
        if (memcpy_s(loader_path, loader_path_size, path_name, path_name_size) != EOK) {
            tloge("native set loader path fail\n");
            return -EINVAL;
        }

        if (strncpy_s(argv->task_name, sizeof(argv->task_name), path_name, path_name_size) != EOK)
            return -EINVAL;
    }
    return 0;
}

static int32_t init_spawn_buffer(struct spawn_buffer *sbuf, char **argv, uint32_t argv_size,
    char **env, uint32_t env_size)
{
    if (argv_size < ARGV_MAX || env_size < ENV_MAX) {
        tloge("argv size:%u env size:%u invalid\n", argv_size, env_size);
        return -1;
    }

    env[ENV_PRIORITY_INDEX] = sbuf->env.priority;
    env[ENV_UID_INDEX] = sbuf->env.uid;
    env[ENV_TARGET_TYPE_INDEX] = sbuf->env.target_type;

    argv[ARGV_ELF_PATH_INDEX] = sbuf->argv.elf_path;
    argv[ARGV_TASK_NAME_INDEX] = sbuf->argv.task_name;
    argv[ARGV_TASK_PATH_INDEX] = sbuf->argv.task_path;
    argv[ARGV_UNCOMMIT_INDEX] = sbuf->argv.uncommit;
    argv[ARGV_CLIENT_NAME_INDEX] = sbuf->argv.client_name;

    return 0;
}

static int32_t init_spawn_argv_env(const struct tsk_init_param *init_param, struct spawn_buffer *sbuffer,
    char *loader_path, uint32_t loader_path_size)
{
    char path_name[MAX_PATH_NAME_LEN] = { 0 };

    struct env_param eparam = { 0 };
    eparam.target_type = TA_TARGET_TYPE;

    /* get elf path for current service */
    if (ta_name_to_path(get_cur_service(), path_name, sizeof(path_name), &(eparam.priority)) != TEE_SUCCESS)
        return -EINVAL;

    if (set_env_for_task(&eparam, &(init_param->uuid), &(sbuffer->env)) != 0)
        return -EINVAL;

    if (set_argv_for_tsk(&(sbuffer->argv), loader_path, loader_path_size,  path_name, sizeof(path_name)) != 0)
        return -EINVAL;

    return 0;
}

static int gt_create_proc(const struct tsk_init_param *init_param, uint32_t *task_id)
{
    char loader_path[MAX_PATH_NAME_LEN] = { 0 };
    int ret;
    char *argv[ARGV_MAX] = { NULL };
    char *env[ENV_MAX] = { NULL }; /* need NULL-terminated */
    spawn_uuid_t uuid = {0};

    /* make spawn_buffer in one page */
    char buffer[2 * sizeof(struct spawn_buffer)] = { 0 };
    struct spawn_buffer *sbuffer = (struct spawn_buffer *)&buffer;
    if (((uintptr_t)buffer & (PAGE_SIZE - 1)) + sizeof(struct spawn_buffer) > PAGE_SIZE)
        sbuffer = (struct spawn_buffer *)(buffer + sizeof(struct spawn_buffer));

    if (init_spawn_buffer(sbuffer, argv, ARGV_MAX, env, ENV_MAX) != 0)
        return -1;

    if (init_spawn_argv_env(init_param, sbuffer, loader_path, sizeof(loader_path)) != 0)
        return -1;

    if (memmove_s(&uuid.uuid, sizeof(uuid.uuid), &(init_param->uuid), sizeof(init_param->uuid)) != EOK) {
        tloge("memmove uuid failed\n");
        return -EINVAL;
    }

    if (strncmp(loader_path, TAFS_MOUNTPOINT, strlen(TAFS_MOUNTPOINT)) == 0)
        uuid.uuid_valid = 1;

    ret = create_service_thread(loader_path, argv, env, &uuid, task_id);
    return ret;
}

int sre_task_create(const struct tsk_init_param *init_param, uint32_t *task_id)
{
    int ret;

    if (init_param == NULL || task_id == NULL || get_cur_service() == NULL) {
        tloge("invalid param!\n");
        return -EINVAL;
    }

    if (get_cur_service()->service_thread == 0) {
        ret = gt_create_proc(init_param, task_id);
    } else {
        /* create working thread */
        ret = gt_create_thread((pid_t *)task_id);
    }
    return ret;
}

int32_t sre_task_delete_ex(uint32_t uw_task_pid, bool is_service_dead, uint32_t session_id)
{
    int ret;

    /* Multi-thread task */
    (void)ipc_release_from_taskid(uw_task_pid, 0);

    /* service has exception, cannot send msg to it anymore */
    if (is_service_dead)
        return SUCC_RET;

    ret = gt_recycle_thread((uint32_t)uw_task_pid, session_id);
    return ret;
}
