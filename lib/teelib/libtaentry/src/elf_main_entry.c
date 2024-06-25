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
#include "elf_main_entry.h"
#include <sys/mman.h>
#include <string.h>
#include <pthread.h>
#include <securec.h>
#include <inttypes.h>
#include <tee_defines.h>
#include <tee_init.h>
#include <tee_property_inner.h>
#include <ta_mt.h>
#include <tee_mem_mgmt_api.h>
#include <tee_log.h>
#include <mem_ops.h>
#include <ipclib_hal.h>
#include "client_auth.h"

#define VERSION_EME     "RELEASE - v1.2"
#define BSS_START_MAGIC 0x12345678
#define BSS_END_MAGIC   0x87654321
#define PARAM_TYPE_ALL             0xFFFF
#define PARAM_TYPE_MASK            0xFFF0
#define PARAM_TYPE_SHIFT           4

/*
 * Add for TAINTED_SCALAR
 * when change g_image_hd.manifest_str_len in gtask,
 * should ensure it will not exceed PROPERTY_MAX_LEN
 */
#define PROPERTY_MAX_LEN 0x10000

#define INIT_DONE     1
#define INIT_NOT_DONE 0

static bool g_state_create_entry = false;

/* Force these 2 variable locate in data section */
static __attribute__((section(".data"))) pthread_mutex_t g_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static __attribute__((section(".data"))) pthread_cond_t g_init_cond   = PTHREAD_COND_INITIALIZER;
static __attribute__((section(".data"))) char g_init_done             = INIT_NOT_DONE;

typedef void (*func_ptr)(void);

bool is_create_entry_processed(void)
{
    return g_state_create_entry;
}

static int32_t mutex_lock_ops(pthread_mutex_t *mtx)
{
    int32_t ret;

    ret = pthread_mutex_lock(mtx);
    if (ret == EOWNERDEAD) /* owner died, use consistent to recover and lock the mutex */
        return pthread_mutex_consistent(mtx);

    return ret;
}

static void init(const struct ta_routine_info *append_args)
{
    if (append_args == NULL)
        return;

    func_ptr *func  = NULL;
    func_ptr *begin = (func_ptr *)append_args->info[INIT_ARRAY_START_INDEX];
    func_ptr *end   = (func_ptr *)append_args->info[INIT_ARRAY_END_INDEX];
    for (func = begin; func < end; func++) {
        if (*func != NULL)
            (*func)();
    }
    tlogd("cxx-support: End of constructors initialization\n");
}

static void clear_ta_bss(const struct ta_routine_info *append_args)
{
    void *ta_bss_start = NULL;
    void *ta_bss_end = NULL;
    int32_t sret;

    if (append_args == NULL)
        return;

    ta_bss_start = append_args->info[BSS_START_INDEX];
    ta_bss_end = append_args->info[BSS_END_INDEX];
    bool flag = (ta_bss_start == NULL) || (ta_bss_end == NULL) || (ta_bss_start == ta_bss_end);
    if (flag) {
        tlogd("no bss section\n");
        return;
    }

    if (ta_bss_end > ta_bss_start) {
        sret = memset_s(ta_bss_start, (uintptr_t)ta_bss_end - (uintptr_t)ta_bss_start, 0,
                        (uintptr_t)ta_bss_end - (uintptr_t)ta_bss_start);
        if (sret != EOK)
            tloge("Failed to clear ta bss\n");
        return;
    }

    tloge("failed:ta bss start is larger than ta bss end\n");
}

static TEE_Result ta_invoke_command_entry_point(void *session_context, uint32_t cmd_id, uint32_t param_types,
                                                TEE_Param params[TEE_PARAMS_NUM],
                                                const struct ta_routine_info *routine)
{
    if ((routine != NULL) && (routine->info[INVOKE_COMMAND_INDEX] != NULL)) {
        TEE_Result (*fun)(void *, uint32_t, uint32_t, TEE_Param *) = routine->info[INVOKE_COMMAND_INDEX];
        return fun(session_context, cmd_id, param_types, params);
    }

    tlogi("default invoke command entry point func\n");
    return TEE_SUCCESS;
}

static TEE_Result ta_create_entry_point(const struct ta_routine_info *routine)
{
    if ((routine != NULL) && routine->info[CREATE_ENTRY_INDEX] != NULL) {
        TEE_Result (*fun)(void) = routine->info[CREATE_ENTRY_INDEX];
        return fun();
    }

    tlogi("default create entry point func\n");
    return TEE_SUCCESS;
}

static TEE_Result ta_open_session_entry_point(uint32_t type, TEE_Param param[TEE_PARAMS_NUM], void **context,
                                              const struct ta_routine_info *routine)
{
    if ((routine != NULL) && (routine->info[OPEN_SESSION_INDEX] != NULL)) {
        TEE_Result (*fun)(uint32_t, TEE_Param *, void **) = routine->info[OPEN_SESSION_INDEX];
        return fun(type, param, context);
    }

    tlogi("default open session entry point func\n");
    return TEE_SUCCESS;
}

static void ta_close_session_entry_point(void *session_context, const struct ta_routine_info *routine)
{
    if ((routine != NULL) && (routine->info[CLOSE_SESSION_INDEX] != NULL)) {
        void (*fun)(void *) = routine->info[CLOSE_SESSION_INDEX];
        fun(session_context);
    } else {
        tlogi("default close session entry point func\n");
    }
}

static void ta_destroy_entry_point(const struct ta_routine_info *routine)
{
    if ((routine != NULL) && (routine->info[DESTROY_ENTRY_INDEX] != NULL)) {
        void (*fun)(void) = routine->info[DESTROY_ENTRY_INDEX];
        fun();
    } else {
        tlogi("default destroy entry point func\n");
    }
}

/*
 * This is a wrapper of ipc_msg_rcv_a.
 * It use to process the possible result of ipc_msg_rcv_a,
 * So no need to process this function's return value.
 * if ipc_msg_rcv_a return NOT OK, only log it and return.
 * if ipc_msg_rcv_a return OK, but the MsgSender is NOT GLOBAL_HANDLE,
 * then try ipc_msg_rcv_a again, until get the Msg from globaltask.
 */
static void msg_rcv_elf(uint32_t timeout, uint32_t *msg_id, void *msgp, uint32_t size)
{
    uint32_t ret;
    uint32_t sender = TASK_INVALID_HANDLE;

    while (sender != GLOBAL_HANDLE) {
        ret = ipc_msg_rcv_a(timeout, msg_id, msgp, size, &sender);
        if (ret != SRE_OK) {
            tloge("Msg recv failed, ret = %u\n", ret);
            sender = TASK_INVALID_HANDLE;
            continue;
        }

        if (sender != GLOBAL_HANDLE)
            tlogw("Msg Rcv recv from sender = %u\n", sender);
    }
}

/*
 * This is a wrapper of ipc_msg_snd.
 * It use to process the possible result of ipc_msg_snd,
 * So no need to process this function's return value.
 * consider add while(1) or TEE_Panic(must success)
 * when ipc_msg_snd return is NOT SRE_OK.
 */
static void msg_send_elf(uint32_t msg_id, taskid_t dst_pid, const void *msgp, uint32_t size)
{
    uint32_t ret;

    ret = ipc_send_msg_sync(msg_id, dst_pid, msgp, size);
    if (ret != SRE_OK)
        tloge("Msg Snd failed, ret = %u\n", ret);
}

/* TA's main entry */
static TEE_Result tee_task_entry_open_session_check(uint32_t init_build,
                                                    const struct ta_init_msg *init_msg,
                                                    char **non_standard_property,
                                                    const struct ta_routine_info *routine)
{
    TEE_Result ret;

    if (init_build != INIT_BUILD)
        return TEE_SUCCESS;

    ret = tee_init(init_msg);
    if (ret != TEE_SUCCESS) {
        tloge("tee init failed\n");
        return ret;
    }
    /*
     * if other_len >= PROPERTY_MAX_LEN
     * non_standard_property is NULL
     */
    if (init_msg->prop.other_len != 0 && init_msg->prop.other_len < PROPERTY_MAX_LEN) {
        init_non_std_property(*non_standard_property, init_msg->prop.other_len);
        TEE_Free(*non_standard_property);
        *non_standard_property = NULL;
    }

    g_state_create_entry = false;
    tlogd("[elf main entry]: Eme Version is %s\n", VERSION_EME);
    ret                  = ta_create_entry_point(routine);
    g_state_create_entry = true;
    if (mutex_lock_ops(&g_init_mutex)) {
        tloge("lock init mutex failed\n");
        return TEE_ERROR_GENERIC;
    }

    g_init_done = INIT_DONE;
    if (pthread_cond_broadcast(&g_init_cond) != 0) {
        tloge("init cond broadcast failed\n");
        (void)pthread_mutex_unlock(&g_init_mutex);
        return TEE_ERROR_GENERIC;
    }
    tlogd("broadcast for init done\n");

    if (pthread_mutex_unlock(&g_init_mutex) != 0) {
        tloge("unlock init mutex failed\n");
        return TEE_ERROR_GENERIC;
    }

    return ret;
}

struct init_build_param {
    uint32_t init_build;
    struct ta_init_msg init_msg;
    char *non_standard_property;
};

static void __attribute__((noinline)) tee_task_entry_init_for_build(struct init_build_param *param, struct ta_to_global_msg *ret_msg,
                                          const struct ta_routine_info *append_args)
{
    uint32_t cmd;

    if (param->init_build != INIT_BUILD) {
        param->non_standard_property = NULL;
        return;
    }
    clear_ta_bss(append_args);
    init(append_args);

    /*
     * Notice:
     * we don't call init func here, but in CALL_TA_OPEN_SESSION cmd,
     * so that global task will have only one pending point.
     *
     * receive teelib init data
     */
    msg_rcv_elf(OS_WAIT_FOREVER, &cmd, &(param->init_msg), sizeof(param->init_msg));
    if (cmd != CALL_TA_OPEN_SESSION_INIT) {
        tloge("receive init cmd error:0x%x\n", cmd);
        ret_msg->ret = TEE_ERROR_INVALID_CMD;
    } else {
        ret_msg->ret = TEE_SUCCESS;
    }
    msg_send_elf(cmd, GLOBAL_HANDLE, ret_msg, sizeof(*ret_msg));

    /* receive non-standard property */
    if (param->init_msg.prop.other_len != 0) {
        /*
         * it is illegal if other_len >= PROPERTY_MAX_LEN
         * so do not malloc mem for it
         */
        if (param->init_msg.prop.other_len < PROPERTY_MAX_LEN)
            param->non_standard_property = TEE_Malloc(param->init_msg.prop.other_len, 0);

        if (param->non_standard_property == NULL) {
            char no_use[1]; /* malloc failed just receive 1 byte data */

            ret_msg->ret = TEE_ERROR_OUT_OF_MEMORY;
            /* just receive 1 byte pending msg */
            msg_rcv_elf(OS_WAIT_FOREVER, &cmd, no_use, 1);
        } else {
            msg_rcv_elf(OS_WAIT_FOREVER, &cmd, param->non_standard_property,
                        param->init_msg.prop.other_len);
        }

        msg_send_elf(cmd, GLOBAL_HANDLE, ret_msg, sizeof(*ret_msg));
    }
}

static TEE_Result tee_task_entry_open_session_main(const struct global_to_ta_msg *entry_msg,
                                                   const uint32_t param_type, const TEE_Param *params,
                                                   bool caller_flag)
{
    if (mutex_lock_ops(&g_init_mutex)) {
        tloge("lock init mutex failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (g_init_done == INIT_NOT_DONE) {
        tlogd("first session not init done, wait\n");
        if (pthread_cond_wait(&g_init_cond, &g_init_mutex) != 0) {
            tloge("init cond wait failed\n");
            pthread_mutex_unlock(&g_init_mutex);
            return TEE_ERROR_GENERIC;
        }
        tlogd("first session init done, go\n");
    }

    if (pthread_mutex_unlock(&g_init_mutex) != 0) {
        tloge("unlock init mutex failed\n");
        return TEE_ERROR_GENERIC;
    }

    tee_session_init(entry_msg->session_id);

    if (caller_flag) {
        TEE_Result ret;
        tlogd("add caller flag set\n");
        ret = check_client_perm(param_type, params);
        if (ret != TEE_SUCCESS) {
            tloge("check client perm failed 0x%x\n", ret);
            return TEE_ERROR_ACCESS_DENIED;
        }
    }

    return TEE_SUCCESS;
}

static void tee_task_entry_init_for_while(uint32_t *cmd, struct global_to_ta_msg *entry_msg, void **session_context_in)
{
    void *session_context = *session_context_in;

    /*
     * Attention:
     *    do not add operation has mutex lock before MsgRcv_ELF
     * exception case:
     *  1.in cpux, TA send msg to gtask after call close_session_entry, and then will call
     *    this function to wait msg
     *  2.in cpuy, gtask recv TA close session msg, and then send REMOVE_THREAD msg to TA service_thread,
     *    service_thread will call hm_thread_termiante to make tcb exit
     *  when case 1 and case 2 occur at the same time, it will cause ta session's state be zombied,
     *  and if it hold lock, it cannot be unlocked
     */
    msg_rcv_elf(OS_WAIT_FOREVER, cmd, entry_msg, sizeof(*entry_msg));
    tlogd("-- TA rsv cmd : 0x%x\n", *cmd);

    if (*cmd == CALL_TA_INVOKE_CMD || *cmd == CALL_TA_CLOSE_SESSION)
        session_context = entry_msg->session_context;

    /*
     * session_id and dev_id may diff
     * between TA calls, so we need
     * re-init tee's context
     */
    tee_init_context(entry_msg->session_id, entry_msg->dev_id);
    set_current_session_type(entry_msg->session_type);
    *session_context_in = session_context;
}

static void close_session_handle(const struct global_to_ta_msg *entry_msg, const struct ta_routine_info *append_args,
                                 void *session_context)
{
    ta_close_session_entry_point(session_context, append_args);
    if (entry_msg->last_session != 0) {
        ta_destroy_entry_point(append_args);
        tee_exit();
    }

    tee_session_exit(entry_msg->session_id);
}

struct open_session_param {
    uint32_t init_build;
    struct ta_init_msg *msg;
    char **property_buf;
    uint32_t param_type;
    TEE_Param *params;
};

static bool get_caller_flag(const struct ta_routine_info *append_args)
{
    /* return true for mandatory check */
    if (append_args == NULL)
        return true;

    return append_args->addcaller_flag;
}

static TEE_Result __attribute__((noinline)) open_session_handle(struct init_build_param *init_param,
                                      const struct global_to_ta_msg *entry_msg,
                                      const struct ta_routine_info *append_args,
                                      void **session_context)
{
    TEE_Result ret;

    ret = tee_task_entry_open_session_check(init_param->init_build, &(init_param->init_msg),
                                            &(init_param->non_standard_property), append_args);
    if (ret != TEE_SUCCESS)
        return ret;

    bool caller_flag = get_caller_flag(append_args);
    ret = tee_task_entry_open_session_main(entry_msg, entry_msg->param_type, entry_msg->params, caller_flag);
    if (ret != TEE_SUCCESS)
        return ret;

    ret = ta_open_session_entry_point(entry_msg->param_type, entry_msg->params, session_context, append_args);
    return ret;
}

static TEE_Result map_params(struct global_to_ta_msg *entry_msg, size_t *map_size, int32_t map_size_size,
                             uint64_t *map_addrs, int32_t map_addrs_size)
{
    bool is_invalid = (entry_msg == NULL || map_size == NULL || map_size_size == 0 || map_addrs == NULL ||
                       map_addrs_size == 0);
    if (is_invalid) {
        tloge("invalid parameters\n");
        return TEE_ERROR_GENERIC;
    }

    if (entry_msg->params == NULL)
        return TEE_SUCCESS;

    uint64_t vaddr = 0;
    uint64_t params_vaddrs[] = { 0, 0, 0, 0 };

    if (map_sharemem(0, (uint64_t)(uintptr_t)entry_msg->params, sizeof(TEE_Param) * map_addrs_size, &vaddr) != 0) {
        tloge("map params sharemem failed\n");
        return TEE_ERROR_GENERIC;
    }
    entry_msg->params = (TEE_Param *)(uintptr_t)vaddr;

    for (int i = 0; i < map_size_size; i++) {
        uint32_t type = TEE_PARAM_TYPE_GET(entry_msg->param_type, i);
        if (type == TEE_PARAM_TYPE_MEMREF_INPUT || type == TEE_PARAM_TYPE_MEMREF_OUTPUT ||
            type == TEE_PARAM_TYPE_MEMREF_INOUT) {
            if (map_sharemem(0, (uint64_t)(uintptr_t)entry_msg->params[i].memref.buffer,
                                 entry_msg->params[i].memref.size + 1, &(params_vaddrs[i])) != 0) {
                tloge("map buffer failed\n");
                goto out;
            }
            entry_msg->params[i].memref.buffer = (void *)(uintptr_t)params_vaddrs[i];
            map_addrs[i] = params_vaddrs[i];
            map_size[i] = entry_msg->params[i].memref.size + 1;
        }
    }

    return TEE_SUCCESS;

out:
    for (int i = 0; i < map_size_size; i++) {
        if (params_vaddrs[i] != 0) {
            if (free_sharemem((void *)(uintptr_t)params_vaddrs[i], map_size[i]) != 0)
                tloge("free sharemem param's vaddr failed\n");
            map_addrs[i] = 0;
        }
        map_size[i] = 0;
    }

    if ((vaddr != 0) && (free_sharemem((void *)(uintptr_t)vaddr, sizeof(TEE_Param) * map_addrs_size) != 0))
        tloge("free sharemem vaddr failed\n");

    return TEE_ERROR_GENERIC;
}

static void unmap_params(struct global_to_ta_msg *entry_msg, size_t *map_size, int32_t map_size_size,
                         uint64_t *map_addrs, int32_t map_addrs_size)
{
    bool is_invalid = (entry_msg == NULL || map_size == NULL || map_size_size == 0 || map_addrs == NULL ||
                       map_addrs_size == 0);
    if (is_invalid) {
        tloge("invalid parameters\n");
        return;
    }

    if (entry_msg->params == NULL)
        return;

    for (int i = 0; i < map_size_size; i++) {
        if (map_size[i] != 0) {
            /*
             * cannot use memref.size because it may be changed by TA
             * must use map_size[i]
             */
            if (free_sharemem((void *)(uintptr_t)map_addrs[i], map_size[i]) != 0)
                tloge("free sharemem buffer failed\n");
            map_addrs[i] = 0;
        }
        map_size[i] = 0;
    }

    if (free_sharemem(entry_msg->params, sizeof(TEE_Param) * map_addrs_size) != 0)
        tloge("free sharemem params failed\n");
    entry_msg->params = NULL;
}

void tee_task_entry(uint32_t init_build, const struct ta_routine_info *append_args)
{
    TEE_Result ret;
    void *session_context = NULL;
    struct global_to_ta_msg entry_msg = {0};
    struct ta_to_global_msg ret_msg = {0};
    uint32_t cmd;
    struct init_build_param init_param = {0};
    size_t map_size[] = { 0, 0, 0, 0 };
    uint64_t map_addrs[] = { 0, 0, 0, 0 };

    init_param.init_build = init_build;
    tee_task_entry_init_for_build(&init_param, &ret_msg, append_args);
    tee_pre_init(init_build, &(init_param.init_msg));

    while (1) {
        tee_task_entry_init_for_while(&cmd, &entry_msg, &session_context);
        if (cmd == CALL_TA_OPEN_SESSION || cmd == CALL_TA_INVOKE_CMD || cmd == CALL_TA_CLOSE_SESSION) {
            ret = map_params(&entry_msg, map_size, sizeof(map_size) / sizeof(size_t),
                             map_addrs, sizeof(map_addrs) / sizeof(uint64_t));
            if (ret != TEE_SUCCESS) {
                tloge("map params failed\n");
                ret_msg.ret = ret;
                msg_send_elf(cmd, GLOBAL_HANDLE, &ret_msg, sizeof(ret_msg));
                continue;
            }
        }

        switch (cmd) {
        case CALL_TA_OPEN_SESSION:
            ret = open_session_handle(&init_param, &entry_msg, append_args, &session_context);
            break;
        case CALL_TA_INVOKE_CMD:
            ret = ta_invoke_command_entry_point(session_context, entry_msg.cmd_id,
                                                entry_msg.param_type, entry_msg.params, append_args);
            break;
        case CALL_TA_CLOSE_SESSION:
            close_session_handle(&entry_msg, append_args, session_context);
            ret = TEE_SUCCESS;
            break;
        default:
            tloge("invalid cmd 0x%x\n", cmd);
            continue;
        }

        unmap_params(&entry_msg, map_size, sizeof(map_size) / sizeof(size_t),
                     map_addrs, sizeof(map_addrs) / sizeof(uint64_t));
        ret_msg.ret = ret;
        if (ret == TEE_SUCCESS && cmd == CALL_TA_OPEN_SESSION)
            ret_msg.session_context = session_context;

        msg_send_elf(cmd, GLOBAL_HANDLE, &ret_msg, sizeof(ret_msg));
    }
}
