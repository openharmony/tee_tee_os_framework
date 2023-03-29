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

#include "tee_core_api.h"
#include <pthread.h>
#include <securec.h>
#include <dlist.h>
#include <mem_ops.h>
#include <ipclib.h>
#include <ipclib_hal.h>
#include "tee_mem_mgmt_api.h"
#include "ta_framework.h"
#include "tee_log.h"
#include "tee_bitmap.h"
#include "tee_init.h"
#include "securec.h"
#include "tee_ta2ta.h"
#include "tee_secfile_load_agent.h"
#include "tee_inner_uuid.h"

#define TASK_SHARE_MEM_PT_NO 0x2
#define OFFSET               7U
#define MOVE_BIT             3
#define MOVE_OFFSET          32
#define MEMORY_OFFSET        4
#define MEMORY_MASK          3
#define COREAPI_ADDR_MASK    0xFFFFFFFF
#define MUTEX_SUCC_RET       0 /* mutex operation will return 0 when it succ */

struct ta2ta_session_handle {
    TEE_TASessionHandle handle;
    TEE_UUID uuid;
    uint32_t session_id;
    uint32_t src_tid;
    struct dlist_node list;
};

struct ta2ta_smc_call_params {
    uint32_t call_type;
    const TEE_UUID *uuid;
    uint32_t session_id;
    uint32_t command_id;
    uint32_t param_types;
    TEE_Param *params;
    TEE_TASessionHandle *handle;
};

static dlist_head(g_handle_head);
static uint8_t g_handle_bitmap[(HANDLE_MAX + OFFSET) >> MOVE_BIT];

struct cancel_state_struct {
    uint32_t session_id;
    bool mask;
    bool flag;
    struct dlist_node list;
};

struct ret_vaild_handle {
    TEE_Result ret;
    TEE_TASessionHandle valid_handle;
};

static dlist_head(g_session_cancel_state);
static pthread_mutex_t g_global_mutex = PTHREAD_MUTEX_INITIALIZER;

static int32_t mutex_lock_ops(pthread_mutex_t *mtx)
{
    int32_t ret = pthread_mutex_lock(mtx);
    if (ret == EOWNERDEAD) /* owner died, use consistent to recover and lock the mutex */
        return pthread_mutex_consistent(mtx);

    return ret;
}

/* add session tls info begin */
static dlist_head(g_tls_info);

void add_tls_info(struct running_info *info)
{
    struct tls_info *tls = NULL;
    int32_t ret;

    if (info == NULL) {
        tloge("invalid info\n");
        return;
    }

    tls = TEE_Malloc(sizeof(*tls), 0);
    if (tls == NULL) {
        tloge("alloc tls info failed\n");
        return;
    }
    tls->info = info;

    ret = mutex_lock_ops(&g_global_mutex);
    if (ret != MUTEX_SUCC_RET) {
        tloge("mutex lock failed with ret %d\n", ret);
        tls->info = NULL;
        TEE_Free(tls);
        return;
    }

    dlist_insert_tail(&tls->list, &g_tls_info);

    ret = pthread_mutex_unlock(&g_global_mutex);
    if (ret != MUTEX_SUCC_RET)
        tloge("mutex unlock failed with ret %d\n", ret);
}

void delete_tls_info(uint32_t session_id)
{
    struct tls_info *info    = NULL;
    struct running_info *tls = NULL;
    bool find                = false;

    int32_t ret = mutex_lock_ops(&g_global_mutex);
    if (ret != MUTEX_SUCC_RET) {
        tloge("mutex lock failed with ret %d\n", ret);
        return;
    }

    dlist_for_each_entry(info, &g_tls_info, struct tls_info, list) {
        tls = info->info;
        if ((tls != NULL) && (tls->session_id == session_id)) {
            find = true;
            break;
        }
    }

    if (find) {
        dlist_delete(&info->list);
        if (memset_s(tls, sizeof(*tls), 0, sizeof(*tls)) != EOK)
            tloge("memset tls failed\n");
        TEE_Free(tls);
        tls        = NULL;
        info->info = NULL;
        TEE_Free(info);
        info = NULL;
    }

    ret = pthread_mutex_unlock(&g_global_mutex);
    if (ret != MUTEX_SUCC_RET)
        tloge("mutex unlock failed with ret %d\n", ret);
}

/* add session tls info end */
static struct cancel_state_struct *get_session_cancel_state(uint32_t session_id)
{
    struct cancel_state_struct *state = NULL;

    dlist_for_each_entry(state, &g_session_cancel_state, struct cancel_state_struct, list) {
        if (state->session_id == session_id)
            return state;
    }

    /* should get here */
    tloge("get cancel state failed!\n");

    return NULL;
}

void add_session_cancel_state(uint32_t session_id)
{
    struct cancel_state_struct *cancel_state = NULL;
    int32_t ret;

    cancel_state = TEE_Malloc(sizeof(*cancel_state), 0);
    if (cancel_state == NULL) {
        tloge("alloc cancel state failed\n");
        return;
    }
    cancel_state->session_id = session_id;
    cancel_state->mask       = true;
    cancel_state->flag       = false;

    ret = mutex_lock_ops(&g_global_mutex);
    if (ret != MUTEX_SUCC_RET) {
        tloge("mutex lock failed with ret %d\n", ret);
        TEE_Free(cancel_state);
        return;
    }
    dlist_insert_tail(&cancel_state->list, &g_session_cancel_state);

    ret = pthread_mutex_unlock(&g_global_mutex);
    if (ret != MUTEX_SUCC_RET)
        tloge("mutex unlock failed with ret %d\n", ret);
}

void del_session_cancel_state(uint32_t session_id)
{
    struct cancel_state_struct *state = NULL;
    int32_t ret                       = mutex_lock_ops(&g_global_mutex);
    if (ret != MUTEX_SUCC_RET) {
        tloge("mutex lock failed with ret %d\n", ret);
        return;
    }

    dlist_for_each_entry(state, &g_session_cancel_state, struct cancel_state_struct, list) {
        if (state->session_id == session_id) {
            dlist_delete(&state->list);
            ret = pthread_mutex_unlock(&g_global_mutex);
            if (ret != MUTEX_SUCC_RET)
                tloge("mutex unlock failed with ret %d\n", ret);

            TEE_Free(state);
            return;
        }
    }

    ret = pthread_mutex_unlock(&g_global_mutex);
    if (ret != MUTEX_SUCC_RET)
        tloge("mutex unlock failed with ret %d\n", ret);
}

void set_session_cancel_flag(bool flag)
{
    int32_t ret = mutex_lock_ops(&g_global_mutex);
    if (ret != MUTEX_SUCC_RET) {
        tloge("mutex lock failed with ret %d\n", ret);
        return;
    }

    struct cancel_state_struct *state = get_session_cancel_state(get_current_session_id());
    if (state != NULL)
        state->flag = flag;

    ret = pthread_mutex_unlock(&g_global_mutex);
    if (ret != MUTEX_SUCC_RET)
        tloge("mutex unlock failed with ret %d\n", ret);
}

void TEE_Panic(TEE_Result panicCode)
{
    PARAM_NOT_USED(panicCode);
    tloge("TEE Panic with panicCode 0x%x\n", panicCode);
    abort();
}

void init_tee_internal_api(void)
{
    set_bitmap(g_handle_bitmap, HANDLE_MAX, 0);
}

static TEE_Result new_ta2ta_session_handle(TEE_TASessionHandle *handle)
{
    struct ta2ta_session_handle *session_handle = NULL;
    int32_t valid_handle;
    uint32_t task_id;
    int32_t ret;

    session_handle = TEE_Malloc(sizeof(*session_handle), 0);
    if (session_handle == NULL) {
        tloge("alloc session handle failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ret = mutex_lock_ops(&g_global_mutex);
    if (ret != MUTEX_SUCC_RET) {
        tloge("mutex lock failed with ret %d\n", ret);
        TEE_Free(session_handle);
        return TEE_ERROR_GENERIC;
    }

    valid_handle = get_valid_bit(g_handle_bitmap, HANDLE_MAX);
    if (valid_handle == -1) { /* -1 means invalid handle */
        ret = pthread_mutex_unlock(&g_global_mutex);
        if (ret != MUTEX_SUCC_RET)
            tloge("mutex unlock failed with ret %d\n", ret);

        TEE_Free(session_handle);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    session_handle->handle = (TEE_TASessionHandle)valid_handle;
    task_id = get_self_taskid();
    if (task_id == SRE_PID_ERR) {
        tloge("get taskid failed\n");
        TEE_Free(session_handle);

        ret = pthread_mutex_unlock(&g_global_mutex);
        if (ret != MUTEX_SUCC_RET)
            tloge("mutex unlock failed with ret %d\n", ret);

        return TEE_ERROR_GENERIC;
    }

    session_handle->src_tid = taskid_to_tid(task_id);
    dlist_init(&session_handle->list);

    set_bitmap(g_handle_bitmap, HANDLE_MAX, valid_handle);
    dlist_insert_tail(&session_handle->list, &g_handle_head);

    ret = pthread_mutex_unlock(&g_global_mutex);
    if (ret != MUTEX_SUCC_RET)
        tloge("mutex unlock failed with ret %d\n", ret);

    *handle = valid_handle;

    return TEE_SUCCESS;
}

static TEE_Result set_ta2ta_session_handle(const TEE_UUID *uuid, uint32_t session_id, TEE_TASessionHandle handle)
{
    struct ta2ta_session_handle *s_handle = NULL;
    bool find                             = false;
    TEE_Result s_ret                      = TEE_ERROR_GENERIC;

    int32_t ret = mutex_lock_ops(&g_global_mutex);
    if (ret != MUTEX_SUCC_RET) {
        tloge("mutex lock failed with ret %d\n", ret);
        return s_ret;
    }

    dlist_for_each_entry(s_handle, &g_handle_head, struct ta2ta_session_handle, list) {
        if (s_handle->handle == handle) {
            find = true;
            break;
        }
    }

    if (find) {
        if (uuid == NULL) {
            clear_bitmap(g_handle_bitmap, HANDLE_MAX, s_handle->handle);
            tlogd("find handle session_handle:0x%x\n", handle);
            dlist_delete(&s_handle->list);
            TEE_Free(s_handle);
            s_handle = NULL;
            s_ret    = TEE_SUCCESS;
        } else {
            s_handle->session_id = session_id;
            s_handle->uuid       = *uuid;
            s_ret                = TEE_SUCCESS;
        }
    }

    ret = pthread_mutex_unlock(&g_global_mutex);
    if (ret != MUTEX_SUCC_RET)
        tloge("mutex unlock failed with ret %d\n", ret);

    return s_ret;
}

static void delete_ta2ta_session_id(TEE_TASessionHandle session_handle)
{
    /* input param NULL/0 will clear all mem */
    if (set_ta2ta_session_handle(NULL, 0, session_handle) != TEE_SUCCESS)
        tloge("delete ta session failed\n");
}

static TEE_Result get_ta2ta_session_handle(TEE_TASessionHandle handle, struct ta2ta_session_handle **session_handle)
{
    struct ta2ta_session_handle *s_handle = NULL;
    int32_t ret;

    if (session_handle == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    ret = mutex_lock_ops(&g_global_mutex);
    if (ret != MUTEX_SUCC_RET) {
        tloge("mutex lock failed with ret %d\n", ret);
        return TEE_ERROR_GENERIC;
    }

    if (!is_bit_seted(g_handle_bitmap, HANDLE_MAX, handle)) {
        ret = pthread_mutex_unlock(&g_global_mutex);
        if (ret != MUTEX_SUCC_RET)
            tloge("mutex unlock failed with ret %d\n", ret);

        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    dlist_for_each_entry(s_handle, &g_handle_head, struct ta2ta_session_handle, list) {
        if (s_handle->handle == handle) {
            *session_handle = s_handle;
            ret             = pthread_mutex_unlock(&g_global_mutex);
            if (ret != MUTEX_SUCC_RET)
                tloge("mutex unlock failed with ret %d\n", ret);

            return TEE_SUCCESS;
        }
    }
    ret = pthread_mutex_unlock(&g_global_mutex);
    if (ret != MUTEX_SUCC_RET)
        tloge("mutex unlock failed with ret %d\n", ret);

    return TEE_ERROR_ITEM_NOT_FOUND;
}

static void *alloc_sharemem(uint32_t size)
{
    TEE_UUID gtask_uuid = TEE_SERVICE_GLOBAL;
    return alloc_sharemem_aux(&gtask_uuid, size);
}

static void common_free_sharemem(const int8_t *addr, int32_t size)
{
    if (free_sharemem((void *)addr, size) != 0) /* 0 means success */
        tloge("free share memory fail\n");
}

static inline TEE_Result push_params_check(const TEE_Param *params, const struct smc_operation *operation)
{
    if (params == NULL || operation == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    return TEE_SUCCESS;
}

static TEE_Result handle_mem_buffer(uint32_t i, const TEE_Param *params, struct smc_operation *operation, int8_t **buf)
{
    if (params[i].memref.size > UINT32_MAX) {
        tloge("buffer size is invalid\n");
        return TEE_ERROR_GENERIC;
    }
    operation->params[i].memref.size   = (uint32_t)params[i].memref.size;
    buf[i]                             = alloc_sharemem(params[i].memref.size);
    operation->params[i].memref.buffer = (uint32_t)((uintptr_t)buf[i] & COREAPI_ADDR_MASK);

    /* change for codex CONSTANT_EXPRESSION_RESULT */
#ifdef __aarch64__
    operation->p_h_addr[i] = (uint32_t)(((uintptr_t)buf[i]) >> MOVE_OFFSET);
#else
    operation->p_h_addr[i] = 0;
#endif

    if (buf[i] == NULL) {
        tloge("alloc params[%u] membuff fail, size = %zu\n", i, params[i].memref.size);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    if (memcpy_s(buf[i], params[i].memref.size, params[i].memref.buffer, params[i].memref.size) != EOK)
        return TEE_ERROR_GENERIC;

    return TEE_SUCCESS;
}

static void handle_malloc_fail(uint32_t types, int8_t **buf, uint32_t buf_num, const TEE_Param *params)
{
    uint32_t i;
    uint32_t param_type;

    for (i = 0; i < buf_num; i++) {
        param_type = TEE_PARAM_TYPE_GET(types, i);
        switch (param_type) {
        case TEE_PARAM_TYPE_NONE:
        case TEE_PARAM_TYPE_VALUE_INPUT:
        case TEE_PARAM_TYPE_VALUE_OUTPUT:
        case TEE_PARAM_TYPE_VALUE_INOUT:
            break;
        case TEE_PARAM_TYPE_MEMREF_INPUT:
        case TEE_PARAM_TYPE_MEMREF_OUTPUT:
        case TEE_PARAM_TYPE_MEMREF_INOUT:
            if (buf[i] != NULL) {
                common_free_sharemem(buf[i], params[i].memref.size);
                buf[i] = NULL;
            }
            break;
        default:
            tloge("invalid param[%u] type %u\n", i, param_type);
            break;
        }
    }
}

static TEE_Result push_params_in_shareregion(uint32_t types, const TEE_Param *params, struct smc_operation *operation)
{
    uint32_t i;
    uint32_t param_type;
    void *buf[TEE_PARAM_NUM] = {0};

    TEE_Result ret = push_params_check(params, operation);
    if (ret != TEE_SUCCESS)
        return ret;

    if (memset_s(operation, sizeof(*operation), 0x0, sizeof(*operation)) != EOK)
        return TEE_ERROR_GENERIC;

    operation->types = types;
    for (i = 0; i < TEE_PARAM_NUM; i++) {
        param_type = TEE_PARAM_TYPE_GET(types, i);
        switch (param_type) {
        case TEE_PARAM_TYPE_NONE:
            break;
        case TEE_PARAM_TYPE_VALUE_INPUT:
        case TEE_PARAM_TYPE_VALUE_OUTPUT:
        case TEE_PARAM_TYPE_VALUE_INOUT:
            operation->params[i].value.a = params[i].value.a;
            operation->params[i].value.b = params[i].value.b;
            break;
        case TEE_PARAM_TYPE_MEMREF_INPUT:
        case TEE_PARAM_TYPE_MEMREF_OUTPUT:
        case TEE_PARAM_TYPE_MEMREF_INOUT:
            ret = handle_mem_buffer(i, params, operation, (int8_t **)buf);
            if (ret != TEE_SUCCESS)
                goto malloc_fail;
            break;
        default:
            tloge("invalid param[%u] type %u\n", i, param_type);
            ret = TEE_ERROR_BAD_PARAMETERS;
            goto malloc_fail;
        }
    }

    return TEE_SUCCESS;

malloc_fail:
    handle_malloc_fail(types, (int8_t **)buf, TEE_PARAM_NUM, params);
    return ret;
}

static TEE_Result param_check(const TEE_Param *params, const struct smc_operation *orig_operation,
                              const struct smc_operation *operation)
{
    if (params == NULL || orig_operation == NULL || operation == NULL) {
        tloge("param invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static void clean_buf_addr(struct smc_operation *orig_operation, struct smc_operation *operation, uint32_t i)
{
    operation->p_h_addr[i]                  = 0;
    operation->params[i].memref.buffer      = 0;
    orig_operation->p_h_addr[i]             = 0;
    orig_operation->params[i].memref.buffer = 0;
}

static TEE_Result pop_params_from_shareregion(uint32_t types, TEE_Param *params, struct smc_operation *orig_operation,
                                              struct smc_operation *operation, bool copy)
{
    uint32_t param_type;

    TEE_Result ret = param_check(params, orig_operation, operation);
    if (ret != TEE_SUCCESS)
        return ret;

    for (uint32_t i = 0; i < TEE_PARAM_NUM; i++) {
        param_type = TEE_PARAM_TYPE_GET(types, i);
        switch (param_type) {
        case TEE_PARAM_TYPE_NONE:
            break;
        case TEE_PARAM_TYPE_VALUE_INPUT:
        case TEE_PARAM_TYPE_VALUE_OUTPUT:
        case TEE_PARAM_TYPE_VALUE_INOUT:
            if (copy) {
                params[i].value.a = operation->params[i].value.a;
                params[i].value.b = operation->params[i].value.b;
            }
            break;
        case TEE_PARAM_TYPE_MEMREF_INPUT:
        case TEE_PARAM_TYPE_MEMREF_OUTPUT:
        case TEE_PARAM_TYPE_MEMREF_INOUT:
            tlogd("params buffer %x!\n", orig_operation->params[i].memref.buffer);
            void *orig_buf = (void *)(uintptr_t)orig_operation->params[i].memref.buffer;
            unsigned int orig_size = orig_operation->params[i].memref.size;
            if (orig_operation->p_h_addr[i] != 0) {
                uint64_t tmp_addr = (((uint64_t)orig_operation->p_h_addr[i]) << MOVE_OFFSET) | (uintptr_t)orig_buf;
                orig_buf          = (void *)(uintptr_t)tmp_addr;
            }

            if (orig_buf == NULL)
                continue;

            if (copy && memcpy_s(params[i].memref.buffer, orig_size, orig_buf, orig_size) != EOK)
                ret = TEE_ERROR_GENERIC;

            params[i].memref.size = operation->params[i].memref.size;

            if (copy && memset_s(orig_buf, orig_size, 0, orig_size) != EOK)
                ret = TEE_ERROR_GENERIC;

            common_free_sharemem(orig_buf, orig_size);
            clean_buf_addr(orig_operation, operation, i); /* orig_buf leaves its scope, no need to set to NULL */
            break;
        default:
            ret = TEE_ERROR_BAD_PARAMETERS;
            break;
        }
    }

    return ret;
}

static void ta2ta_pseudo_free_sharedmem(uint8_t *op, smc_cmd_t *smc_cmd, struct ret_vaild_handle *ret_handle,
                                        const struct ta2ta_ret_msg *ret_msg)
{
    if (op != NULL) {
        TEE_Free(op);
        op = NULL;
    }

    if (ret_msg->ret == TEE_ERROR_SERVICE_NOT_EXIST)
        ret_handle->ret = TEE_ERROR_ITEM_NOT_FOUND;

    /* smc cmd points to the beggining of the shared memory area */
    if (memset_s(smc_cmd, PAGE_SIZE, 0, PAGE_SIZE) != EOK) {
        if (ret_handle->ret == TEE_SUCCESS)
            ret_handle->ret = TEE_ERROR_GENERIC;
    }

    common_free_sharemem((int8_t *)smc_cmd, PAGE_SIZE);
    smc_cmd = NULL;

    if (ret_handle->valid_handle != UINT32_MAX)
        delete_ta2ta_session_id(ret_handle->valid_handle);
}

static void release_mem_in_params(uint32_t types, struct smc_operation *orig_operation,
                                  struct smc_operation *operation)
{
    uint32_t i;
    uint32_t param_type;
    uint64_t tmp_addr;

    /* type is 0 means no need to handle */
    if (types == 0)
        return;

    if (orig_operation == NULL || operation == NULL)
        return;

    for (i = 0; i < TEE_PARAM_NUM; i++) {
        param_type = TEE_PARAM_TYPE_GET(types, i);
        switch (param_type) {
        case TEE_PARAM_TYPE_MEMREF_INPUT:
        case TEE_PARAM_TYPE_MEMREF_OUTPUT:
        case TEE_PARAM_TYPE_MEMREF_INOUT:
            tmp_addr = ((((uint64_t)orig_operation->p_h_addr[i]) << MOVE_OFFSET) |
                        ((uint64_t)orig_operation->params[i].memref.buffer));
            common_free_sharemem((int8_t *)(uintptr_t)tmp_addr, orig_operation->params[i].memref.size);
            clean_buf_addr(orig_operation, operation, i);
            tmp_addr = 0;
            break;
        default:
            break;
        }
    }
}

/*
 * Notice:
 * TA2TA call will alloc a copy of TA's params in all TA sharemem region,
 * It may be cause some secure problem.
 */
#define TA2TA_OPEN_SESSION   0x1
#define TA2TA_INVOKE_COMMAND 0x2
#define TA2TA_CLOSE_SESSION  0x3

static TEE_Result ta2ta_pseudo_init_smc_cmd(const struct ta2ta_smc_call_params *smc_call_params,
                                            struct ta2ta_msg *call_msg, TEE_TASessionHandle *valid_handle,
                                            smc_cmd_t *smc_cmd)
{
    switch (smc_call_params->call_type) {
    case TA2TA_OPEN_SESSION:
        smc_cmd->cmd_type = CMD_TYPE_GLOBAL;
        smc_cmd->context    = 0;
        smc_cmd->cmd_id     = GLOBAL_CMD_ID_OPEN_SESSION;
        if (new_ta2ta_session_handle(valid_handle) != TEE_SUCCESS) {
            tloge("get valid handle failed\n");
            return TEE_ERROR_GENERIC;
        }
        call_msg->handle = *valid_handle;
        break;
    case TA2TA_INVOKE_COMMAND:
        smc_cmd->cmd_type = CMD_TYPE_TA;
        smc_cmd->context    = smc_call_params->session_id;
        smc_cmd->cmd_id     = smc_call_params->command_id;
        break;
    case TA2TA_CLOSE_SESSION:
        smc_cmd->cmd_type = CMD_TYPE_GLOBAL;
        smc_cmd->context    = smc_call_params->session_id;
        smc_cmd->cmd_id     = GLOBAL_CMD_ID_CLOSE_SESSION;
        break;
    default:
        /* should not get here */
        tloge("invalid call type %u\n", smc_call_params->call_type);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result ta2ta_pseudo_alloc_sharedmem(const TEE_UUID *uuid, smc_cmd_t **smc_cmd, uint8_t **shared_mem)
{
    if (uuid == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    /*
     * Allocate shared memory buffer for all the information that is needed,
     * We need to allocate it all at once because the operation allocates page aligned buffers
     * and the fractions are very small which would lead to waste of shared memory
     */
    *shared_mem = alloc_sharemem(PAGE_SIZE);
    if (*shared_mem == NULL) {
        tloge("alloc smc cmd fail\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    if (memset_s(*shared_mem, PAGE_SIZE, 0, PAGE_SIZE) != EOK) {
        common_free_sharemem((int8_t *)(*shared_mem), PAGE_SIZE);
        *shared_mem = NULL;
        return TEE_ERROR_GENERIC;
    }

    /* construct new smc cmd */
    *smc_cmd = (smc_cmd_t *)(*shared_mem);
    *shared_mem += sizeof(**smc_cmd);

    if (memcpy_s((*smc_cmd)->uuid, sizeof((*smc_cmd)->uuid), uuid, sizeof(*uuid)) != EOK) {
        common_free_sharemem((int8_t *)(*smc_cmd), sizeof(**smc_cmd));
        *smc_cmd = NULL;
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

static TEE_Result ta2ta_pseudo_handle_msg(const struct ta2ta_smc_call_params *smc_call_params,
                                          const smc_cmd_t *smc_cmd, struct ta2ta_msg *call_msg,
                                          struct ta2ta_ret_msg *ret_msg)
{
    uint32_t ret;

    call_msg->cmd = (uintptr_t)smc_cmd;
    if (ipc_msg_snd(TA2TA_CALL, get_global_handle(), call_msg, sizeof(*call_msg)) != SRE_OK) {
        tloge("message send failed\n");
        return TEE_ERROR_GENERIC;
    }
    ret = ipc_msg_rcv_safe(OS_WAIT_FOREVER, NULL, ret_msg, sizeof(*ret_msg), get_global_handle());
    if (ret != SRE_OK) {
        tloge("receive msg fail in ta2ta call, ret=0x%x\n", ret);
        return TEE_ERROR_GENERIC;
    }

    (void)smc_call_params;
    return TEE_SUCCESS;
}

static TEE_Result ta2ta_pseudo_handle_ret(struct ta2ta_smc_call_params *smc_call_params, struct ta2ta_ret_msg *ret_msg,
                                          uint8_t *op, struct smc_operation *operation,
                                          TEE_TASessionHandle *valid_handle)
{
    TEE_Result ret   = ret_msg->ret;
    smc_cmd_t *t_cmd = &(ret_msg->cmd);

    if (smc_call_params->param_types) {
        /*
         * operation was part of the shared memory and might be corrupted so use the saved
         * copy for buffer addresses
         */
        if (pop_params_from_shareregion(smc_call_params->param_types, smc_call_params->params,
                                        (struct smc_operation *)op, operation,
                                        ret_msg->ret == TEE_SUCCESS) != TEE_SUCCESS)
            tloge("pop params from share region failed\n");
    }

    if (ret_msg->ret == TEE_SUCCESS) {
        /* in TA2TA_OPEN_SESSION, handle cannot be NULL */
        if ((smc_call_params->call_type == TA2TA_OPEN_SESSION) && (smc_call_params->handle != NULL)) {
            tlogd("ta2ta session id = 0x%x\n", t_cmd->context);
            ret = set_ta2ta_session_handle(smc_call_params->uuid, t_cmd->context, *valid_handle);
            if (ret == TEE_SUCCESS) {
                *(smc_call_params->handle) = *valid_handle;
                *valid_handle              = UINT32_MAX; /* not delete session handle */
            }
        }
    }
    return ret;
}

static TEE_Result ta2ta_pseudo_smc_call(struct ta2ta_smc_call_params *smc_call_params)
{
    smc_cmd_t *smc_cmd                 = NULL;
    struct smc_operation *operation    = NULL;
    struct ta2ta_msg call_msg          = {0};
    struct ta2ta_ret_msg ret_msg       = {0};
    struct ret_vaild_handle ret_handle = {TEE_ERROR_GENERIC, UINT32_MAX};
    uint8_t *shared_mem                = NULL;
    uint8_t *op                        = NULL;

    ret_handle.ret = ta2ta_pseudo_alloc_sharedmem(smc_call_params->uuid, &smc_cmd, &shared_mem);
    if (ret_handle.ret != TEE_SUCCESS)
        return ret_handle.ret;

    ret_handle.ret = TEE_ERROR_GENERIC;

    if (ta2ta_pseudo_init_smc_cmd(smc_call_params, &call_msg, &ret_handle.valid_handle, smc_cmd) != TEE_SUCCESS)
        goto free_shardmem;

    if (smc_call_params->param_types) {
        /* operation has to be 4 byte aligned */
        operation = (struct smc_operation *)(((uintptr_t)shared_mem + MEMORY_OFFSET) & (~MEMORY_MASK));
        op        = TEE_Malloc(sizeof(*operation), 0);
        if (op == NULL)
            goto free_shardmem;

        ret_handle.ret = push_params_in_shareregion(smc_call_params->param_types, smc_call_params->params,
                                                    (struct smc_operation *)op);
        if (ret_handle.ret != TEE_SUCCESS)
            goto free_shardmem;

        if (memcpy_s(operation, PAGE_SIZE - ((uintptr_t)(operation) - (uintptr_t)(smc_cmd)), op,
            sizeof(*operation)) != EOK) {
            ret_handle.ret = TEE_ERROR_GENERIC;
            goto release_param_mem;
        }

        smc_cmd->operation_phys = (uint32_t)((uintptr_t)operation & COREAPI_ADDR_MASK);
#ifdef __aarch64__
        smc_cmd->operation_h_phys = (uint32_t)(((uintptr_t)operation) >> MOVE_OFFSET);
#else
        smc_cmd->operation_h_phys = 0;
#endif
    } else {
        smc_cmd->operation_phys   = 0;
        smc_cmd->operation_h_phys = 0;
    }
    /* Not set:dev_file_id, agent_id, login_method, login_data, err_origin */
    ret_handle.ret = ta2ta_pseudo_handle_msg(smc_call_params, smc_cmd, &call_msg, &ret_msg);
    if (ret_handle.ret != TEE_SUCCESS)
        goto release_param_mem;

    ret_handle.ret = ta2ta_pseudo_handle_ret(smc_call_params, &ret_msg, op, operation, &ret_handle.valid_handle);
    goto free_shardmem;

release_param_mem:
    release_mem_in_params(smc_call_params->param_types, (struct smc_operation *)op, operation);
free_shardmem:
    ta2ta_pseudo_free_sharedmem(op, smc_cmd, &ret_handle, &ret_msg);
    return ret_handle.ret;
}

TEE_Result TEE_OpenTASession(const TEE_UUID *destination, uint32_t cancellationRequestTimeout, uint32_t paramTypes,
                             TEE_Param params[TEE_PARAM_NUM], TEE_TASessionHandle *session, uint32_t *returnOrigin)
{
    TEE_Result ret;

    if ((destination == NULL) || (session == NULL))
        return TEE_ERROR_BAD_PARAMETERS;

    PARAM_NOT_USED(cancellationRequestTimeout);

    if (returnOrigin != NULL)
        *returnOrigin = TEE_ORIGIN_TEE;

    struct ta2ta_smc_call_params smc_call_params = {0};
    smc_call_params.call_type                    = TA2TA_OPEN_SESSION;
    smc_call_params.uuid                         = destination;
    smc_call_params.param_types                  = paramTypes;
    smc_call_params.params                       = params;
    smc_call_params.handle                       = session;
    ret                                          = ta2ta_pseudo_smc_call(&smc_call_params);

    return ret;
}

void TEE_CloseTASession(TEE_TASessionHandle session)
{
    struct ta2ta_session_handle *session_handle = NULL;
    TEE_Result ret;
    int32_t pthread_ret;

    if (get_ta2ta_session_handle(session, &session_handle) != TEE_SUCCESS) {
        tloge("ta2ta session id is not exist\n");
        return;
    }

    struct ta2ta_smc_call_params smc_call_params = {0};
    smc_call_params.call_type                    = TA2TA_CLOSE_SESSION;
    smc_call_params.uuid                         = &session_handle->uuid;
    smc_call_params.session_id                   = session_handle->session_id;
    smc_call_params.handle                       = NULL;

    ret = ta2ta_pseudo_smc_call(&smc_call_params);
    if (ret != TEE_SUCCESS) {
        tloge("ta2ta close sesion failed ret:0x%x\n", ret);
        return;
    }

    pthread_ret = mutex_lock_ops(&g_global_mutex);
    if (pthread_ret != MUTEX_SUCC_RET) {
        tloge("mutex lock failed with ret %d\n", pthread_ret);
        return;
    }

    clear_bitmap(g_handle_bitmap, HANDLE_MAX, session_handle->handle);
    dlist_delete(&session_handle->list);

    pthread_ret = pthread_mutex_unlock(&g_global_mutex);
    if (pthread_ret != MUTEX_SUCC_RET)
        tloge("mutex unlock failed with ret %d\n", pthread_ret);

    TEE_Free(session_handle);
}

TEE_Result TEE_InvokeTACommand(TEE_TASessionHandle session, uint32_t cancellationRequestTimeout, uint32_t commandID,
                               uint32_t paramTypes, TEE_Param params[TEE_PARAM_NUM], uint32_t *returnOrigin)
{
    TEE_Result ret;
    PARAM_NOT_USED(cancellationRequestTimeout);

    struct ta2ta_session_handle *session_handle = NULL;

    if (returnOrigin != NULL)
        *returnOrigin = TEE_ORIGIN_TEE;

    if (get_ta2ta_session_handle(session, &session_handle) != TEE_SUCCESS) {
        tloge("ta2ta session_handle is not exist\n");
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    struct ta2ta_smc_call_params smc_call_params = {0};
    smc_call_params.call_type                    = TA2TA_INVOKE_COMMAND;
    smc_call_params.uuid                         = &session_handle->uuid;
    smc_call_params.session_id                   = session_handle->session_id;
    smc_call_params.command_id                   = commandID;
    smc_call_params.param_types                  = paramTypes;
    smc_call_params.params                       = params;
    smc_call_params.handle                       = NULL;
    ret                                          = ta2ta_pseudo_smc_call(&smc_call_params);

    return ret;
}

bool TEE_GetCancellationFlag(void)
{
    return false; /* not suport */
}

bool TEE_UnmaskCancellation(void)
{
    return false; /* not suport */
}

bool TEE_MaskCancellation(void)
{
    return false; /* not suport */
}

void delete_all_ta2ta_session(uint32_t tid)
{
    struct ta2ta_session_handle *handle_entry = NULL;
    struct ta2ta_session_handle *tmp_entry = NULL;

    int32_t ret = mutex_lock_ops(&g_global_mutex);
    if (ret != MUTEX_SUCC_RET) {
        tloge("mutex lock failed with ret %d\n", ret);
        return;
    }

    dlist_for_each_entry_safe(handle_entry, tmp_entry, &g_handle_head, struct ta2ta_session_handle, list) {
        if (handle_entry->src_tid == tid) {
            clear_bitmap(g_handle_bitmap, HANDLE_MAX, handle_entry->handle);
            dlist_delete(&handle_entry->list);
            TEE_Free(handle_entry);
            handle_entry = NULL;
        }
    }

    ret = pthread_mutex_unlock(&g_global_mutex);
    if (ret != MUTEX_SUCC_RET)
        tloge("mutex unlock failed with ret %d\n", ret);
}

void clear_session_exception(uint32_t session_id)
{
    delete_tls_info(session_id);
    del_session_cancel_state(session_id);
}

__attribute__((weak)) TEE_UUID *get_current_uuid(void)
{
    return get_running_uuid();
}

uint32_t get_current_session_id(void)
{
    struct running_info *info = get_tls_running_info();

    return (info != NULL) ? info->session_id : 0U;
}
