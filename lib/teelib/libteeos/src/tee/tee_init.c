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
#include "tee_init.h"

#include <securec.h>

#include <unistd.h>
#include "spawn_ext.h"
#include "tee_defines.h"
#include "tee_obj.h"
#include "tee_reserved_api.h"
#include "tee_log.h"
#include "tee_ext_api.h"
#include "tee_mem_mgmt_api.h"
#include "tee_ta2ta.h"

/* TLS support for running_info per session */
static pthread_key_t g_info_key;
static bool g_info_key_state = false;
/*
 * For compatible reason, an old TA may not use the tls to set running info,
 * we will use the global value.
 */
static struct running_info g_running_info;

static bool init_tls_running_info_key(void)
{
    if (!g_info_key_state) {
        if (pthread_key_create(&g_info_key, NULL) == 0)
            g_info_key_state = true;
        else
            tloge("create info key failed\n");
    }

    return g_info_key_state;
}

/* It only affect running_info, ignore this error. */
void tee_pre_init(int32_t init_build, const struct ta_init_msg *init_msg)
{
    struct running_info *info = NULL;

    if ((init_build == 0) && (init_msg != NULL)) {
        if (memcpy_s(&g_running_info.uuid, sizeof(g_running_info.uuid), &(init_msg->prop.uuid),
                     sizeof(init_msg->prop.uuid)) != EOK) {
            tloge("copy data failed\n");
            return;
        }
    }

    if (!init_tls_running_info_key()) {
        tloge("init tls running info key failed\n");
        return;
    }

    info = TEE_Malloc(sizeof(*info), 0);
    if (info == NULL) {
        tloge("alloc info failed\n");
        return;
    }
    info->session_id = 0;
    (void)pthread_setspecific(g_info_key, info); /* only has one return value */

    add_tls_info(info);
}

/* tee lib inititial, 1 TA's instance call 1 time only */
TEE_Result tee_init(const struct ta_init_msg *init_msg)
{
    if (init_msg == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (memcpy_s(&g_running_info.uuid, sizeof(g_running_info.uuid), &(init_msg->prop.uuid),
                 sizeof(init_msg->prop.uuid)) != EOK) {
        tloge("copy data failed\n");
        return TEE_ERROR_SECURITY;
    }

    /* Notice: there's one ipc with ssa in init_property */
    init_property(init_msg->login_method, NULL, &init_msg->prop);
    init_tee_internal_api();
    tee_log_init(&init_msg->prop.uuid);
    TEE_Result ret = tee_obj_init();
    if (ret != TEE_SUCCESS) {
        tloge("tee obj init failed\n");
        return ret;
    }

    return TEE_SUCCESS;
}

void tee_exit(void)
{
    /* for backward compatible */
}

void tee_session_init(uint32_t session_id)
{
    add_session_cancel_state(session_id);
}

void tee_session_exit(uint32_t session_id)
{
    struct running_info *info = NULL;

    del_session_cancel_state(session_id);

    info = get_tls_running_info();
    if (info != NULL) {
        delete_tls_info(session_id);
        info = NULL;
    }
    if (g_info_key_state)
        (void)pthread_setspecific(g_info_key, NULL); /* only has one return value */
}

void tee_init_context(uint32_t session_id, uint32_t dev_id)
{
    struct running_info *info = NULL;

    info = get_tls_running_info();
    if (info != NULL) {
        info->dev_id     = dev_id;
        info->session_id = session_id;
    }
}

uint32_t get_current_dev_id(void)
{
    struct running_info *info = NULL;

    info = get_tls_running_info();
    if (info != NULL)
        return info->dev_id;
    else
        return INVALID_DEV_ID;
}

void set_global_handle(uint32_t handle)
{
    struct running_info *info = NULL;

    info = get_tls_running_info();
    if (info != NULL)
        info->global_handle = handle;
}

/* TA's global variable can be modified by TA, So here Must return GLOBAL_HANDLE(0) */
uint32_t get_global_handle(void)
{
    return GLOBAL_HANDLE;
}

void set_current_session_type(uint32_t session_type)
{
    struct running_info *info = NULL;

    info = get_tls_running_info();
    if (info != NULL)
        info->session_type = session_type;
}

struct running_info *get_tls_running_info(void)
{
    if (!g_info_key_state)
        return &g_running_info;

    return pthread_getspecific(g_info_key);
}

void set_running_uuid(void)
{
    struct running_info *info = NULL;
    spawn_uuid_t uuid = {0};
    pid_t pid;

    pid = getpid();
    if (pid < 0) {
        tloge("get pid is error\n");
        return;
    }

    int32_t ret = getuuid(pid, &uuid);
    if (ret < 0) {
        tloge("get uuid is error\n");
        return;
    }

    info = get_tls_running_info();
    if (info != NULL)
        info->uuid = uuid.uuid;
}

TEE_UUID *get_running_uuid(void)
{
    return &g_running_info.uuid;
}
