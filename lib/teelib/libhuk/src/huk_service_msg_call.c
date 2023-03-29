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
#include <errno.h>
#include <ipclib.h>
#include <securec.h>
#include <pthread.h>
#include <tee_log.h>
#include <tee_ext_api.h>
#include "huk_service_msg_call.h"

static pthread_mutex_t g_msg_call_mutex = PTHREAD_MUTEX_INITIALIZER;
int32_t huk_srv_msg_call(struct huk_srv_msg *msg, struct huk_srv_rsp *rsp)
{
    errno_t rc;
    cref_t rslot = 0;

    if (msg == NULL || rsp == NULL) {
        tloge("msg or rsp is NULL\n");
        return -1;
    }

    if (pthread_mutex_lock(&g_msg_call_mutex) != 0) {
        tloge("huk msg call mutex lock failed\n");
        return -1;
    }
    rc = ipc_get_ch_from_path(HUK_PATH, &rslot);
    if (rc == -1) {
        tloge("huksrv: get channel from pathmgr failed\n");
        if (pthread_mutex_unlock(&g_msg_call_mutex) != 0)
            tloge("huk msg call mutex unlock failed\n");
        return rc;
    }

    rc = ipc_msg_call(rslot, msg, sizeof(*msg), rsp, sizeof(*rsp), -1);
    if (rc < 0)
        tloge("msg send 0x%llx failed: 0x%x\n", rslot, rc);

    (void)ipc_release_from_path(HUK_PATH, rslot);
    if (pthread_mutex_unlock(&g_msg_call_mutex) != 0) {
        tloge("huk msg call mutex unlock failed\n");
        return -1;
    }
    return rc;
}

