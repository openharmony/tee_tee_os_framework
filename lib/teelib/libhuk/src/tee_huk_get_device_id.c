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
#include "tee_huk_get_device_id.h"
#include "tee_huk_derive_key.h"
#include <securec.h>
#include <errno.h>
#include <tee_log.h>
#include "huk_service_msg.h"
#include "huk_service_msg_call.h"

TEE_Result get_device_id_prop(uint8_t *dst, uint32_t len)
{
    if (dst == NULL || len != sizeof(TEE_UUID)) {
        tloge("invalid param\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    struct huk_srv_msg msg;
    struct huk_srv_rsp rsp;
    (void)memset_s(&msg, sizeof(msg), 0, sizeof(msg));
    (void)memset_s(&rsp, sizeof(rsp), 0, sizeof(rsp));

    uint8_t *dev_id_shared = huk_alloc_shared_mem(len);
    if (dev_id_shared == NULL) {
        tloge("malloc device id buff shared failed, size = 0x%x\n", len);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    msg.data.deviceid_msg.buf = (uintptr_t)dev_id_shared;
    msg.data.deviceid_msg.size = len;
    msg.header.send.msg_id = CMD_HUK_GET_DEVICEID;

    if (huk_srv_msg_call(&msg, &rsp) < 0)
        goto clean;

    if (rsp.data.ret == TEE_SUCCESS) {
        if (memcpy_s(dst, len, dev_id_shared, len) != EOK) {
            tloge("copy device id shared failed\n");
            rsp.data.ret = TEE_ERROR_GENERIC;
        }
    }
clean:
    huk_free_shared_mem(dev_id_shared, len);
    return rsp.data.ret;
}
